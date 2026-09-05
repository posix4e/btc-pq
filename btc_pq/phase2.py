"""Regtest-only puzzle lifecycle; all witness material is public test data.

QSB's RIPEMD160-to-DER predicate has fixed difficulty. A signature-size
surrogate is a different experiment, not a reduced implementation of that hash.
The compiler shares fixed-ALL pinning and HORS/FindAndDelete subset machinery.
"""
from copy import deepcopy
from dataclasses import dataclass
from hashlib import new, sha256
from itertools import combinations
from math import comb, log2
from pathlib import Path
import json
import platform
import struct
import time

from .bitcoin import Tx, Input, Output, push, num, compact, instructions, legacy_sighash, script_metrics, hash256
from .core import Core, RPCError, verify, VERIFIER
from .crypto import ROOT, ec, encode, recover, secret
from .experiments import write_tx


def hash160(data):
    return new('ripemd160', sha256(data).digest()).digest()


def find_and_delete(script, signatures):
    """Legacy deletion of complete signature pushes at opcode boundaries."""
    targets = {push(s) for s in signatures}
    return b''.join(script[a:b] for a, _, _, b in instructions(script)
                    if script[a:b] not in targets)


@dataclass(frozen=True)
class Parameters:
    entries: int = 48
    selections: int = 5
    puzzle: str = 'hash-to-der'
    signature_bytes: int = 69

    def validate(self):
        if self.puzzle not in ('hash-to-der', 'signature-size-surrogate'):
            raise ValueError('unknown puzzle')
        if not 2 <= self.entries <= 64 or not 1 <= self.selections <= min(6, self.entries):
            raise ValueError('require 2..64 entries and 1..6 selections')
        if not 68 <= self.signature_bytes <= 71:
            raise ValueError('surrogate signature size must be 68..71 bytes')


class Instance:
    def __init__(self, params):
        params.validate()
        self.params = params
        # Public k=1, s=1 makes Q=((1-z)/r)G computable without private data.
        # Surrogate signatures use this SAME public nonce and the SINGLE bug.
        self.r = ec.G[0]
        self.fixed = ec.encode_der_sig(self.r, 1, 1)
        self.preimages = [secret(f'phase2/hors/{i}') for i in range(params.entries)]
        self.commitments = list(map(hash160, self.preimages))
        self.dummies = [ec.encode_der_sig(2, i + 1, 3) for i in range(params.entries)]
        # r=2 is on curve; select a public recovery branch, with exact Core z=1.
        self.dummy_keys = [encode(recover(2, i + 1, b'\x01' + bytes(31)))
                           for i in range(params.entries)]
        self.script = self.compile()
        metrics = script_metrics(self.script)
        self.metrics = dict(**metrics, counted_opcodes=metrics['static_non_push_opcodes'] + params.selections + 1,
                            counted_opcodes_note='Adds N for the executed N-of-N CHECKMULTISIGVERIFY.')
        if self.metrics['bytes'] > 10000 or self.metrics['counted_opcodes'] > 201:
            raise ValueError(f'compiled instance exceeds legacy budgets: {self.metrics}')

    def compile(self):
        n, t = self.params.entries, self.params.selections
        # Witness names, bottom to top. Each entry denotes one stack element.
        stack = ['digest_proof', 'digest_key']
        stack += [f'pub{i}' for i in reversed(range(t))]
        for i in reversed(range(t)):
            stack += [f'pre{i}', f'index{i}']
        stack += ['pin_proof', 'pin_key']
        script = bytearray()

        def roll(name):
            depth = len(stack) - 1 - stack.index(name)
            script.extend(num(depth) + b'\x7a')
            stack.append(stack.pop(stack.index(name)))

        def puzzle():
            # stack: ... proof, key; preserve key for the fixed-ALL check.
            if self.params.puzzle == 'hash-to-der':
                # proof is the public key recovered for RIPEMD160(key).
                script.extend(b'\x76\xa6\x52\x7a\xad')
            else:
                # proof is a DER signature on the SINGLE-bug digest (input 1,
                # only output 0). Exact SIZE is enforced by native Script; the short fixed signature cannot itself serve as this proof.
                script.extend(b'\x7c\x82' + num(self.params.signature_bytes) + b'\x88\x78\xad')
            stack.pop()  # key and proof replaced by preserved key
            stack[-1] = 'preserved_key'

        # Pinning first; its fixed signature always commits with SIGHASH_ALL.
        script.extend(push(self.fixed) + b'\x78\xad')
        puzzle()
        script.extend(b'\x75')
        stack.pop()
        # Paired table: sig_i immediately below commitment_i; index zero on top.
        for i in reversed(range(n)):
            script.extend(push(self.dummies[i]) + push(self.commitments[i]))
            stack += [f'dummy{i}', f'commit{i}']
        # Strict ascending indices prevent repeated use of one table entry.
        script.extend(b'\x4f\x6b')  # -1 TOALTSTACK
        for j in range(t):
            roll(f'index{j}')
            script.extend(b'\x76\x00' + num(n) + b'\xa5\x69')  # range
            script.extend(b'\x76\x6c\xa0\x69\x76\x6b')  # ascending; retain index
            # 2*index, retain for the second lookup. Table stays in place.
            script.extend(b'\x76\x93\x76' + num(j + 1) + b'\x93\x79')
            stack[-1] = 'offset'
            stack.append('selected_commitment')
            roll(f'pre{j}')
            script.extend(b'\xa9\x88')
            stack.pop(); stack.pop()
            script.extend(num(j + 1) + b'\x93\x79')
            stack[-1] = f'selected{j}'
        script.extend(b'\x6c\x75')  # discard final index
        # Stash selected signatures, then insert CHECKMULTISIG's null dummy and
        # fixed signature before them. No witness can substitute the ALL flag.
        for j in reversed(range(t)):
            script.extend(b'\x6b'); stack.pop()
        script.extend(b'\x00' + push(self.fixed))
        stack += ['null_dummy', 'fixed_signature']
        for j in range(t):
            script.extend(b'\x6c'); stack.append(f'selected{j}')
        roll('digest_proof'); roll('digest_key'); puzzle()
        script.extend(num(t + 1) + b'\x7c')
        stack.append('sig_count')
        stack[-2], stack[-1] = stack[-1], stack[-2]
        for j in range(t):
            roll(f'pub{j}')
        script.extend(num(t + 1) + b'\xaf\x51')
        # Unused table elements deliberately remain: legacy consensus does not
        # require CLEANSTACK. They never serve as signatures or public keys.
        return bytes(script)

    def script_code(self, subset=None):
        signatures = [self.fixed]
        if subset is not None:
            signatures += [self.dummies[i] for i in subset]
        return find_and_delete(self.script, signatures)

    def digest(self, tx, subset=None):
        return legacy_sighash(tx, 1, self.script_code(subset))

    def key(self, digest):
        scalar = (1 - int.from_bytes(digest, 'big')) * pow(self.r, -1, ec.N) % ec.N
        return encode(ec.point_mul(scalar, ec.G)) if scalar else None

    def proof(self, tx, digest):
        """Return a witness only if the selected predicate actually passes."""
        if self.params.puzzle == 'signature-size-surrogate':
            # Core's SINGLE-bug digest is 01 00...00, interpreted BIG endian by
            # ECDSA, not the integer 1. No low-S normalization in this search.
            s = (int.from_bytes(b'\x01' + bytes(31), 'big') + 1 - int.from_bytes(digest, 'big')) % ec.N
            sig = ec.encode_der_sig(self.r, s, 3)
            return sig if s and len(sig) == self.params.signature_bytes else None
        key = self.key(digest)
        if key is None:
            return None
        sig = new('ripemd160', key).digest()
        if not ec.is_valid_der_sig(sig):
            return None
        rlen = sig[3]
        r = int.from_bytes(sig[4:4+rlen], 'big')
        slen = sig[5+rlen]
        s = int.from_bytes(sig[6+rlen:6+rlen+slen], 'big')
        z = legacy_sighash(tx, 1, self.script, sig, sig[-1])
        for branch in range(4):
            key_puzzle = recover(r, s, z, branch)
            if key_puzzle is not None:
                return encode(key_puzzle)
        return None

    def witness(self, pin, digest, subset, preimages=None):
        pin_z, pin_proof = pin
        digest_z, digest_proof = digest
        preimages = self.preimages if preimages is None else preimages
        out = push(digest_proof) + push(self.key(digest_z))
        out += b''.join(push(self.dummy_keys[i]) for i in reversed(subset))
        out += b''.join(push(preimages[i]) + num(i) for i in reversed(subset))
        return out + push(pin_proof) + push(self.key(pin_z))


def timing(start, count=None, unit=None):
    elapsed = time.perf_counter() - start
    return dict(wall_seconds=elapsed, candidates=count, candidate_unit=unit,
                candidates_per_second=count / elapsed if count is not None else None)


class Search:
    """CPU enumeration; hashing templates are checked against legacy_sighash."""
    def __init__(self, instance, tx, max_candidates, deadline):
        self.instance, self.tx = instance, tx
        self.max_candidates, self.deadline = max_candidates, deadline
        self.progress = None
        self.code = instance.script_code()
        self.prefix = (struct.pack('<i', tx.version) + compact(2)
                       + Input(tx.inputs[0].txid, tx.inputs[0].vout, sequence=tx.inputs[0].sequence).serialize()
                       + bytes.fromhex(tx.inputs[1].txid)[::-1] + struct.pack('<I', tx.inputs[1].vout))
        self.tail = (compact(1) + tx.outputs[0].serialize() + struct.pack('<II', tx.locktime, 1))
        self.spans = {}
        lookup = {sig: i for i, sig in enumerate(instance.dummies)}
        for a, _, data, b in instructions(self.code):
            if data in lookup:
                self.spans[lookup[data]] = (a, b)

    def check_budget(self, count, start, phase):
        if count >= self.max_candidates or time.perf_counter() >= self.deadline:
            self.progress = dict(phase=phase, **timing(start,count,phase), found=False,
                                 budget_exhausted=True)
            raise RuntimeError('phase2 search budget exhausted; no solution fabricated')

    def pin(self, first_counter):
        start = time.perf_counter()
        midstate = sha256(self.prefix + compact(len(self.code)) + self.code)
        for count in range(self.max_candidates):
            interval = 32 if self.instance.params.puzzle == 'hash-to-der' else 4096
            if count % interval == 0:
                self.check_budget(count,start,'pinning_search')
            counter = first_counter + count
            if counter >= 2**31:
                raise RuntimeError('sequence search space exhausted')
            self.tx.inputs[1].sequence = 0x80000000 | counter
            state = midstate.copy()
            state.update(struct.pack('<I', self.tx.inputs[1].sequence) + self.tail)
            digest = sha256(state.digest()).digest()
            proof = self.instance.proof(self.tx, digest)
            if proof is not None:
                if digest != self.instance.digest(self.tx):
                    raise AssertionError('pinning template/reference mismatch')
                return (digest, proof), dict(**timing(start, count + 1, 'transaction sequence variants'),
                    start_counter=first_counter, winning_counter=counter,
                    sequence=self.tx.inputs[1].sequence, digest_hex=digest.hex(), proof_hex=proof.hex())
        self.check_budget(self.max_candidates,start,'pinning_search')

    def subsets(self):
        start = time.perf_counter()
        suffix = struct.pack('<I', self.tx.inputs[1].sequence) + self.tail
        count = 0
        for subset in combinations(range(self.instance.params.entries), self.instance.params.selections):
            interval = 32 if self.instance.params.puzzle == 'hash-to-der' else 4096
            if count >= self.max_candidates or count % interval == 0:
                self.check_budget(count,start,'digest_subset_search')
            parts = []; last = 0
            for a, b in sorted(self.spans[i] for i in subset):
                parts.append(self.code[last:a]); last = b
            parts.append(self.code[last:])
            code = b''.join(parts)
            digest = hash256(self.prefix + compact(len(code)) + code + suffix)
            proof = self.instance.proof(self.tx, digest)
            count += 1
            if proof is not None:
                if digest != self.instance.digest(self.tx, subset):
                    raise AssertionError('subset template/reference mismatch')
                return (digest, proof), subset, dict(**timing(start, count, 'distinct lexicographic subsets'),
                    found=True, selected_indices=list(subset), digest_hex=digest.hex(),
                    proof_hex=proof.hex(), script_code_hex=code.hex())
        return None, None, dict(**timing(start, count, 'distinct lexicographic subsets'), found=False)


def run(outdir, bitcoind='bitcoind', params=None, max_candidates=10_000_000, max_seconds=300):
    params = params or Parameters()
    params.validate()
    if max_candidates < 1 or max_seconds <= 0:
        raise ValueError('search budgets must be positive')
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    if (outdir/'results.json').exists():
        raise ValueError('output already contains results.json; choose a fresh --outdir')
    blocks = outdir/'blocks'; blocks.mkdir(exist_ok=True)
    total_start = time.perf_counter()
    setup_start = time.perf_counter()
    instance = Instance(params)
    setup = timing(setup_start, params.entries, 'public table entries')
    sbytes = params.signature_bytes - 7 - len(ec.int_to_der_int(instance.r))
    # int_to_der_int returns only the integer bytes in the pinned helper.
    surrogate = params.puzzle == 'signature-size-surrogate'
    result = dict(schema_version=1, scope='isolated_regtest_public_test_data_only',
        experiment='signature_size_lifecycle_surrogate' if surrogate else 'qsb_hash_to_der_reduced_tables',
        full_strength_demonstration=False, qsb_hash_to_der_end_to_end_demonstrated=False,
        reduced_lifecycle_demonstrated=False, secure_candidate_demonstrated=False,
        parameters=dict(puzzle=params.puzzle, reduced=True, digest_rounds=1, published_digest_rounds=2,
            table_entries_per_round=params.entries, signed_selections=params.selections, bonus_selections=0,
            subset_space=comb(params.entries, params.selections),
            subset_space_bits=log2(comb(params.entries, params.selections)),
            published_table_entries_per_round=150, published_signed_selections=[8,7],
            published_bonus_selections=[1,2], published_puzzle_work_approx_bits=46.4,
            surrogate_exact_signature_bytes=params.signature_bytes if surrogate else None,
            surrogate_fixed_nonce_s_der_bytes=sbytes if surrogate else None,
            nominal_fixed_nonce_search_work_bits=256-(8*sbytes-1) if surrogate else None,
            nominal_work_is_probability_model=True if surrogate else None,
            nominal_work_scope='Fixed public nonce k=1, unnormalized s; not an adversarial lower bound. Script does not fix the puzzle signature nonce or sighash byte.' if surrogate else None,
            puzzle_changes=['RIPEMD160-to-DER replaced by OP_SIZE plus CHECKSIGVERIFY on the transaction-bound key.'] if surrogate else [],
            fixed_signature_hex=instance.fixed.hex(), fixed_signature_sighash='ALL',
            surrogate_puzzle_sighash='SINGLE bug at input index 1 with one output' if surrogate else None,
            single_bug_digest_hex=(b'\x01'+bytes(31)).hex(),
            candidate_key_branch='R=G; compressed key',
            public_nonce=1, low_s_normalization=False,
            search_max_candidates_per_phase=max_candidates, search_max_seconds_per_lifecycle=max_seconds),
        limitations=['All HORS preimages and test nonce material are public; no secret-key security is tested.',
            'Only one digest round is compiled; no full-strength or quantum-security claim.',
            'Native consensus and block acceptance are measured; relay policy acceptance is not measured.'],
        environment=dict(python=platform.python_version(), platform=platform.platform(), processor=platform.machine()),
        consensus_changes=[], relay_policy_changes=[], script=instance.metrics,
        setup=setup, lifecycles=[], cases=[], setup_blocks=[])
    result['provenance'] = dict(
        pinned_reference_commit=json.loads((ROOT/'vendor/qsb/manifest.json').read_text())['commit'],
        source_sha256={str(p.relative_to(ROOT)):sha256(p.read_bytes()).hexdigest()
                       for p in [Path(__file__),ROOT/'btc_pq/cli.py',ROOT/'btc_pq/bitcoin.py',ROOT/'btc_pq/core.py',
                                 ROOT/'vendor/qsb/paper/QSB.tex',VERIFIER]},
        fixed_difficulty_reference='vendor/qsb/paper/QSB.tex: Fixed puzzle difficulty; no knob to tune',
        surrogate_is_hash_to_signature=False if surrogate else None)
    if surrogate:
        result['limitations'].append('This is not the QSB hash-to-signature predicate. Its fixed-nonce search rate and target do not establish unavoidable work for a transaction modification.')
    (outdir/'locking-script.hex').write_text(instance.script.hex()+'\n')
    (outdir/'public-tables.json').write_text(json.dumps(dict(
        scope='PUBLIC REGTEST DATA; never use for coins with value',
        entries=[dict(index=i, preimage_hex=instance.preimages[i].hex(), commitment_hex=instance.commitments[i].hex(),
                      dummy_signature_hex=instance.dummies[i].hex(), dummy_public_key_hex=instance.dummy_keys[i].hex())
                 for i in range(params.entries)]), indent=2)+'\n')

    def save(partial=False):
        result['total_wall_seconds'] = time.perf_counter()-total_start
        (outdir/('partial-results.json' if partial else 'results.json')).write_text(json.dumps(result, indent=2)+'\n')

    try:
        with Core(bitcoind) as core:
            result['core_version'] = core.info['version']
            if core.rpc('getblockchaininfo')['chain'] != 'regtest' or core.rpc('getnetworkinfo')['networkactive']:
                raise AssertionError('node is not isolated regtest')
            result['node_isolation'] = dict(chain='regtest', networkactive=False, listen=False, temporary_datadir=True)
            start = time.perf_counter()
            core.rpc('generatetoaddress', 101, core.address)
            utxo = sorted(core.rpc('listunspent',100), key=lambda x:x['txid'])[0]
            change = bytes.fromhex(core.rpc('getaddressinfo',core.address)['scriptPubKey'])
            value = round(utxo['amount']*100_000_000)
            funding = Tx([Input(utxo['txid'],utxo['vout'])],
                         [Output(1_000_000,b'\x51'), Output(1_000_000,instance.script), Output(value-2_010_000,change)])
            signed = core.rpc('signrawtransactionwithwallet',funding.serialize().hex())
            if not signed['complete']:
                raise RuntimeError('regtest funding not signed')
            funding = Tx.parse(signed['hex'])
            parent = outdir/'funding-parent.hex'
            parent.write_text(core.rpc('gettransaction',utxo['txid'])['hex']+'\n')
            funding_path = write_tx(outdir/'funding.hex',funding)
            funding_native = verify(funding_path,[parent])
            if not funding_native['valid']:
                raise AssertionError('funding native verification failed')
            funding_block = core.mine(funding)
            result['funding'] = dict(**timing(start), transaction=funding.metrics(), native=funding_native,
                                    blockhash=funding_block, file='funding.hex',
                                    timing_scope='101 maturity blocks, wallet signing, native verification, funding block')
            for height in range(1,core.rpc('getblockcount')+1):
                h = core.rpc('getblockhash',height)
                path = blocks/f'setup-{height:03}.hex'
                path.write_text(core.rpc('getblock',h,0)+'\n')
                result['setup_blocks'].append(str(path.relative_to(outdir)))
            base_tip = core.rpc('getbestblockhash'); result['base_tip'] = base_tip
            result['regtest_deployments'] = core.rpc('getdeploymentinfo')

            def validate(name, tx, expected):
                if core.rpc('getbestblockhash') != base_tip:
                    raise AssertionError('case must start from funded tip')
                path = write_tx(outdir/f'{name}.hex',tx)
                start = time.perf_counter(); native = verify(path,[funding_path]*2)
                row = dict(name=name, file=path.name, transaction=tx.metrics(), expected_acceptance=expected,
                           native=native, native_verification=timing(start))
                start = time.perf_counter()
                try:
                    h = core.mine(tx)
                    row.update(block_accepted=True, blockhash=h)
                except RPCError as error:
                    row.update(block_accepted=False, block_rejection=error.error)
                row['block_acceptance'] = timing(start)
                if row['block_accepted']:
                    if core.rpc('getbestblockhash') != h or tx.txid not in core.rpc('getblock',h,1)['tx']:
                        raise AssertionError('transaction not in active accepted block')
                    path = blocks/f'{name}.hex'; path.write_text(core.rpc('getblock',h,0)+'\n')
                    row['block_file'] = str(path.relative_to(outdir))
                    core.rpc('invalidateblock',h)
                result['cases'].append(row)
                if native['valid'] != expected or row['block_accepted'] != expected:
                    raise AssertionError(f'{name}: native/block outcome did not match expected {expected}: {row}')
                return row

            def lifecycle(name, value):
                tx = Tx([Input(funding.txid,0),Input(funding.txid,1,sequence=0x80000000)], [Output(value,b'\x51')])
                row = dict(name=name, attempts=[]); result['lifecycles'].append(row)
                search = Search(instance,tx,max_candidates,time.perf_counter()+max_seconds)
                next_counter = 0
                while True:
                    attempt = {}; row['attempts'].append(attempt)
                    try:
                        pin, pin_stats = search.pin(next_counter)
                        attempt['pinning_search'] = pin_stats
                        digest, subset, digest_stats = search.subsets()
                    except RuntimeError:
                        if search.progress is not None:
                            attempt[search.progress['phase']] = search.progress
                        raise
                    attempt['digest_subset_search'] = digest_stats
                    save(partial=True)
                    if digest is not None:
                        break
                    next_counter = pin_stats['winning_counter']+1
                start = time.perf_counter()
                tx.inputs[1].script = instance.witness(pin,digest,subset)
                row['assembly'] = timing(start)
                row.update(selected_indices=list(subset), pin_key_hex=instance.key(pin[0]).hex(),
                           digest_key_hex=instance.key(digest[0]).hex(), transaction=tx.metrics(),
                           sequence=tx.inputs[1].sequence, output_value_sats=value)
                checked = validate(name,tx,True)
                row['native_verification'] = checked['native_verification']
                row['block_acceptance'] = checked['block_acceptance']
                return tx, pin, digest, subset

            tx,pin,digest,subset = lifecycle('honest',1_980_000)
            changed = deepcopy(tx); changed.outputs[0].value -= 1
            validate('changed-amount-stale-witness',changed,False)
            changed.inputs[1].script = instance.witness((instance.digest(changed),pin[1]),
                (instance.digest(changed,subset),digest[1]),subset)
            validate('changed-amount-recovered-keys-stale-proofs',changed,False)
            if surrogate:
                bad = deepcopy(tx)
                bad.inputs[1].script = instance.witness((pin[0],instance.fixed),digest,subset)
                validate('fixed-signature-reused-as-puzzle-proof',bad,False)
            corrupt = list(instance.preimages); corrupt[subset[0]] = bytes(32)
            bad = deepcopy(tx); bad.inputs[1].script = instance.witness(pin,digest,subset,corrupt)
            validate('wrong-hors-preimage',bad,False)
            replacement = next(s for s in combinations(range(params.entries),params.selections) if s != subset)
            bad = deepcopy(tx); bad.inputs[1].script = instance.witness(pin,digest,replacement)
            validate('changed-subset-correct-preimages-stale-digest-key',bad,False)
            if params.selections > 1:
                duplicate = tuple([subset[0]]*params.selections)
                bad = deepcopy(tx); bad.inputs[1].script = instance.witness(pin,digest,duplicate)
                validate('duplicate-subset-index',bad,False)
            lifecycle('changed-amount-fresh-search',1_979_999)
            result['reduced_lifecycle_demonstrated'] = True
            result['qsb_hash_to_der_end_to_end_demonstrated'] = not surrogate
        start = time.perf_counter()
        result['replay'] = replay(outdir,bitcoind,result)
        result['replay']['wall_seconds'] = time.perf_counter()-start
        result['status'] = 'complete_surrogate_lifecycle' if surrogate else 'complete_hash_to_der_lifecycle'
        result['reproduction_command'] = (f'.venv/bin/python -m btc_pq.cli phase2 --puzzle {params.puzzle} '
            f'--entries {params.entries} --selections {params.selections} --signature-bytes {params.signature_bytes} '
            '--outdir results/phase2-rerun')
        save()
        (outdir/'partial-results.json').unlink(missing_ok=True)
        return result
    except BaseException as error:
        result['failure'] = str(error)
        result['status'] = 'incomplete'
        save(partial=True)
        raise


def replay(outdir,bitcoind='bitcoind',result=None):
    outdir = Path(outdir)
    result = result or json.loads((outdir/'results.json').read_text())
    rows = []
    with Core(bitcoind) as core:
        for path in result['setup_blocks']:
            outcome = core.rpc('submitblock',(outdir/path).read_text().strip())
            if outcome is not None:
                raise AssertionError(f'setup block replay rejected: {outcome}')
        if core.rpc('getbestblockhash') != result['base_tip']:
            raise AssertionError('replay setup tip mismatch')
        for row in result['cases']:
            native = verify(outdir/row['file'],[outdir/'funding.hex']*2)
            if native['valid'] != row['block_accepted']:
                raise AssertionError('native fixture replay mismatch')
            if row['block_accepted']:
                outcome = core.rpc('submitblock',(outdir/row['block_file']).read_text().strip())
                if outcome is not None or core.rpc('getbestblockhash') != row['blockhash']:
                    raise AssertionError(f'accepted block replay failed: {outcome}')
                core.rpc('invalidateblock',row['blockhash'])
            else:
                try:
                    core.mine(Tx.parse((outdir/row['file']).read_text().strip()))
                except RPCError:
                    pass
                else:
                    raise AssertionError('rejected fixture accepted during replay')
            rows.append(dict(name=row['name'],native_valid=native['valid'],block_accepted=row['block_accepted'],reproduced=True))
    return dict(core_version=310100,setup_blocks_replayed=len(result['setup_blocks']),cases=rows)
