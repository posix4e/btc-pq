"""Fresh instances of the deployed QSB construction and durable CPU searches.

The full SHA256-to-DER predicate is retained. Preparation, search, assembly,
and replay are separate operations; bounded no-hit runs remain resumable.
"""
from contextlib import contextmanager
from copy import deepcopy
from hashlib import sha256
from math import comb, isfinite
from pathlib import Path
import fcntl
import json
import os
import secrets
import struct
import time

from .bitcoin import Tx, Input, Output, legacy_sighash, num, push
from .core import Core, VERIFIER, verify
from .crypto import encode, recover
from .phase3 import (Construction, Pinning, Search, SEARCH_BIN, build_native, der_nonzero,
                     der_parts, execute, hash160, native_call, native_request,
                     native_vectors, published)

SCHEMA = 1
SEQUENCE_SPACE = 1 << 31
PINNING_SPACE = 1 << 62
SINGLE_BUG = b'\x01' + bytes(31)


def fingerprint(value):
    return sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def atomic_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + f'.{os.getpid()}.tmp')
    try:
        with tmp.open('w') as stream:
            json.dump(value, stream, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        tmp.unlink(missing_ok=True)


@contextmanager
def locked(path, wait=False):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('a') as stream:
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | (0 if wait else fcntl.LOCK_NB))
        except BlockingIOError as error:
            raise RuntimeError(f'workspace operation already running: {path}') from error
        try:
            yield
        finally:
            fcntl.flock(stream, fcntl.LOCK_UN)


def tables(c, kind, rnd):
    return [data for at, _, data, _ in c.ins
            if c.table_tags.get(at, ())[:2] == (kind, rnd)]


def fresh_instance(seed=None):
    seed = secrets.token_bytes(32) if seed is None else seed
    if len(seed) != 32:
        raise ValueError('instance seed must contain 32 bytes')
    _, _, _, template = published()
    preimages = [[sha256(b'btc-pq/phase4/hors/v1' + seed + struct.pack('<II', rnd, i)).digest()[:20]
                  for i in range(layout['entries'])]
                 for rnd, layout in enumerate(template.rounds, 1)]
    chunks = []
    for at, _, data, end in template.ins:
        tag = template.table_tags.get(at)
        chunks.append(push(hash160(preimages[tag[1] - 1][tag[2]]))
                      if tag and tag[0] == 'commitment' else template.script[at:end])
    script = b''.join(chunks)
    c = Construction(script)
    counted = c.metrics['static_non_push_opcodes'] + sum(r['n'] for r in c.rounds)
    if len(script) != len(template.script) or counted > 201 or len(script) > 10000:
        raise ValueError('fresh instance does not preserve the deployed script budgets')
    return dict(schema=SCHEMA, construction='deployed-sha256-config-a',
                seed_hex=seed.hex(), material='public regtest signing material',
                template_sha256=sha256(template.script).hexdigest(),
                script_hex=script.hex(), script_sha256=sha256(script).hexdigest(),
                metrics=dict(c.metrics, counted_opcodes=counted),
                preimages=[[p.hex() for p in row] for row in preimages])


def candidate_tx(base, counter):
    if not 0 <= counter < PINNING_SPACE:
        raise ValueError('pinning counter must be in [0, 2^62)')
    if len(base.inputs) != 2 or len(base.outputs) != 1 or base.locktime != 0:
        raise ValueError('two inputs, one output, and locktime zero are required')
    tx = deepcopy(base)
    tx.inputs[0].sequence = 0x80000000 | (counter >> 31)
    tx.inputs[1].sequence = 0x80000000 | (counter & (SEQUENCE_SPACE - 1))
    return tx


def worker_range(total, worker, workers):
    if workers < 1 or workers > total or not 0 <= worker < workers:
        raise ValueError('require 1 <= workers <= search space and 0 <= worker < workers')
    return total * worker // workers, total * (worker + 1) // workers


def subset_at(n, k, rank):
    """Unrank lexicographic combinations without visiting earlier subsets."""
    if not 0 <= k <= n or not 0 <= rank < comb(n, k):
        raise ValueError('subset rank out of range')
    result, first = [], 0
    for remaining in range(k - 1, -1, -1):
        for value in range(first, n - remaining):
            size = comb(n - value - 1, remaining)
            if rank < size:
                result.append(value)
                first = value + 1
                break
            rank -= size
    return result


def subset_rank(n, subset):
    if sorted(set(subset)) != list(subset) or any(p < 0 or p >= n for p in subset):
        raise ValueError('subset must contain distinct ascending table positions')
    rank, first, k = 0, 0, len(subset)
    for j, value in enumerate(subset):
        rank += sum(comb(n - p - 1, k - j - 1) for p in range(first, value))
        first = value + 1
    return rank


def stage_context(c, stage, subset=None):
    if stage == 'pin':
        if subset is not None:
            raise ValueError('pinning has no subset')
        signature = c.pin_sig
        deleted = [signature]
    elif stage in ('round1', 'round2'):
        rnd = int(stage[-1])
        layout = c.rounds[rnd - 1]
        if subset is None or len(subset) != layout['m'] - 1:
            raise ValueError('incorrect number of digest selections')
        subset_rank(layout['entries'], subset)
        signature = layout['sig_nonce']
        dummy = tables(c, 'dummy', rnd)
        deleted = [signature] + [dummy[p] for p in subset]
    else:
        raise ValueError('unknown search stage')
    return signature, c.script_code(deleted)


def validate_proof(c, tx, proof, expected_stage=None):
    """Recompute both ECDSA stages, including each signature's FindAndDelete."""
    try:
        stage = proof['stage']
        if expected_stage is not None and stage != expected_stage:
            raise ValueError('proof belongs to a different stage')
        sig, code = stage_context(c, stage, proof.get('subset'))
        z = legacy_sighash(tx, 1, code, hash_type=sig[-1])
        if proof['digest_hex'] != z.hex():
            raise ValueError('stale proof digest')
        r, s, _ = der_parts(sig)
        key = recover(r, s, z, proof['recovery_branch'])
        if key is None or encode(key).hex() != proof['key_nonce_hex']:
            raise ValueError('invalid nonce proof key')
        puzzle = sha256(encode(key)).digest()
        if not der_nonzero(puzzle) or proof['sig_puzzle_hex'] != puzzle.hex():
            raise ValueError('hash-to-DER predicate failed')
        r2, s2, flag = der_parts(puzzle)
        z2 = legacy_sighash(tx, 1, c.script_code([puzzle]), hash_type=flag)
        key2 = recover(r2, s2, z2, proof['puzzle_recovery_branch'])
        if (key2 is None or encode(key2).hex() != proof['key_puzzle_hex']
                or proof['sig_puzzle_z_hex'] != z2.hex()):
            raise ValueError('invalid puzzle proof key')
        if stage != 'pin' and 'subset_rank' in proof:
            if proof['subset_rank'] != subset_rank(c.entries, proof['subset']):
                raise ValueError('subset rank does not match its selections')
    except (KeyError, TypeError, IndexError) as error:
        raise ValueError('incomplete or malformed proof') from error
    return proof


def complete_proof(c, tx, stage, context, event, counter, subset=None):
    z = bytes.fromhex(event['digest_hex'])
    key = bytes.fromhex(event['key_nonce_hex'])
    puzzle = bytes.fromhex(event['sha256_key_hex'])
    extra = context.validate_hit(tx, 1, c.script, z, event['recovery_branch'], key, puzzle)
    if extra is None:
        return None
    proof = dict(stage=stage, digest_hex=z.hex(), recovery_branch=event['recovery_branch'],
                 key_nonce_hex=key.hex(), **extra)
    if stage == 'pin':
        proof['counter'] = counter
    else:
        proof.update(subset=subset, subset_rank=counter)
    return validate_proof(c, tx, proof, stage)


def assemble_tx(base, c, preimages, pin, rounds):
    """Assemble Config A in table-position order; require all three real proofs."""
    if len(rounds) != 2:
        raise ValueError('both digest-round proofs are required')
    validate_proof(c, base, pin, 'pin')
    for rnd, proof in enumerate(rounds, 1):
        validate_proof(c, base, proof, f'round{rnd}')
    witness = b''
    for rnd in (2, 1):
        proof, layout = rounds[rnd - 1], c.rounds[rnd - 1]
        subset = proof['subset']
        witness += push(bytes.fromhex(proof['key_puzzle_hex']))
        witness += push(bytes.fromhex(proof['key_nonce_hex']))
        dummy = tables(c, 'dummy', rnd)
        branches = proof.get('dummy_recovery_branches', [0] * len(subset))
        if len(branches) != len(subset):
            raise ValueError('dummy recovery branch count mismatch')
        for position, branch in zip(subset, branches):
            r, s, flag = der_parts(dummy[position])
            if flag != 3 or legacy_sighash(base, 1, b'', hash_type=flag) != SINGLE_BUG:
                raise ValueError('dummy signature requires the legacy SINGLE-bug digest')
            key = recover(r, s, SINGLE_BUG, branch)
            if key is None:
                raise ValueError('invalid dummy recovery branch')
            witness += push(encode(key))
        commitments = tables(c, 'commitment', rnd)
        for position in subset[layout['bonus']:]:
            preimage = preimages.get((rnd, position))
            if preimage is None or hash160(preimage) != commitments[position]:
                raise ValueError('missing or incorrect HORS preimage')
            witness += push(preimage)
        witness += b''.join(num(layout['entries'] + 1 - p) for p in subset)
    witness += push(bytes.fromhex(pin['key_puzzle_hex'])) + push(bytes.fromhex(pin['key_nonce_hex']))
    tx = deepcopy(base)
    tx.inputs[1].script = witness
    execute(tx, 1, c)  # Cross-check stack layout; native Core decides acceptance.
    return tx


def prepare(outdir, bitcoind='bitcoind', seed=None):
    outdir = Path(outdir)
    if outdir.exists() and any(outdir.iterdir()):
        raise ValueError('prepare requires an empty output directory')
    if not VERIFIER.exists():
        raise RuntimeError('native verifier is required; see README build instructions')
    outdir.mkdir(parents=True, exist_ok=True)
    started = time.perf_counter()
    instance = fresh_instance(seed)
    atomic_json(outdir/'instance.json', instance)
    script = bytes.fromhex(instance['script_hex'])
    (outdir/'locking-script.hex').write_text(script.hex() + '\n')
    blocks = outdir/'blocks'
    blocks.mkdir()
    with Core(bitcoind) as core:
        core.rpc('generatetoaddress', 101, core.address)
        utxo = sorted(core.rpc('listunspent', 100), key=lambda u: u['txid'])[0]
        change = bytes.fromhex(core.rpc('getaddressinfo', core.address)['scriptPubKey'])
        value = round(utxo['amount'] * 100_000_000)
        funding = Tx([Input(utxo['txid'], utxo['vout'])],
                     [Output(10_000, script), Output(10_000, b'\x51'), Output(value - 21_000, change)])
        signed = core.rpc('signrawtransactionwithwallet', funding.serialize().hex())
        if not signed['complete']:
            raise RuntimeError('funding signing incomplete')
        funding = Tx.parse(signed['hex'])
        (outdir/'funding-parent.hex').write_text(core.rpc('gettransaction', utxo['txid'])['hex'] + '\n')
        (outdir/'funding.hex').write_text(funding.serialize().hex() + '\n')
        verification = verify(outdir/'funding.hex', [outdir/'funding-parent.hex'])
        if not verification['valid']:
            raise RuntimeError('native funding verification failed')
        core.mine(funding)
        paths = []
        for height in range(1, core.rpc('getblockcount') + 1):
            path = blocks/f'setup-{height:03}.hex'
            path.write_text(core.rpc('getblock', core.rpc('getblockhash', height), 0) + '\n')
            paths.append(str(path.relative_to(outdir)))
        tip = core.rpc('getbestblockhash')
    base = Tx([Input(funding.txid, 1, sequence=0x80000000),
               Input(funding.txid, 0, sequence=0x80000000)], [Output(19_000, b'\x51')])
    (outdir/'spend-template.hex').write_text(base.serialize().hex() + '\n')
    files = ['instance.json', 'locking-script.hex', 'funding-parent.hex', 'funding.hex',
             'spend-template.hex'] + paths
    manifest = dict(schema=SCHEMA, network='regtest', core_version=310100,
                    consensus_changes=[], status='prepared', setup_blocks=paths, base_tip=tip,
                    instance_sha256=instance['script_sha256'], funding_native=verification,
                    candidate_mapping='two-disabled-sequences-v1', pinning_space=PINNING_SPACE,
                    spend_fee_sats=1000, preparation_wall_seconds=time.perf_counter() - started,
                    files={p: sha256((outdir/p).read_bytes()).hexdigest() for p in files})
    manifest['workspace_id'] = fingerprint(manifest)
    atomic_json(outdir/'manifest.json', manifest)
    return manifest


def load_workspace(outdir):
    outdir = Path(outdir)
    manifest = json.loads((outdir/'manifest.json').read_text())
    identity = manifest.pop('workspace_id')
    if identity != fingerprint(manifest) or manifest['schema'] != SCHEMA or manifest['network'] != 'regtest':
        raise ValueError('workspace manifest mismatch')
    manifest['workspace_id'] = identity
    for path, expected in manifest['files'].items():
        if sha256((outdir/path).read_bytes()).hexdigest() != expected:
            raise ValueError(f'workspace artifact changed: {path}')
    instance = json.loads((outdir/'instance.json').read_text())
    if instance != fresh_instance(bytes.fromhex(instance['seed_hex'])):
        raise ValueError('instance cannot be reproduced from its seed')
    c = Construction(bytes.fromhex(instance['script_hex']))
    base = Tx.parse((outdir/'spend-template.hex').read_text().strip())
    return manifest, instance, c, base


def read_hit(path, workspace_id, stage):
    doc = json.loads(Path(path).read_text())
    if doc.get('workspace_id') != workspace_id:
        raise ValueError('proof belongs to a different workspace')
    proof = doc.get('proof') or doc.get('hit')
    if not isinstance(proof, dict) or proof.get('stage') != stage:
        raise ValueError(f'{stage} proof is missing')
    return proof


def search(outdir, stage='pin', max_candidates=100_000, max_seconds=10,
           backend='native', worker=0, workers=1, pin_path=None, next_hit=False):
    if max_candidates < 1 or not isfinite(max_seconds) or max_seconds <= 0:
        raise ValueError('search budgets must be positive and finite')
    if backend not in ('native', 'python') or stage not in ('pin', 'round1', 'round2'):
        raise ValueError('unknown backend or stage')
    outdir = Path(outdir)
    manifest, _, c, base = load_workspace(outdir)
    pin = None
    if stage != 'pin':
        if pin_path is None:
            raise ValueError('digest search requires --pin with a validated pinning hit')
        pin = read_hit(pin_path, manifest['workspace_id'], 'pin')
        base = candidate_tx(base, pin['counter'])
        validate_proof(c, base, pin, 'pin')
    elif pin_path is not None:
        raise ValueError('--pin applies to digest searches')
    total = PINNING_SPACE if stage == 'pin' else comb(c.entries, c.rounds[int(stage[-1]) - 1]['m'] - 1)
    first, stop = worker_range(total, worker, workers)
    job = dict(schema=SCHEMA, workspace_id=manifest['workspace_id'], stage=stage,
               pinning_proof=pin, enumeration='two-disabled-sequences-v1' if stage == 'pin' else 'lexicographic-subsets-v1')
    directory = outdir/'search'/fingerprint(job)
    directory.mkdir(parents=True, exist_ok=True)
    # Fix one worker partition per job. A different worker count must never
    # silently overlap ranges already searched by other checkpoints.
    with locked(directory/'partition.lock', wait=True):
        partition = dict(job=job, workers=workers, total=total)
        path = directory/'partition.json'
        if path.exists() and json.loads(path.read_text()) != partition:
            raise ValueError('worker partition differs from the saved job')
        if not path.exists():
            atomic_json(path, partition)
    checkpoint = directory/f'worker-{worker}.json'
    with locked(directory/f'worker-{worker}.lock'):
        expected = dict(job=job, workspace_id=manifest['workspace_id'], worker=worker,
                        workers=workers, first_counter=first, stop_counter=stop)
        if checkpoint.exists():
            state = json.loads(checkpoint.read_text())
            if any(state.get(k) != v for k, v in expected.items()):
                raise ValueError('checkpoint identity mismatch')
            if not first <= state['next_counter'] <= stop or state['candidates'] != state['next_counter'] - first:
                raise ValueError('checkpoint range or candidate count mismatch')
        else:
            state = dict(expected, next_counter=first, candidates=0, key_trials=0,
                         der_passes=0, wall_seconds=0.0, hit=None, hits=[], status='ready')
            atomic_json(checkpoint, state)
        if next_hit:
            if stage != 'pin' or not state['hit']:
                raise ValueError('--next-hit requires a pinning checkpoint with a hit')
            previous = state['hits'].index(state['hit'])
            state['hit'] = state['hits'][previous + 1] if previous + 1 < len(state['hits']) else None
            state['status'] = 'hit' if state['hit'] else 'ready'
            atomic_json(checkpoint, state)
        if state['hit']:
            hit_tx = candidate_tx(base, state['hit']['counter']) if stage == 'pin' else base
            validate_proof(c, hit_tx, state['hit'], stage)
            return dict(state, checkpoint=str(checkpoint))
        signature = c.pin_sig if stage == 'pin' else c.rounds[int(stage[-1]) - 1]['sig_nonce']
        context = Pinning(signature)
        binary = None
        if backend == 'native':
            # Workers share one build tree; serialize Ninja invocations while
            # allowing their searches and checkpoint writes to run independently.
            with locked(SEARCH_BIN.parent/'phase4-build.lock', wait=True):
                binary = build_native()
        if binary:
            vectors = [bytes(32), sha256(b'phase4 cross-check').digest()]
            checked = native_vectors(binary, context, vectors)
            if checked['mismatches']:
                raise RuntimeError('native recovery cross-check failed')
        started, completed = time.perf_counter(), 0
        deadline = started + max_seconds
        state['status'] = 'searching'
        try:
            while (completed < max_candidates and state['next_counter'] < stop
                   and time.perf_counter() < deadline and not state['hit']):
                begin = state['next_counter']
                budget = min(max_candidates - completed, stop - begin)
                batch_start = time.perf_counter()
                candidates = []
                if stage == 'pin' and binary:
                    tx = candidate_tx(base, begin)
                    template = Search(context, c.script, tx)
                    # The existing native loop covers one low-sequence range.
                    # The outer loop changes input 0 and rebuilds the midstate.
                    low = begin & (SEQUENCE_SPACE - 1)
                    batch = native_call(binary, native_request(
                        context, 'pin', prefix_hex=template.prefix.hex(), code_hex=template.code.hex(),
                        tail_hex=template.tail.hex(), counter=low,
                        max_candidates=min(budget, SEQUENCE_SPACE - low),
                        stop_on_der=True,
                        max_seconds=max(0.000001, min(1.0, deadline - time.perf_counter()))), 30)
                    count = batch['measurement']['candidates']
                    if not 0 <= count <= min(budget, SEQUENCE_SPACE - low) or batch['next_counter'] != low + count:
                        raise RuntimeError('native pinning returned an inconsistent range')
                    events = [(begin - low + e['winning_counter'], None, e) for e in batch['der_pass_events']]
                    trials, passes = batch['key_trials'], batch['der_passes']
                else:
                    for offset in range(min(budget, 64 if binary else 1)):
                        if time.perf_counter() >= deadline:
                            break
                        counter = begin + offset
                        subset = None if stage == 'pin' else subset_at(c.entries, c.rounds[int(stage[-1]) - 1]['m'] - 1, counter)
                        tx = candidate_tx(base, counter) if stage == 'pin' else base
                        _, code = stage_context(c, stage, subset)
                        z = legacy_sighash(tx, 1, code, hash_type=signature[-1])
                        candidates.append((counter, subset, z))
                    if not candidates:
                        break
                    if binary:
                        batch = native_call(binary, native_request(context, 'screen',
                            digests=[z.hex() for _, _, z in candidates]), 30)
                        count = batch['candidates']
                        if count != len(candidates):
                            raise RuntimeError('native screening returned an incomplete batch')
                        events = [(candidates[e['winning_counter']][0], candidates[e['winning_counter']][1], e)
                                  for e in batch['der_pass_events']]
                        trials, passes = batch['key_trials'], batch['der_passes']
                    else:
                        count, trials, events = len(candidates), 0, []
                        for counter, subset, z in candidates:
                            for branch, key in context.keys(z):
                                trials += 1
                                hashed = sha256(key).digest()
                                if der_nonzero(hashed):
                                    events.append((counter, subset, dict(digest_hex=z.hex(), recovery_branch=branch,
                                        key_nonce_hex=key.hex(), sha256_key_hex=hashed.hex())))
                        passes = len(events)
                if count == 0:
                    break
                hits = []
                for counter, subset, event in events:
                    tx = candidate_tx(base, counter) if stage == 'pin' else base
                    proof = complete_proof(c, tx, stage, context, event, counter, subset)
                    if proof is not None:
                        hits.append(proof)
                        atomic_json(directory/f'hit-{fingerprint(proof)}.json',
                                    dict(workspace_id=manifest['workspace_id'], proof=proof))
                # Commit a whole batch only after all reported hits are checked.
                state['hits'].extend(hits)
                state['hit'] = hits[0] if hits else None
                state['next_counter'] += count
                state['candidates'] += count
                state['key_trials'] += trials
                state['der_passes'] += passes
                state['wall_seconds'] += time.perf_counter() - batch_start
                completed += count
                state['last_backend'] = backend
                state['status'] = 'hit' if state['hit'] else 'searching'
                atomic_json(checkpoint, state)
            state['status'] = 'hit' if state['hit'] else ('exhausted' if state['next_counter'] == stop else 'paused')
            state['last_run'] = dict(candidates=completed, wall_seconds=time.perf_counter() - started,
                                     backend=backend)
            if stage != 'pin' and state['status'] == 'exhausted':
                state['next_step'] = 'Combine all worker outcomes. If no round hit exists, request the next pinning hit and restart both rounds for it.'
            atomic_json(checkpoint, state)
        except BaseException:
            state['status'] = 'interrupted'
            atomic_json(checkpoint, state)
            raise
    return dict(state, checkpoint=str(checkpoint))


def restore_chain(core, outdir, manifest):
    for path in manifest['setup_blocks']:
        result = core.rpc('submitblock', (outdir/path).read_text().strip())
        if result is not None:
            raise RuntimeError(f'setup replay rejected: {result}')
    if core.rpc('getbestblockhash') != manifest['base_tip']:
        raise RuntimeError('setup replay tip mismatch')


def assemble(outdir, pin_path, round1_path, round2_path, bitcoind='bitcoind'):
    outdir = Path(outdir)
    with locked(outdir/'assembly.lock'):
        if (outdir/'assembly.json').exists():
            raise ValueError('this workspace already has an assembled spend; use replay')
        manifest, instance, c, base = load_workspace(outdir)
        pin = read_hit(pin_path, manifest['workspace_id'], 'pin')
        rounds = [read_hit(p, manifest['workspace_id'], f'round{r}')
                  for r, p in enumerate((round1_path, round2_path), 1)]
        tx = candidate_tx(base, pin['counter'])
        preimages = {(r, i): bytes.fromhex(p) for r, row in enumerate(instance['preimages'], 1)
                     for i, p in enumerate(row)}
        tx = assemble_tx(tx, c, preimages, pin, rounds)
        path = outdir/'spend.hex'
        path.write_text(tx.serialize().hex() + '\n')
        native = verify(path, [outdir/'funding.hex', outdir/'funding.hex'])
        if not native['valid']:
            raise RuntimeError('assembled spend rejected by native Core')
        with Core(bitcoind) as core:
            restore_chain(core, outdir, manifest)
            blockhash = core.mine(tx)
            (outdir/'spend-block.hex').write_text(core.rpc('getblock', blockhash, 0) + '\n')
        result = dict(workspace_id=manifest['workspace_id'], status='accepted', transaction=tx.metrics(),
                      native=native, blockhash=blockhash, proofs=[pin] + rounds,
                      spend_sha256=sha256(path.read_bytes()).hexdigest(),
                      block_sha256=sha256((outdir/'spend-block.hex').read_bytes()).hexdigest(),
                      qsb_hash_to_der_end_to_end_demonstrated=True)
        atomic_json(outdir/'assembly.json', result)
        return result


def replay(outdir, bitcoind='bitcoind'):
    outdir = Path(outdir)
    manifest, _, c, _ = load_workspace(outdir)
    funding = Tx.parse((outdir/'funding.hex').read_text().strip())
    if funding.outputs[0].script != c.script or funding.outputs[1].script != b'\x51':
        raise ValueError('funding outputs do not match the prepared instance')
    native = verify(outdir/'funding.hex', [outdir/'funding-parent.hex'])
    if not native['valid']:
        raise RuntimeError('funding native replay failed')
    result = dict(workspace_id=manifest['workspace_id'], funding_native_valid=True,
                  setup_blocks_replayed=len(manifest['setup_blocks']), spend_replayed=False)
    with Core(bitcoind) as core:
        restore_chain(core, outdir, manifest)
        if (outdir/'assembly.json').exists():
            assembly = json.loads((outdir/'assembly.json').read_text())
            if assembly['workspace_id'] != manifest['workspace_id']:
                raise ValueError('assembly workspace mismatch')
            for name, field in [('spend.hex', 'spend_sha256'), ('spend-block.hex', 'block_sha256')]:
                if sha256((outdir/name).read_bytes()).hexdigest() != assembly[field]:
                    raise ValueError('assembly artifact mismatch')
            native = verify(outdir/'spend.hex', [outdir/'funding.hex', outdir/'funding.hex'])
            if not native['valid']:
                raise RuntimeError('spend native replay failed')
            outcome = core.rpc('submitblock', (outdir/'spend-block.hex').read_text().strip())
            if outcome is not None or core.rpc('getbestblockhash') != assembly['blockhash']:
                raise RuntimeError(f'spend block replay failed: {outcome}')
            result.update(spend_replayed=True, spend_native_valid=True, blockhash=assembly['blockhash'])
    atomic_json(outdir/'replay.json', result)
    return result
