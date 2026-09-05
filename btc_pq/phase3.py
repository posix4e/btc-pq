"""Phase 3: exact published-construction pipeline validation + bounded pinning search.

All transaction material is public (fixtures/mainnet, pinned vendor commit).
Regtest uses valueless coins on an isolated node only; Core decides validity.

Validated fact: the published, Core-verified locking script executes OP_SHA256
(0xa8) at all three hash-to-signature puzzle sites. The pinned paper text
describes RIPEMD-160 throughout. Both exponents are reported as probability
arithmetic; only the deployed SHA256 pinning predicate is searched below.
"""
from hashlib import sha256, new
from math import comb, log2
from pathlib import Path
import json
import platform
import struct
import subprocess
import time

from .baseline import FIXTURES, TXID, check_vendor
from .bitcoin import Tx, Input, Output, push, compact, instructions, legacy_sighash, script_metrics
from .core import Core, verify, VERIFIER
from .crypto import ROOT, ec, encode, recover
from .experiments import write_tx

SEARCH_BIN = ROOT/'.cache/native-build/btc-pq-phase3-search'

OP_0, OP_1, OP_16 = 0x00, 0x51, 0x60
OP_ROLL, OP_MIN, OP_DUP, OP_ADD, OP_HASH160, OP_EQUALVERIFY = 0x7a, 0xa3, 0x76, 0x93, 0xa9, 0x88
OP_SHA256, OP_SWAP, OP_OVER, OP_CHECKSIGVERIFY, OP_CHECKMULTISIG = 0xa8, 0x7c, 0x78, 0xad, 0xae


def hash160(data):
    return new('ripemd160', sha256(data).digest()).digest()


# ------------------------------------------------------------------ DER syntax --

def is_strict_der(sig):
    """Port of Bitcoin Core's IsValidSignatureEncoding (BIP66; consensus via DERSIG)."""
    n = len(sig)
    if n < 9 or n > 73 or sig[0] != 0x30 or sig[1] != n - 3:
        return False
    lenr = sig[3]
    if 5 + lenr >= n:
        return False
    lens = sig[5 + lenr]
    if lenr + lens + 7 != n or sig[2] != 0x02 or lenr == 0 or sig[4] & 0x80:
        return False
    if lenr > 1 and sig[4] == 0 and not sig[5] & 0x80:
        return False
    if sig[lenr + 4] != 0x02 or lens == 0 or sig[lenr + 6] & 0x80:
        return False
    if lens > 1 and sig[lenr + 6] == 0 and not sig[lenr + 7] & 0x80:
        return False
    return True


def der_parts(sig):
    if not is_strict_der(sig):
        raise ValueError('not a strict-DER signature')
    lenr = sig[3]
    r = int.from_bytes(sig[4:4 + lenr], 'big')
    lens = sig[5 + lenr]
    s = int.from_bytes(sig[6 + lenr:6 + lenr + lens], 'big')
    return r, s, sig[-1]


def der_nonzero(sig):
    if not is_strict_der(sig):
        return False
    r, s, _ = der_parts(sig)
    return r > 0 and s > 0


def der_integer_count(length):
    """Number of `length`-byte strings that are valid DER positive integers."""
    if length == 1:
        return 128  # 0x00..0x7f
    return 127 * 256 ** (length - 1) + 128 * 256 ** (length - 2)


def der_work_bits(size):
    """Syntactic work exponent for a `size`-byte hash output (any sighash byte).

    Recoverability and ECDSA verification can only add work; this is the
    consensus DER-syntax model, matching measurements.json for size 20.
    """
    body = size - 7
    valid = 256 * sum(der_integer_count(a) * der_integer_count(body - a)
                      for a in range(1, body))
    return -log2(valid / 256 ** size)


# ------------------------------------------------------------ script numbers --

def scriptnum(data):
    if not data:
        return 0
    value = int.from_bytes(data, 'little')
    if data[-1] & 0x80:
        return -(value & ~(0x80 << (8 * (len(data) - 1))))
    return value


def encode_num(n):
    if n == 0:
        return b''
    negative, n = n < 0, abs(n)
    out = bytearray()
    while n:
        out.append(n & 0xff)
        n >>= 8
    if out[-1] & 0x80:
        out.append(0x80 if negative else 0)
    elif negative:
        out[-1] |= 0x80
    return bytes(out)


def small_int(op):
    if op == OP_0:
        return 0
    if OP_1 <= op <= OP_16:
        return op - OP_1 + 1
    return None


# ------------------------------------------------------ published structure --

class Construction:
    """The published locking script, parsed structurally (no byte is read twice)."""

    def __init__(self, script):
        self.script = script
        self.ins = list(instructions(script))
        ops = [op for _, op, _, _ in self.ins]
        data = [d for _, _, d, _ in self.ins]
        if not (data[0] is not None and
                ops[1:6] == [OP_OVER, OP_CHECKSIGVERIFY, OP_SHA256, OP_SWAP, OP_CHECKSIGVERIFY]):
            raise ValueError('unrecognized pinning prefix')
        self.pin_sig = data[0]
        self.pin_hash_op = ops[3]
        self.rounds = []
        self.table_tags = {}
        i = 6
        while i < len(self.ins):
            commitments = []
            while i < len(self.ins) and data[i] is not None and len(data[i]) == 20:
                commitments.append(self.ins[i][0]); i += 1
            dummies = []
            while i < len(self.ins) and data[i] is not None and len(data[i]) == 9:
                dummies.append(self.ins[i][0]); i += 1
            if not commitments or len(dummies) != len(commitments) or ops[i] != OP_0:
                raise ValueError('unrecognized round table layout')
            rnd = len(self.rounds) + 1
            for pos, a in enumerate(commitments):
                self.table_tags[a] = ('commitment', rnd, pos)
            for pos, a in enumerate(dummies):
                self.table_tags[a] = ('dummy', rnd, pos)
            i += 1
            sig_nonce = data[i]; i += 1
            signed = 0; puzzle_ops = 0; m = None
            while i < len(self.ins) and ops[i] != OP_CHECKMULTISIG:
                if ops[i] == OP_HASH160:
                    signed += 1
                if ops[i] == OP_SHA256:
                    puzzle_ops += 1
                    j = i
                    while ops[j] != OP_CHECKSIGVERIFY:
                        j += 1
                    m = small_int(ops[j + 1])
                i += 1
            if i >= len(self.ins) or puzzle_ops != 1 or m is None:
                raise ValueError('unrecognized round verification layout')
            n = small_int(ops[i - 1])
            i += 1
            self.rounds.append(dict(entries=len(commitments), sig_nonce=sig_nonce,
                                    signed=signed, bonus=m - 1 - signed, m=m, n=n))
        self.metrics = script_metrics(script)

    @property
    def entries(self):
        return self.rounds[0]['entries']

    def script_code(self, deleted):
        """Legacy FindAndDelete of complete signature pushes at opcode boundaries."""
        targets = {push(s) for s in deleted if s}
        return b''.join(self.script[a:b] for a, _, _, b in self.ins
                        if self.script[a:b] not in targets)


def published():
    spend = Tx.parse((FIXTURES/'spend.hex').read_text().strip())
    if spend.txid != TXID:
        raise ValueError('published txid mismatch')
    index = next(k for k, i in enumerate(spend.inputs) if i.script)
    parent = Tx.parse((FIXTURES/(spend.inputs[index].txid + '.hex')).read_text().strip())
    script = parent.outputs[spend.inputs[index].vout].script
    return spend, index, parent, Construction(script)


# ----------------------------------------------------------- stack simulator --

class ScriptError(Exception):
    pass


def execute(spend, index, c):
    """Re-execute the published spend under legacy semantics for the opcodes the
    construction uses. Raises on any failure; returns a tagged trace. Validity
    itself is decided only by Core (baseline native verify); this cross-checks
    the sighash/recovery/hash/DER pipeline against the published hit.
    """
    stack = []
    for a, op, data, _ in instructions(spend.inputs[index].script):
        if data is not None:
            stack.append((data, ('witness', a)))
        elif small_int(op) is not None:
            stack.append((encode_num(small_int(op)), ('smallint', small_int(op))))
        else:
            raise ScriptError(f'scriptSig opcode {op:#x} at @{a}')
    events = []

    def check_sig(sig, stag, key, ptag, at, deleted):
        if not is_strict_der(sig):
            raise ScriptError(f'signature not strict DER @{at}')
        r, s, hash_type = der_parts(sig)
        code = c.script_code(deleted)
        z = legacy_sighash(spend, index, code, hash_type=hash_type)
        if not ec.ecdsa_verify(ec.decompress_pubkey(key), int.from_bytes(z, 'big'), r, s):
            raise ScriptError(f'ECDSA verification failed @{at}')
        return z, len(code)

    for a, op, data, _ in c.ins:
        if data is not None:
            stack.append((data, c.table_tags.get(a, ('script', a))))
            continue
        value = small_int(op)
        if value is not None:
            stack.append((encode_num(value), ('smallint', value)))
            continue
        if op == OP_ROLL:
            depth = scriptnum(stack.pop()[0])
            if depth < 0 or depth >= len(stack):
                raise ScriptError('roll out of range')
            stack.append(stack.pop(-1 - depth))
        elif op == OP_MIN:
            x, y = scriptnum(stack.pop()[0]), scriptnum(stack.pop()[0])
            stack.append((encode_num(min(y, x)), ('min',)))
        elif op == OP_DUP:
            stack.append(stack[-1])
        elif op == OP_ADD:
            x, y = scriptnum(stack.pop()[0]), scriptnum(stack.pop()[0])
            stack.append((encode_num(y + x), ('add',)))
        elif op == OP_HASH160:
            stack.append((hash160(stack.pop()[0]), ('hash160',)))
        elif op == OP_SHA256:
            stack.append((sha256(stack.pop()[0]).digest(), ('sha256',)))
        elif op == OP_EQUALVERIFY:
            x, y = stack.pop(), stack.pop()
            if x[0] != y[0]:
                raise ScriptError(f'EQUALVERIFY failed @{a}')
            commitment = next((t for t in (x[1], y[1]) if t[0] == 'commitment'), None)
            if commitment is not None:
                events.append(dict(event='hors_verified', offset=a, round=commitment[1],
                                   position=commitment[2], commitment_hex=y[0].hex()))
        elif op == OP_SWAP:
            stack[-1], stack[-2] = stack[-2], stack[-1]
        elif op == OP_OVER:
            stack.append(stack[-2])
        elif op == OP_CHECKSIGVERIFY:
            key, ptag = stack.pop()
            sig, stag = stack.pop()
            z, code_bytes = check_sig(sig, stag, key, ptag, a, [sig])
            events.append(dict(event='checksigverify', offset=a, signature=sig.hex(),
                               public_key=key.hex(), sighash_byte=sig[-1], z_hex=z.hex(),
                               script_code_bytes=code_bytes, sig_tag=stag, key_tag=ptag))
        elif op == OP_CHECKMULTISIG:
            n = scriptnum(stack.pop()[0])
            pubs = [stack.pop() for _ in range(n)][::-1]
            m = scriptnum(stack.pop()[0])
            sigs = [stack.pop() for _ in range(m)][::-1]
            dummy, _ = stack.pop()
            if dummy != b'':
                raise ScriptError(f'CHECKMULTISIG dummy not null @{a}')
            code = c.script_code([sv for sv, _ in sigs])
            ikey, pairs = 0, []
            for sv, stag in sigs:
                if not is_strict_der(sv):
                    raise ScriptError(f'CHECKMULTISIG sig not strict DER @{a}')
                r, s, hash_type = der_parts(sv)
                z = legacy_sighash(spend, index, code, hash_type=hash_type)
                matched = False
                while ikey < n:
                    pv, ptag = pubs[ikey]
                    ikey += 1
                    if ec.ecdsa_verify(ec.decompress_pubkey(pv), int.from_bytes(z, 'big'), r, s):
                        pairs.append(dict(signature=sv.hex(), public_key=pv.hex(),
                                          sighash_byte=hash_type, z_hex=z.hex(),
                                          sig_tag=stag, key_tag=ptag))
                        matched = True
                        break
                if not matched:
                    raise ScriptError(f'CHECKMULTISIG unmatched signature @{a}')
            stack.append((b'\x01', ('checkmultisig',)))
            events.append(dict(event='checkmultisig', offset=a, m=m, n=n,
                               script_code_bytes=len(code), pairs=pairs))
        else:
            raise ScriptError(f'unsupported opcode {op:#x} at @{a}')
    if not stack or stack[-1][0] != b'\x01':
        raise ScriptError('script finished false')
    return events, len(stack)


# --------------------------------------------------------------- validation --

def recovery_branch(sig, z, key):
    r, s, _ = der_parts(sig)
    for branch in range(4):
        q = recover(r, s, z, branch)
        if q is not None and encode(q) == key:
            return branch
    return None


def validate_published():
    """Reproduce every check of the pinned mainnet spend; raise on any mismatch."""
    spend, index, parent, c = published()
    events, depth = execute(spend, index, c)
    csv = [e for e in events if e['event'] == 'checksigverify']
    cms = [e for e in events if e['event'] == 'checkmultisig']
    hors = [e for e in events if e['event'] == 'hors_verified']
    # Two pinning CHECKSIGVERIFYs plus one stage-3a CHECKSIGVERIFY per round;
    # the rounds' sig_nonces are verified inside CHECKMULTISIG instead.
    if len(csv) != 2 + len(c.rounds) or len(cms) != len(c.rounds):
        raise AssertionError('unexpected check structure')
    witness = [d for _, _, d, _ in instructions(spend.inputs[index].script) if d is not None]
    pin, puzzles = csv[0], csv[1:]
    if pin['public_key'] != witness[-1].hex() or puzzles[0]['public_key'] != witness[-2].hex():
        raise AssertionError('pinning witness keys are not the last two scriptSig pushes')
    sig_puzzle = bytes.fromhex(puzzles[0]['signature'])
    key_nonce = bytes.fromhex(pin['public_key'])
    if puzzles[0]['sig_tag'] != ('sha256',) or sig_puzzle != sha256(key_nonce).digest():
        raise AssertionError('pinning puzzle signature is not SHA256(key_nonce)')
    if not der_nonzero(sig_puzzle):
        raise AssertionError('pinning puzzle signature failed strict-DER/nonzero')
    ripemd_puzzle = new('ripemd160', key_nonce).digest()
    if is_strict_der(ripemd_puzzle):
        raise AssertionError('RIPEMD160(key_nonce) unexpectedly passes DER; contrast broken')
    single_bug_z = (b'\x01' + bytes(31)).hex()
    rounds = []
    for rnd, (layout, multi) in enumerate(zip(c.rounds, cms), start=1):
        selected = [p for p in multi['pairs'] if p['sig_tag'][0] == 'dummy']
        hardcoded = [p for p in multi['pairs'] if p['sig_tag'][0] == 'script']
        verified = sorted(h['position'] for h in hors if h['round'] == rnd)
        if len(hardcoded) != 1 or len(selected) != multi['m'] - 1:
            raise AssertionError('round is missing its hardcoded sig_nonce')
        if any(p['sighash_byte'] != 3 or p['z_hex'] != single_bug_z for p in selected):
            raise AssertionError('dummy signatures lost their SIGHASH_SINGLE-bug z=1')
        positions = sorted(p['sig_tag'][2] for p in selected)
        if len(positions) != len(verified) + layout['bonus']:
            raise AssertionError('selection count is not signed + bonus')
        rounds.append(dict(round=rnd, entries=layout['entries'], m=multi['m'], n=multi['n'],
            signed_selections=layout['signed'], bonus_selections=layout['bonus'],
            script_code_bytes=multi['script_code_bytes'],
            subset_space=comb(layout['entries'], multi['m'] - 1),
            subset_space_bits=log2(comb(layout['entries'], multi['m'] - 1)),
            sig_nonce_hex=hardcoded[0]['signature'], sig_nonce_z_hex=hardcoded[0]['z_hex'],
            sig_nonce_sighash_byte=hardcoded[0]['sighash_byte'],
            dummy_positions_multisig_order=[p['sig_tag'][2] for p in selected],
            hors_verified_positions=verified,
            bonus_positions=sorted(set(positions) - set(verified)),
            witness_index_pushes=sorted(151 - p for p in positions),
            auth_index_convention='Earlier attempt indexed from the opposite table end: auth = 149 - position = witness_push - 2.',
            puzzle_signature_hex=puzzles[rnd]['signature'],
            puzzle_z_hex=puzzles[rnd]['z_hex'], puzzle_key_hex=puzzles[rnd]['public_key']))
    if [r['bonus_selections'] for r in rounds] != [1, 2]:
        raise AssertionError('published bonus selection counts are not 1 and 2')
    pinning = dict(sig_nonce_hex=pin['signature'], sighash_byte=pin['sighash_byte'],
        z_hex=pin['z_hex'], script_code_bytes=pin['script_code_bytes'],
        key_nonce_hex=pin['public_key'],
        key_nonce_recovery_branch=recovery_branch(bytes.fromhex(pin['signature']),
                                                  bytes.fromhex(pin['z_hex']), key_nonce),
        key_puzzle_hex=puzzles[0]['public_key'],
        sig_puzzle_hex=sig_puzzle.hex(), sig_puzzle_sighash_byte=sig_puzzle[-1],
        sig_puzzle_z_hex=puzzles[0]['z_hex'], sig_puzzle_strict_der=True,
        sig_puzzle_recovery_branch=recovery_branch(sig_puzzle,
                                                   bytes.fromhex(puzzles[0]['z_hex']),
                                                   bytes.fromhex(puzzles[0]['public_key'])))
    return dict(spend_txid=spend.txid, qsb_input_index=index, funding_txid=parent.txid,
        funding_vout=spend.inputs[index].vout,
        funding_value_sats=parent.outputs[spend.inputs[index].vout].value,
        script=c.metrics, script_sha256=sha256(c.script).hexdigest(),
        deployed_puzzle_hash='SHA256', deployed_puzzle_opcode=hex(c.pin_hash_op),
        paper_text_puzzle_hash='RIPEMD160',
        ripemd160_key_nonce_hex=ripemd_puzzle.hex(), ripemd160_key_nonce_strict_der=False,
        hors_equalverify_checks=len(hors), final_stack_depth=depth,
        pinning=pinning, digest_rounds=rounds)


# ------------------------------------------------------------------- search --

class Pinning:
    """Precomputed public recovery context for one hardcoded sig_nonce."""

    def __init__(self, sig_nonce):
        self.sig = sig_nonce
        self.sighash_byte = sig_nonce[-1]
        self.r, self.s, _ = der_parts(sig_nonce)
        self.inverse_r = pow(self.r, -1, ec.N)
        self.branches = []  # (recovery id, C = s*R/r), the constant key offset
        for branch in range(4):
            x = self.r + (branch >> 1) * ec.N
            if x >= ec.P:
                continue
            y2 = (pow(x, 3, ec.P) + 7) % ec.P
            y = pow(y2, (ec.P + 1) // 4, ec.P)
            if y * y % ec.P != y2:
                continue
            if y % 2 != branch % 2:
                y = ec.P - y
            self.branches.append((branch, ec.point_mul(self.s * self.inverse_r % ec.N, (x, y))))

    def keys(self, digest):
        """Candidate key_nonce per valid recovery branch: Q = u1*G + C_b."""
        z = int.from_bytes(digest, 'big') % ec.N
        if z == 0:
            return
        point = ec.point_mul(-z * self.inverse_r % ec.N, ec.G)
        for branch, constant in self.branches:
            q = ec.point_add(point, constant)
            if q != ec.INF:
                yield branch, encode(q)

    def screen(self, digest):
        """The deployed per-candidate predicate, evaluated on every recovered key."""
        out = []
        for branch, key in self.keys(digest):
            hashed = sha256(key).digest()
            if der_nonzero(hashed):
                out.append((branch, key, hashed))
        return out

    def validate_hit(self, tx, index, script, digest, branch, key, sig_puzzle):
        """Full end-to-end check: both pinning CHECKSIGVERIFY stages must pass."""
        if encode(recover(self.r, self.s, digest, branch)) != key:
            return None
        code = delete_sigs(script, [sig_puzzle])
        z2 = legacy_sighash(tx, index, code, hash_type=sig_puzzle[-1])
        r2, s2, _ = der_parts(sig_puzzle)
        for branch2 in range(4):
            point = recover(r2, s2, z2, branch2)
            if point is not None:
                return dict(key_puzzle_hex=encode(point).hex(), puzzle_recovery_branch=branch2,
                            sig_puzzle_hex=sig_puzzle.hex(),
                            sig_puzzle_sighash_byte=sig_puzzle[-1], sig_puzzle_z_hex=z2.hex())
        return None


def delete_sigs(script, signatures):
    targets = {push(s) for s in signatures if s}
    return b''.join(script[a:b] for a, _, _, b in instructions(script)
                    if script[a:b] not in targets)


class Search:
    """CPU enumeration over input-1 nSequence; hashing uses a SHA256 midstate."""

    def __init__(self, pinning, script, tx, index=1):
        self.pinning, self.script, self.tx, self.index = pinning, script, tx, index
        self.code = delete_sigs(script, [pinning.sig])
        self.prefix = (struct.pack('<i', tx.version) + compact(len(tx.inputs))
                       + b''.join(tx.inputs[j].serialize() for j in range(index))
                       + bytes.fromhex(tx.inputs[index].txid)[::-1]
                       + struct.pack('<I', tx.inputs[index].vout))
        self.tail = (compact(len(tx.outputs)) + b''.join(o.serialize() for o in tx.outputs)
                     + struct.pack('<II', tx.locktime, pinning.sighash_byte))
        self.midstate = sha256(self.prefix + compact(len(self.code)) + self.code)

    def digest(self, sequence):
        state = self.midstate.copy()
        state.update(struct.pack('<I', sequence) + self.tail)
        return sha256(state.digest()).digest()

    def stats(self, start, count, first_counter, der_passes, events,
              found=False, budget=False, space=False):
        elapsed = time.perf_counter() - start
        return dict(wall_seconds=elapsed, candidates=count,
            candidate_unit='transaction sequence variants',
            candidates_per_second=count / elapsed if elapsed else None,
            key_trials=count * len(self.pinning.branches),
            key_trials_per_second=count * len(self.pinning.branches) / elapsed if elapsed else None,
            first_counter=first_counter, next_counter=first_counter + count,
            found=found, der_passes=der_passes, der_pass_events=events,
            budget_exhausted=budget, sequence_space_exhausted=space)

    def pin(self, first_counter, max_candidates, deadline):
        start = time.perf_counter()
        der_passes, events, count = 0, [], 0
        while count < max_candidates:
            if count % 1024 == 0 and time.perf_counter() >= deadline:
                return None, self.stats(start, count, first_counter, der_passes, events, budget=True)
            counter = first_counter + count
            if counter >= 2**31:
                return None, self.stats(start, count, first_counter, der_passes, events, space=True)
            sequence = 0x80000000 | counter
            self.tx.inputs[self.index].sequence = sequence
            digest = self.digest(sequence)
            count += 1
            for branch, key, sig_puzzle in self.pinning.screen(digest):
                der_passes += 1
                hit = self.pinning.validate_hit(self.tx, self.index, self.script,
                                                digest, branch, key, sig_puzzle)
                event = dict(winning_counter=counter, sequence=sequence, digest_hex=digest.hex(),
                             recovery_branch=branch, key_nonce_hex=key.hex(),
                             sha256_key_hex=sig_puzzle.hex(), full_hit=hit is not None)
                if hit is not None:
                    reference = legacy_sighash(self.tx, self.index, self.code,
                                               hash_type=self.pinning.sighash_byte)
                    if reference != digest:
                        raise AssertionError('pinning template/reference mismatch')
                    event.update(hit)
                    return event, self.stats(start, count, first_counter, der_passes,
                                             events + [event], found=True)
                events.append(event)
        return None, self.stats(start, count, first_counter, der_passes, events, budget=True)


# ------------------------------------------------------------------- native --

def build_native():
    cmake, build = ROOT/'.venv/bin/cmake', ROOT/'.cache/native-build'
    if not (build/'CMakeCache.txt').exists():
        raise RuntimeError('native build cache missing; see native/CMakeLists.txt')
    p = subprocess.run([str(cmake), '--build', str(build), '--parallel', '6',
                        '--target', 'btc-pq-phase3-search'], capture_output=True, text=True)
    if p.returncode != 0 or not SEARCH_BIN.exists():
        raise RuntimeError('native search build failed: ' + (p.stderr or p.stdout)[-400:])
    return SEARCH_BIN


def native_request(pinning, mode, **extra):
    return dict(mode=mode, inverse_r_hex=pinning.inverse_r.to_bytes(32, 'big').hex(),
                r_hex=pinning.r.to_bytes(32, 'big').hex(),
                s_hex=pinning.s.to_bytes(32, 'big').hex(),
                branch_constants=[ec.compress_pubkey(c).hex() for _, c in pinning.branches], **extra)


def native_call(binary, request, timeout):
    p = subprocess.run([str(binary)], input=json.dumps(request),
                       capture_output=True, text=True, timeout=timeout)
    if p.returncode != 0:
        raise RuntimeError('native search failed: ' + p.stderr.strip()[:300])
    return json.loads(p.stdout)


def native_vectors(binary, pinning, digests):
    """Cross-check native keys/hashes/DER against the Python pipeline."""
    out = native_call(binary, native_request(pinning, 'vectors',
                                             digests=[d.hex() for d in digests]), 60)
    mismatches = []
    for row, digest in zip(out['vectors'], digests):
        keys = {b: encode(q) for b in range(4)
                if (q := recover(pinning.r, pinning.s, digest, b)) is not None}
        for branch_row in row['branches']:
            b, key = branch_row['branch'], bytes.fromhex(branch_row['key_hex'])
            hashed = sha256(key).digest()
            if keys.get(b) != key or branch_row['sha256_hex'] != hashed.hex() \
                    or branch_row['der_pass'] != der_nonzero(hashed):
                mismatches.append(dict(digest_hex=digest.hex(), branch=b))
        general = {g['recid']: bytes.fromhex(g['key_hex']) for g in row['general_recovery']}
        if {b: k.hex() for b, k in keys.items()} != {b: k.hex() for b, k in general.items()}:
            mismatches.append(dict(digest_hex=digest.hex(), general=True))
    return dict(vectors=len(digests), mismatches=mismatches)


# -------------------------------------------------------------- orchestration --

def template_tx(funding, fee_utxo, value=9_000):
    return Tx([Input(fee_utxo['txid'], fee_utxo['vout'], sequence=0xfffffffd),
               Input(funding.txid, 0, sequence=0x80000000)],
              [Output(value, b'\x51')])


def replay(outdir, bitcoind='bitcoind', result=None):
    outdir = Path(outdir)
    result = result or json.loads((outdir/'results.json').read_text())
    _, _, _, c = published()
    script = bytes.fromhex((outdir/'locking-script.hex').read_text().strip())
    if script != c.script:
        raise AssertionError('saved locking script differs from the published script')
    with Core(bitcoind) as core:
        for path in result['setup_blocks']:
            outcome = core.rpc('submitblock', (outdir/path).read_text().strip())
            if outcome is not None:
                raise AssertionError(f'setup block replay rejected: {outcome}')
        if core.rpc('getbestblockhash') != result['base_tip']:
            raise AssertionError('replay setup tip mismatch')
        native = verify(outdir/'funding.hex', [outdir/'funding-parent.hex'])
        if not native['valid']:
            raise AssertionError('funding native replay failed')
        funding = Tx.parse((outdir/'funding.hex').read_text().strip())
        if funding.outputs[0].script != c.script:
            raise AssertionError('funded script is not the published script')
    return dict(core_version=310100, setup_blocks_replayed=len(result['setup_blocks']),
                funding_native_valid=True, funded_script_matches_published=True,
                spend_cases=[], note='No spend was assembled; the bounded search found no hit.')


def run(outdir, bitcoind='bitcoind', max_candidates=20_000_000, max_seconds=120, native=True):
    if max_candidates < 1 or max_seconds <= 0:
        raise ValueError('search budgets must be positive')
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    if (outdir/'results.json').exists():
        raise ValueError('output already contains results.json; choose a fresh --outdir')
    blocks = outdir/'blocks'
    blocks.mkdir(exist_ok=True)
    total_start = time.perf_counter()
    result = dict(schema_version=1, scope='isolated_regtest_public_test_data_only',
        experiment='qsb_published_construction_exact_pinning_search',
        published_pipeline_validated=False, pinning_hit_found=False,
        regtest_spend_demonstrated=False, qsb_hash_to_der_end_to_end_demonstrated=False,
        secure_candidate_demonstrated=False, full_strength_demonstration=False,
        deployed_puzzle=dict(hash='SHA256', opcode='0xa8', sites='pinning and both digest rounds',
            evidence='validated re-execution of the published spend plus baseline Core 31.1 native verification',
            syntactic_work_bits=der_work_bits(32)),
        paper_text_puzzle=dict(hash='RIPEMD160', syntactic_work_bits=der_work_bits(20),
            note='The pinned paper text adopts RIPEMD-160 throughout; the deployed script uses SHA256.'),
        limitations=['The search covers only the pinning predicate; even a pinning hit could not be assembled into a regtest spend without the undisclosed HORS preimages and two further ~2^45.4 digest-round searches.',
            'Candidate rates measure this CPU/implementation only; the expected-time rows are probability arithmetic, not measurements of a completed setup.',
            'Native consensus and block acceptance are measured for funding only; no spend exists to relay or mine.'],
        environment=dict(python=platform.python_version(), platform=platform.platform(),
                         processor=platform.machine()),
        consensus_changes=[], relay_policy_changes=[], searches=[], setup_blocks=[])

    start = time.perf_counter()
    spend, index, parent, c = published()
    validation = validate_published()
    result['published_validation'] = validation
    result['published_pipeline_validated'] = True
    result['published_validation_wall_seconds'] = time.perf_counter() - start
    pinning = Pinning(bytes.fromhex(validation['pinning']['sig_nonce_hex']))
    result['bounded_parameters'] = dict(
        search_variable='input 1 nSequence (0x80000000|counter), nLockTime fixed at 0',
        input_count=2, output_count=1, sighash='ALL with FindAndDelete(sig_nonce)',
        per_candidate_key_trials=len(pinning.branches),
        valid_recovery_branches=[b for b, _ in pinning.branches],
        max_candidates_per_implementation=max_candidates,
        max_seconds_per_implementation=max_seconds)
    result['provenance'] = dict(
        pinned_reference_commit=check_vendor()['commit'],
        source_sha256={str(p.relative_to(ROOT)): sha256(p.read_bytes()).hexdigest()
                       for p in [Path(__file__), ROOT/'btc_pq/cli.py', ROOT/'btc_pq/bitcoin.py',
                                 ROOT/'btc_pq/core.py', ROOT/'vendor/qsb/paper/QSB.tex',
                                 ROOT/'native/phase3_search.cpp', VERIFIER]})
    (outdir/'locking-script.hex').write_text(c.script.hex() + '\n')
    (outdir/'published-parent.hex').write_text(parent.serialize().hex() + '\n')

    try:
        with Core(bitcoind) as core:
            result['core_version'] = core.info['version']
            if core.rpc('getblockchaininfo')['chain'] != 'regtest' or core.rpc('getnetworkinfo')['networkactive']:
                raise AssertionError('node is not isolated regtest')
            result['node_isolation'] = dict(chain='regtest', networkactive=False, listen=False,
                                            temporary_datadir=True)
            start = time.perf_counter()
            core.rpc('generatetoaddress', 101, core.address)
            utxo = sorted(core.rpc('listunspent', 100), key=lambda x: x['txid'])[0]
            change = bytes.fromhex(core.rpc('getaddressinfo', core.address)['scriptPubKey'])
            value = round(utxo['amount'] * 100_000_000)
            funding = Tx([Input(utxo['txid'], utxo['vout'])],
                         [Output(10_000, c.script), Output(value - 20_000, change)])
            signed = core.rpc('signrawtransactionwithwallet', funding.serialize().hex())
            if not signed['complete']:
                raise RuntimeError('regtest funding not signed')
            funding = Tx.parse(signed['hex'])
            parent_path = outdir/'funding-parent.hex'
            parent_path.write_text(core.rpc('gettransaction', utxo['txid'])['hex'] + '\n')
            funding_path = write_tx(outdir/'funding.hex', funding)
            funding_native = verify(funding_path, [parent_path])
            if not funding_native['valid']:
                raise AssertionError('funding native verification failed')
            funding_block = core.mine(funding)
            result['funding'] = dict(wall_seconds=time.perf_counter() - start,
                transaction=funding.metrics(), native=funding_native, blockhash=funding_block,
                file='funding.hex', funded_script_bytes=len(c.script),
                timing_scope='101 maturity blocks, wallet signing, native verification, funding block')
            for height in range(1, core.rpc('getblockcount') + 1):
                h = core.rpc('getblockhash', height)
                path = blocks/f'setup-{height:03}.hex'
                path.write_text(core.rpc('getblock', h, 0) + '\n')
                result['setup_blocks'].append(str(path.relative_to(outdir)))
            result['base_tip'] = core.rpc('getbestblockhash')
            # The funding block matured the next coinbase; use it for the fee input.
            fee_utxo = sorted(core.rpc('listunspent', 100), key=lambda x: x['txid'])[0]

            tx = template_tx(funding, fee_utxo)
            write_tx(outdir/'spend-template.hex', tx)
            result['spend_template'] = dict(file='spend-template.hex', transaction=tx.metrics(),
                fee_input=dict(txid=fee_utxo['txid'], vout=fee_utxo['vout']),
                note='Search template only: unsigned, never broadcast; sighash fields are fixed except input 1 nSequence.')
            search = Search(pinning, c.script, tx)
            if search.digest(tx.inputs[1].sequence) != \
                    legacy_sighash(tx, 1, search.code, hash_type=pinning.sighash_byte):
                raise AssertionError('search template does not match the reference sighash')
            hit, stats = search.pin(0, max_candidates, time.perf_counter() + max_seconds)
            stats['implementation'] = ('python: vendored pure-Python secp256k1 '
                '(vendor/qsb/v16/pipeline/secp256k1.py); P=u1*G per digest, Q=P+C_b per branch; '
                'hashlib SHA256; strict-DER port of Core IsValidSignatureEncoding plus r,s>0')
            result['searches'].append(stats)
            if hit is not None:
                result['pinning_hit_found'] = True
                result['pinning_hit'] = dict(hit, implementation='python', spend_assembled=False,
                    assembly_note='Digest rounds require undisclosed HORS preimages and further searches; no spend fabricated.')
            next_counter = stats['next_counter']

            if native:
                try:
                    binary = build_native()
                    result['provenance']['source_sha256'][str(binary.relative_to(ROOT))] = \
                        sha256(binary.read_bytes()).hexdigest()
                    digests = [bytes.fromhex(validation['pinning']['z_hex'])] + \
                        [sha256(f'phase3 vector {i}'.encode()).digest() for i in range(63)]
                    vectors = native_vectors(binary, pinning, digests)
                    if vectors['mismatches']:
                        raise AssertionError(f"native/python vector mismatch: {vectors['mismatches'][:2]}")
                    benchmark = native_call(binary, native_request(
                        pinning, 'benchmark', max_candidates=200_000, max_seconds=10.0), 30)
                    native_out = native_call(binary, native_request(
                        pinning, 'pin', prefix_hex=search.prefix.hex(), code_hex=search.code.hex(),
                        tail_hex=search.tail.hex(), counter=next_counter,
                        max_candidates=max_candidates, max_seconds=max_seconds), max_seconds + 120)
                    rate = native_out['measurement']
                    nstats = dict(rate,
                        key_trials=rate['candidates'] * len(pinning.branches),
                        key_trials_per_second=rate['candidates_per_second'] * len(pinning.branches),
                        first_counter=native_out['first_counter'],
                        next_counter=native_out['next_counter'],
                        found=False, der_passes=native_out['der_passes'],
                        budget_exhausted=native_out['budget_exhausted'],
                        sequence_space_exhausted=native_out['space_exhausted'],
                        implementation='native: btc-pq-phase3-search (libsecp256k1 from the unchanged Core 31.1 tree); same algorithm',
                        vectors_checked=vectors['vectors'], vectors_mismatched=0,
                        synthetic_benchmark=benchmark['measurement'], consensus_modified=False)
                    for event in native_out['der_pass_events']:
                        full = pinning.validate_hit(tx, 1, c.script,
                            bytes.fromhex(event['digest_hex']), event['recovery_branch'],
                            bytes.fromhex(event['key_nonce_hex']),
                            bytes.fromhex(event['sha256_key_hex']))
                        event['full_hit'] = full is not None
                        if full is not None and not result['pinning_hit_found']:
                            result['pinning_hit_found'] = True
                            result['pinning_hit'] = dict(event, **full, implementation='native',
                                spend_assembled=False,
                                assembly_note='Digest rounds require undisclosed HORS preimages and further searches; no spend fabricated.')
                    nstats['der_pass_events'] = native_out['der_pass_events']
                    result['searches'].append(nstats)
                except (RuntimeError, subprocess.SubprocessError) as error:
                    result['native_search_error'] = str(error)
        rows = []
        for row in result['searches']:
            rate = row.get('key_trials_per_second')
            if not rate:
                continue
            rows.append(dict(implementation=row['implementation'].split(':')[0],
                measured_key_trials_per_second=rate,
                expected_seconds_deployed=2 ** der_work_bits(32) / rate,
                expected_years_deployed=2 ** der_work_bits(32) / rate / 31_557_600,
                expected_seconds_paper_text=2 ** der_work_bits(20) / rate,
                expected_years_paper_text=2 ** der_work_bits(20) / rate / 31_557_600))
        result['expected_time_model'] = dict(
            model='probability arithmetic over the measured single-CPU rates; not a measurement of a completed search',
            per_key_trial_note='Each candidate yields one SHA256 hash per valid recovery branch; the DER probability applies per key trial.',
            deployed_syntactic_work_bits=der_work_bits(32),
            paper_text_syntactic_work_bits=der_work_bits(20), rows=rows)
        start = time.perf_counter()
        result['replay'] = replay(outdir, bitcoind, result)
        result['replay']['wall_seconds'] = time.perf_counter() - start
        result['status'] = 'pinning_hit_unassembled' if result['pinning_hit_found'] \
            else 'bounded_search_exhausted_no_hit'
        result['reproduction_command'] = ('.venv/bin/python -m btc_pq.cli phase3 '
            f'--max-candidates {max_candidates} --max-seconds {max_seconds} '
            '--outdir results/phase3-rerun')
        result['total_wall_seconds'] = time.perf_counter() - total_start
        (outdir/'results.json').write_text(json.dumps(result, indent=2) + '\n')
        (outdir/'partial-results.json').unlink(missing_ok=True)
        return result
    except BaseException as error:
        result['failure'] = str(error)
        result['status'] = 'incomplete'
        result['total_wall_seconds'] = time.perf_counter() - total_start
        (outdir/'partial-results.json').write_text(json.dumps(result, indent=2) + '\n')
        raise
