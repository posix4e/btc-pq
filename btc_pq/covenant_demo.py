"""Executable proposal demo: hash-only authorization, transaction binding, no key path.

Uses full 256-bit Lamport messages and SHA256 preimages. All fixture keys are
deterministic public test data. Each key signs exactly one message. This is a
teaching compiler, not a wallet or a replacement implementation of SHRINCS.
"""
from copy import deepcopy
from hashlib import sha256
from pathlib import Path
import json
import struct
import sys
import time

from .bitcoin import Input, Output, Tx, blob, num, push, script_metrics
from .crypto import ROOT
from .core import verify, VERIFIER as STOCK_VERIFIER
from .covenant_build import VERIFIER, BUILD


def tagged_hash(tag, data):
    prefix = sha256(tag.encode()).digest()
    return sha256(prefix + prefix + data).digest()


def template_hash(tx, index=0, annex=None):
    """BIP446: deliberately excludes outpoints, spent values and spent scripts."""
    if not 0 <= index < len(tx.inputs):
        raise ValueError('input index out of range')
    if annex is not None and (not annex or annex[0] != 0x50):
        raise ValueError('annex must start with 0x50')
    message = struct.pack('<iI', tx.version, tx.locktime)
    message += sha256(b''.join(struct.pack('<I', i.sequence) for i in tx.inputs)).digest()
    message += sha256(b''.join(o.serialize() for o in tx.outputs)).digest()
    message += bytes([annex is not None]) + struct.pack('<I', index)
    if annex is not None:
        message += sha256(blob(annex)).digest()
    return tagged_hash('TemplateHash', message)


def test_keys(label):
    return [[sha256(b'PUBLIC COVENANT DEMO/' + label.encode() + struct.pack('<HB', i, bit)).digest()
             for bit in (0, 1)] for i in range(256)]


# Convert a nonnegative ScriptNum in [0,255] into exactly one raw byte. In the
# upper half OP_NEGATE creates the desired high bit; 0x80 needs a special case.
BYTE_ENCODING = (b'\x76' + num(128) + b'\x9f\x63\x76\x91\x63\x75' + push(b'\x00') +
                 b'\x68\x67' + num(128) + b'\x94\x76\x91\x63\x75' + push(b'\x80') +
                 b'\x67\x8f\x68\x68')


def lamport_script(keys, bound=True):
    if len(keys) != 256 or any(len(pair) != 2 or any(len(k) != 32 for k in pair) for pair in keys):
        raise ValueError('256 pairs of 32-byte secrets required')
    script = b'\x00\x6b'  # empty reconstructed digest on altstack
    for byte_index in range(32):
        script += b'\x00\x6b'  # byte accumulator above the digest
        for bit_index in range(8):
            zero, one = keys[byte_index * 8 + bit_index]
            # Main stack: secret, bit. Preserve bit, select its committed hash,
            # verify preimage; then update byte = 2*byte + bit on the altstack.
            script += b'\x76\x63' + push(sha256(one).digest())
            script += b'\x67' + push(sha256(zero).digest()) + b'\x68\x7b\xa8\x88'
            script += b'\x6c\x76\x93\x93\x6b'
        script += b'\x6c' + BYTE_ENCODING + b'\x6c\x7c\x7e\x6b'
    return script + b'\x6c' + (b'\xce\x87' if bound else b'\x75\x51')


def lamport_witness(keys, digest):
    if len(digest) != 32:
        raise ValueError('full 32-byte message required')
    pairs = []
    for index in range(256):
        bit = (digest[index // 8] >> (7 - index % 8)) & 1
        pairs.append([keys[index][bit], b'\x01' if bit else b''])
    return [item for pair in reversed(pairs) for item in pair]


def tapleaf(script, version=0xc0):
    return tagged_hash('TapLeaf', bytes([version]) + blob(script))


def p2mr(script):
    # BIP360 v0.12.1 reserves depth zero for success. Use a depth-one proof and
    # an OP_RETURN sibling, so neither committed leaf provides a bypass.
    sibling = tapleaf(b'\x6a')
    root = tagged_hash('TapBranch', b''.join(sorted([tapleaf(script), sibling])))
    return b'\x52\x20' + root, b'\xc1' + sibling


def funding(script_pubkey, label, duplicate=False):
    # Synthetic linked parents, not mined coins. The native verifier checks the
    # spend against these exact prevouts; it does not validate their ancestry.
    return Tx([Input(sha256(label.encode()).hexdigest(), 0)],
              [Output(100_000, script_pubkey) for _ in range(2 if duplicate else 1)])


def payment(parents):
    # Hash-only recipient address; its spend is outside this demo.
    destination, _ = p2mr(lamport_script(test_keys('recipient')))
    return Tx([Input(parent.txid, 0) for parent in parents],
              [Output(sum(parent.outputs[0].value for parent in parents) - 1_000, destination)])


def core_test_helpers():
    """Use the pinned Core functional-test BIP340/341 signer for the key path control."""
    path = str(ROOT/'.cache/bitcoin/test/functional')
    if path not in sys.path:
        sys.path.insert(0, path)
    from test_framework.key import compute_xonly_pubkey, sign_schnorr, tweak_add_privkey
    from test_framework.script import taproot_construct, TaprootSignatureHash
    from test_framework.messages import tx_from_hex
    return compute_xonly_pubkey, sign_schnorr, tweak_add_privkey, taproot_construct, TaprootSignatureHash, tx_from_hex


def run(outdir, build=False):
    if build:
        from .covenant_build import build as build_verifier
        build_verifier()
    if not VERIFIER.exists() or not STOCK_VERIFIER.exists():
        raise RuntimeError('build the stock verifier first, then run covenant-demo --build')
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    cases, metrics = [], {}

    def record(name, tx, parents, expected, explanation, stock=False, digests=None):
        spend_file = outdir / f'{name}.hex'
        spend_file.write_text(tx.serialize().hex()+'\n')
        parent_files = []
        for parent in parents:
            parent_file = outdir / f'parent-{parent.txid}.hex'
            parent_file.write_text(parent.serialize().hex()+'\n')
            parent_files.append(parent_file)
        result = verify(spend_file, parent_files, STOCK_VERIFIER if stock else VERIFIER)
        if result['valid'] != expected:
            raise AssertionError(f'{name}: expected {expected}, got {result}')
        if digests is not None:
            actual = [i['template_hash'] for i in result['inputs']]
            if actual != [d.hex() for d in digests]:
                raise AssertionError(f'{name}: native/Python TemplateHash mismatch: {actual}')
        row = dict(name=name, expected_valid=expected, explanation=explanation,
                   verifier='stock_upgrade_hook' if stock else 'proposal_model',
                   spend=spend_file.name, parents=[p.name for p in parent_files],
                   result=result, transaction=tx.metrics())
        cases.append(row)

    def mutate(tx, field):
        changed = deepcopy(tx)
        if field == 'recipient':
            changed.outputs[0].script = p2mr(b'\x51')[0]
        elif field == 'amount':
            changed.outputs[0].value -= 1
        elif field == 'sequence':
            changed.inputs[0].sequence -= 1
        elif field == 'locktime':
            changed.locktime += 1
        elif field == 'version':
            changed.version += 1
        elif field == 'secret':
            changed.inputs[0].witness[0] = bytes(32)
        elif field == 'bit':
            w = changed.inputs[0].witness
            w[1] = b'' if w[1] else b'\x01'
        elif field == 'nonminimal_bit':
            changed.inputs[0].witness[1] = b'\x02'
        elif field == 'merkle_proof':
            w = changed.inputs[0].witness
            w[-1] = w[-1][:-1] + bytes([w[-1][-1] ^ 1])
        else:
            raise ValueError(field)
        return changed

    # Three independent one-time keys, each signs only one template digest.
    for label, bound, output_type in [('p2mr-unbound', False, 'p2mr'),
                                       ('taproot-bound', True, 'taproot'),
                                       ('p2mr-bound', True, 'p2mr')]:
        start = time.perf_counter()
        keys = test_keys(label)
        script = lamport_script(keys, bound)
        prepare_ms = (time.perf_counter()-start)*1000
        if output_type == 'p2mr':
            script_pubkey, control = p2mr(script)
        else:
            xonly, schnorr, tweak_priv, construct, sighash, parse = core_test_helpers()
            internal_key = sha256(b'PUBLIC DEMO KEY PATH CONTROL').digest()
            tree = construct(xonly(internal_key)[0], [('auth', script), ('disabled', b'\x6a')])
            script_pubkey = bytes(tree.scriptPubKey)
            control = bytes([0xc0 | tree.negflag]) + tree.internal_pubkey + tree.leaves['auth'].merklebranch
        parent = funding(script_pubkey, label, duplicate=True)
        tx = payment([parent])
        digest = template_hash(tx)
        start = time.perf_counter()
        auth = lamport_witness(keys, digest)
        sign_ms = (time.perf_counter()-start)*1000
        tx.inputs[0].witness = auth + [script, control]
        record(label+'-valid', tx, [parent], True, 'Owner authorizes the original payment.',
               digests=[digest] if bound else None)
        metrics[label] = dict(script=script_metrics(script), signature_preimage_bytes=256*32,
                              signature_bit_bytes=sum(map(len, auth[1::2])),
                              authorization_items=len(auth), control_bytes=len(control),
                              keygen_and_compile_ms=prepare_ms, signing_ms=sign_ms,
                              rare_hash_search_trials=0, transaction=tx.metrics())
        for field in ('recipient', 'amount', 'sequence'):
            record(label+'-changed-'+field, mutate(tx, field), [parent], not bound,
                   'Same disclosed authorization, changed '+field+'.')
        if output_type == 'taproot':
            bypass = mutate(tx, 'recipient')
            digest_ec = sighash(parse(bypass.serialize().hex()), [parse(parent.serialize().hex()).vout[0]], 0)
            bypass.inputs[0].witness = [schnorr(tweak_priv(internal_key, tree.tweak), digest_ec)]
            record('taproot-known-key-bypass', bypass, [parent], True,
                   'Known tweaked private key spends without Lamport; demonstrates the bypass, not Shor execution.')
            record('stock-taproot-invalid-secret', mutate(tx, 'secret'), [parent], True,
                   'Stock consensus returns OP_SUCCESS before enforcing these proposed opcodes.', stock=True)
        if label == 'p2mr-bound':
            for field in ('locktime', 'version', 'secret', 'bit', 'nonminimal_bit', 'merkle_proof'):
                record(label+'-changed-'+field, mutate(tx, field), [parent], False,
                       'Same authorization with invalid '+field+'.')
            lone = deepcopy(tx)
            lone.inputs[0].witness = [bytes(64)]
            record('p2mr-no-key-path', lone, [parent], False, 'A lone signature has no key-path interpretation.')
            rebind = deepcopy(tx)
            rebind.inputs[0].vout = 1
            record('template-allows-outpoint-rebinding', rebind, [parent], True,
                   'BIP446 omits outpoints; the duplicate output deliberately reuses this one-time key.', digests=[digest])
            record('stock-p2mr-invalid-secret', mutate(tx, 'secret'), [parent], True,
                   'Stock consensus treats witness version 2 as an unenforced upgrade hook.', stock=True)
            annexed = deepcopy(tx)
            annexed.inputs[0].witness.append(b'\x50changed-annex')
            record('p2mr-added-annex', annexed, [parent], False, 'Annex is part of TemplateHash; adding one changes authorization.')

    # Two separate owners and two separately signed input-index commitments.
    multi_keys = [test_keys('multi-'+str(i)) for i in range(2)]
    scripts = [lamport_script(k) for k in multi_keys]
    trees = [p2mr(s) for s in scripts]
    parents = [funding(tree[0], 'multi-'+str(i)) for i, tree in enumerate(trees)]
    multi = payment(parents)
    hashes = [template_hash(multi, i) for i in range(2)]
    for i in range(2):
        multi.inputs[i].witness = lamport_witness(multi_keys[i], hashes[i]) + [scripts[i], trees[i][1]]
    record('two-inputs-two-pq-signatures', multi, parents, True,
           'Both owners authorize the outputs; distinct input indexes produce distinct digests.', digests=hashes)
    metrics['two-inputs'] = multi.metrics()
    missing = deepcopy(multi)
    missing.inputs[1].witness = [scripts[1], trees[1][1]]
    record('two-inputs-missing-second-authorization', missing, parents, False,
           'Removing the second PQ signature fails. Neither P2MR nor a covenant implements aggregation.')
    swapped = deepcopy(multi)
    swapped.inputs[1].witness = multi.inputs[0].witness[:512] + [scripts[1], trees[1][1]]
    record('two-inputs-copied-first-signature', swapped, parents, False,
           'The first owner cannot authorize the second owner by copying a witness.')

    report = dict(scope='local proposal Script verifier; not Bitcoin mainnet or a full-node deployment',
                  proposal_versions={'BIP360': '0.12.1', 'BIP347': 'retrieved 2026-09-05', 'BIP446': 'retrieved 2026-09-05'},
                  build=json.loads((BUILD/'build-manifest.json').read_text()),
                  lamport=dict(message_bits=256, preimage_bits=256, one_time=True, fixture_keys_public=True),
                  comparison=dict(shrincs='Literature comparison only; no SHRINCS verifier is substituted or benchmarked.',
                                  cisa='BIP460 Schnorr aggregation is not implemented and does not aggregate these Lamport witnesses.'),
                  metrics=metrics, cases=cases, all_expectations_met=True)
    report['harness_sha256'] = {str(p.relative_to(ROOT)): sha256(p.read_bytes()).hexdigest()
                               for p in (ROOT/'btc_pq/covenant_demo.py', ROOT/'btc_pq/covenant_build.py',
                                         ROOT/'btc_pq/bitcoin.py', ROOT/'tests/test_covenant_demo.py')}
    report['stock_verifier_sha256'] = sha256(STOCK_VERIFIER.read_bytes()).hexdigest()
    report['fixture_sha256'] = {p.name: sha256(p.read_bytes()).hexdigest()
                                for p in sorted(outdir.glob('*.hex'))}
    (outdir/'report.json').write_text(json.dumps(report, indent=2)+'\n')
    return report


def replay(outdir):
    outdir = Path(outdir)
    report = json.loads((outdir/'report.json').read_text())
    for name, digest in report['fixture_sha256'].items():
        if sha256((outdir/name).read_bytes()).hexdigest() != digest:
            raise ValueError('fixture changed: '+name)
    results = []
    for case in report['cases']:
        binary = STOCK_VERIFIER if case['verifier'] == 'stock_upgrade_hook' else VERIFIER
        result = verify(outdir/case['spend'], [outdir/p for p in case['parents']], binary)
        if result['valid'] != case['expected_valid']:
            raise AssertionError(case['name'])
        results.append(dict(name=case['name'], result=result))
    result = dict(all_expectations_met=True, cases=results)
    (outdir/'replay.json').write_text(json.dumps(result, indent=2)+'\n')
    return result
