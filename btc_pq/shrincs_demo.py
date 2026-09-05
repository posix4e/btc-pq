"""P2MR and an explicitly local transaction-aware SHRINCS-B32 opcode."""
from copy import deepcopy
from hashlib import sha256, sha512
from pathlib import Path
import json
import subprocess

from .bitcoin import push
from .core import verify, VERIFIER as STOCK_VERIFIER
from .crypto import ROOT
from .covenant_demo import core_test_helpers, funding, payment, p2mr, tagged_hash
from .shrincs_build import VERIFIER, TOOL, BUILD


def signed_message(tx, parents, index, script, annex=None):
    """BIP341 DEFAULT + BIP342 script extension, with a separate SHRINCS domain."""
    *_, sighash, parse = core_test_helpers()
    spent = [parse(parent.serialize().hex()).vout[inp.vout]
             for inp, parent in zip(tx.inputs, parents, strict=True)]
    digest = sighash(parse(tx.serialize().hex()), spent, 0, input_index=index,
                     scriptpath=True, leaf_script=script, annex=annex, codeseparator_pos=0xffffffff)
    return tagged_hash('btc-pq/SHRINCS-B32/v1', digest)


def auth_script(public_key):
    if len(public_key) != 32:
        raise ValueError('SHRINCS-B32 key must be 32 bytes')
    return push(public_key) + b'\xcf'  # Local experimental allocation only.


def witness(signature, script, control, annex=None):
    if not 1 <= len(signature) <= 4160:
        raise ValueError('signature cannot fit the demo chunk envelope')
    chunks = [signature[i:i+520] for i in range(0, len(signature), 520)]
    return chunks + [bytes([len(chunks)]), script, control] + ([annex] if annex is not None else [])


def native_tool(*args):
    result = subprocess.run([str(TOOL), *map(str, args)], capture_output=True, text=True, timeout=180)
    if result.returncode not in (0, 1):
        raise RuntimeError(result.stderr.strip() or 'SHRINCS fixture tool failed')
    return json.loads(result.stdout)


def run(outdir, build=False):
    if build:
        from .shrincs_build import build as build_verifier
        build_verifier()
    if not VERIFIER.exists() or not TOOL.exists():
        raise RuntimeError('run shrincs-demo --build first')
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    cases, metrics = [], {}

    def record(name, tx, parents, expected, note, stock=False, messages=None):
        file = outdir/(name+'.hex')
        file.write_text(tx.serialize().hex()+'\n')
        paths = []
        for parent in parents:
            path = outdir/('parent-'+parent.txid+'.hex')
            path.write_text(parent.serialize().hex()+'\n')
            paths.append(path)
        result = verify(file, paths, STOCK_VERIFIER if stock else VERIFIER)
        if result['valid'] != expected:
            raise AssertionError(f'{name}: expected {expected}, got {result}')
        if messages is not None:
            actual = [inp['message_digest'] for inp in result['inputs']]
            if actual != [message.hex() for message in messages]:
                raise AssertionError(f'{name}: Python/Core transaction digest mismatch: {actual}')
        cases.append(dict(name=name, expected_valid=expected, note=note,
                          verifier='stock_upgrade_hook' if stock else 'shrincs_proposal_model',
                          spend=file.name, parents=[p.name for p in paths],
                          result=result, transaction=tx.metrics()))

    def key(label):
        seed_path = outdir/(label+'-PUBLIC-seed.hex')
        seed_path.write_text(sha512(('PUBLIC SHRINCS DEMO/'+label).encode()).digest()[:48].hex()+'\n')
        metadata = native_tool('pubkey', seed_path)
        pk = bytes.fromhex(metadata['public_key'])
        script = auth_script(pk)
        spk, control = p2mr(script)
        return seed_path, pk, script, control, funding(spk, label, duplicate=True)

    def signatures(label, seed, message):
        message_file = outdir/(label+'-message.hex')
        message_file.write_text(message.hex()+'\n')
        directory = outdir/(label+'-signer')
        metadata = native_tool('fixture', seed, message_file, directory)
        sigs = {s['name']: bytes.fromhex((directory/(s['name']+'.sig.hex')).read_text())
                for s in metadata['signatures']}
        return sigs, metadata

    seed, pk, script, control, parent = key('single-owner')
    tx = payment([parent])
    message = signed_message(tx, [parent], 0, script)
    sigs, signing = signatures('single-owner', seed, message)
    for name, sig in sigs.items():
        tx.inputs[0].witness = witness(sig, script, control)
        record(name+'-valid', tx, [parent], True, 'Same funded key accepts this signing mode.', messages=[message])
        metrics[name] = dict(signature_bytes=len(sig), signature_chunks=(len(sig)+519)//520,
                             public_key_bytes=len(pk), script_bytes=len(script), control_bytes=len(control),
                             transaction=tx.metrics(),
                             signing=next(s for s in signing['signatures'] if s['name'] == name))
        if name not in ('compact-q1', 'recovery'):
            continue
        for field in ('recipient', 'amount', 'sequence', 'locktime', 'version', 'outpoint',
                      'signature', 'truncated', 'appended', 'chunk_count', 'merkle_proof'):
            changed = deepcopy(tx)
            w = changed.inputs[0].witness
            if field == 'recipient': changed.outputs[0].script = p2mr(b'\x51')[0]
            elif field == 'amount': changed.outputs[0].value -= 1
            elif field == 'sequence': changed.inputs[0].sequence -= 1
            elif field == 'locktime': changed.locktime += 1
            elif field == 'version': changed.version += 1
            elif field == 'outpoint': changed.inputs[0].vout = 1
            elif field == 'signature': w[0] = bytes([w[0][0] ^ 1]) + w[0][1:]
            elif field == 'truncated': changed.inputs[0].witness = witness(sig[:-1], script, control)
            elif field == 'appended': changed.inputs[0].witness = witness(sig+b'\x00', script, control)
            elif field == 'chunk_count': w[-3] = b'\x00'
            elif field == 'merkle_proof': w[-1] = control[:-1] + bytes([control[-1] ^ 1])
            record(name+'-changed-'+field, changed, [parent], False, 'Original authorization with changed '+field+'.')
        changed = deepcopy(tx)
        changed.inputs[0].witness.append(b'\x50new-annex')
        record(name+'-added-annex', changed, [parent], False, 'Annex is included in the signed message.')
        # Re-funding an identical script with a different value cannot reuse authorization.
        other_parent = deepcopy(parent)
        other_parent.outputs[0].value += 1
        changed = deepcopy(tx)
        changed.inputs[0].txid = other_parent.txid
        record(name+'-changed-funding', changed, [other_parent], False,
               'Full signature message commits to input outpoints and spent values.')

    # Structural controls on the primary compact witness.
    tx.inputs[0].witness = witness(sigs['compact-q1'], script, control)
    changed = deepcopy(tx)
    changed.inputs[0].witness = [bytes(64)]
    record('no-key-path', changed, [parent], False, 'P2MR cannot be spent through an EC key path.')
    changed.inputs[0].witness = witness(bytes(324), script, control)
    record('stock-p2mr-unenforced', changed, [parent], True,
           'Unknown witness v2 succeeds in stock Script rules without checking SHRINCS.', stock=True)
    changed.inputs[0].witness = [sigs['compact-q1'][:100], sigs['compact-q1'][100:], b'\x02', script, control]
    record('noncanonical-chunk-split', changed, [parent], False, 'All nonfinal chunks must have exactly 520 bytes.')

    # A second owner has its own seed and native signature. The first owner's
    # distinct multi-input message is signed under a fresh fixture key as well.
    first = key('multi-first')
    second = key('multi-second')
    parents = [first[-1], second[-1]]
    multi = payment(parents)
    multi_metadata, messages = [], []
    for index, material in enumerate((first, second)):
        seed_i, _, script_i, control_i, _ = material
        msg = signed_message(multi, parents, index, script_i)
        multi_sigs, metadata = signatures('multi-'+str(index), seed_i, msg)
        multi.inputs[index].witness = witness(multi_sigs['compact-q1'], script_i, control_i)
        multi_metadata.append(metadata)
        messages.append(msg)
    record('two-inputs-valid', multi, parents, True, 'Both owners sign the full payment.', messages=messages)
    metrics['two-inputs'] = multi.metrics()
    changed = deepcopy(multi)
    changed.inputs[1].witness = [b'\x01', second[2], second[3]]
    record('two-inputs-missing-second-signature', changed, parents, False, 'Each input still requires PQ authorization.')
    changed.inputs[1].witness = multi.inputs[0].witness[:-2] + [second[2], second[3]]
    record('two-inputs-copied-first-signature', changed, parents, False, 'First owner cannot authorize the second owner.')
    changed = deepcopy(multi)
    changed.inputs.reverse()
    record('two-inputs-reordered', changed, list(reversed(parents)), False, 'Input order and indexes are committed.')

    report = dict(scope='linked-prevout Script checks under a local opcode model; not mainnet or a full node',
                  build=json.loads((BUILD/'build-manifest.json').read_text()),
                  parameters='upstream SHRINCS_B32 signer; locally bounded native verifier',
                  digest='TaggedHash(btc-pq/SHRINCS-B32/v1, BIP341 SIGHASH_DEFAULT with BIP342 extension)',
                  experimental_opcode='0xcf; local allocation, not an assigned BIP opcode',
                  signing=signing, multi_signing=multi_metadata, metrics=metrics, cases=cases,
                  all_expectations_met=True, cisa_implemented=False)
    report['fixture_sha256'] = {str(p.relative_to(outdir)):sha256(p.read_bytes()).hexdigest()
                                for p in sorted(outdir.rglob('*.hex'))}
    report['harness_sha256'] = {str(p.relative_to(ROOT)):sha256(p.read_bytes()).hexdigest()
                               for p in (ROOT/'btc_pq/shrincs_demo.py', ROOT/'btc_pq/shrincs_build.py',
                                         ROOT/'btc_pq/shrincs_kat.py', ROOT/'tests/test_shrincs_demo.py',
                                         ROOT/'btc_pq/bitcoin.py', ROOT/'btc_pq/covenant_demo.py')}
    (outdir/'report.json').write_text(json.dumps(report, indent=2)+'\n')
    return report


def replay(outdir):
    outdir = Path(outdir)
    report = json.loads((outdir/'report.json').read_text())
    for name, digest in report['fixture_sha256'].items():
        if sha256((outdir/name).read_bytes()).hexdigest() != digest:
            raise ValueError('fixture changed: '+name)
    cases = []
    for case in report['cases']:
        binary = STOCK_VERIFIER if case['verifier'] == 'stock_upgrade_hook' else VERIFIER
        result = verify(outdir/case['spend'], [outdir/p for p in case['parents']], binary)
        if result['valid'] != case['expected_valid']:
            raise AssertionError(case['name'])
        cases.append(dict(name=case['name'], result=result))
    result = dict(all_expectations_met=True, cases=cases)
    (outdir/'replay.json').write_text(json.dumps(result, indent=2)+'\n')
    return result
