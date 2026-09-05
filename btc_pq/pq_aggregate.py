"""Real leanVM hash-signature proofs bound to synthetic Bitcoin payments.

The host recomputes every expected claim from the transaction and committed
script. This models a new transaction-level verifier; Bitcoin does not enforce
it. The proved signature is leanVM's BLAKE2s XMSS, not SHRINCS or Schnorr CISA.
"""
from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import tempfile

from .crypto import ROOT
from .covenant_demo import core_test_helpers, funding, p2mr, payment, tagged_hash

COMMIT = '574521665891ad040580833d3cae62c9bd347c9b'
SOURCE = ROOT/'.cache/lean-vm'
TOOL = SOURCE/'target/release/btc-pq-aggregate'


def build():
    if not SOURCE.exists():
        subprocess.run(['git', 'clone', 'https://github.com/leanEthereum/leanVM', str(SOURCE)], check=True)
        subprocess.run(['git', 'checkout', '--detach', COMMIT], cwd=SOURCE, check=True)
    head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=SOURCE, text=True).strip()
    dirty = subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=no'], cwd=SOURCE, text=True)
    if head != COMMIT or dirty:
        raise ValueError('requires an unmodified pinned leanVM checkout')
    env = dict(os.environ, CARGO_TARGET_DIR=str(SOURCE/'target'), RUSTFLAGS='-C target-cpu=native')
    subprocess.run(['cargo', 'build', '--release', '--locked', '--manifest-path',
                    str(ROOT/'native/pq-aggregate/Cargo.toml')], env=env, check=True)


def native(*args):
    result = subprocess.run([str(TOOL), *map(str, args)], capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(result.stderr[-3000:])
    return json.loads(result.stdout)


def script(public_key):
    return b'\x20'+bytes.fromhex(public_key)+b'\xd0'  # Local model allocation only.


def claims(tx, parents, keys):
    if len(tx.inputs) != len(parents) or len(keys) != len(parents):
        raise ValueError('input/parent/key count')
    *_, sighash, parse = core_test_helpers()
    spent = [parse(p.serialize().hex()).vout[0] for p in parents]
    result = []
    for i, (inp, parent, key) in enumerate(zip(tx.inputs, parents, keys)):
        leaf = script(key['public_key'])
        if inp.txid != parent.txid or inp.vout != 0 or parent.outputs[0].script != p2mr(leaf)[0]:
            raise ValueError('parent or committed authorization does not match input')
        annex = inp.witness[-1] if len(inp.witness) >= 2 and inp.witness[-1][:1] == b'\x50' else None
        digest = sighash(parse(tx.serialize().hex()), spent, 0, input_index=i, scriptpath=True,
                         leaf_script=leaf, codeseparator_pos=0xffffffff, annex=annex)
        message = tagged_hash('btc-pq/leanVM-XMSS/v1', digest)
        result.append(dict(epoch=i, public_key=key['public_key'], message=message.hex()))
    return result


def verify(tx, parents, keys, proof):
    try:
        expected = claims(tx, parents, keys)
    except ValueError:
        return dict(valid=False, reason='transaction/authorization structure')
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory)/'expected.json'
        path.write_text(json.dumps(expected))
        return native('verify', path, proof)


def run(directory, counts=(2, 10), replay_existing=False):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    previous = json.loads((directory/'report.json').read_text()) if replay_existing else None
    if previous:
        counts = tuple(m['inputs'] for m in previous['measurements'])
    cases, measurements = [], []
    for count in counts:
        prefix = directory/str(count)
        claim_path, proof = prefix.with_suffix('.claims.json'), prefix.with_suffix('.proof.bin')
        if previous:
            from .bitcoin import Tx
            keys = json.loads(prefix.with_suffix('.keys.json').read_text())
            parents = [Tx.parse(raw) for raw in json.loads(prefix.with_suffix('.parents.json').read_text())]
            tx = Tx.parse(prefix.with_suffix('.tx.hex').read_text().strip())
            if claims(tx, parents, keys) != json.loads(claim_path.read_text()):
                raise ValueError('saved transaction claims changed')
            measured = next(m for m in previous['measurements'] if m['inputs'] == count)
            if measured['proof_sha256'] != sha256(proof.read_bytes()).hexdigest():
                raise ValueError('saved proof changed')
        else:
            keys = native('keys', count)['keys']
            parents = [funding(p2mr(script(k['public_key']))[0], f'aggregate-{i}') for i, k in enumerate(keys)]
            tx = payment(parents)
            claim_path.write_text(json.dumps(claims(tx, parents, keys), indent=2)+'\n')
            prefix.with_suffix('.tx.hex').write_text(tx.serialize().hex()+'\n')
            prefix.with_suffix('.parents.json').write_text(json.dumps([p.serialize().hex() for p in parents], indent=2)+'\n')
            prefix.with_suffix('.keys.json').write_text(json.dumps(keys, indent=2)+'\n')
            measured = native('prove', claim_path, proof)
            measured['transaction_without_authorization_bytes'] = len(tx.serialize())
            measured['proof_sha256'] = sha256(proof.read_bytes()).hexdigest()
        measurements.append(measured)
        for mutation in ('none', 'recipient', 'amount', 'sequence', 'version', 'locktime',
                         'spent_amount', 'outpoint', 'input_order', 'annex', 'wrong_key', 'proof'):
            t, p, k = deepcopy(tx), deepcopy(parents), deepcopy(keys)
            proof_path = proof
            if mutation == 'recipient': t.outputs[0].script = b'\x6a'
            if mutation == 'amount': t.outputs[0].value -= 1
            if mutation == 'sequence': t.inputs[0].sequence -= 1
            if mutation == 'version': t.version += 1
            if mutation == 'locktime': t.locktime += 1
            if mutation == 'spent_amount':
                p[0].outputs[0].value += 1
                t.inputs[0].txid = p[0].txid
            if mutation == 'outpoint':
                p[0].locktime += 1
                t.inputs[0].txid = p[0].txid
            if mutation == 'input_order':
                t.inputs.reverse(); p.reverse(); k.reverse()
            if mutation == 'annex': t.inputs[0].witness = [b'', b'\x50changed']
            if mutation == 'wrong_key': k[0]['public_key'] = '00'*32
            if mutation == 'proof':
                data = bytearray(proof.read_bytes()); data[-1] ^= 1
                proof_path = prefix.with_suffix('.mutated-proof.bin')
                proof_path.write_bytes(data)
            observed = verify(t, p, k, proof_path)
            if observed['valid'] != (mutation == 'none'):
                raise AssertionError((count, mutation, observed))
            cases.append(dict(inputs=count, mutation=mutation, expected=mutation == 'none', **observed))
    inputs = [ROOT/'native/pq-aggregate/Cargo.toml', ROOT/'native/pq-aggregate/Cargo.lock',
              ROOT/'native/pq-aggregate/src/main.rs', ROOT/'btc_pq/pq_aggregate.py']
    result = dict(leanvm_commit=COMMIT, scheme='leanVM BLAKE2s XMSS', parameters=dict(signature_bytes=1208, public_key_bytes=32),
                  real_proofs_generated=True, native_bitcoin_consensus=False, shrincs_aggregation=False,
                  scope='Host-recomputed BIP341/342 payment claims; local transaction-level verification model',
                  source_sha256={str(p.relative_to(ROOT)):sha256(p.read_bytes()).hexdigest() for p in inputs},
                  binary_sha256=sha256(TOOL.read_bytes()).hexdigest(), measurements=measurements,
                  cases=cases, all_expectations_met=True)
    result['replayed_existing_proofs'] = replay_existing
    (directory/('replay.json' if replay_existing else 'report.json')).write_text(json.dumps(result, indent=2)+'\n')
    return result


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', action='store_true')
    parser.add_argument('--replay', action='store_true', help='verify all saved payment cases without generating signatures/proofs')
    parser.add_argument('--counts', default='2,10')
    parser.add_argument('--outdir', type=Path, default=ROOT/'results/pq-aggregate')
    args = parser.parse_args()
    if args.build:
        build()
    result = run(args.outdir, tuple(map(int, args.counts.split(','))), args.replay)
    print(f"PQ proof aggregation: {len(result['cases'])} payment expectations met")
