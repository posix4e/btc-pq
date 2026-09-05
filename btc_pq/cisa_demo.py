"""BIP460 default-sighash key-path aggregation experiment using its pinned code.

This models all-input half/full groups. It is not a general consensus checker,
does not aggregate Script signatures, and does not implement post-quantum CISA.
"""
from copy import deepcopy
from functools import lru_cache
from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import urllib.request

from .bitcoin import Tx
from .crypto import ROOT

COMMIT = '855b4ccfbebd07554c1e400415467b62d2b40713'
SOURCE = ROOT/'.cache/cisa-vectors'
FILES = ['test-vectors.py', 'halfagg.py', 'fullagg.py', 'consensus-test-vectors.json',
         'wallet-test-vectors.json', 'secp256k1lab/COPYING'] + [
    'secp256k1lab/src/secp256k1lab/'+name for name in
    ('__init__.py', 'bip340.py', 'keys.py', 'secp256k1.py', 'util.py')]


def fetch():
    base = f'https://raw.githubusercontent.com/fjahr/bips/{COMMIT}/bip-0460/'
    hashes = {}
    for name in FILES:
        content = urllib.request.urlopen(base+name).read()
        path = SOURCE/name
        if path.exists() and path.read_bytes() != content:
            raise ValueError('cached CISA source differs from pin: '+name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        hashes[name] = sha256(content).hexdigest()
    manifest = dict(commit=COMMIT, source_sha256=hashes)
    (SOURCE/'manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
    return manifest


@lru_cache
def upstream():
    manifest = json.loads((SOURCE/'manifest.json').read_text())
    if manifest['commit'] != COMMIT or set(manifest['source_sha256']) != set(FILES):
        raise ValueError('CISA source manifest mismatch')
    for name, digest in manifest['source_sha256'].items():
        if sha256((SOURCE/name).read_bytes()).hexdigest() != digest:
            raise ValueError('CISA source changed: '+name)
    spec = importlib.util.spec_from_file_location('btc_pq_cisa_reference', SOURCE/'test-vectors.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verify_group(tx, utxos, mode):
    """Validate this demo's exact default-sighash/all-input witness shape."""
    u = upstream()
    try:
        count = len(tx.vin)
        if not count or len(utxos) != count or len(tx.witnesses) != count:
            return False
        if any(len(p.script_pubkey) != 34 or p.script_pubkey[:2] != b'\x52\x20' for p in utxos):
            return False
        if any(len(w) != 1 for w in tx.witnesses):
            return False
        keys = [p.script_pubkey[2:] for p in utxos]
        data = [w[0] for w in tx.witnesses]
        if mode == 'plain':
            return all(len(s) == 64 and u.schnorr_verify(u.sigmsg_v1(tx, utxos, i, 0), keys[i], s)
                       for i, s in enumerate(data))
        marker = {'half': 0xbc, 'full': 0xbd}[mode]
        size = 32 if mode == 'half' else 0
        if any(len(s) != size for s in data[:-1]) or len(data[-1]) != 65 or data[-1][-1] != marker:
            return False
        messages = [u.sigmsg_v2(tx, utxos, i, 0, marker) for i in range(count)]
        if mode == 'half':
            aggregate = b''.join(data[:-1])+data[-1][:-1]
            return u.halfagg.VerifyAggregate(aggregate, list(zip(keys, messages)))
        aggregate = data[-1][:-1]
        return u.fullagg.Verify([u.GE.from_bytes_xonly(k) for k in keys], messages,
                                (u.GE.from_bytes_xonly(aggregate[:32]), u.Scalar.from_bytes_checked(aggregate[32:])))
    except (ValueError, IndexError, OverflowError):
        return False


def run(directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    u = upstream()
    # Reproduce all published wallet vectors byte-for-byte, including Taproot
    # key tweaking, addresses, mixed groups, and its single Script-path example.
    wallet_matches = u.make_wallet_vectors() == json.loads((SOURCE/'wallet-test-vectors.json').read_text())
    if not wallet_matches:
        raise AssertionError('upstream wallet vector reproduction changed')
    cases, measurements = [], []
    for count in (2, 10):
        for mode in ('plain', 'half', 'full'):
            keys = [u.tweak_keypair(u.test_seckey(i)) for i in range(count)]
            parents = [u.TxOut(100_000_000, u.v2_script_pubkey(k[3])) for k in keys]
            tx = u.Tx([u.TxIn(u.test_prevout_txid(i), 0) for i in range(count)],
                      [u.TxOut(100_000_000*count-1000, u.v2_script_pubkey(keys[0][3]))])
            members = [(i, key[2], 0) for i, key in enumerate(keys)]
            if mode == 'plain':
                for i, sk, _ in members:
                    tx.witnesses[i] = [u.sign_optout(tx, parents, i, sk, 0)[1]]
            elif mode == 'half':
                _, sigs, aggregate = u.sign_halfagg_group(tx, parents, members)
                for i, sig in enumerate(sigs):
                    tx.witnesses[i] = [sig[:32]]
                tx.witnesses[-1] = [u.halfagg_final(aggregate)]
            else:
                # Public deterministic test nonces, different test sessions.
                _, _, _, aggregate = u.sign_fullagg_group(tx, parents, members, nonce_offset=count*10)
                for i in range(count):
                    tx.witnesses[i] = [b'']
                tx.witnesses[-1] = [u.marker_element(0xbd, sig=aggregate)]
            name = f'{mode}-{count}-inputs'
            raw = tx.serialize_signed()
            (directory/(name+'.hex')).write_text(raw.hex()+'\n')
            (directory/(name+'-prevouts.json')).write_text(json.dumps([
                dict(amount=p.amount, script_pubkey=p.script_pubkey.hex()) for p in parents], indent=2)+'\n')
            measurements.append(dict(name=name, mode=mode, inputs=count, **Tx.parse(raw).metrics(),
                                     signature_data_bytes=sum(len(w[0]) for w in tx.witnesses),
                                     marker_bytes=0 if mode == 'plain' else 1))
            for mutation in ('none', 'recipient', 'amount', 'outpoint', 'spent_amount', 'sequence',
                             'version', 'locktime', 'signature', 'missing_authorization', 'input_order'):
                t, p = deepcopy(tx), deepcopy(parents)
                if mutation == 'recipient': t.vout[0].script_pubkey = b'\x51'
                if mutation == 'amount': t.vout[0].amount -= 1
                if mutation == 'outpoint': t.vin[0].vout += 1
                if mutation == 'spent_amount': p[0].amount += 1
                if mutation == 'sequence': t.vin[0].sequence -= 1
                if mutation == 'version': t.version += 1
                if mutation == 'locktime': t.locktime += 1
                if mutation == 'signature':
                    s = t.witnesses[-1][0]
                    t.witnesses[-1][0] = bytes([s[0]^1])+s[1:]
                if mutation == 'missing_authorization': t.witnesses[-1] = []
                if mutation == 'input_order':
                    t.vin.reverse(); t.witnesses.reverse(); p.reverse()
                valid = verify_group(t, p, mode)
                if valid != (mutation == 'none'):
                    raise AssertionError((name, mutation, valid))
                cases.append(dict(name=name+'-'+mutation, valid=valid, expected=mutation == 'none'))
    result = dict(bip460_commit=COMMIT, scope='Python model of default-sighash, all-input key-path groups',
                  native_consensus_validation=False, post_quantum=False, shrincs_aggregation=False,
                  published_wallet_vectors_reproduced=wallet_matches, measurements=measurements,
                  sources=json.loads((SOURCE/'manifest.json').read_text()), cases=cases, all_expectations_met=True)
    (directory/'report.json').write_text(json.dumps(result, indent=2)+'\n')
    return result


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fetch', action='store_true')
    parser.add_argument('--outdir', type=Path, default=ROOT/'results/cisa-demo')
    args = parser.parse_args()
    if args.fetch:
        fetch()
    result = run(args.outdir)
    print(f"CISA: {len(result['cases'])} expectations met; upstream wallet vectors reproduced")
