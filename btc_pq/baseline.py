"""Pinned QSB public transaction, exact parents, and public inclusion evidence."""
import hashlib
import json
import time
import urllib.request
from pathlib import Path
from .bitcoin import Tx, hash256, script_metrics
from .crypto import ROOT
from .core import verify

TXID = '305a24ffea912b9cf428f29ebf952321c96dab5bab284fc0d0801562f5abab07'
QSB_COMMIT = '2c9172051d5c150ef0a994ca6b988a08a3ef9e85'
FIXTURES = ROOT/'fixtures/mainnet'


def check_vendor():
    m = json.loads((ROOT/'vendor/qsb/manifest.json').read_text())
    if m['commit'] != QSB_COMMIT:
        raise ValueError('unexpected reference commit')
    for name, entry in m['files'].items():
        if hashlib.sha256((ROOT/'vendor/qsb'/name).read_bytes()).hexdigest() != entry['sha256']:
            raise ValueError('reference file hash mismatch: '+name)
    return dict(commit=QSB_COMMIT, checked_files=len(m['files']))


def fetch():
    FIXTURES.mkdir(parents=True, exist_ok=True)
    source = 'https://blockstream.info/api'

    def get(path, as_json=False):
        req = urllib.request.Request(source+path, headers={'User-Agent':'btc-pq-public-research/0.1'})
        with urllib.request.urlopen(req, timeout=45) as r:
            text = r.read().decode().strip()
        return json.loads(text) if as_json else text

    raw = get('/tx/'+TXID+'/hex')
    tx = Tx.parse(raw)
    if tx.txid != TXID:
        raise ValueError('published txid mismatch')
    (FIXTURES/'spend.hex').write_text(raw+'\n')
    ids = list(dict.fromkeys(i.txid for i in tx.inputs))
    for txid in ids:
        raw = get('/tx/'+txid+'/hex')
        if Tx.parse(raw).txid != txid:
            raise ValueError('funding txid mismatch')
        (FIXTURES/(txid+'.hex')).write_text(raw+'\n')
    proof = get('/tx/'+TXID+'/merkle-proof', True)
    blockhash = get('/block-height/'+str(proof['block_height']))
    header = get('/block/'+blockhash+'/header')
    metadata = dict(source=source, fetched_unix=time.time(), spend_txid=TXID, parents=ids,
                    merkle_proof=proof, blockhash=blockhash, header=header,
                    trust='Explorer supplies chain anchoring; Merkle inclusion and header PoW checked locally. No full mainnet chain replay.')
    (FIXTURES/'provenance.json').write_text(json.dumps(metadata,indent=2)+'\n')
    return metadata


def reproduce():
    pinned = check_vendor()
    tx = Tx.parse((FIXTURES/'spend.hex').read_text().strip())
    if tx.txid != TXID:
        raise ValueError('published txid mismatch')
    parents = [FIXTURES/(i.txid+'.hex') for i in tx.inputs]
    m = json.loads((FIXTURES/'provenance.json').read_text())
    header = bytes.fromhex(m['header'])
    proof = m['merkle_proof']
    h = bytes.fromhex(tx.txid)[::-1]
    pos = proof['pos']
    for sibling in proof['merkle']:
        other = bytes.fromhex(sibling)[::-1]
        h = hash256(other+h if pos & 1 else h+other)
        pos >>= 1
    bits = int.from_bytes(header[72:76],'little')
    target = (bits & 0x7fffff) * 256**((bits >> 24)-3)
    inclusion = (len(header)==80 and h == header[36:68] and pos == 0 and
                 hash256(header)[::-1].hex() == m['blockhash'] and
                 int.from_bytes(hash256(header),'little') <= target)
    if not inclusion:
        raise ValueError('invalid inclusion proof/header')
    start = time.perf_counter()
    result = verify(FIXTURES/'spend.hex', parents)
    seconds = time.perf_counter()-start
    if not result['valid']:
        raise ValueError('published QSB transaction failed Core 31.1 verification')
    funding = []
    for i, path in zip(tx.inputs, parents):
        parent = Tx.parse(path.read_text().strip())
        funding.append(dict(txid=parent.txid, vout=i.vout, value_sats=parent.outputs[i.vout].value,
                            script=script_metrics(parent.outputs[i.vout].script), transaction=parent.metrics()))
    # Mutations keep exact funding and all proof material; detect replay/redirection.
    from copy import deepcopy
    import tempfile
    attacks=[]
    variants={}
    v=deepcopy(tx); v.outputs[0].script=b'\x51'; variants['output_redirection']=v
    v=deepcopy(tx); v.outputs[0].value-=1; variants['amount_decrease']=v
    v=deepcopy(tx); v.inputs[0].sequence ^= 1; variants['sequence_change']=v
    v=deepcopy(tx); v.inputs[0].witness=[b'mismatch']; variants['unexpected_witness']=v
    with tempfile.TemporaryDirectory(prefix='btc-pq-baseline-') as td:
        for name, v in variants.items():
            path=Path(td)/(name+'.hex'); path.write_text(v.serialize().hex())
            verdict=verify(path,parents)
            attacks.append(dict(name=name, verification=verdict))
            if verdict['valid']:
                raise AssertionError('baseline mutation unexpectedly accepted: '+name)
    return dict(pinned_reference=pinned, mainnet_tx=tx.metrics(), funding_outputs=funding,
                core_verification=result, verification_wall_seconds=seconds,
                measured_work='CPU native verification including subprocess startup; no GPU/grinding measurement',
                inclusion_verified=inclusion, block_height=proof['block_height'], chain_trust=m['trust'],
                local_mainnet_block_replay=False, attacks=attacks)
