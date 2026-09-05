"""Transaction-level SHRINCS proof framing with native Core Script enforcement."""
import argparse
from copy import deepcopy
from hashlib import sha256
import io
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile

from .crypto import ROOT
from .shrincs_build import CORE_COMMIT
from .shrincs_proof import TARGET, fixture, authorizations

SOURCE = ROOT/'.cache/receipt-bitcoin'
BUILD = ROOT/'.cache/receipt-build'
VERIFIER = BUILD/'btc-pq-shrincs-receipt'
RUST_SOURCE = ROOT/'native/receipt-tool'
MAGIC = b'BTC-PQ-PROOF\x01'


def source_hashes():
    files = [ROOT/'native/covenant-core.patch', ROOT/'native/shrincs-core.patch',
             ROOT/'native/shrincs-proof-core.patch', ROOT/'native/shrincs_cost.h',
             ROOT/'native/shrincs_receipt_verify.cpp', ROOT/'native/shrincs-receipt/CMakeLists.txt',
             Path(__file__)]
    files += [p for p in RUST_SOURCE.rglob('*') if p.is_file()]
    return {str(p.relative_to(ROOT)):sha256(p.read_bytes()).hexdigest() for p in sorted(files)}


def build(jobs=2):
    import os
    env = dict(os.environ, CARGO_TARGET_DIR=str(TARGET))
    subprocess.run(['cargo','build','--release','--locked','--manifest-path',str(RUST_SOURCE/'Cargo.toml')],
                   check=True, env=env)
    library = TARGET/('release/libbtc_pq_receipt.dylib' if os.uname().sysname == 'Darwin' else 'release/libbtc_pq_receipt.so')
    pristine = ROOT/'.cache/bitcoin'
    if subprocess.check_output(['git','-C',str(pristine),'rev-parse','HEAD'],text=True).strip() != CORE_COMMIT:
        raise ValueError('requires pinned Core source')
    hashes = source_hashes()
    source_inputs = {p:h for p,h in hashes.items() if p.endswith(('.patch','shrincs_cost.h'))}
    stamp = SOURCE/'.btc-pq-receipt-source.json'
    if SOURCE.exists() and (not stamp.exists() or json.loads(stamp.read_text()) != source_inputs):
        if not stamp.exists(): raise ValueError('unrecognized receipt source directory')
        shutil.rmtree(SOURCE)
    if not SOURCE.exists():
        SOURCE.mkdir(parents=True)
        archive = subprocess.check_output(['git','-C',str(pristine),'archive',CORE_COMMIT])
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar: tar.extractall(SOURCE,filter='data')
        for patch in ('covenant-core.patch','shrincs-core.patch','shrincs-proof-core.patch'):
            subprocess.run(['git','apply',str(ROOT/'native'/patch)],cwd=SOURCE,check=True)
        shutil.copyfile(ROOT/'native/shrincs_cost.h',SOURCE/'src/script/shrincs_cost.h')
        stamp.write_text(json.dumps(source_inputs,indent=2)+'\n')
    cmake, ninja = ROOT/'.venv/bin/cmake', ROOT/'.venv/bin/ninja'
    subprocess.run([str(cmake),'-S',str(ROOT/'native/shrincs-receipt'),'-B',str(BUILD),'-G','Ninja',
                    '-DCMAKE_BUILD_TYPE=Release',f'-DCMAKE_MAKE_PROGRAM={ninja}',
                    f'-DCORE_SOURCE={SOURCE}',f'-DRECEIPT_LIB={library}'],check=True)
    subprocess.run([str(cmake),'--build',str(BUILD),'--parallel',str(jobs),'--target',VERIFIER.name],check=True)
    manifest = dict(core_commit=CORE_COMMIT,source_sha256=hashes,
                    binary_sha256={str(p.relative_to(ROOT)):sha256(p.read_bytes()).hexdigest() for p in (VERIFIER,library)})
    (BUILD/'build-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')


def frame(tx, proof):
    encoded = deepcopy(tx)
    for inp in encoded.inputs:
        if len(inp.witness)<2 or inp.witness[-1][:1] == b'\x50':
            raise ValueError('model requires an unannexed script/control path')
        inp.witness = [b'',*inp.witness[-2:]]
    encoded.inputs[0].witness.insert(0,MAGIC+proof)
    if encoded.txid != tx.txid:
        raise AssertionError('witness-only framing changed txid')
    return encoded


def verify(tx, parents):
    with tempfile.TemporaryDirectory() as directory:
        paths = []
        for i,item in enumerate([tx,*parents]):
            path=Path(directory)/(str(i)+'.hex');path.write_text(item.serialize().hex()+'\n');paths.append(path)
        process=subprocess.run([str(VERIFIER),*map(str,paths)],capture_output=True,text=True)
    if process.returncode not in (0,1): raise RuntimeError(process.stderr[-2000:])
    result=json.loads(process.stdout)
    if result['valid'] != (process.returncode == 0): raise AssertionError('inconsistent native verdict')
    return result


def run(directory, name='compact-q1-valid', receipts=None):
    directory.mkdir(parents=True,exist_ok=True)
    receipts = receipts or ROOT/'results/shrincs-proof'
    proof=(receipts/(name+'.receipt.bin')).read_bytes()
    tx, parents, signatures=fixture(name)
    encoded=frame(tx,proof)
    cases=[]
    mutations=['none','recipient','amount','sequence','version','locktime','spent_amount','outpoint',
               'missing_proof','version_marker','proof','proof_append','proof_truncate','sentinel','control','overweight']
    if len(tx.inputs)>1: mutations += ['input_order','missing_input']
    for mutation in mutations:
        t,p=deepcopy(encoded),deepcopy(parents)
        if mutation=='recipient':t.outputs[0].script=b'\x6a'
        if mutation=='amount':t.outputs[0].value-=1
        if mutation=='sequence':t.inputs[0].sequence-=1
        if mutation=='version':t.version+=1
        if mutation=='locktime':t.locktime+=1
        if mutation=='spent_amount':p[0].outputs[0].value+=1;t.inputs[0].txid=p[0].txid
        if mutation=='outpoint':p[0].locktime+=1;t.inputs[0].txid=p[0].txid
        if mutation=='missing_proof':t.inputs[0].witness.pop(0)
        if mutation=='version_marker':t.inputs[0].witness[0]=MAGIC[:-1]+b'\x02'+proof
        if mutation=='proof':
            changed=bytearray(proof);changed[64]^=1;t.inputs[0].witness[0]=MAGIC+changed
        if mutation=='proof_append':t.inputs[0].witness[0]+=b'\0'
        if mutation=='proof_truncate':t.inputs[0].witness[0]=t.inputs[0].witness[0][:-1]
        if mutation=='sentinel':t.inputs[0].witness[1]=b'\x01'
        if mutation=='control':
            changed=bytearray(t.inputs[0].witness[-1]);changed[-1]^=1;t.inputs[0].witness[-1]=bytes(changed)
        if mutation=='overweight':t.inputs[0].witness[0]+=bytes(4_000_000)
        if mutation=='input_order':
            envelope=t.inputs[0].witness.pop(0);t.inputs.reverse();p.reverse();t.inputs[0].witness.insert(0,envelope)
        if mutation=='missing_input':t.inputs.pop();p.pop()
        result=verify(t,p)
        if result['valid'] != (mutation=='none'):raise AssertionError((mutation,result))
        cases.append(dict(mutation=mutation,tx_sha256=sha256(t.serialize()).hexdigest(),result=result))
    claims=authorizations(tx,parents,signatures)['authorizations']
    statement=b'btc-pq/SHRINCS-proof-claims/v1\0'+len(claims).to_bytes(4,'little')
    for a in claims:statement+=bytes(a['key'])+bytes(a['message'])
    if cases[0]['result']['claims_digest'] != sha256(statement).hexdigest():raise AssertionError('native claim digest mismatch')
    (directory/(name+'.tx.hex')).write_text(encoded.serialize().hex()+'\n')
    (directory/(name+'.parents.json')).write_text(json.dumps([p.serialize().hex() for p in parents])+'\n')
    report=dict(fixture=name,proof_sha256=sha256(proof).hexdigest(),source_sha256=source_hashes(),
                build_manifest=json.loads((BUILD/'build-manifest.json').read_text()),
                cases=cases,all_expectations_met=True,network_node=False)
    (directory/(name+'.json')).write_text(json.dumps(report,indent=2)+'\n')
    return report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build',action='store_true')
    parser.add_argument('--fixture',default='compact-q1-valid')
    parser.add_argument('--receipts',type=Path)
    parser.add_argument('--outdir',type=Path,default=ROOT/'results/shrincs-receipt')
    args=parser.parse_args()
    if args.build:build()
    result=run(args.outdir,args.fixture,args.receipts)
    print(json.dumps(dict(cases=len(result['cases']),all_expectations_met=True)))
