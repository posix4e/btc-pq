"""Compress or replay an existing exact-SHRINCS STARK receipt."""
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess

from .crypto import ROOT
from .shrincs_proof import TARGET, fixture, authorizations, native


def run(directory, name='compact-q1-valid', replay=False):
    directory.mkdir(parents=True,exist_ok=True)
    source=ROOT/'results/shrincs-proof'/(name+'.receipt.bin')
    destination=directory/(name+'.receipt.bin')
    report_path=directory/(name+'.compression.json')
    program=json.loads((ROOT/'results/shrincs-proof/program.json').read_text())
    batch=authorizations(*fixture(name))
    statement=b'btc-pq/SHRINCS-proof-claims/v1\0'+len(batch['authorizations']).to_bytes(4,'little')
    for a in batch['authorizations']:statement+=bytes(a['key'])+bytes(a['message'])
    digest=sha256(statement).hexdigest()
    tool=TARGET/'release/btc-pq-receipt-tool'
    server=ROOT/'.cache/risc0-tools/r0vm'
    env=dict(os.environ,RISC0_PROVER='ipc',RISC0_SERVER_PATH=str(server));env.pop('RISC0_DEV_MODE',None)
    if replay:
        report=json.loads(report_path.read_text())
        if report['image_id']!=program['image_id'] or report['claims_digest']!=digest:
            raise ValueError('saved compression report has different claims')
        if 'receipt_sha256' in report and report['receipt_sha256']!=sha256(destination.read_bytes()).hexdigest():
            raise ValueError('saved compressed receipt changed')
        if 'input_sha256' in report and report['input_sha256']!=sha256(source.read_bytes()).hexdigest():
            raise ValueError('saved source receipt changed')
        if report['input_bytes']!=source.stat().st_size:
            raise ValueError('source receipt length mismatch')
    else:
        if destination.exists():raise ValueError('receipt already exists; use --replay or another output directory')
        process=subprocess.run([str(tool),'compress',str(source),program['image_id'],digest,str(destination)],
                               env=env,text=True,capture_output=True,check=True)
        report=json.loads(process.stdout)
    report['input_replay']=native('verify',batch,source)
    report['replay']=native('verify',batch,destination)
    report.update(input_sha256=sha256(source.read_bytes()).hexdigest(),receipt_sha256=sha256(destination.read_bytes()).hexdigest(),
                  raw_signature_bytes=sum(len(a['signature']) for a in batch['authorizations']),
                  harness_sha256=sha256(Path(__file__).read_bytes()).hexdigest(),
                  binary_sha256={str(p.relative_to(ROOT)):sha256(p.read_bytes()).hexdigest() for p in (tool,server)},
                  source_sha256={str(p.relative_to(ROOT)):sha256(p.read_bytes()).hexdigest()
                                 for p in sorted((ROOT/'native/receipt-tool').rglob('*')) if p.is_file()})
    report_path.write_text(json.dumps(report,indent=2)+'\n')
    return report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fixture',default='compact-q1-valid')
    parser.add_argument('--replay',action='store_true')
    parser.add_argument('--outdir',type=Path,default=ROOT/'results/shrincs-proof-compressed')
    args=parser.parse_args()
    result=run(args.outdir,args.fixture,args.replay)
    print(json.dumps(dict(receipt_bytes=result['receipt_bytes'],valid=result['replay']['valid'])))
