"""Build a separate Core node with receipt rules activated only on regtest."""
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile

from .crypto import ROOT
from .receipt_demo import build as build_checker, source_hashes as checker_hashes
from .shrincs_build import CORE_COMMIT
from .shrincs_proof import TARGET

SOURCE = ROOT/'.cache/receipt-node-bitcoin'
BUILD = ROOT/'.cache/receipt-node-build'
NODE = BUILD/'core/bin/bitcoind'


def source_hashes():
    hashes = checker_hashes()
    for path in (Path(__file__), ROOT/'native/shrincs-node-core.patch',
                 ROOT/'native/shrincs-node/CMakeLists.txt'):
        hashes[str(path.relative_to(ROOT))] = sha256(path.read_bytes()).hexdigest()
    return hashes


def build(jobs=2):
    build_checker(jobs)
    hashes = source_hashes()
    source_inputs = {p:h for p,h in hashes.items() if p.endswith(('.patch', 'shrincs_cost.h'))}
    stamp = SOURCE/'.btc-pq-receipt-node.json'
    if SOURCE.exists() and (not stamp.exists() or json.loads(stamp.read_text()) != source_inputs):
        if not stamp.exists(): raise ValueError('unrecognized node source directory')
        shutil.rmtree(SOURCE)
    if not SOURCE.exists():
        SOURCE.mkdir(parents=True)
        archive = subprocess.check_output(['git','-C',str(ROOT/'.cache/bitcoin'),'archive',CORE_COMMIT])
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            tar.extractall(SOURCE,filter='data')
        for patch in ('covenant-core.patch','shrincs-core.patch','shrincs-proof-core.patch','shrincs-node-core.patch'):
            subprocess.run(['git','apply',str(ROOT/'native'/patch)],cwd=SOURCE,check=True)
        shutil.copyfile(ROOT/'native/shrincs_cost.h',SOURCE/'src/script/shrincs_cost.h')
        stamp.write_text(json.dumps(source_inputs,indent=2)+'\n')
    library = TARGET/('release/libbtc_pq_receipt.dylib' if os.uname().sysname == 'Darwin' else 'release/libbtc_pq_receipt.so')
    cmake = str(ROOT/'.venv/bin/cmake')
    subprocess.run([cmake,'-S',str(ROOT/'native/shrincs-node'),'-B',str(BUILD),'-G','Ninja',
                    f'-DCMAKE_MAKE_PROGRAM={ROOT/".venv/bin/ninja"}',
                    f'-DCORE_SOURCE={SOURCE}',f'-DRECEIPT_LIB={library}',
                    '-DCMAKE_BUILD_TYPE=Release'],check=True)
    subprocess.run([cmake,'--build',str(BUILD),'--parallel',str(jobs),'--target','bitcoind'],check=True)
    manifest = dict(core_commit=CORE_COMMIT,activation='regtest only',source_sha256=hashes,
                    binary_sha256={str(p.relative_to(ROOT)):sha256(p.read_bytes()).hexdigest() for p in (NODE,library)})
    (BUILD/'build-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    return manifest


if __name__ == '__main__':
    build()
