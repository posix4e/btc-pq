"""Build a separate, explicitly modified Core 31.1 regtest-only experiment."""
from hashlib import sha256
from pathlib import Path
import io
import json
import shutil
import subprocess
import tarfile
import time

from .crypto import ROOT

CORE_COMMIT = '9be056a8a72b624dae9623b2f7bded92c2a21c91'
SOURCE = ROOT/'.cache/toy-bitcoin'
BUILD = ROOT/'.cache/toy-build'
NODE = BUILD/'core/bin/bitcoind'
VERIFIER = BUILD/'btc-pq-toy-verify'
SEARCH = BUILD/'btc-pq-toy-search'


def build(jobs=6):
    start = time.perf_counter()
    pristine = ROOT/'.cache/bitcoin'
    commit = subprocess.check_output(['git','-C',str(pristine),'rev-parse','HEAD'],text=True).strip()
    if commit != CORE_COMMIT:
        raise RuntimeError('toy build requires the pinned Core 31.1 source commit')
    inputs = [ROOT/'native/toy-core.patch',ROOT/'native/toy_predicate.h',
              ROOT/'native/toy_search.cpp',ROOT/'native/verify.cpp',ROOT/'native/toy/CMakeLists.txt']
    hashes = {str(p.relative_to(ROOT)):sha256(p.read_bytes()).hexdigest() for p in inputs}
    stamp = SOURCE/'.btc-pq-build-inputs.json'
    if SOURCE.exists() and (not stamp.exists() or json.loads(stamp.read_text()).get('source_inputs') !=
                            {k:v for k,v in hashes.items() if k in ('native/toy-core.patch','native/toy_predicate.h')}):
        # Only our disposable source copy is replaced; the stock tree is untouched.
        if not stamp.exists():
            raise RuntimeError('unrecognized toy source directory; choose a clean cache location')
        shutil.rmtree(SOURCE)
    if not SOURCE.exists():
        SOURCE.mkdir(parents=True)
        archive = subprocess.check_output(['git','-C',str(pristine),'archive',CORE_COMMIT])
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            tar.extractall(SOURCE,filter='data')
        subprocess.run(['git','apply',str(ROOT/'native/toy-core.patch')],cwd=SOURCE,check=True)
        shutil.copyfile(ROOT/'native/toy_predicate.h',SOURCE/'src/script/btc_pq_toy.h')
        stamp.write_text(json.dumps(dict(source_inputs={k:v for k,v in hashes.items()
                              if k in ('native/toy-core.patch','native/toy_predicate.h')}),indent=2)+'\n')
    cmake = str(ROOT/'.venv/bin/cmake')
    subprocess.run([cmake,'-S',str(ROOT/'native/toy'),'-B',str(BUILD),'-G','Ninja',
                    f'-DCMAKE_MAKE_PROGRAM={ROOT/".venv/bin/ninja"}',
                    f'-DCORE_SOURCE={SOURCE}','-DCMAKE_BUILD_TYPE=Release'],check=True)
    subprocess.run([cmake,'--build',str(BUILD),'--parallel',str(jobs),
                    '--target','bitcoind','btc-pq-toy-verify','btc-pq-toy-search'],check=True)
    result = dict(consensus_modified=True,qsb_exact_reproduction=False,core_commit=CORE_COMMIT,
                  source_inputs=hashes,build_wall_seconds=time.perf_counter()-start,
                  binaries={str(p.relative_to(ROOT)):sha256(p.read_bytes()).hexdigest() for p in (NODE,VERIFIER,SEARCH)})
    (BUILD/'build-manifest.json').write_text(json.dumps(result,indent=2)+'\n')
    return result


if __name__ == '__main__':
    build()
