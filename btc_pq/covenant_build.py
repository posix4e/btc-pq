"""Build an isolated Script-only model of BIPs 347, 360 and 446; no network node."""
from hashlib import sha256
import io
import json
import shutil
import subprocess
import tarfile
import time

from .crypto import ROOT

CORE_COMMIT = '9be056a8a72b624dae9623b2f7bded92c2a21c91'
SOURCE = ROOT/'.cache/covenant-bitcoin'
BUILD = ROOT/'.cache/covenant-build'
VERIFIER = BUILD/'btc-pq-covenant-verify'


def build(jobs=6):
    start = time.perf_counter()
    pristine = ROOT/'.cache/bitcoin'
    commit = subprocess.check_output(['git', '-C', str(pristine), 'rev-parse', 'HEAD'], text=True).strip()
    if commit != CORE_COMMIT:
        raise RuntimeError('requires the pinned Core 31.1 source; see README.md Setup')
    inputs = [ROOT/'native/covenant-core.patch', ROOT/'native/covenant_verify.cpp',
              ROOT/'native/covenant/CMakeLists.txt']
    hashes = {str(p.relative_to(ROOT)): sha256(p.read_bytes()).hexdigest() for p in inputs}
    source_inputs = {'native/covenant-core.patch': hashes['native/covenant-core.patch']}
    stamp = SOURCE/'.btc-pq-build-inputs.json'
    if SOURCE.exists() and (not stamp.exists() or json.loads(stamp.read_text()).get('source_inputs') != source_inputs):
        if not stamp.exists():
            raise RuntimeError('refusing to replace an unrecognized covenant source directory')
        shutil.rmtree(SOURCE)
    if not SOURCE.exists():
        SOURCE.mkdir(parents=True)
        archive = subprocess.check_output(['git', '-C', str(pristine), 'archive', CORE_COMMIT])
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            tar.extractall(SOURCE, filter='data')
        subprocess.run(['git', 'apply', str(inputs[0])], cwd=SOURCE, check=True)
        stamp.write_text(json.dumps(dict(source_inputs=source_inputs), indent=2)+'\n')
    cmake = str(ROOT/'.venv/bin/cmake') if (ROOT/'.venv/bin/cmake').exists() else shutil.which('cmake')
    ninja = str(ROOT/'.venv/bin/ninja') if (ROOT/'.venv/bin/ninja').exists() else shutil.which('ninja')
    if not cmake or not ninja:
        raise RuntimeError('CMake and Ninja are required; see README.md Setup')
    subprocess.run([cmake, '-S', str(ROOT/'native/covenant'), '-B', str(BUILD), '-G', 'Ninja',
                    f'-DCMAKE_MAKE_PROGRAM={ninja}',
                    f'-DCORE_SOURCE={SOURCE}', '-DCMAKE_BUILD_TYPE=Release'], check=True)
    subprocess.run([cmake, '--build', str(BUILD), '--parallel', str(jobs),
                    '--target', 'btc-pq-covenant-verify'], check=True)
    result = dict(consensus_modified=True, scope='linked_prevout_script_verification',
                  core_commit=CORE_COMMIT, source_inputs=hashes,
                  build_wall_seconds=time.perf_counter()-start,
                  binary_sha256=sha256(VERIFIER.read_bytes()).hexdigest())
    (BUILD/'build-manifest.json').write_text(json.dumps(result, indent=2)+'\n')
    return result


if __name__ == '__main__':
    build()
