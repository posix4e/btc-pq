"""Pinned upstream SHRINCS-B32 plus a local transaction-aware Script opcode."""
from hashlib import sha256
import io
import json
import shutil
import subprocess
import tarfile
import time

from .crypto import ROOT

CORE_COMMIT = '9be056a8a72b624dae9623b2f7bded92c2a21c91'
SHRINCS_COMMIT = '7643d9530c568f8671b21b9502e51bd9722b2e8d'
UPSTREAM = ROOT/'.cache/shrincs-cpp'
SOURCE = ROOT/'.cache/shrincs-bitcoin'
BUILD = ROOT/'.cache/shrincs-build'
VERIFIER = BUILD/'btc-pq-shrincs-verify'
TOOL = BUILD/'btc-pq-shrincs-tool'
KAT = BUILD/'shrincs-upstream-kat'


def build(jobs=6):
    start = time.perf_counter()
    pristine = ROOT/'.cache/bitcoin'
    commit = subprocess.check_output(['git', '-C', str(pristine), 'rev-parse', 'HEAD'], text=True).strip()
    if commit != CORE_COMMIT:
        raise RuntimeError('requires the pinned Core 31.1 source; see README.md Setup')
    if not UPSTREAM.exists():
        subprocess.run(['git', 'clone', 'https://github.com/BlockstreamResearch/shrincs-cpp', str(UPSTREAM)], check=True)
        subprocess.run(['git', 'checkout', '--detach', SHRINCS_COMMIT], cwd=UPSTREAM, check=True)
    upstream_commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=UPSTREAM, text=True).strip()
    dirty = subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=no'], cwd=UPSTREAM, text=True)
    if upstream_commit != SHRINCS_COMMIT or dirty:
        raise RuntimeError('requires an unmodified pinned SHRINCS checkout; see docs/shrincs-demo.md')
    inputs = [ROOT/'native/covenant-core.patch', ROOT/'native/shrincs-core.patch',
              ROOT/'native/shrincs_verify.cpp', ROOT/'native/shrincs_tool.cpp',
              ROOT/'native/shrincs_bridge.cpp', ROOT/'native/shrincs_bridge.h',
              ROOT/'native/shrincs/CMakeLists.txt']
    hashes = {str(p.relative_to(ROOT)): sha256(p.read_bytes()).hexdigest() for p in inputs}
    source_inputs = {k:v for k,v in hashes.items() if k.endswith('.patch')}
    stamp = SOURCE/'.btc-pq-build-inputs.json'
    if SOURCE.exists() and (not stamp.exists() or json.loads(stamp.read_text()).get('source_inputs') != source_inputs):
        if not stamp.exists():
            raise RuntimeError('refusing to replace an unrecognized SHRINCS source directory')
        shutil.rmtree(SOURCE)
    if not SOURCE.exists():
        SOURCE.mkdir(parents=True)
        archive = subprocess.check_output(['git', '-C', str(pristine), 'archive', CORE_COMMIT])
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            tar.extractall(SOURCE, filter='data')
        for patch in inputs[:2]:
            subprocess.run(['git', 'apply', str(patch)], cwd=SOURCE, check=True)
        stamp.write_text(json.dumps(dict(source_inputs=source_inputs), indent=2)+'\n')
    cmake = str(ROOT/'.venv/bin/cmake') if (ROOT/'.venv/bin/cmake').exists() else shutil.which('cmake')
    ninja = str(ROOT/'.venv/bin/ninja') if (ROOT/'.venv/bin/ninja').exists() else shutil.which('ninja')
    if not cmake or not ninja:
        raise RuntimeError('CMake and Ninja are required; see README.md Setup')
    subprocess.run([cmake, '-S', str(ROOT/'native/shrincs'), '-B', str(BUILD), '-G', 'Ninja',
                    f'-DCMAKE_MAKE_PROGRAM={ninja}',
                    f'-DCORE_SOURCE={SOURCE}', f'-DSHRINCS_SOURCE={UPSTREAM}', '-DCMAKE_BUILD_TYPE=Release'], check=True)
    subprocess.run([cmake, '--build', str(BUILD), '--parallel', str(jobs),
                    '--target', 'btc-pq-shrincs-verify', 'btc-pq-shrincs-tool', 'shrincs-upstream-kat'], check=True)
    result = dict(consensus_modified=True, scope='linked_prevout_script_verification',
                  core_commit=CORE_COMMIT, shrincs_commit=SHRINCS_COMMIT, parameters='SHRINCS_B32', source_inputs=hashes,
                  build_wall_seconds=time.perf_counter()-start,
                  binary_sha256={p.name:sha256(p.read_bytes()).hexdigest() for p in (VERIFIER, TOOL, KAT)})
    (BUILD/'build-manifest.json').write_text(json.dumps(result, indent=2)+'\n')
    return result


if __name__ == '__main__':
    build()
