"""Pinned C implementation, loaded separately for differential verification."""
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys

from .crypto import ROOT

COMMIT = '345b0a64ce8d00c16c35952375dea6d13ec48c85'
SOURCE = ROOT/'.cache/shrincs-c'
BUILD = ROOT/'.cache/shrincs-c-build'
LIBRARY = BUILD/('libshrincs.dylib' if sys.platform == 'darwin' else 'libshrincs.so')


def build():
    if not SOURCE.exists():
        subprocess.run(['git', 'clone', 'https://github.com/BlockstreamResearch/shrincs-c', str(SOURCE)], check=True)
        subprocess.run(['git', 'checkout', '--detach', COMMIT], cwd=SOURCE, check=True)
    head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=SOURCE, text=True).strip()
    dirty = subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=no'], cwd=SOURCE, text=True)
    if head != COMMIT or dirty:
        raise RuntimeError('requires the unmodified pinned SHRINCS C checkout')
    BUILD.mkdir(parents=True, exist_ok=True)
    flags = []
    prefix = os.environ.get('OPENSSL_ROOT_DIR')
    if not prefix and sys.platform == 'darwin':
        prefix = subprocess.check_output(['brew', '--prefix', 'openssl@3'], text=True).strip()
    if prefix:
        flags = ['-I'+str(Path(prefix)/'include'), '-L'+str(Path(prefix)/'lib')]
    sources = sorted((SOURCE/'src').glob('*.c'))
    subprocess.run([os.environ.get('CC', 'cc'), '-shared', '-fPIC', '-O3', '-std=c17',
                    '-Wno-deprecated-declarations', '-DSHRINCS_B32', '-I'+str(SOURCE/'include'),
                    *flags, *map(str, sources), '-lcrypto', '-o', str(LIBRARY)], check=True)
    manifest = dict(commit=COMMIT, parameters='SHRINCS_B32',
                    source_sha256={str(p.relative_to(SOURCE)): sha256(p.read_bytes()).hexdigest()
                                   for p in sources + sorted((SOURCE/'include').glob('*.h'))},
                    library_sha256=sha256(LIBRARY.read_bytes()).hexdigest())
    (BUILD/'manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
    return manifest


class PublicKey(ctypes.Structure):
    _fields_ = [('seed', ctypes.c_ubyte*16), ('root', ctypes.c_ubyte*16)]


class CVerifier:
    def __init__(self):
        self.library = ctypes.CDLL(str(LIBRARY))
        self.function = self.library.shrincs_verify
        self.function.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p,
                                  ctypes.c_uint32, ctypes.POINTER(PublicKey)]
        self.function.restype = ctypes.c_uint32

    def verify(self, message, signature, public_key):
        size = len(signature)
        if len(public_key) != 32 or len(message) >= 2**32:
            return False
        if not (324 <= size <= 3668 and (size-308)%16 == 0 or size == 3680):
            return False  # Guard the upstream raw-pointer API before entry.
        pk = PublicKey.from_buffer_copy(public_key)
        return bool(self.function(message, len(message), signature, size, ctypes.byref(pk)))


if __name__ == '__main__':
    print(json.dumps(build(), indent=2))
