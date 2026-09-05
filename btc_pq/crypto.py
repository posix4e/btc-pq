"""Public deterministic research data only. Never use these keys to hold funds."""
import importlib.util
from pathlib import Path
from hashlib import sha256

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('qsb_secp', ROOT/'vendor/qsb/v16/pipeline/secp256k1.py')
ec = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ec)


def recover(r, s, digest, recovery_id=0):
    # Unlike the reference helper, explicitly includes the rare x = r+n branches.
    if recovery_id not in range(4) or not (0 < r < ec.N and 0 < s < ec.N):
        return None
    x = r + (recovery_id >> 1) * ec.N
    if x >= ec.P:
        return None
    y2 = (pow(x,3,ec.P) + 7) % ec.P
    y = pow(y2, (ec.P+1)//4, ec.P)
    if y*y % ec.P != y2:
        return None
    if y % 2 != recovery_id % 2:
        y = ec.P - y
    z = int.from_bytes(digest,'big')
    inv = pow(r,-1,ec.N)
    q = ec.point_add(ec.point_mul(s*inv, (x,y)), ec.point_mul(-z*inv,ec.G))
    return None if q == ec.INF else q


def encode(q, encoding='compressed'):
    if encoding == 'compressed':
        return ec.compress_pubkey(q)
    prefix = 4 if encoding == 'uncompressed' else 6 + q[1] % 2
    return bytes([prefix]) + q[0].to_bytes(32,'big') + q[1].to_bytes(32,'big')


# Small r selected so all FOUR recovery branches exist: exercises a commonly
# omitted x=r+n corner case, with ordinary strict-DER ECDSA and full secp256k1.
FIXED_R = next(r for r in range(1,1000) if all(recover(r,1,bytes(32),j) for j in range(4)))
FIXED_SIG = ec.encode_der_sig(FIXED_R, 1, 1)


def secret(label):
    return sha256(('PUBLIC BTC-PQ TEST SECRET: '+label).encode()).digest()
