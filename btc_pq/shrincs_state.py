"""Crash-consistent single-host SHRINCS signing state for research experiments.

File locking and durable reservations prevent ordinary restart/concurrency reuse.
Copying or rolling back the whole directory can still reuse state. Seed-only
restoration always uses stateless signing. This is not a production wallet.
"""
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import secrets
import tempfile

from .shrincs_demo import native_tool
from .shrincs_reference import verify


def durable_json(path, value):
    path = Path(path)
    descriptor, temporary = tempfile.mkstemp(prefix='.state-', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'w') as stream:
            json.dump(value, stream, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
            # macOS fsync alone need not flush a drive's volatile write cache.
            if hasattr(fcntl, 'F_FULLFSYNC'):
                fcntl.fcntl(stream.fileno(), fcntl.F_FULLFSYNC)
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def native_sign(seed, message, q):
    with tempfile.TemporaryDirectory(prefix='btc-pq-sign-') as directory:
        seed_path, message_path = [Path(directory)/name for name in ('seed.hex', 'message.hex')]
        seed_path.write_text(seed+'\n')
        seed_path.chmod(0o600)
        message_path.write_text(message+'\n')
        return native_tool('sign-reserved', seed_path, message_path, 'recovery' if q is None else str(q))


def create(directory, *, restore_seed=None):
    directory = Path(directory)
    seed = secrets.token_bytes(48) if restore_seed is None else bytes(restore_seed)
    if len(seed) != 48:
        raise ValueError('SHRINCS seed must have 48 bytes')
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    # Derive before publishing the first complete state. An interrupted setup
    # leaves an unusable directory, never a partially initialized signer.
    with tempfile.TemporaryDirectory() as temporary:
        seed_path = Path(temporary)/'seed.hex'
        seed_path.write_text(seed.hex()+'\n')
        public_key = native_tool('pubkey', seed_path)['public_key']
    state = dict(version=1, parameters='SHRINCS_B32', seed=seed.hex(), public_key=public_key,
                 next_q=1 if restore_seed is None else None, requests={})
    durable_json(directory/'state.json', state)
    return dict(public_key=public_key, compact_enabled=restore_seed is None)


@contextmanager
def locked(directory):
    # A stable separate inode keeps the lock effective across state-file renames.
    with (Path(directory)/'lock').open('a') as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        yield


def read_state(directory):
    state = json.loads((Path(directory)/'state.json').read_text())
    if state['version'] != 1 or state['parameters'] != 'SHRINCS_B32':
        raise ValueError('unsupported signer state')
    if state['next_q'] is not None and (type(state['next_q']) is not int or not 1 <= state['next_q'] <= 212):
        raise ValueError('invalid next counter')
    if len(bytes.fromhex(state['seed'])) != 48 or len(bytes.fromhex(state['public_key'])) != 32:
        raise ValueError('invalid seed/public key')
    return state


def sign(directory, message, request_id, *, after_reserve=None):
    """Reserve durably, sign, then durably cache the result before returning it.

    Repeating a completed request returns its saved signature. Retrying an
    interrupted request reserves another position; the previous one stays spent.
    `after_reserve` is a crash-test hook, called only after durable reservation.
    """
    directory, message = Path(directory), bytes(message)
    if len(message) != 32 or not isinstance(request_id, str) or not 1 <= len(request_id) <= 256:
        raise ValueError('32-byte digest and nonempty request ID (up to 256 characters) required')
    with locked(directory):
        state = read_state(directory)
        request = state['requests'].get(request_id)
        if request:
            if request['message'] != message.hex():
                raise ValueError('request ID already binds a different message')
            if request['status'] == 'complete':
                return request['result']
        else:
            request = dict(message=message.hex(), reservations=[])
            state['requests'][request_id] = request
        q = state['next_q']
        if q is not None and q <= 211:
            state['next_q'] = q+1
        else:
            q = None
        request['reservations'].append(q)
        request['status'] = 'reserved'
        durable_json(directory/'state.json', state)
        if after_reserve:
            after_reserve()
        result = native_sign(state['seed'], message.hex(), q)
        if result['q'] != (q or 0) or result['public_key'] != state['public_key']:
            raise RuntimeError('native signer returned a different reservation or public key')
        if not verify(message, bytes.fromhex(result['signature']), bytes.fromhex(state['public_key']))['valid']:
            raise RuntimeError('Python signature cross-check failed')
        request['result'] = result
        request['status'] = 'complete'
        durable_json(directory/'state.json', state)
        return result
