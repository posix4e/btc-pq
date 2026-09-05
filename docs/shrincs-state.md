# Persistent SHRINCS signing state

`btc_pq.shrincs_state` adds a single-host research signer around the native B32
implementation. Its compact counter is recorded durably **before** the native
signer runs. A crashed or failed attempt consumes its reserved counter, even if
no signature reaches the caller. Successful signatures are saved durably before
being returned.

The same request ID and message return the saved signature. Reusing that ID
with a different message fails. Retrying an interrupted request reserves a new
counter and retains the old reservation in its history. A stable lock file
serializes processes across atomic state-file replacements.

```python
from btc_pq.shrincs_state import create, sign

create("/tmp/pq-research-signer")  # New directory, fresh random test seed.
receipt = sign("/tmp/pq-research-signer", bytes.fromhex(digest_hex), "payment-1")
```

The message must be the 32-byte transaction digest computed by the SHRINCS
transaction harness. This module manages signing state; it does not select
coins, build transactions, broadcast payments, or act as a production wallet.

```python
create("/tmp/pq-restored-signer", restore_seed=seed_bytes)
receipt = sign("/tmp/pq-restored-signer", digest, "recovered-payment")
assert receipt["mode"] == "recovery"
```

Seed restoration preserves the public key and enables only stateless signing.
After compact position 211, normal signing also switches to stateless mode.
The native `sign-reserved` command is a low-level backend: invoking it directly
does not provide the state manager's counter guarantees.

## What was checked

Run `python -m unittest tests.test_shrincs_state -v` after building the SHRINCS
demo. The tests use real native signatures, checked again in Python. They cover:

- Two separate processes signing concurrently receive distinct positions.
- A subprocess exits immediately after a durable reservation; its retry uses
  the next position.
- Separate calls advance the counter, while completed requests remain
  idempotent and reject a changed message.
- Seed-only restoration and exhaustion use 3,680-byte recovery signatures;
  the final compact signature uses 3,668 bytes.
- Malformed state fails without silently creating a fresh counter.

Writes use a temporary file, file synchronization, atomic rename, and directory
synchronization. On macOS the file also uses `F_FULLFSYNC` where Python exposes
it. These checks cover ordinary process interruption and single-host
concurrency. They do not establish power-loss behavior for every storage device.

Copying an active signer directory or restoring an old complete state file can
still reuse counters. Plain local files cannot detect that rollback. Keep one
active state directory; a seed-only backup intentionally restores to the
stateless path. An actual wallet needs a device/backup policy that addresses
rollback as well as ordinary crashes.
