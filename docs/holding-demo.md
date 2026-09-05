# Hash-commitment holding with recovery deferred

The user-selected scope is to establish ownership and park coins now, leaving
the choice of a future PQ scheme and recovery destination for later. This
experiment implements that holding component on **unchanged Bitcoin Core 31.1**.
It uses isolated regtest coins, with no mainnet wallet or transaction involved.

A fresh, uniformly random 32-byte secret is kept in a local backup. The output
is P2WSH, committing to this 35-byte witness script:

```text
OP_SHA256 <SHA256(secret)> OP_EQUAL
```

The funding output's scriptPubKey is **34 bytes** (43 bytes including its value
and serialized script length). The hidden witness script is 35 bytes, and the
ownership secret is 32 bytes. There is no elliptic-curve key path or expiry in
this script. While the secret stays private, authorization rests on finding a
SHA256 preimage, rather than recovering an ECDSA/Schnorr private key.

Holding alone uses existing hashlock rules and does not require a covenant.
These small byte counts describe the commitment and secret; they are not a
64-byte general-purpose PQ signature or an estimate of a future migration
transaction's size.

## What the executed checks establish

The [saved report](../results/holding-demo/replay.json) contains eight cases,
each checked by the unchanged native Script verifier and a fresh stock node's
`testmempoolaccept` RPC:

- A fresh Python process restores the backup and can satisfy the original lock.
- Incorrect or missing secrets, signature-shaped bytes, another witness script,
  and extra stack items fail.
- Reusing a disclosed correct secret with a different recipient or amount
  succeeds. This explicitly demonstrates that the existing hashlock does not
  bind the destination.

The node replays all 102 saved funding blocks. The output remains unspent after
ten additional blocks, and the mempool stays empty. The harness does not submit
or mine any secret-bearing spend. The script has no time condition; the ten-block
check is a runtime control, not a simulation of indefinite time or quantum work.

## Deferred recovery

The backup preserves ownership information. It does not implement a safe future
spending protocol. Revealing the secret under the current rules allows anyone
who sees it to authorize another destination, even without quantum computing.
A future migration would need additional agreed validation rules that bind the
owner's claim to the intended payment. Those rules, the future signature scheme,
and the destination address are deliberately deferred in this experiment.

This is conditional holding while the secret remains private, not an output
that consensus rejects under every possible witness. No automatic network
recovery, future activation, or recovery guarantee is claimed.

## Reproduction

```sh
python -m btc_pq.holding_demo prepare
python -m btc_pq.holding_demo replay
python -m unittest tests.test_holding_demo -v
```

Preparation requires an empty output directory and a new backup path. The
default backup lives at `.cache/holding-demo/backup.json`, outside Git, with
mode 0600 and durable writes. Only public funding blocks, commitments, and
verification results are published. The regression test creates a separate
temporary backup and checks that no public artifact contains its secret.

The separate [native SHRINCS demo](shrincs-demo.md) provides transaction-bound
authorization, while [the covenant comparison](covenant-demo.md) demonstrates
enforced transaction templates. Neither is required merely to retain the
unspent hash-committed output shown here.
