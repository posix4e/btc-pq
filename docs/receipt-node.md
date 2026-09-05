# Exact SHRINCS receipts in a patched regtest node

The node build connects the shared native receipt validator to Core 31.1's
`CheckInputScripts`. The caller supplies spent outputs from its UTXO view.
Mempool and block validation activate the local P2MR/SHRINCS/receipt flags only
when the chain type is regtest. The witness contract and pinned guest image
are defined in [the transaction proof demo](receipt-transaction.md).

The full group is checked inline before ordinary per-input checks would be
queued. Successful results use Core's existing script execution cache key,
which includes the transaction's **wtxid and verification flags**. A changed
receipt changes the wtxid, even when the txid stays the same.

This build is a proposed-rule research node. It is not a Bitcoin activation
proposal or a complete implementation of all other opcodes demonstrated by
the standalone tools. In particular, its custom SHRINCS authorization path
requires a receipt; the ordinary signature checker does not implement direct
SHRINCS verification. The regtest harness permits nonstandard output types.

## Current evidence

- The separate node builds successfully against the pinned Core source and
  links the same Rust receipt verifier as the standalone checker.
- Stock Core generated and mined a fresh funding transaction. The public
  fixture includes all 102 setup blocks, the linked funding transaction, a
  new 324-byte SHRINCS signature, and its actual zkVM execution result.
- A patched node [replayed that funding](../results/shrincs-node/funding-replay.json)
  and rejected the earlier valid receipt for a different payment in both
  mempool and block validation (`bad-shrincs-receipt`).
- The matching new receipt is being generated. Valid mempool acceptance,
  mining, changed-witness checks after warming the cache, and fresh-node
  replay remain pending until the receipt is available.

The harness contains these pending checks but does not treat their presence as
executed evidence. The future recovery mechanism for the separate
[holding experiment](holding-demo.md) remains deferred.

## Reproduction

```sh
python -m btc_pq.receipt_node_build
python -m btc_pq.receipt_node prepare
python -m btc_pq.receipt_node prove
python -m btc_pq.receipt_node replay
```

Preparation requires an empty fixture directory. It uses fresh signing state
under `.cache/receipt-node-signers`, reserves a one-time position durably, and
publishes only public keys and the valueless test payment's signature. Existing
receipt files are verified before reuse; proof generation and compression are
separate saved stages. The default node and stock setup nodes have networking
disabled and use temporary regtest data directories.

The prototype still needs aggregate verification-cost analysis, review of the
local rules and proof soundness assumptions, and broader node integration
testing. Its per-transaction receipt and block-weight bounds do not substitute
for that analysis.
