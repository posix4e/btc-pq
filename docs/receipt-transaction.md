# Native transaction proof demo

This experiment puts a real SHRINCS proof receipt inside a serialized Bitcoin
transaction's witness and requires it for transaction authorization. It combines
Core 31.1's transaction and Script checks with a native Rust receipt verifier.
It is a separate proposed-rule checker, not a Bitcoin network node.

## Witness contract

Version 1 covers **every input**, in transaction order. The first input carries:

```text
"BTC-PQ-PROOF" || 0x01 || serialized receipt
empty byte string                         # shared-authorization sentinel
PUSH32 public_key OP_SHRINCS               # exact 34-byte leaf
one-level P2MR control block
```

Every other input carries the same three trailing items with its own committed
key and control block. Annexes, partial groups, extra stack items, and other
leaf shapes are outside this version and are rejected.

The outer checker removes the proof envelope before Script execution. This is
an explicit consensus-model change: existing Script limits would reject that
large item if it were passed to Script as an ordinary argument. The zero-count
sentinel is enabled only by a separate local flag. A sentinel merely requests
shared authorization; it is not an independently valid signature.

Core verifies each committed Script path and computes its BIP341/BIP342
transaction digest. The checker forms the same ordered `(key, message)` claim
commitment as the SHRINCS proof guest, verifies the receipt against a fixed
program image ID, and requires that exact journal commitment. Overall acceptance
requires both all Script checks and successful receipt verification.

The envelope changes the wtxid and weight but does not change the txid or the
signed digest. This avoids a circular requirement to sign the proof containing
the signature. A payment change does alter the expected digest and invalidates
the saved proof.

## Bounds and scope

The model accepts 1–512 inputs, checks exact linked parents, rejects duplicate
inputs and outputs exceeding inputs, and requires the whole transaction to fit
the 4,000,000-weight-unit block limit. Its native receipt entry point rejects
receipts above 4,000,000 bytes, trailing bytes, mock receipts, Groth16 receipts,
assumption receipts, and statements for another program or payment.

This is an encoding and authorization prototype. Its size/decoder restrictions
are not a complete consensus CPU-cost analysis. Full node integration still
requires chain/UTXO context, activation rules, policy, block-level accounting,
cache design, and further review. A passing linked-prevout check does not establish
mempool acceptance or block inclusion.

## Executed result

The first compact signature's **1,381,282-byte composite STARK receipt** produces
a **1,381,467-byte transaction**, weighing **1,381,749 WU (345,438 vB)**. The direct
SHRINCS transaction is 495 bytes. This uncompressed proof format has very large
overhead; recursive compression is a separate measurement.

The saved [compressed receipt](../results/shrincs-proof-compressed/compact-q1-valid.compression.json)
occupies **223,290 bytes**. Its transaction is **223,475 bytes**,
**223,757 WU (55,940 vB)**. All
[16 compressed-receipt cases](../results/shrincs-receipt-compressed/compact-q1-valid.json)
also pass. Both formats still cost far more than one direct SHRINCS signature.

All [16 native cases](../results/shrincs-receipt/compact-q1-valid.json) match their
expectations. Changed payments, funding, proof bytes, version markers, sentinels,
control paths, missing proofs, and an overweight witness fail. The native claim
digest also agrees with the separate Python computation. The
[serialized transaction](../results/shrincs-receipt/compact-q1-valid.tx.hex)
contains the actual proof bytes.

```sh
python -m btc_pq.receipt_demo --build
python -m btc_pq.receipt_compress --replay
python -m btc_pq.receipt_demo --receipts results/shrincs-proof-compressed --outdir results/shrincs-receipt-compressed
python -m unittest tests.test_receipt_demo -v
```

The build uses a separate Core source tree and leaves the earlier direct
SHRINCS checker unchanged. Source pins, native libraries, binaries, and the
proof receipt are identified by hashes in the result manifest.
