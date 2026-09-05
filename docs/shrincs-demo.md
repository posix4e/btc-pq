# P2MR + transaction-bound SHRINCS

This experiment replaces the previous Lamport script with the unmodified
upstream **SHRINCS-B32** implementation and a small, locally defined signature
opcode. It demonstrates compact signing and seed-recovery signing under the
same P2MR public key. Both bind the complete default transaction signature
message, including input outpoints and spent amounts.

The first compact spend is **495 bytes**, compared with **30,073 bytes** for our
Lamport demonstration. Recovery uses a **3,870-byte transaction**. All **37
transaction cases** match their expected outcomes. This is a local consensus
experiment, not a Bitcoin mainnet deployment or a proposed production opcode.

## How the parts work together

1. The P2MR output commits to a script containing the SHRINCS public key.
2. The signer hashes the transaction, its spent outputs and the spending script.
3. SHRINCS signs that digest using either its compact stateful path or its
   stateless recovery path.
4. The local opcode recomputes the digest from the actual transaction and checks
   the signature with the upstream library.
5. P2MR permits only a committed script path, so an EC key signature cannot
   bypass that check.

This version does **not need CAT or TemplateHash for authorization**. Its native
signature operation supplies transaction binding directly. Replacing a large
script verifier with native code accounts for part of the size reduction;
SHRINCS's smaller signature accounts for another part. The comparison is between
these two concrete demonstrations, not a comparison at matched security
parameters or an estimate of production wallet performance.

Neither of these direct-signature demonstrations implements CISA. Two independent inputs still need two
SHRINCS signatures. The two-input compact transaction is 935 bytes / 1,340 WU /
335 vB; deleting one authorization or copying the other owner's signature fails.
The [separate aggregation experiments](aggregation-demo.md) now execute Schnorr
CISA and real leanVM proofs of XMSS payment signatures. They do not compress
these SHRINCS signatures.

## Reproduce

First follow the root README's Core 31.1 and stock native-verifier setup.
This build also requires OpenSSL development files. On a Mac with Homebrew,
`brew install openssl@3` supplies them. CMake normally discovers that installation;
otherwise set the standard `OPENSSL_ROOT_DIR` environment variable.

```sh
btc-pq shrincs-demo --build
btc-pq shrincs-demo --replay
python -m btc_pq.shrincs_kat
python -m btc_pq.shrincs_c
python -m btc_pq.shrincs_kat --full
python -m btc_pq.shrincs_differential --path results/shrincs-demo/upstream-kat-full.rsp --expected-count 375
python -m unittest discover -s tests -v
```

The build downloads the public upstream repository if absent and pins it to
`7643d9530c568f8671b21b9502e51bd9722b2e8d`. If an existing cache is at another
revision or has tracked changes, the builder stops instead of overwriting it.
Core is pinned to `9be056a8a72b624dae9623b2f7bded92c2a21c91` and built in a separate
`.cache/shrincs-bitcoin` source copy. The original Core and covenant-demo builds
remain separate. Use `--outdir` to save another fixture set.

The [upstream C++ source](https://github.com/BlockstreamResearch/shrincs-cpp/tree/7643d9530c568f8671b21b9502e51bd9722b2e8d)
is compiled without changes and with `SHRINCS_B32` for signing and reference
verification. The opcode now uses a [bounded native verifier](shrincs-work.md),
checked against those references, with deterministic work limits and charges. Upstream
identifies this implementation as research software; the local integration adds
no production-readiness claim.

## Measured sizes

These are one-input, one-output spends of the same funded script. Public keys
are 32 bytes, scripts 34 bytes, and depth-one P2MR control blocks 33 bytes.

| Signing mode | Raw signature bytes | Signature chunks | Transaction bytes | Weight | vB |
| --- | ---: | ---: | ---: | ---: | ---: |
| Compact, first signature (`q=1`) | 324 | 1 | 495 | 777 | 195 |
| Compact, second signature (`q=2`) | 340 | 1 | 511 | 793 | 199 |
| Compact, seventeenth signature (`q=17`) | 580 | 2 | 752 | 1,034 | 259 |
| Stateless recovery | 3,680 | 8 | 3,870 | 4,152 | 1,038 |

The selected parameters are `N=16`, `W=256`, `L=16`, `HSF=210`, `HSL=32`, `D=4`,
`T=109571`, `B=17`, `K=11`, `M_MAX=111`. Compact signatures grow by 16 bytes per
counter step until the final level; `q=210` and `q=211` both occupy 3,668 bytes.
The fallback is fixed at 3,680 bytes. These values follow the
[pinned parameter definitions](https://github.com/BlockstreamResearch/shrincs-cpp/blob/7643d9530c568f8671b21b9502e51bd9722b2e8d/include/constants.h)
and the sizes of the signatures we generated.

Consequently, the earlier 580-byte and 4,336-byte literature examples are not
universal SHRINCS sizes. This implementation starts at 324 bytes, reaches 580
bytes at its seventeenth compact signature, and uses a different fallback
parameter selection. [Earlier proposal context](https://blog.blockstream.com/op_checkshrincs-a-hash-based-signature-opcode-for-post-quantum-bitcoin/).

Native signing, verification, key derivation and recovery timings are recorded
in [report.json](../results/shrincs-demo/report.json). They are single local
measurements, not a statistical benchmark. The signer uses upstream's CPU
implementation and its thread scheduling, with no GPU backend. Its WOTS+C and
PORS+FP components perform their own hash searches. It avoids the QSB
hash-to-classical-signature puzzle, not all forms of grinding.

## State and recovery

The fixture generator initializes one fresh test signer and consumes counters
1 through 17 in order, retaining signatures 1, 2 and 17. These authorize the
same unsigned payment to compare witness sizes without changing transaction
content. Signature counters count signing events, including discarded or
unbroadcast signatures; they are not a count of confirmed transactions.

It then invokes upstream's actual seed-restoration function. The public key is
unchanged and the returned compact state is invalid. An attempted compact
signature throws; the stateless signer successfully creates the recovery
signature. This demonstrates the backup behavior under the same P2MR output.

All seeds and keys are public fixture material. The generator uses the upstream
KAT initialization convention to model a fresh signer from a known seed. It is
not a wallet API. The separate [persistent signer](shrincs-state.md) now records
counters before signing and tests concurrency, process interruption, retry
idempotence, exhaustion, and seed-only restoration. It does not detect rollback
of a copied complete state directory or establish production wallet readiness.

## Binding and witness rules in this experiment

The signed message is:

```text
TaggedHash("btc-pq/SHRINCS-B32/v1",
           BIP341 SIGHASH_DEFAULT with BIP342 script-path extension)
```

The [BIP341 message](https://github.com/bitcoin/bips/blob/09e21036a4001fe6c9ba65c1d3a39b737768132f/bip-0341.mediawiki)
commits to transaction version, locktime, input outpoints, spent values and
scripts, input sequences, outputs, input index and annex. The script extension
adds the leaf hash and code-separator context. Python's pinned Core test helper
and the native Core interpreter agree on the digest, including annexes and
multiple inputs. Tests do not infer binding merely from the wrapper rejecting
a mismatched parent transaction.

The local `0xcf` opcode consumes a 32-byte public key and a minimally encoded
chunk count, reassembles 1–8 signature chunks, and returns the upstream verdict.
All nonfinal chunks must contain exactly 520 bytes; the final chunk must contain
1–520 bytes. The script and control block follow the chunks and count in the
transaction witness. This preserves the existing 520-byte stack-element limit
without requiring CAT. The opcode value is **our local allocation**, not an
assigned `OP_CHECKSHRINCS` BIP opcode.

The valid signature lengths are 324 through 3,668 bytes in 16-byte steps for
compact mode, or exactly 3,680 bytes for recovery. Extra bytes, truncation and
other lengths are rejected before entering upstream verification. Tests cover
malformed counts, nonminimal numbers, oversized elements and noncanonical
chunk splits.

The P2MR tree uses the previous demo's depth-one construction with a failing
`OP_RETURN` sibling. The native build reuses that patch but the SHRINCS spending
script uses neither CAT nor TemplateHash. Signature cost accounting follows the [local bounded-work rule](shrincs-work.md);
the wrapper is not a consensus-complete deployment of any BIP.
It validates Script against synthetic linked parent transactions, not an actual
UTXO set, chain, mempool or block. Stock-Core acceptance of the witness-v2
control means unknown-version rules are not enforcing the new authorization.

## Verification evidence

- [37 transaction cases](../results/shrincs-demo/report.json) and their
  [fresh replay](../results/shrincs-demo/replay.json): original spends pass;
  changed recipient, amount, version, locktime, sequence, input outpoint,
  funding value/outpoint, signature, annex and Merkle proof fail for both the
  first compact and recovery modes. No key path exists.
- [15 upstream-generated vectors](../results/shrincs-demo/upstream-kat.rsp)
  and [replay results](../results/shrincs-demo/upstream-kat-report.json): the
  first complete message group from the unmodified upstream generator, covering
  recovery and 14 compact positions, including final states 210 and 211.
  Each public key re-derives correctly, every signature verifies, and each
  changed-message control fails.
- The upstream generator lacks a B32 display-label branch and prints `L` in
  those records. Their actual compile configuration is **B32**, recorded in the
  build and vector manifests. The original record bytes are retained.
- The [complete 375-vector pass-generator output](../results/shrincs-demo/upstream-kat-full.rsp)
  covers 25 message lengths and all 15 selected signing modes/positions per
  message. The unmodified generator exited successfully after all 375 records.
  [Native replay](../results/shrincs-demo/upstream-kat-full-report.json) re-derives
  the public keys and checks every signature and changed-message control.
- [Four-implementation differential replay](../results/shrincs-demo/upstream-kat-full-differential.json)
  checks the same 375 signatures in upstream C++, the separate pinned C port,
  a local Python verifier, and bounded native C++. All accept the originals and reject
  1,875 selected message, signature-root, key-root, truncation, and append
  controls. This provides implementation diversity, not an independent
  cryptographic security audit.
- Regenerate the sample with `python -m btc_pq.shrincs_kat --generate`, or the
  complete pass-generator output with `python -m btc_pq.shrincs_kat --full --generate`.
  The latter takes several minutes. This is the complete pass-vector generator,
  not a claim to have executed every test or parameter set in the upstream repository.

The full vectors exercise a PORS proof detail absent from the first sample:
the pinned implementation stops when its frontier has one node at index zero,
sometimes at height 16 rather than 17. The Python verifier now matches that
behavior and has a full-vector regression test. The verifiers also all accept
changes to the serialized randomness of an internal XMSS WOTS component, which
does not use that field when verifying an already-digested message. Therefore
arbitrary byte changes are not universally invalid signatures; the mutation
reports identify precisely which fields they tested.

The Python verifier counts SHA256 calls and compression blocks, recorded in
the differential report. These are execution measurements for those vectors,
also cross-checked against the bounded native verifier. Its [cost model](shrincs-work.md)
now caps PORS index sampling and charges a derived upper bound before running
the opcode. Deployment would still need review of these local rule choices.

Build inputs, binary files, fixtures, the vector sample and harness sources
have recorded SHA256 hashes. Signing uses parallel grinding, so fresh runs may
select different valid counters; replay checks the exact saved bytes.

The experiment establishes a compact, transaction-bound PQ spending path under
the modeled rules. Production work still includes a consensus specification
and review of the cost model, independent cryptographic validation, and wallet/device
integration. The separate [exact SHRINCS proof program](shrincs-proof.md) now
proves this verifier, with a completed compact-signature receipt and recursive
STARK compression. The [native witness experiment](receipt-transaction.md)
enforces its transaction claims; larger batches and network-node integration
remain open.
