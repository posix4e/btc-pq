# Proving exact SHRINCS-B32 verification

This experiment ports the bounded SHA256 SHRINCS-B32 verifier into a RISC Zero
guest. It consumes the same public keys, transaction digests, and signature
bytes as the native opcode demo. It does not replace SHRINCS with leanVM's
BLAKE2s XMSS scheme.

The public statement is a SHA256 commitment to a domain tag, a little-endian
32-bit input count, and an ordered list of 32-byte public keys and 32-byte
transaction digests. The guest verifies every signature before committing this
statement. The host recomputes the transaction digests using the existing
SHRINCS domain and BIP341/BIP342 rules, checks each parent and committed script,
verifies the receipt against the compiled program's image ID, and compares the
journal with its own expected statement.

This harness stores the receipt separately from the transaction. The companion
[native transaction proof demo](receipt-transaction.md) places it in a witness
and enforces the same claims using Core's Script and transaction code. Bitcoin
network-node integration remains separate work.

## Implementation and validation

The common Rust verifier uses ordinary SHA256 on the host and the zkVM's SHA256
accelerator inside the guest. It preserves the native verifier's 64-block PORS
sampling cap and compression-work bounds. Its logical compression counter
matches the native model; actual guest cycles also include address construction,
serialization, memory access, and recomputation of the shared SHA256 prefix.

The [native Rust differential report](../results/shrincs-proof/rust-differential.json)
covers all 375 upstream pass vectors and 1,875 selected negative controls.
Every valid signature's hash counts match the existing Python and bounded C++
reports. A separate maximal-work invalid compact signature consumes exactly
4,941 modeled compression blocks and is rejected.

Native differential replay is not a proof-system execution or an independent
cryptographic review. The harness writes `execution.json`, `proofs.json`, and
`replay.json` only when those corresponding runs finish successfully. The
execution command does not produce a proof. Proof and replay reports include
the program image ID, ordered claim digest, receipt size, timing, and source
hashes.

The saved [zkVM execution run](../results/shrincs-proof/execution.json) accepts
the three payment fixtures and rejects their changed-signature controls:

| Authorization | Signature bytes | Guest user cycles | Segments |
| --- | ---: | ---: | ---: |
| One compact `q=1` signature | 324 | 4,010,781 | 5 |
| One recovery signature | 3,680 | 16,808,867 | 18 |
| Two compact `q=1` signatures | 648 | 8,012,663 | 9 |

These cycle counts describe the verifier port, not an optimized SHA256 circuit.
The compiler wrapper removes checkout and Cargo-cache paths from the guest;
changing that wrapper invalidates the guest compilation cache. The saved
program identity is recorded in the execution report.
The [compiled program](../results/shrincs-proof/program.bin) and its
[image/build manifest](../results/shrincs-proof/program.json) are saved as well.

The host permits only composite or succinct STARK receipts and compiles with
`disable-dev-mode`. It rejects mock and Groth16 receipts. Its batch limit is
512 authorizations. These choices avoid silently measuring a mock proof or a
pairing-based compression wrapper; they do not establish a reviewed level of
post-quantum soundness for this application.

## Completed receipts and compression

The first [compact-signature proof](../results/shrincs-proof/compact-q1-valid.proof.json)
is a real composite STARK receipt of **1,381,282 bytes**. Generation took
492,456 ms (8.2 minutes); verification took 67 ms. Its 12 checks cover the valid
payment, changed transaction fields, funding, annex, key, and malformed proof
lengths. The recovery and two-input receipts are still being generated.

Recursive STARK compression reduces that receipt to **223,290 bytes**, without
changing the guest image or authorization claims. Compression took 212,456 ms
(3.5 minutes), with a 20 ms verification measurement. The
[compression report](../results/shrincs-proof-compressed/compact-q1-valid.compression.json)
records both receipt hashes and replays both against the original guest verifier.
These are single local timings under other system load, not controlled benchmarks.

The compressed proof remains much larger than a 324-byte direct signature.
Batch crossover must be measured using larger proofs; extrapolating this one
receipt does not establish an aggregation benefit.

```sh
# Build the receipt utility and native transaction checker.
python -m btc_pq.receipt_demo --build
# Compress an existing receipt into a new directory, or replay the saved result.
python -m btc_pq.receipt_compress --outdir results/new-compression
python -m btc_pq.receipt_compress --replay
```

## Reproduction on Apple Silicon

The SDK and `r0vm` release are pinned to **3.0.6**. The upstream source tag is
[`1cc70cf05033a79ebc90f07c679cb4bd1cd301b9`](https://github.com/risc0/risc0/tree/1cc70cf05033a79ebc90f07c679cb4bd1cd301b9).
Both host and guest Cargo lockfiles are committed. The guest toolchain is
RISC Zero Rust **1.88.0**. Its lockfile retains compatible versions of
`enum-ordinalize`, `enum-ordinalize-derive`, and `ruint`; an unconstrained update
currently selects releases requiring newer compilers.

The official Apple Silicon SDK archive is
[`cargo-risczero-aarch64-apple-darwin.tgz`](https://github.com/risc0/risc0/releases/download/v3.0.6/cargo-risczero-aarch64-apple-darwin.tgz),
SHA256 `efd2f26434ec60ca6c1b6a1398c00dfea7fb5e0cbac09aa99a504b6bd592f38b`.
Extract `r0vm` to `.cache/risc0-tools/r0vm`.

Install the guest compiler with the official `rzup` tool, using a project-local
installation directory:

```sh
RISC0_HOME="$PWD/.cache/risc0-home" rzup install rust 1.88.0
```

The corresponding official Rust archive's SHA256 is
`f3d6a3dbe09536f7166cff53fd5ded632a0b5409b7cfaa5202423f6c3323c04c`.
See the [upstream installation instructions](https://dev.risczero.com/api/zkvm/install).

```sh
# Build and execute the three saved payment fixtures, without producing proofs.
python -m btc_pq.shrincs_proof --build

# Recheck all upstream signatures with the native Rust verifier.
python -m btc_pq.shrincs_proof --reference

# Generate real receipts and check payment/proof mutations.
python -m btc_pq.shrincs_proof --prove
python -m btc_pq.shrincs_proof --replay

# Optional in-process prover build.
python -m btc_pq.shrincs_proof --build --local --prove
```

The default uses the pinned local `r0vm` process. `--local` selects the in-process
prover instead. In this SDK release, the RISC-V segment prover uses CPU or CUDA;
its [Metal branch is commented out](https://github.com/risc0/risc0/blob/1cc70cf05033a79ebc90f07c679cb4bd1cd301b9/risc0/circuit/rv32im/src/prove/mod.rs).
These Mac runs therefore do not demonstrate GPU acceleration of segment proving.
The harness does not submit jobs to a remote proving service. Proving latency and proof size must be measured: neither a zkVM nor
GPU acceleration implies that aggregation is smaller than direct SHRINCS
authorization at a particular batch size.
