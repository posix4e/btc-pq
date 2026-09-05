# Proof-based replacement for QSB: feasibility check

Checked 2026-09-05. Target: authorize an arbitrary payment on unchanged Bitcoin,
using post-quantum authentication, without QSB's hash-to-signature search.

**Result:** the inspected implementations do not provide a direct replacement.
They show useful proof-verification techniques, including checked hints, but
either require additional script semantics or use an optimistic dispute
protocol. This is a finding about these implementations, not an impossibility
claim about every proof system or Bitcoin encoding.

This pass inspected pinned source files and replayed one existing native Core
fixture. It did not build or execute the external proof systems, generate a ZK
proof, or benchmark a replacement signer. Source revisions and file hashes are
recorded in [sources.json](../results/zk-feasibility/sources.json).

A [follow-up experiment](aggregation-demo.md) now generates and verifies real
leanVM proofs of XMSS payment signatures. It models a new transaction-level
verification rule; it does not supply a replacement on unchanged Bitcoin.

## Why hints do not solve QSB's search

A verifier hint is an intermediate result supplied by the prover and checked by
the verifier. For example, checking that a proposed modular inverse satisfies
`a * inverse = 1 mod p` can be cheaper than computing the inverse inside Script.
This helps when the prover already has a way to compute the value.

QSB instead needs a witness that is hard to find: a transaction-dependent public
key whose hash has a usable signature encoding. Once a candidate has been found,
the existing script already checks it cheaply. A proof that such a candidate
works does not supply a faster way to find it. An almost-valid hash provides no
known useful direction for choosing the next candidate under the usual
random-looking-hash model. Caching and algebraic optimization can still reduce
the cost of each trial.

The alternative worth investigating changes the statement being proved:
authenticate a payment with a known signing key, instead of prove that a rare
QSB candidate was found. Zero knowledge is optional for that performance goal;
the essential requirement is a sound authorization proof the chain can verify.

## Required interface

A candidate must connect three checks:

1. The verification key belongs to the key commitment fixed by the coin's
   spending condition.
2. A hash-based signature verifies against that key and a payment digest.
3. That digest commits to the actual spending transaction under an explicitly
   specified coverage rule, including the intended inputs and outputs.

The proof can establish the first two checks. The third still needs a connection
to Bitcoin's live transaction context. Giving a proof verifier a caller-supplied
transaction hash does not establish that connection. Even a circuit that hashes
supplied transaction bytes needs a way to check that those bytes describe the
transaction being validated. Likewise, proving knowledge of a secret while
leaving the payment unconstrained is insufficient.

This distinction already appears in our [transaction-binding experiments](../REPORT.md):
local secret checks can pass while authorization remains reusable for a changed
payment. Those experiments did not test a ZK system.

## Implementations inspected

| Candidate | Source evidence | Consequence for this target |
| --- | --- | --- |
| Bitcoin Wildlife Sanctuary Circle-STARK | Merkle-path verification and transcript updates explicitly concatenate stack values with `OP_CAT`. The code also consumes prover-supplied hints. | These routines depend on CAT semantics that unchanged Bitcoin does not provide. This is a concrete dependency, not a measured lower bound for all STARK verifiers. |
| BitVM Groth16 verifier | The verifier constructs checked arithmetic hints; the repository describes optimistic execution and chunking. Its README reports an approximately 1 GB verifier script. | The reported full script is not a single-spend verifier. The dispute protocol is a different application architecture. The size is an upstream claim, not a build measurement from this pass. |
| Liquid Simplicity / SHRINCS | Confirmed Liquid mainnet transactions demonstrate hash-based verification in a different execution environment. | Useful reference code and examples, but they do not add Simplicity execution to Bitcoin mainnet. They also do not establish that a ZK wrapper would improve on direct signature verification. |

Pinned Circle-STARK code:
[Merkle path](https://github.com/Bitcoin-Wildlife-Sanctuary/bitcoin-circle-stark/blob/9540164f243b23e4ca995c153f70ec64744df28a/src/merkle_tree/bitcoin_script.rs#L84),
[transcript](https://github.com/Bitcoin-Wildlife-Sanctuary/bitcoin-circle-stark/blob/9540164f243b23e4ca995c153f70ec64744df28a/src/channel/bitcoin_script.rs#L18).

Pinned BitVM code:
[hinted verifier](https://github.com/BitVM/BitVM/blob/7d1ca3660cac08aab62e76f3aa4daec0d7403ecc/bitvm/src/groth16/verifier.rs#L25),
[implementation overview](https://github.com/BitVM/BitVM/blob/7d1ca3660cac08aab62e76f3aa4daec0d7403ecc/README.md#L43).
BN254/Groth16 also does not supply the post-quantum soundness needed here; a
post-quantum hash signature inside a proof does not upgrade the proof system's
own assumptions.

Liquid reference:
[Blockstream's mainnet demonstration](https://blog.blockstream.com/blockstream-research-demonstrates-quantum-resistant-transaction-signing-on-liquid-using-simplicity-smart-contracts/).
The mainnet confirmation checks from the preceding investigation should not be
confused with a local replay or audit of those contracts.

## Bitcoin execution constraints

For a construction retaining QSB's legacy machinery, the relevant limits include
10,000 script bytes and 201 counted operations. The reproduced QSB script already
uses 9,923 bytes and all 201 counted operations. A new verifier must replace
existing work, not merely be appended.

Those legacy limits must not be applied indiscriminately to Tapscript.
[BIP 342](https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki)
removes the legacy script-size and opcode-count limits for Tapscript, while
other resource limits still apply. However, unchanged Tapscript treats byte
`0x7e` as `OP_SUCCESS126`, not concatenation. Acceptance through that upgrade
hook would not verify a proof.
[BIP 347](https://github.com/bitcoin/bips/blob/master/bip-0347.mediawiki)
proposes the required CAT semantics. Its document status being complete does
not mean that those semantics are activated on Bitcoin mainnet. Its change is
for Tapscript; it does not enable CAT in QSB's legacy script.

A complete post-quantum output design also has to address Taproot's alternative
key-spending path. Selecting a hash-based proof does not remove that path.

## Local check performed

Replayed `results/regtest/limits--op_cat_reconstruction.hex` with its linked
`funding.hex` parent through the existing unmodified Core 31.1 Script wrapper.
It returned invalid with a disabled-opcode error, as expected.

The [check record](../results/zk-feasibility/legacy-cat-check.json) contains file
and executable hashes plus the native result. This verifies the legacy CAT
constraint only. It is not a STARK-verification test, a Tapscript test, or a new
block-validation run.

## Decision and next experiment

Do not start a full ZK-to-QSB integration based on these implementations alone.
The useful next artifact would be a concrete verifier-and-binding design with
its actual opcode dependencies and resource estimate. Prover speed measurements
become relevant after that design has a credible execution path.

If unchanged Bitcoin remains the target, a new candidate must first demonstrate
its essential composition operation and transaction binding under those rules.
Test a valid payment and then reuse its proof after changing the recipient,
amount, input outpoint, or authorized key; each unauthorized change must fail.
This is an acceptance plan, not a claim that the candidate currently exists.

If experimental consensus changes are acceptable, a CAT-enabled environment
with an explicit transaction-hash primitive provides a concrete place to test
the proof architecture. Compare it against direct hash-signature verification
under the same rules; a ZK wrapper is useful only if its total cost or other
properties justify it. Such an experiment would establish nothing about
unchanged Bitcoin mainnet compatibility by itself.
