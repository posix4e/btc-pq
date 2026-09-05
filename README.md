# btc-pq

A reproduction and measurement harness for **QSB** (Quantum-Safe Bitcoin), the
hash-to-signature transaction scheme by Avihu Levy / StarkWare that landed the
first quantum-safe Bitcoin transaction on mainnet in August 2026.

Everything here is evidence-first: it verifies the published on-chain
transaction against unchanged Bitcoin Core, funds the exact locking script on an
isolated regtest node, and measures the puzzle. **Regtest only, valueless coins,
public data, no keys that hold funds.**

For the proof-based alternative, see the [ZK feasibility check](docs/zk-feasibility.md):
pinned verifier source dependencies, the distinction between checked hints and
QSB's search, and a replay of the legacy OP_CAT constraint.

For an executable alternative without QSB's rare-hash search, see the
[covenant/P2MR demo and SHRINCS/CISA comparison](docs/covenant-demo.md).
`btc-pq covenant-demo --build` runs 27 cases with a separate proposal Script
verifier; `btc-pq covenant-demo --replay` checks the saved fixtures again.
This models proposed consensus changes, not Bitcoin mainnet support.

The follow-up [P2MR + native SHRINCS experiment](docs/shrincs-demo.md) uses the
pinned upstream implementation for compact and seed-recovery signatures, with
full transaction binding. Run `btc-pq shrincs-demo --build` and
`btc-pq shrincs-demo --replay`; the first compact spend is 495 bytes.

The [aggregation experiments](docs/aggregation-demo.md) execute both Schnorr
CISA modes and generate real hash-based proofs of XMSS payment signatures.
They measure the cost of aggregation and check that changing the payment
invalidates its authorization. The [persistent signer](docs/shrincs-state.md)
also exercises concurrent signing, process crashes, and seed restoration.
Results and remaining work are tracked in [issue #3](https://github.com/posix4e/btc-pq/issues/3).

## The finding

The confirmed mainnet spend
`305a24ffea912b9cf428f29ebf952321c96dab5bab284fc0d0801562f5abab07`
(block 964,199) runs its hash-to-DER puzzle with **`OP_SHA256` (`0xa8`) at all
three sites** — the pinning check and both digest rounds — while the QSB paper
and README adopt `OP_RIPEMD160` "throughout." A 32-byte SHA-256 output is valid
DER with probability 2<sup>-45.43</sup>; a 20-byte RIPEMD-160 output,
2<sup>-46.43</sup>. So the deployed transaction ran a puzzle at about **half**
the advertised ~2<sup>46</sup> off-chain work.

This is not a vulnerability. The transaction is valid and Bitcoin Core accepts
it; SHA-256 is a variant the paper itself describes. It is a precise gap between
the documented design and the deployed bytes. Full write-up:
<https://apnewman.com/p/the-ripemd-160-that-wasnt/>.

## What it does, in phases

| Phase | Subcommand(s) | What it establishes |
| --- | --- | --- |
| 1 | `baseline`, `run`, `replay`, `measure` | Native Core verification of the pinned mainnet spend; a 62-case regtest matrix with fresh-node replay; CPU hash-rate measurements. |
| 2 | `phase2`, `phase2-toy` | A reduced signature-size **surrogate** lifecycle on stock regtest, and a separate **modified-consensus toy** (clearly labeled `consensus_modified: true`). Neither is the exact QSB predicate. |
| 3 | `phase3` | The **exact** published construction: re-executes the full spend, funds the real 9,923-byte script on regtest, and runs a bounded CPU search for the SHA-256 hash-to-DER puzzle. |
| 4 | `phase4 prepare/search/assemble/replay` | Fresh HORS commitments in the deployed construction, durable funding fixtures, resumable pinning and both digest searches, and proof-checked assembly. A fresh full-predicate spend has not yet been found. |

Machine-readable results land in `results/`; `REPORT.md` narrates them with every
number cited to its JSON artifact.

## Requirements

- **Python ≥ 3.11** — the package has zero third-party dependencies (standard
  library only).
- **Bitcoin Core 31.1** (`bitcoind` / `bitcoin-cli` on `PATH`) for every regtest
  subcommand. The harness spins up its own isolated, network-disabled regtest
  node in a temp datadir.
- **A native consensus verifier** built from a Bitcoin Core 31.1 source tree.
  `baseline` and `phase3` decide Script validity with Core's own consensus code,
  never with the Python transaction codec.

## Setup

```sh
python -m venv .venv && . .venv/bin/activate
pip install -e .              # installs the `btc-pq` console script (no deps)

# Verify the pinned QSB reference files — pure Python, no build needed:
btc-pq check-vendor
```

Building the native verifier (needed for `baseline` and `phase3`) requires a
Bitcoin Core 31.1 checkout and a C++20 toolchain, CMake, and Ninja:

```sh
git clone --branch v31.1 --depth 1 https://github.com/bitcoin/bitcoin .cache/bitcoin
cmake -S native -B .cache/native-build -G Ninja \
      -DCORE_SOURCE="$PWD/.cache/bitcoin" -DCMAKE_BUILD_TYPE=Release
cmake --build .cache/native-build --target btc-pq-verify btc-pq-phase3-search
```

`.cache/` and `.venv/` are gitignored; the Core checkout and build tree stay
out of the repository.

## Reproduce the finding

```sh
btc-pq baseline    # verify the confirmed mainnet spend under Core 31.1
btc-pq phase3      # fund the exact script on isolated regtest; bounded puzzle search
btc-pq phase3 --replay   # replay the saved chain in a fresh node
python -m unittest discover -s tests
```

`phase3` writes `results/phase3/results.json` with the disassembled puzzle
opcode, the DER probabilities recomputed from first principles, the re-executed
spend (four `CHECKSIGVERIFY`, two 10-of-10 `CHECKMULTISIG`, fifteen HORS checks),
the measured search rate, and the implied cost. On a single CPU core the bounded
search finds no hit — expected for a 2<sup>45</sup>-scale puzzle.

## Generate and search a fresh instance

Phase 4 keeps the deployed SHA-256 puzzle, both 150-entry tables, and the 8+1 / 7+2
selection counts. It generates all 300 HORS preimages and replaces their
commitments while preserving the 9,923-byte script and 201 counted opcodes.
The public fixed signatures and dummy tables stay the same. Work is tracked in
[issue #1](https://github.com/posix4e/btc-pq/issues/1).

```sh
# Use an empty directory. A random seed is saved for reproducibility;
# --seed accepts an explicit 32-byte hexadecimal seed for regtest fixtures.
btc-pq phase4 prepare --outdir results/phase4-new

# Repeat this command to resume the same search.
btc-pq phase4 search --outdir results/phase4-new --max-candidates 100000 --max-seconds 10

# Funding can be replayed after the original process and node have exited.
btc-pq phase4 replay --outdir results/phase4-new
```

Preparation saves `instance.json`, the funded script, linked parent transactions,
102 setup blocks, and an unsigned spend template. Both inputs spend outputs of
the saved funding transaction; the fee input uses `OP_TRUE`, so resuming or
assembling does not require the temporary wallet. A manifest binds these files
to the workspace identity.

The pinning counter maps to **62 bits across both input sequences**. Both
relative-locktime disable bits remain set and absolute locktime stays zero.
Digest search uses lexicographically ranked, distinct nine-element subsets.
`--backend python` selects the reference implementation; the default native
backend uses libsecp256k1 for recovery. Digest sighashes are currently generated
in Python and screened in native batches. GPU integration is a later milestone.

Each search prints its checkpoint path and, on success, an immutable hit JSON
path. Once a pinning hit exists, use that printed path for `--pin`:

```sh
btc-pq phase4 search --outdir results/phase4-new --stage round1 --pin /path/to/pinning-hit.json
btc-pq phase4 search --outdir results/phase4-new --stage round2 --pin /path/to/pinning-hit.json

# Run only after all three searches have produced validated hits.
btc-pq phase4 assemble --outdir results/phase4-new \
  --pin /path/to/pinning-hit.json \
  --round1 /path/to/round1-hit.json --round2 /path/to/round2-hit.json
btc-pq phase4 replay --outdir results/phase4-new
```

Assembly recomputes every proof, checks the HORS preimages and witness layout,
verifies with unchanged Core, and mines the spend on the restored regtest chain.
Published-fixture tests reproduce the original transaction byte for byte and
pass native Core verification. This establishes assembly support; the saved
fresh-instance run is still a bounded search with no hit.

To partition a stage, choose `--workers N --worker-id I` on its first invocation
and keep the same `N` on subsequent runs. Each worker receives a disjoint
contiguous range and its own locked checkpoint. One worker count is fixed per
stage and pinning proof. Checkpoints are written atomically after each batch;
an interrupted uncommitted batch may be repeated, while saved progress resumes
at the recorded next counter. Search budgets apply to each invocation and
exclude native build/startup checks; a final in-flight batch can exceed the
wall deadline slightly.

If every worker exhausts either digest round without a hit, run pinning again
with `--next-hit` using the worker that found the selected pinning hit. Restart
both digest stages with the new immutable pinning-hit path. Their checkpoints
are kept separate for each proof. Retain the whole workspace to resume it.

## Layout

```
btc_pq/        Python package (transaction codec, sighash, Core wrapper, phase drivers)
native/        C++ consensus verifier and search loops (link unchanged Core / libsecp256k1)
fixtures/      Pinned mainnet transaction, funding parent, inclusion proof
results/       Machine-readable artifacts and saved tx/block hex fixtures
tests/         Unit tests (unittest)
vendor/qsb/    Pinned QSB sources, commit 2c917205 (see vendor/qsb/LICENSE)
REPORT.md      Narrative findings, every figure cited to its artifact
```

## Provenance and license

QSB sources under `vendor/qsb/` are pinned at commit
`2c9172051d5c150ef0a994ca6b988a08a3ef9e85` of
<https://github.com/avihu28/Quantum-Safe-Bitcoin-Transactions> and carry their
own license (`vendor/qsb/LICENSE`). `check-vendor` verifies their SHA-256 hashes
against `vendor/qsb/manifest.json`.

All HORS preimages and nonce material in this repository are public,
deterministically derived test data for regtest experiments. None of it
protects value.
