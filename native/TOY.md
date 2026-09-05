# Toy hash-to-signature experiment — modified consensus, regtest only

This experiment uses a separate patched Bitcoin Core 31.1 daemon and verifier.
It is **not** QSB's RIPEMD160-to-DER construction. Stock Core rejects the
experimental spends. Every result sets `consensus_modified: true` and
`qsb_exact_reproduction: false`; all HORS material is public test data.

## Exact predicate

In legacy BASE scripts, with the experimental verification flag enabled,
opcode byte `7e` consumes `<compressed public key Q> <work bits b>`. This is a
new experimental operation, **not an implementation of OP_CAT**. Stock Core
treats the byte as a disabled opcode.

1. Require a 33-byte key starting with `02` or `03`, and a minimally encoded
   integer `1 <= b <= 24`.
2. Compute `h = SHA256(ASCII("BTC-PQ-TOY-H2S-v1") || uint8(b) || Q)`.
   Domain strings contain no trailing NUL byte.
3. Fail Script unless the first `b` most significant bits of `h` are zero.
4. Compute `s = 1 + BE(SHA256(ASCII("BTC-PQ-TOY-S-v1") || h)[0:16])`.
5. Push the strict DER encoding of `(r=2, s)` followed by sighash byte `01`.

The `b` literal is in the funded locking script. The resulting signature is
consumed by ordinary `OP_CHECKSIGVERIFY`; DER parsing and ECDSA validation are
unchanged. The signature has a recoverable curve point at `r=2`, and `s` is
always nonzero and less than the curve order. Invalid curve points supplied as
`Q` cannot satisfy the separate fixed-signature verification.

The compiler retains fixed `SIGHASH_ALL` pinning, HORS preimage/index checks,
strictly increasing indices, and subset-dependent legacy FindAndDelete in
CHECKMULTISIG. It uses one digest round and no bonus selections. These
reductions are recorded for every instance. Legacy size, opcode, stack, and
element limits remain in force.

`toy-core.patch` enables the experimental flag only for regtest block
validation and makes the daemon refuse non-regtest startup. The separate
native verifier enables the same flag. `toy_predicate.h` is shared by the
patched interpreter and native searcher; `btc_pq/toy.py` contains an independent
Python definition for comparison.

## Reproduction

Use the project's existing Python environment and pinned Core source checkout
at `.cache/bitcoin`. The builder requires CMake, Ninja, a C++20 compiler, Boost,
libevent, and pkg-config. On this host the missing `pkgconf` dependency was
installed with Homebrew; CMake and Ninja come from `.venv/bin`.

```sh
.venv/bin/python -m btc_pq.cli phase2-toy --build --outdir results/phase2-toy-rerun
.venv/bin/python -m btc_pq.cli phase2-toy --replay --outdir results/phase2-toy-rerun
.venv/bin/python -m unittest discover -s tests -v
```

Choose a fresh output directory. `--build` archives Core commit
`9be056a8a72b624dae9623b2f7bded92c2a21c91` into `.cache/toy-bitcoin`, applies the
recorded patch, and builds under `.cache/toy-build`. It does not patch the stock
source checkout or replace the installed daemon/native verifier. The build
manifest records source inputs, binary hashes, and build time. The default
stock rejection-control daemon is `bitcoind`, overridable with `--bitcoind`.

Default authorized-spend levels are `8,12,16,20`; the compiler selects smaller
tables at the easier levels. Default frozen-disclosure levels are `4,6`, with
three modified transactions per level. A quick run is:

```sh
.venv/bin/python -m btc_pq.cli phase2-toy --levels 4 --reuse-bits 4 --reuse-trials 1 --outdir results/toy-quick
```

Search budgets apply per native search. Budget exhaustion saves an incomplete
artifact and exits unsuccessfully. A new funding transaction changes the
search counts; saved transactions and blocks reproduce the recorded outcomes.

## What is measured

The native worker computes fixed-signature key recovery using the public
identity `Q = ((1-z)/r)G`, with `r = x(G)`, and libsecp256k1 scalar operations
and generator multiplication. It hashes the serialized key on **every**
candidate. Fifty-four vectors, including scalar boundary cases, are checked
against native general ECDSA recovery and the independent Python recovery.
Each search hit's sighash, public key, and toy signature are checked in Python
before assembly. The preliminary synthetic benchmark is labeled separately
from transaction search rates.

Native search `measurement.wall_seconds` measures the search loop, excluding
process startup and Python hit validation. `subprocess_wall_seconds` additionally
includes native process startup/setup. Funding, assembly, native verification,
block submission, and replay have separate wall timers. Frozen searches also
separate all pinning candidates from fixed-subset checks performed only after
pinning passes; their phase timers partition the native search-loop time.

Authorized modified spends can select and reveal a new HORS subset.
Frozen-disclosure searches keep the original subset fixed and assemble with a
restricted mapping containing only its disclosed preimages. The actual
serialized preimage/index pushes are compared byte for byte against the
original witness and saved as `authorization_hex`. The full public table is
not used as a source of additional authorization for these attempts.

The stock node funds the outputs, and its 102-block setup chain is imported
into the experimental node. Accepted experimental blocks are saved and
invalidated between cases. A fresh replay submits those same blocks to both
nodes: the experimental node must accept them and stock Core must reject them.
The remaining controls are rechecked by the experimental node and both native
verifiers. All nodes use temporary directories and disabled networking.

These are observations of a specified search strategy at toy difficulty.
They establish no unavoidable-work lower bound, quantum-security claim, or
exact QSB reproduction. Keeping disclosed authorization fixed makes the reuse
experiment distinct from signing another transaction with new preimages.
