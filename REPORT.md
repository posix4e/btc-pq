# BTC-PQ measurement and reproduction findings

The saved artifacts reproduce the pinned public QSB spend and demonstrate authorization-binding failures and compiler limits in the regtest candidates. They do not demonstrate a secure replacement candidate or a complete polyglot transaction: `secure_candidate_demonstrated` and `full_polyglot_transaction_demonstrated` are both false. This writeup uses the existing results; the experimental transactions use isolated regtest coins, and the mainnet work verifies public transaction data. [Regtest results](results/regtest/results.json), [measurements](results/measurements.json).

The mainnet artifact is spend `305a24ffea912b9cf428f29ebf952321c96dab5bab284fc0d0801562f5abab07`. The recorded reference check covers 9 files at QSB commit `2c9172051d5c150ef0a994ca6b988a08a3ef9e85`. Both inputs passed Bitcoin Core 31.1 native Script verification against their linked previous outputs. The verified fee is 5,179 sats. [baseline.json: pinned_reference, mainnet_tx, core_verification](results/baseline.json).

The following dimensions are recorded in [baseline.json: mainnet_tx, funding_outputs](results/baseline.json).

| Artifact component | Recorded dimension |
| --- | ---: |
| Spend serialized size | 1,403 bytes |
| Spend stripped size | 1,293 bytes |
| Spend weight | 5,282 weight units |
| Spend virtual size | 1,321 vbytes |
| QSB input scriptSig | 1,168 bytes |
| QSB funding output script | 9,923 bytes |
| QSB funding script static non-push opcodes | 181 |
| QSB funding script CHECKSIG / CHECKSIGVERIFY operations | 4 |
| QSB funding script CHECKMULTISIG / CHECKMULTISIGVERIFY operations | 2 |

Merkle inclusion and header proof of work were checked locally for the recorded block height 964,199. The explorer supplies the chain anchoring; `local_mainnet_block_replay` is false. Thus the artifact establishes linked-prevout Script validity and inclusion in the supplied header, without reproducing full mainnet chain validation. Native verification took approximately 21.802 ms, including subprocess startup; this timing measures verification, with no setup search or GPU work. [baseline.json: inclusion_verified, block_height, chain_trust, verification_wall_seconds, measured_work](results/baseline.json).

All 4 recorded baseline mutations were invalid: output redirection, amount decrease, sequence change, and unexpected witness. For the first 3, both inputs failed; for unexpected witness, the first input failed while the QSB input still passed. These are outcomes for the saved mutations, not a general security proof. [baseline.json: attacks](results/baseline.json).

The regtest matrix contains 62 cases: 27 accepted and 35 rejected, with every block result and native verification result matching its expected outcome. These counts are aggregated from `cases`. The artifact records Core version `310100` and no consensus or relay-policy changes. Accepted blocks were saved and invalidated between competing spends. A fresh-node replay reproduced all 62 outcomes after replaying 102 setup blocks. These results concern block acceptance; they do not establish ordinary relay acceptance. [results.json: cases, core_version, block_method, consensus_changes, relay_policy_changes](results/regtest/results.json), [replay.json: setup_blocks_replayed, cases](results/replay.json).

Family counts below are aggregated from [results.json: `cases[].family`, `block_accepted`, `expected_acceptance`, `native.valid`](results/regtest/results.json). The full-size compiler cases retain their separate family names from the artifact.

| Recorded family | Cases | Accepted | Rejected |
| --- | ---: | ---: | ---: |
| `direct` | 17 | 9 | 8 |
| `lamport` | 19 | 9 | 10 |
| `winternitz` | 19 | 9 | 10 |
| `whole_key` | 2 | 0 | 2 |
| `lamport_full` | 1 | 0 | 1 |
| `winternitz_full` | 1 | 0 | 1 |
| `limits` | 3 | 0 | 3 |
| **Total** | **62** | **27** | **35** |

For `direct`, the honest diagnostic passed. Changing the destination script, output amount, or funded input while retaining the old public key failed. Replacing that key with the public key recovered for the changed transaction made each spend pass, with the same empty authorization. This demonstrates that the fixed-signature check alone did not authorize the intended transaction in this construction. “Recovered key” here means a public key compatible with the fixed signature and transaction digest, not recovery of a private key. [results.json: cases with family direct, fixed_signature, fixed_sighash](results/regtest/results.json).

The reduced `lamport` diagnostic uses the last 8 key bits; `winternitz` uses the last 2 base-4 digits with a checksum. Both repeated the same stale-key failures and recovered-key successes while reusing identical authorization bytes. Wrong preimages and message/secret mismatches failed with `OP_EQUALVERIFY` errors. The demonstrated distinction is that these scripts enforce their local hash/selector checks but do not bind the authenticated selectors to the public key consumed by the signature check. The compiler records `message_key_binding: false` for both. These diagnostic failures do not establish a weakness in correctly bound Lamport or Winternitz signatures. [results.json: reduced_instances, compiler_limits, cases with families lamport and winternitz](results/regtest/results.json).

Across `direct`, `lamport`, and `winternitz`, recovery branches 1, 2, and 3 all passed using the existing authorization, as did uncompressed and hybrid public-key encodings. Recovery under substituted sighash values 2, 3, and 129 failed while Script retained its fixed `SIGHASH_ALL` signature. Unexpected witnesses and malformed public-key encodings also failed. The accepted encoding cases establish behavior under the tested legacy consensus checks; relay behavior was not measured. [results.json: corresponding `cases[].name`, `detail`, and `native` fields](results/regtest/results.json).

For `whole_key`, the public key recovered after funding failed the exact-byte commitment check; the originally committed key passed authentication but failed the fixed signature. The accompanying dependency trace made 8 unsigned hypothetical funding revisions and found no matching commitment (`solved: false`). That trace illustrates the funding-transaction/key dependency; it is not a convergence bound or impossibility proof. [results.json: whole_key cases and whole_key_dependency_trace](results/regtest/results.json).

The `limits` family rejected attempted `OP_CAT` reconstruction as a disabled opcode, a 521-byte pushed element with a push-size error, and 1,001 stack elements with a stack-size error. The full Lamport case failed with “Script is too big”; the full Winternitz case failed with “Operation limit exceeded.” These are the recorded rejection reasons, rather than claims that each transaction has only one possible defect. [results.json: `limits`, `lamport_full`, and `winternitz_full` cases, `native.inputs[].error`](results/regtest/results.json).

Compiler feasibility is limited by the harness's legacy Script budgets of 10,000 script bytes and 201 counted non-push opcodes. These thresholds are implemented in [candidates.py: limits()](btc_pq/candidates.py:85); all dimensions and pass/fail flags below come from [results.json: compiler_limits](results/regtest/results.json).

| Compiled instance | Script bytes | Static non-push opcodes | Size budget | Opcode budget |
| --- | ---: | ---: | --- | --- |
| Lamport, full 264 bits | 19,021 | 1,587 | Exceeds | Exceeds |
| Winternitz, full 132 base-4 digits plus checksum | 9,360 | 4,139 | Fits | Exceeds |
| Lamport diagnostic, 8 bits | 589 | 51 | Fits | Fits |
| Winternitz diagnostic, 2 digits plus checksum | 302 | 137 | Fits | Fits |

The full Lamport compiler exceeds both budgets; the full Winternitz compiler fits the byte budget but exceeds the opcode budget. The reduced instances fit both budgets and still lack message/key binding. The static opcode metric is a syntactic count, so the mainnet script's smaller static count should not be interpreted as a measurement of remaining execution budget. These results constrain the compilers tested here and do not establish that every possible encoding is infeasible. [results.json: compiler_limits](results/regtest/results.json), [baseline.json: `funding_outputs[].script`](results/baseline.json), [bitcoin.py: script_metrics()](btc_pq/bitcoin.py:162).

The CPU measurements ran on the recorded macOS 26.6.2 arm64 environment with Python 3.14.7. Each hash used 100,000 iterations per timing sample, 3 timing samples, and 20-byte payloads. Rates below are the stored median rates rounded to whole operations per second. The opcode column reports the artifact's availability flag; these timings measure local Python/hashlib API throughput, not execution inside Bitcoin Script. [measurements.json: environment, measurement_kind, hashes, hash_warning](results/measurements.json).

| Algorithm | Median operations/second | Native Bitcoin Script opcode recorded |
| --- | ---: | --- |
| SHA-256 | 2,884,733 | Yes |
| Double SHA-256 | 1,883,989 | Yes |
| RIPEMD-160 | 1,933,186 | Yes |
| HASH160 | 1,273,809 | Yes |
| BLAKE2s | 4,265,999 | No |
| SHA3-256 | 2,497,139 | No |

The RIPEMD160-to-DER search tested 100,000 deterministic public 20-byte preimages in approximately 0.058271 seconds, or 1,716,128 trials/second. It found 0 syntactic DER hits and no usable hits. The predicate checks the full digest for strict DER form and then ECDSA recoverability; it uses no truncated target. Because no digest passed the DER check, the measured loop did not exercise the recoverability stage on a hit. The preimages are public test data, not signing secrets. [measurements.json: polyglot.trials, wall_seconds, cpu_trials_per_second, input_bytes, syntactic_der_hits, usable_hits, predicate, secrets](results/measurements.json), [measure.py: polyglot()](btc_pq/measure.py:19).

The following setup figures are probability-model outputs and an extrapolation from the measured loop rate, not measurements of a completed setup. All values come from [measurements.json: polyglot](results/measurements.json), rounded where shown.

| Setup-model quantity | Recorded value |
| --- | ---: |
| Expected syntactic hits in the measured trial count | 1.05819 × 10^-9 |
| Syntactic work exponent | 46.425388 bits |
| Paper-rounded setup work for 180 polyglots | 1.26664 × 10^16 hashes |
| Syntax-based expected setup work for 180 polyglots | 1.70101 × 10^16 hashes |
| Optimistic CPU time for that syntax-based work | 314.089 years |

The time extrapolation divides expected syntactic search work by the observed Python CPU trial rate. Recoverability requirements can add work, and the run produced no usable polyglot. The artifact explicitly records `spending_puzzle_eliminated: false` and `full_polyglot_transaction_demonstrated: false`; neither a GPU setup time nor QSB end-to-end performance was measured. [measurements.json: polyglot.extrapolation, polyglot.spending_puzzle_eliminated, polyglot.full_polyglot_transaction_demonstrated, hash_warning](results/measurements.json).

The fallback comparisons are conditional arithmetic models, not compiled or validated polyglot transactions. Every row calculates 201 opcodes. The calculation assumes a saving of 2 opcodes per signed selection and 21 fixed/round-overhead opcodes inferred from the published script. Table bytes exclude all other script elements. The QSB row's zero polyglot-setup hashes means this particular setup component is absent; it is not a claim of zero total QSB setup work. [measurements.json: fallback_models, model_scope](results/measurements.json).

Model dimensions and setup costs below come from [measurements.json: fallback_models](results/measurements.json). Pairs list the respective rounds; hash counts are rounded.

| Model | n per round | Signed / bonus selections by round | Dummy and HORS table bytes | Polyglots to generate | Syntactic setup hashes |
| --- | ---: | --- | ---: | ---: | ---: |
| QSB published dimensions | 150 | (8, 7) / (1, 2) | 9,300 | 0 | 0 |
| Polyglot n=90 | 90 | (10, 10) / (0, 0) | 3,780 | 180 | 1.70101 × 10^16 |
| Polyglot n=110 | 110 | (10, 10) / (0, 0) | 4,620 | 220 | 2.07901 × 10^16 |
| Polyglot n=120 | 120 | (10, 10) / (0, 0) | 5,040 | 240 | 2.26801 × 10^16 |

The corresponding search-space and success figures are also model outputs, rounded from [measurements.json: `fallback_models[].signed_subset_space_bits`, `mean_der_solutions_per_round`, `optimistic_pinned_attempts_independent_poisson`](results/measurements.json).

| Model | Signed subset-space bits | Mean DER solutions per round (same in each round) | Optimistic pinned attempts |
| --- | ---: | ---: | ---: |
| QSB published dimensions | 80.355 | 1.754911 | 1.461867 |
| Polyglot n=90 | 84.759 | 0.121032 | 76.954784 |
| Polyglot n=110 | 90.829 | 0.992213 | 2.525580 |
| Polyglot n=120 | 93.444 | 2.455653 | 1.196532 |

These success estimates assume independent random outputs and one SHA-256/recovered-key candidate per subset, checking DER syntax only. The pinned-attempt estimate uses an independent Poisson approximation for success in both rounds. It omits recoverability, multiple-key grinding, correlated subsets, and mining implementation. Signed subset-space bits are not security bits; the artifacts establish neither the author-reported QSB security estimates nor Binohash collision estimates, and they measure no speedup from these models. [measurements.json: probability_scope, security, fallback_models](results/measurements.json).

## Phase 2 — lifecycle surrogate; exact hash-to-DER reproduction incomplete

The requested reduced-difficulty QSB hash-to-DER lifecycle is **not demonstrated**. The pinned paper describes a fixed DER target with no tuning knob. The new `phase2` CLI keeps that predicate as its default; the completed experiment explicitly selects a **signature-size surrogate**. [Pinned paper](vendor/qsb/paper/QSB.tex:408), [implementation](btc_pq/phase2.py).

The surrogate uses **48 entries, one round, 5 signed selections, no bonus selections, and exactly 69 signature bytes**: 1,712,304 possible subsets and a configured nominal fixed-nonce target of approximately **2^17**. This is a different predicate, not QSB's hash-only puzzle or an adversarial work bound. All HORS material is public. The script measures 1,773 bytes and 141 counted opcodes, including the multisig key-count charge. [Parameters, limitations, and measurements](results/phase2/results.json).

Both the honest transaction and a transaction reducing its output by 1 sat completed funding, separate pinning/subset searches, assembly, native verification, and block acceptance on unchanged isolated Core 31.1:

| Transaction | Search phase | Candidates | Wall seconds | Candidates/second |
| --- | --- | ---: | ---: | ---: |
| Honest | Pinning | 76,559 | 0.126011 | 607,556 |
| Honest | Subset | 23,760 | 0.075553 | 314,479 |
| Modified amount | Pinning | 114,275 | 0.188640 | 605,782 |
| Modified amount | Subset | 12,634 | 0.040462 | 312,245 |

Total run time, including automatic replay, was **3.174 s**. The JSON separately times funding, assembly, native verification, and block acceptance; non-search candidate rates are null. Six controls involving stale proofs/keys, fixed-signature reuse, incorrect HORS authorization, changed subsets, and duplicate indices were rejected. Fresh-node replay reproduced **2 accepted and 6 rejected cases** after 102 setup blocks. Transaction/block hex and public tables accompany the artifact. These observations do not establish that every modification requires fresh work. [Results](results/phase2/results.json), [separate replay](results/phase2/replay.json).

The exact hash-to-DER mode tried **64 pinning candidates in 0.550812 s**, found no hit, and exited on its deliberate candidate cap without assembling a spend. Its artifact is explicitly incomplete. [Bounded exact-mode result](results/phase2-exact-bounded/partial-results.json).

Reproduce using a fresh output directory:

```sh
.venv/bin/python -m btc_pq.cli phase2 --puzzle signature-size-surrogate --outdir results/phase2-rerun
.venv/bin/python -m btc_pq.cli phase2 --replay --outdir results/phase2-rerun
```

For the bounded exact attempt, omit `--puzzle` and use `--max-candidates 64 --max-seconds 10` with a different output directory. Fresh funding changes search counts; saved fixtures replay the recorded outcomes. Five focused unit tests, the pinned vendor check, and phase-1 baseline verification passed. Both `qsb_hash_to_der_end_to_end_demonstrated` and `secure_candidate_demonstrated` remain false.

## Phase 2 follow-up — toy hash-to-signature with modified regtest consensus

The approved toy experiment completed in **36.766 s**, excluding the separately recorded **78.240 s build**. It uses a separate patched Core 31.1 node and verifier; **`consensus_modified: true` and `qsb_exact_reproduction: false`** remain explicit throughout. A funded work-bit literal controls a SHA-256 prefix gate; a passing key deterministically produces a strict DER signature, which still undergoes ordinary ECDSA verification. Stock Core disables the experimental opcode. The exact predicate, patch, build steps, and timing definitions are documented in [native/TOY.md](native/TOY.md).

The run retains fixed-ALL transaction pinning, HORS checks, and subset-dependent FindAndDelete. It uses one digest round and no bonus selections. The synthetic native benchmark measured 121,826 candidates/s; all 54 comparison vectors matched Python and native general ECDSA recovery. The honest-spend search measurements were:

| Work bits | Table entries | Selections | Pinning: candidates (seconds) | Subset: candidates (seconds) |
| --- | ---: | ---: | ---: | ---: |
| 8 | 24 | 3 | 111 (0.000875 s) | 132 (0.001299 s) |
| 12 | 32 | 4 | 85 (0.000659 s) | 1,129 (0.012141 s) |
| 16 | 40 | 5 | 91,943 (0.778028 s) | 16,688 (0.195636 s) |
| 20 | 64 | 5 | 943,752 (7.978031 s) | 342,571 (4.351581 s) |

An authorized transaction reducing the output by 1 sat was independently searched and accepted at each of these four levels. The JSON records their search counts/rates, assembly, native verification, block submission, and all reduced parameters separately. Native search-loop timings exclude process startup and Python hit validation; subprocess timings are also saved. [Complete measurements and fixture references](results/phase2-toy/results.json).

Six additional modified transactions succeeded while retaining **byte-identical original HORS preimage/index pushes**, with no additional preimages available to their assembly step. Each search kept the disclosed subset fixed. Their observed counts were:

| Work bits | Pinning candidates, trials 1–3 | Fixed-subset checks after pinning passed, trials 1–3 |
| --- | --- | --- |
| 4 | 168, 538, 30 | 11, 31, 3 |
| 6 | 2,475, 1,558, 1,561 | 36, 29, 32 |

The experimental node accepted **16 cases** and rejected **30 controls** involving stale witnesses/proof keys, wrong HORS preimages, changed subsets, and repeated indices. Stock native verification and stock block generation rejected all **46 experimental spends**. Fresh-node replay reproduced all outcomes after importing 102 setup blocks per node; submitting the 16 saved accepted blocks to stock Core also failed with its disabled-opcode error. The experimental daemon rejected non-regtest startup. [Results](results/phase2-toy/results.json), [separate CLI replay](results/phase2-toy/replay.json).

All 11 unit tests and the stock phase-1 baseline check passed. These measurements demonstrate this toy lifecycle and the specified searches with frozen authorization; they establish neither a general work lower bound nor full-strength/QSB security. Reproduce with `.venv/bin/python -m btc_pq.cli phase2-toy --build --outdir results/phase2-toy-rerun`, then replay with the same subcommand and `--replay`.

## Phase 3 — exact published-construction validation; bounded pinning search, no hit

The full published construction was validated against the pinned fixtures, and a bounded exact-predicate pinning search ran against the real 9,923-byte locking script funded on isolated regtest. **No hit occurred.** The recorded outcome is `bounded_search_exhausted_no_hit`; `pinning_hit_found`, `regtest_spend_demonstrated`, and `qsb_hash_to_der_end_to_end_demonstrated` are all false, and `consensus_changes` is empty. [results.json](results/phase3/results.json).

The validation pipeline recomputes, from the pinned sources and fixtures only: the legacy `SIGHASH_ALL` sighash with `FindAndDelete(sig_nonce)` over the published script for the published spend (`1a4ff137…ae23`), ECDSA key recovery of the hardcoded `sig_nonce` (recovery branch 0 reproduces the published witness `key_nonce`), the puzzle hash of that key, and a strict-DER check. **The deployed script computes the puzzle hash with `OP_SHA256` (`0xa8`) at all three puzzle sites — pinning and both digest rounds — while the pinned paper text adopts RIPEMD-160 throughout.** The recorded contrast: `SHA256(key_nonce)` = `301d020b…0138` passes strict DER with `r,s > 0`; `RIPEMD160(key_nonce)` = `6cad02e9…c2b8` does not. A minimal legacy-semantics re-execution of the entire published spend reproduces all 4 `CHECKSIGVERIFY` and 2 `CHECKMULTISIG` verifications (including the second-stage `key_puzzle` recovery at branch 2 over `z2 = 4d350dd9…3640`, sighash byte `0x38`) and all 15 HORS `HASH160`/`EQUALVERIFY` checks, in 0.428 s. The mainnet transaction was not re-broadcast or mutated. [results.json: published_validation, published_pipeline_validated, published_validation_wall_seconds](results/phase3/results.json).

The re-execution also fixes the exact auth/witness index mapping. The digest rounds consume table positions [139, 95, 74, 63, 50, 40, 30, 19, 11] (round 1) and [144, 134, 124, 117, 113, 77, 70, 39, 8] (round 2) in multisig order, of which [139, 95, 74, 63, 50, 40, 30, 19] and [144, 134, 124, 117, 113, 77, 70] are HORS-verified; the remaining [11] and [8, 39] are the bonus selections. The scriptSig pushes satisfy `position = 151 − push`; counted from the opposite table end (`149 − position`) these are [10, 54, 75, 86, 99, 109, 119, 130] and [5, 15, 25, 32, 36, 72, 79], matching the earlier attempt. Both rounds are 10-of-10 multisigs (9 selected dummies plus the hardcoded `sig_nonce`); every dummy signature keeps the `SIGHASH_SINGLE`-bug `z = 1`. [results.json: published_validation.digest_rounds, hors_equalverify_checks](results/phase3/results.json).

On regtest, output 0 of the recorded funding transaction carries the exact published script as a bare scriptPubKey (10,000 valueless sats, 9,923 bytes), passed unchanged Core 31.1 native verification, and was mined; a fresh-node replay re-submitted the 102 setup blocks and re-verified funding and script bytes. [results.json: funding, base_tip](results/phase3/results.json), [replay.json](results/phase3/replay.json).

The bounded search varies input-1 `nSequence` (`0x80000000|counter`, `nLockTime` fixed at 0) over the exact pinning predicate: legacy sighash with `FindAndDelete(sig_nonce)`, one recovery per valid branch (2 branches here; `x = r + n ≥ p`), `SHA256` of each compressed recovered key, then strict DER with `r,s > 0`; any pass would undergo full second-stage recovery validation. Both implementations use one point multiplication per candidate (`P = u1·G`) plus one point addition per branch (`Q = P + C_b`). Measured rates, each labeled by implementation [results.json: searches, bounded_parameters](results/phase3/results.json):

| Implementation | Candidates | Key trials | Wall seconds | Candidates/second | Key trials/second | DER passes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Python vendored pure-Python secp256k1 | 14,336 | 28,672 | 125.291 | 114.4 | 228.8 | 0 |
| Native libsecp256k1 (unchanged Core 31.1 tree) | 9,999,360 | 19,998,720 | 120.003 | 83,325.6 | 166,651.2 | 0 |

The native loop is `btc-pq-phase3-search` ([phase3_search.cpp](native/phase3_search.cpp), built from the unchanged tree; it executes no consensus code). Its 64 cross-check vectors — vector 0 is the published pinning digest, which it screens as a pass — matched the Python pipeline exactly, and its synthetic benchmark measured 83,772 candidates/second. Combined, the two disjoint counter ranges tested 10,013,696 candidates (20,027,392 key trials) with zero DER passes. [results.json: `searches[].vectors_checked`, `vectors_mismatched`, `synthetic_benchmark`, `der_passes`](results/phase3/results.json).

The following rows are probability arithmetic over the measured single-CPU rates, not measurements of a completed search. The deployed predicate is a 32-byte SHA256 output in strict-DER form (syntactic work 2^45.425859 per key trial); the paper-text RIPEMD-160 variant is 2^46.425388, matching the phase-1 measurement. Expected hits in the combined 20,027,392 key trials were ≈ 4 × 10^-7. [results.json: expected_time_model, deployed_puzzle, paper_text_puzzle](results/phase3/results.json).

| Implementation | Expected time, deployed 2^45.425859 | Expected time, paper-text 2^46.425388 |
| --- | ---: | ---: |
| Python (228.8 key trials/s) | ≈ 6,545 years | ≈ 13,086 years |
| Native (166,651 key trials/s) | ≈ 9.0 years | ≈ 18.0 years |

Even a pinning hit would not have produced a regtest spend: the digest rounds require the authors' undisclosed HORS preimages plus two further ~2^45.4 subset searches, so no assembly was attempted and none is claimed. Total run time was 252.515 s including validation, funding, both searches, and automatic replay. Reproduce with:

```sh
.venv/bin/python -m btc_pq.cli phase3 --max-candidates 20000000 --max-seconds 120 --outdir results/phase3-rerun
.venv/bin/python -m btc_pq.cli phase3 --replay --outdir results/phase3-rerun
```

All 17 unit tests (11 pre-existing plus 6 new) pass. `published_pipeline_validated` is true; `qsb_hash_to_der_end_to_end_demonstrated` and `secure_candidate_demonstrated` remain false.
