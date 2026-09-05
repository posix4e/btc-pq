# Bounded SHRINCS verification and opcode charging

The local SHRINCS opcode now uses a native verifier with explicit work limits.
It reserves a signature's maximum charge before executing the verifier. The
unmodified upstream implementation remains the signer and a verification
reference; it is no longer the interpreter's signature-checking backend.

This specifies the research model's rule. It does not assign a Bitcoin opcode
or establish network activation, and the charge ratio is an explicit local
parameter rather than a proposed universally optimal fee schedule.

## Rules

The opcode continues to sign exactly a 32-byte transaction digest and accept
the previous canonical B32 signature/chunk shapes. Invalid lengths fail before
cryptographic work. For valid lengths:

| Shape | Maximum SHA256 compression blocks | Charge in validation-weight units |
| --- | ---: | ---: |
| Compact, `q=1` | 2,053 | 257 |
| Compact, `q=17` | 2,085 | 261 |
| Compact, final 3,668-byte shape | 4,941 | 618 |
| Stateless recovery, 3,680 bytes | 8,635 | 1,080 |

The [shared cost definitions](../native/shrincs_cost.h) use:

```text
compact q < 210:       bound = 2051 + 2*q
final compact shape:   bound = 4941
recovery:              bound = 8635
charge:                ceil(bound / 8)
```

The final compact shape can represent either `q=210` or `q=211`. Its bound
covers two complete WOTS and tree checks, including a first candidate whose
checksum is valid but whose root is wrong.

Recovery may evaluate at most **64 XOF blocks**, numbered 0 through 63. This
includes the pinned algorithm's extra XOF block after the fixed prefix. It
rejects if the required indices are still unavailable. This finite cutoff is
an additional validation rule: the uncapped upstream algorithm could, in
principle, accept a signature that needs more sampling. None of the 375 saved
vectors requires more than three XOF blocks.

The verifier also has a compression-work counter and checks available work
**before** every hash. Exhausting either limit rejects the signature. All
temporary data uses normal C++ lifetime management; an early budget failure
does not abandon upstream raw-pointer allocations.

## Where the bounds come from

The SHA256 seed prefix occupies one shared compression block. A 32-byte message
digest check costs two more. The WOTS checksum must equal 2,040 before chain
completion starts, so every successful checksum fixes the number of remaining
chain hashes at `16*255 - 2040 = 2040`. The WOTS public-key hash costs five
compression blocks, and each Merkle parent costs two.

A compact candidate therefore costs `2 + 1 + 2040 + 5 + 2*q + 2` after the
shared prefix. For the final shape, both candidates fit under
`1 + 2*(2 + 1 + 2040 + 5 + 420 + 2) = 4941`.

Recovery costs at most:

```text
1                         shared prefix
+ 2                       message hash
+ 64*2                    bounded index sampling
+ 11                      PORS leaves
+ (111+11-1)*2            at most 121 PORS parents
+ 1                       PORS public key
+ 4*(1+2040+5+8*2)       four WOTS/XMSS layers
+ 2                       combined root
= 8635 compression blocks
```

PORS stores at most 111 authentication nodes. A reconstruction has at most
`authentication nodes + selected leaves - 1` parents, including the cases
that terminate below the maximum tree height. Invalid proofs cannot perform
additional parent hashes after exhausting their fixed authentication bytes.

## Repeated checks and transaction weight

Every executed opcode subtracts its complete charge from the existing
Tapscript validation budget, even if the signature fails or the script reuses
the same witness chunks. The budget starts at serialized witness-stack bytes
plus 50; padding the witness therefore also costs transaction weight.

For these SHRINCS checks, `actual compression blocks <= 8 * charged units`.
Summed over inputs, witness bytes plus the 50-unit allowance per input are
less than transaction weight, since even a minimal input contributes 164
non-witness weight units. Under a 4,000,000-weight-unit block limit this bounds
the SHRINCS checks at 32,000,000 compression blocks per block. This statement
excludes transaction sighash construction, Merkle commitments, and other Script
operations; it is not a bound on all node work.

The relevant existing rules are the pinned Core
[budget initialization](https://github.com/bitcoin/bitcoin/blob/9be056a8a72b624dae9623b2f7bded92c2a21c91/src/script/interpreter.cpp)
and [block-weight limit](https://github.com/bitcoin/bitcoin/blob/9be056a8a72b624dae9623b2f7bded92c2a21c91/src/consensus/consensus.h).

## Evidence

`python -m unittest tests.test_shrincs_work -v` checks exact work-limit boundaries,
sampling cutoffs, and real interpreter execution of scripts that reuse
signature chunks and discard false results. The checks fail when their charge
exceeds the witness budget.

The [maximal-work invalid compact fixture](../results/shrincs-demo/work-bounds/report.json)
reaches exactly 4,941 compression blocks: both final-position checksums pass,
both full chain/tree checks execute, and the signature is rejected. Reducing
the work limit by one stops verification within that lower limit.

The [full differential replay](../results/shrincs-demo/upstream-kat-full-differential.json)
compares 375 valid signatures and 1,875 selected negative controls across
upstream C++, upstream C, Python, and bounded C++. The valid signatures also
produce identical native/Python hash and compression counts. This tests
agreement and resource accounting; it is not an independent cryptographic audit.
