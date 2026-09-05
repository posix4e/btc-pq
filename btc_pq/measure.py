"""CPU measurements and explicitly conditional cost models; never GPU results."""
import hashlib
import math
import platform
import statistics
import sys
import time
from .crypto import ec, recover


def der_probability(length):
    # BIP66 structure: six fixed bytes, two positive minimal integers, final
    # unrestricted sighash byte. Integer zero is DER-valid (not ECDSA-valid).
    def prefix(n):
        return .5 if n==1 else 127/256 + 1/512
    return 2**-48 * sum(prefix(r)*prefix(length-7-r) for r in range(1,length-7))


def polyglot(trials=100_000):
    if trials < 1:
        raise ValueError('positive trial budget required')
    hits=[]; syntactic=0
    prefix=hashlib.sha256(b'PUBLIC POLYGLOT TEST DATA').digest()[:12]
    start=time.perf_counter()
    for i in range(trials):
        preimage=prefix+i.to_bytes(8,'big')
        digest=hashlib.new('ripemd160',preimage).digest()
        if ec.is_valid_der_sig(digest):
            syntactic+=1
            rl=digest[3]; sl=digest[5+rl]
            r=int.from_bytes(digest[4:4+rl],'big')
            s=int.from_bytes(digest[6+rl:6+rl+sl],'big')
            if any(recover(r,s,bytes(32),j) for j in range(4)):
                hits.append(dict(preimage=preimage.hex(),digest=digest.hex()))
    seconds=time.perf_counter()-start
    rate=trials/seconds
    p=der_probability(20)
    return dict(trials=trials,wall_seconds=seconds,cpu_trials_per_second=rate,
                predicate='Full RIPEMD160 -> strict DER -> ECDSA recoverability. No truncated target.',
                input_bytes=20,syntactic_der_hits=syntactic,usable_hits=hits,
                secrets='All trial preimages are deterministic PUBLIC TEST DATA; unusable as signing secrets.',
                expected_syntactic_hits=trials*p,syntactic_work_bits=-math.log2(p),
                paper_rounded_setup_hashes_180=180*2**46,
                syntactic_expected_setup_hashes_180=180/p,
                optimistic_extrapolated_cpu_years_180=180/p/rate/(365.25*86400),
                extrapolation='From this Python CPU search loop, not measured full setup. Recoverability can only add work. Not a GPU estimate.',
                spending_puzzle_eliminated=False,full_polyglot_transaction_demonstrated=False)


def measure(trials=100_000):
    prefix=b'public research!'
    functions={
        'sha256':lambda b:hashlib.sha256(b).digest(),
        'sha256d':lambda b:hashlib.sha256(hashlib.sha256(b).digest()).digest(),
        'ripemd160':lambda b:hashlib.new('ripemd160',b).digest(),
        'hash160':lambda b:hashlib.new('ripemd160',hashlib.sha256(b).digest()).digest(),
        'blake2s':lambda b:hashlib.blake2s(b).digest(),
        'sha3_256':lambda b:hashlib.sha3_256(b).digest(),
    }
    # Exactly 20-byte payloads, same pre-generated inputs and count for each hash.
    payloads=[(prefix+i.to_bytes(8,'big'))[-20:] for i in range(1024)]
    hashes=[]
    for name,fn in functions.items():
        timings=[]
        for _ in range(3):
            start=time.perf_counter()
            for i in range(trials):
                fn(payloads[i%1024])
            timings.append(time.perf_counter()-start)
        median=statistics.median(timings)
        hashes.append(dict(algorithm=name,iterations=trials,payload_bytes=20,seconds=timings,
                           median_cpu_hashes_per_second=trials/median,
                           native_bitcoin_script_opcode=name in ('sha256','sha256d','ripemd160','hash160')))
    fallback=[]
    p=der_probability(32)  # Published QSB uses SHA256, not RIPEMD160, for puzzles.
    for n,signed,bonus in [(150,(8,7),(1,2)),(90,(10,10),(0,0)),(110,(10,10),(0,0)),(120,(10,10),(0,0))]:
        poly=n!=150
        totals=[a+b for a,b in zip(signed,bonus)]
        means=[math.comb(n,t)*p for t in totals]
        successes=[-math.expm1(-m) for m in means]
        fallback.append(dict(name='QSB published dimensions' if not poly else f'polyglot model n={n}',
            n_per_round=n,signed_per_round=signed,bonus_per_round=bonus,
            calculated_opcodes=21+(9 if poly else 11)*sum(signed)+5*sum(bonus),
            signed_subset_space_bits=sum(math.log2(math.comb(n,t)) for t in signed),
            dummy_and_hors_table_bytes=2*n*(21 if poly else 31),
            secret_polyglots_to_generate=2*n if poly else 0,
            syntactic_setup_hashes=2*n/der_probability(20) if poly else 0,
            mean_der_solutions_per_round=means,
            optimistic_pinned_attempts_independent_poisson=1/math.prod(successes)))
    return dict(environment=dict(platform=platform.platform(),machine=platform.machine(),python=sys.version,
                processor=platform.processor()),measurement_kind='Local CPU/Python API throughput only',hashes=hashes,
                hash_warning='Small-input Python/hashlib call throughput is not a native/GPU circuit benchmark and does not predict QSB end-to-end performance.',
                polyglot=polyglot(trials),fallback_models=fallback,
                model_scope='Conditional arithmetic, not compiled or validated polyglot transactions. Assumes the two-opcode saving transfers to each signed selection; 21 fixed/round-overhead ops inferred from the published script. Table bytes exclude every other script element.',
                probability_scope='Independent random outputs and one SHA256/recovered-key candidate per subset; strict DER only. Ignores recoverability, multi-key grinding, correlated subsets, and mining implementation. Optimistic comparative model, not a security proof or measured speedup.',
                security='Signed subset-space bits are not security bits. Author-reported QSB security estimates and Binohash collision estimates are different claims; this harness proves neither.')
