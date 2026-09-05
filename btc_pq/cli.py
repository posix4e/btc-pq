"""Command line harness for the research pipeline.

Subcommands write machine-readable JSON under results/ and print a one-line
summary. Regtest subcommands use valueless coins on an isolated node only.
"""
import argparse
import json
from pathlib import Path

from . import baseline, experiments
from . import measure as measure_mod
from . import phase2
from .crypto import ROOT


def write_json(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + '\n')
    return path


def main(argv=None):
    parser = argparse.ArgumentParser(prog='btc-pq', description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)

    p = sub.add_parser('covenant-demo', help='local proposal model: P2MR + CAT + TEMPLATEHASH + Lamport')
    p.add_argument('--build', action='store_true', help='build a separate modified Script verifier')
    p.add_argument('--outdir', default=str(ROOT/'results/covenant-demo'))
    p.add_argument('--replay', action='store_true', help='verify saved fixtures without signing again')

    p = sub.add_parser('shrincs-demo', help='local P2MR + transaction-bound upstream SHRINCS-B32 experiment')
    p.add_argument('--build', action='store_true')
    p.add_argument('--outdir', default=str(ROOT/'results/shrincs-demo'))
    p.add_argument('--replay', action='store_true')

    sub.add_parser('check-vendor', help='verify pinned QSB reference files')

    sub.add_parser('fetch', help='fetch mainnet fixtures from the public explorer (network)')

    p = sub.add_parser('baseline', help='reproduce pinned mainnet baseline verification')
    p.add_argument('--out', default=str(ROOT/'results/baseline.json'))

    p = sub.add_parser('run', help='regtest experiment matrix (isolated node, valueless coins)')
    p.add_argument('--outdir', default=str(ROOT/'results/regtest'))
    p.add_argument('--bitcoind', default='bitcoind')

    p = sub.add_parser('replay', help='replay the saved chain in a fresh isolated node')
    p.add_argument('--outdir', default=str(ROOT/'results/regtest'))
    p.add_argument('--bitcoind', default='bitcoind')
    p.add_argument('--out', default=str(ROOT/'results/replay.json'))

    p = sub.add_parser('measure', help='local CPU hash throughput and cost models')
    p.add_argument('--trials', type=int, default=100_000)
    p.add_argument('--out', default=str(ROOT/'results/measurements.json'))

    p = sub.add_parser('phase2', help='isolated regtest puzzle lifecycle; surrogate must be explicitly selected')
    p.add_argument('--outdir', default=str(ROOT/'results/phase2'))
    p.add_argument('--bitcoind', default='bitcoind')
    p.add_argument('--puzzle', choices=['hash-to-der','signature-size-surrogate'], default='hash-to-der',
                   help='hash-to-der retains the fixed ~2^46 target; the surrogate is a different size predicate')
    p.add_argument('--entries', type=int, default=48)
    p.add_argument('--selections', type=int, default=5)
    p.add_argument('--signature-bytes', type=int, default=69, help='surrogate exact DER signature size, including sighash byte')
    p.add_argument('--max-candidates', type=int, default=10_000_000)
    p.add_argument('--max-seconds', type=float, default=300)
    p.add_argument('--replay', action='store_true', help='replay existing phase2 fixtures without searching')

    p = sub.add_parser('phase2-toy', help='MODIFIED CONSENSUS: regtest-only toy hash-to-signature measurements')
    p.add_argument('--build', action='store_true', help='build separate patched node, verifier, and native search')
    p.add_argument('--outdir', default=str(ROOT/'results/phase2-toy'))
    p.add_argument('--bitcoind', default='bitcoind', help='unchanged Core used for funding and rejection controls')
    p.add_argument('--levels', default='8,12,16,20', help='comma-separated authorized-spend work bits')
    p.add_argument('--reuse-bits', default='4,6', help='comma-separated work bits for frozen-disclosure searches')
    p.add_argument('--reuse-trials', type=int, default=3)
    p.add_argument('--max-candidates', type=int, default=32_000_000)
    p.add_argument('--max-seconds', type=float, default=300)
    p.add_argument('--replay', action='store_true')

    p = sub.add_parser('phase3', help='exact published-construction validation and bounded pinning search')
    p.add_argument('--outdir', default=str(ROOT/'results/phase3'))
    p.add_argument('--bitcoind', default='bitcoind')
    p.add_argument('--max-candidates', type=int, default=20_000_000)
    p.add_argument('--max-seconds', type=float, default=120, help='wall budget per search implementation')
    p.add_argument('--no-native', action='store_true', help='skip the native libsecp256k1 search loop')
    p.add_argument('--replay', action='store_true', help='replay existing phase3 fixtures without searching')

    p = sub.add_parser('phase4', help='fresh QSB instances, resumable full-predicate search, assembly, and replay')
    p.add_argument('action', choices=['prepare', 'search', 'assemble', 'replay'])
    p.add_argument('--outdir', default=str(ROOT/'results/phase4'))
    p.add_argument('--bitcoind', default='bitcoind')
    p.add_argument('--seed', help='32-byte hexadecimal seed for reproducible regtest material (prepare)')
    p.add_argument('--stage', choices=['pin', 'round1', 'round2'], default='pin')
    p.add_argument('--backend', choices=['native', 'python'], default='native')
    p.add_argument('--max-candidates', type=int, default=100_000)
    p.add_argument('--max-seconds', type=float, default=10)
    p.add_argument('--worker-id', type=int, default=0)
    p.add_argument('--workers', type=int, default=1)
    p.add_argument('--pin', help='pinning hit JSON or checkpoint (digest search and assembly)')
    p.add_argument('--round1', help='round 1 hit JSON or checkpoint (assembly)')
    p.add_argument('--round2', help='round 2 hit JSON or checkpoint (assembly)')
    p.add_argument('--next-hit', action='store_true', help='continue pinning after the selected hit')

    args = parser.parse_args(argv)

    if args.command == 'shrincs-demo':
        from . import shrincs_demo
        if args.replay:
            if args.build:
                from .shrincs_build import build
                build()
            result = shrincs_demo.replay(args.outdir)
        else:
            result = shrincs_demo.run(args.outdir, args.build)
        print(f"shrincs-demo: {len(result['cases'])} cases matched expectations -> {args.outdir}")
        return

    if args.command == 'covenant-demo':
        from . import covenant_demo
        if args.replay:
            if args.build:
                from .covenant_build import build
                build()
            result = covenant_demo.replay(args.outdir)
        else:
            result = covenant_demo.run(args.outdir, args.build)
        print(f"covenant-demo: {len(result['cases'])} cases matched expectations -> {args.outdir}")
        return

    if args.command == 'phase4':
        from . import phase4
        try:
            if args.action == 'prepare':
                result = phase4.prepare(args.outdir, args.bitcoind,
                                        bytes.fromhex(args.seed) if args.seed else None)
                print(f"phase4: prepared {result['instance_sha256']} -> {Path(args.outdir)/'manifest.json'}")
            elif args.action == 'search':
                result = phase4.search(args.outdir, args.stage, args.max_candidates, args.max_seconds,
                                       args.backend, args.worker_id, args.workers, args.pin, args.next_hit)
                print(f"phase4 {args.stage}: {result['status']}; candidates={result['candidates']} "
                      f"next={result['next_counter']} -> {result['checkpoint']}")
                if result['hit']:
                    print(f"validated hit: {Path(result['checkpoint']).parent}/hit-{phase4.fingerprint(result['hit'])}.json")
            elif args.action == 'assemble':
                if not all((args.pin, args.round1, args.round2)):
                    raise ValueError('assembly requires --pin, --round1, and --round2')
                result = phase4.assemble(args.outdir, args.pin, args.round1, args.round2, args.bitcoind)
                print(f"phase4: accepted {result['transaction']['txid']} -> {Path(args.outdir)/'assembly.json'}")
            else:
                result = phase4.replay(args.outdir, args.bitcoind)
                print(f"phase4 replay: {result['setup_blocks_replayed']} setup blocks; "
                      f"spend replayed={result['spend_replayed']} -> {Path(args.outdir)/'replay.json'}")
        except (ValueError, RuntimeError, OSError) as error:
            parser.exit(1, f'phase4: {error}\n')
        return

    if args.command == 'phase3':
        from . import phase3
        if args.replay:
            result = phase3.replay(args.outdir, args.bitcoind)
            out = write_json(Path(args.outdir)/'replay.json', result)
            print(f"phase3 replay: {result['setup_blocks_replayed']} setup blocks, "
                  f"funding native={result['funding_native_valid']} -> {out}")
        else:
            print('phase3: EXACT published predicate; bounded search; no hit expected', flush=True)
            try:
                result = phase3.run(args.outdir, args.bitcoind, args.max_candidates,
                                    args.max_seconds, not args.no_native)
            except (ValueError, RuntimeError) as error:
                parser.exit(1, f'phase3: {error}\n')
            rates = ', '.join(f"{s['implementation'].split(':')[0]} "
                              f"{s['candidates_per_second']:.0f} cand/s" for s in result['searches']
                              if s.get('candidates_per_second'))
            print(f"phase3: {result['status']}; validated={result['published_pipeline_validated']} "
                  f"hit={result['pinning_hit_found']}; {rates} -> {Path(args.outdir)/'results.json'}")
        return

    if args.command == 'phase2-toy':
        from . import toy, toy_build
        print('phase2-toy: MODIFIED CONSENSUS, REGTEST ONLY; QSB exact reproduction=false',flush=True)
        if args.build:
            toy_build.build()
        if args.replay:
            result=toy.replay(args.outdir,args.bitcoind)
            out=write_json(Path(args.outdir)/'replay.json',result)
            print(f"phase2-toy replay: {len(result['cases'])} cases reproduced -> {out}")
        else:
            try:
                levels=tuple(int(b) for b in args.levels.split(',') if b)
                reuse=tuple(int(b) for b in args.reuse_bits.split(',') if b)
                result=toy.run(args.outdir,levels,reuse,args.reuse_trials,args.bitcoind,args.max_candidates,args.max_seconds)
            except (ValueError,RuntimeError) as error:
                parser.exit(1,f'phase2-toy: {error}\n')
            print(f"phase2-toy: {result['status']}; {len(result['cases'])} cases -> {Path(args.outdir)/'results.json'}")
        return

    if args.command == 'phase2':
        if args.replay:
            result = phase2.replay(args.outdir,args.bitcoind)
            out = write_json(Path(args.outdir)/'replay.json',result)
            print(f"phase2 replay: {len(result['cases'])} cases -> {out}")
        else:
            params = phase2.Parameters(args.entries,args.selections,args.puzzle,args.signature_bytes)
            print(f'phase2: {args.puzzle}; REDUCED PUBLIC REGTEST EXPERIMENT; not full strength',flush=True)
            try:
                result = phase2.run(args.outdir,args.bitcoind,params,args.max_candidates,args.max_seconds)
            except (ValueError,RuntimeError) as error:
                parser.exit(1, f'phase2: {error}\n')
            print(f"phase2: lifecycle={result['reduced_lifecycle_demonstrated']} "
                  f"QSB hash-to-DER={result['qsb_hash_to_der_end_to_end_demonstrated']} -> {Path(args.outdir)/'results.json'}")
        return

    if args.command == 'check-vendor':
        result = baseline.check_vendor()
        print(f"vendor reference pinned at {result['commit']} ({result['checked_files']} files)")
        return

    if args.command == 'fetch':
        meta = baseline.fetch()
        print(f"fetched spend {meta['spend_txid']} at block height {meta['merkle_proof']['block_height']}")
        return

    if args.command == 'baseline':
        result = baseline.reproduce()
        out = write_json(args.out, result)
        v = result['core_verification']
        print(f"baseline: native valid={v['valid']} inclusion={result['inclusion_verified']} "
              f"mutations_rejected={len(result['attacks'])} -> {out}")
        return

    if args.command == 'run':
        result = experiments.run(args.outdir, bitcoind=args.bitcoind)
        cases = result['cases']
        ok = sum(c['block_accepted'] == c['expected_acceptance'] for c in cases)
        print(f"run: {ok}/{len(cases)} cases matched expectations -> {Path(args.outdir)/'results.json'}")
        return

    if args.command == 'replay':
        result = experiments.replay(args.outdir, bitcoind=args.bitcoind)
        out = write_json(args.out, result)
        print(f"replay: {len(result['cases'])} cases reproduced, "
              f"{result['setup_blocks_replayed']} setup blocks -> {out}")
        return

    if args.command == 'measure':
        result = measure_mod.measure(args.trials)
        out = write_json(args.out, result)
        print(f"measure: {len(result['hashes'])} hashes x {args.trials} iterations -> {out}")
        return


if __name__ == '__main__':
    main()
