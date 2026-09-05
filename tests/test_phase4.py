"""Exact assembly, independent enumeration, and durable search continuation."""
from copy import deepcopy
from itertools import combinations
from pathlib import Path
import json
import tempfile
import unittest
from unittest.mock import patch

from btc_pq.baseline import FIXTURES
from btc_pq.bitcoin import Tx, Input, Output, instructions, legacy_sighash
from btc_pq.core import VERIFIER, verify
from btc_pq.phase3 import (Pinning, Search, SEARCH_BIN, execute, hash160,
                           native_call, native_request, published, recovery_branch)
from btc_pq.phase4 import (PINNING_SPACE, SEQUENCE_SPACE, assemble_tx, atomic_json,
                           candidate_tx, fresh_instance, locked, search, stage_context,
                           subset_at, subset_rank, tables, validate_proof, worker_range)


def published_proofs():
    """Extract known successful proof material from the public execution trace."""
    spend, index, _, c = published()
    events, _ = execute(spend, index, c)
    checks = [e for e in events if e['event'] == 'checksigverify']
    multis = [e for e in events if e['event'] == 'checkmultisig']
    records = [(checks[0]['signature'], checks[0]['z_hex'], checks[0]['public_key'])]
    for multi in multis:
        fixed = next(p for p in multi['pairs'] if p['sig_tag'][0] == 'script')
        records.append((fixed['signature'], fixed['z_hex'], fixed['public_key']))
    proofs = []
    for i, (sighex, zhex, keyhex) in enumerate(records):
        puzzle = checks[i + 1]
        sig, z, key = bytes.fromhex(sighex), bytes.fromhex(zhex), bytes.fromhex(keyhex)
        p = dict(stage='pin' if i == 0 else f'round{i}', digest_hex=zhex,
                 recovery_branch=recovery_branch(sig, z, key), key_nonce_hex=keyhex,
                 key_puzzle_hex=puzzle['public_key'], sig_puzzle_hex=puzzle['signature'],
                 sig_puzzle_z_hex=puzzle['z_hex'],
                 puzzle_recovery_branch=recovery_branch(bytes.fromhex(puzzle['signature']),
                     bytes.fromhex(puzzle['z_hex']), bytes.fromhex(puzzle['public_key'])))
        if i:
            selected = sorted((q for q in multis[i - 1]['pairs'] if q['sig_tag'][0] == 'dummy'),
                              key=lambda q: q['sig_tag'][2])
            p['subset'] = [q['sig_tag'][2] for q in selected]
            p['subset_rank'] = subset_rank(c.entries, p['subset'])
            p['dummy_recovery_branches'] = [recovery_branch(bytes.fromhex(q['signature']),
                bytes.fromhex(q['z_hex']), bytes.fromhex(q['public_key'])) for q in selected]
        proofs.append(p)
    disclosed = {hash160(d): d for _, _, d, _ in instructions(spend.inputs[index].script)
                 if d is not None and len(d) == 20}
    preimages = {(rnd, p): disclosed[commitment] for rnd in (1, 2)
                 for p, commitment in enumerate(tables(c, 'commitment', rnd)) if commitment in disclosed}
    return spend, c, proofs, preimages


class Phase4Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.spend, cls.c, cls.proofs, cls.preimages = published_proofs()

    def base(self):
        return Tx([Input('11' * 32, 1), Input('22' * 32, 0)], [Output(19000, b'\x51')])

    def workspace(self):
        return dict(workspace_id='test-workspace'), {}, self.c, self.base()

    def test_fresh_commitments_are_reproducible_and_preserve_opcodes(self):
        first = fresh_instance(bytes(32))
        self.assertEqual(first, fresh_instance(bytes(32)))
        other = fresh_instance(bytes([1]) * 32)
        self.assertNotEqual(first['script_sha256'], other['script_sha256'])
        self.assertEqual((first['metrics']['bytes'], first['metrics']['counted_opcodes']), (9923, 201))
        old = list(instructions(self.c.script))
        new = list(instructions(bytes.fromhex(first['script_hex'])))
        self.assertEqual(len(old), len(new))
        for before, after in zip(old, new):
            tag = self.c.table_tags.get(before[0])
            if tag and tag[0] == 'commitment':
                preimage = bytes.fromhex(first['preimages'][tag[1] - 1][tag[2]])
                self.assertEqual(hash160(preimage), after[2])
                self.assertNotEqual(before[2], after[2])
            else:
                self.assertEqual(before, after)

    def test_sequence_mapping_is_unique_across_old_boundary(self):
        counters = [0, 1, SEQUENCE_SPACE - 1, SEQUENCE_SPACE, SEQUENCE_SPACE + 1, PINNING_SPACE - 1]
        pairs = []
        for counter in counters:
            tx = candidate_tx(self.base(), counter)
            pair = tuple(i.sequence for i in tx.inputs)
            self.assertEqual(((pair[0] & 0x7fffffff) << 31) | (pair[1] & 0x7fffffff), counter)
            self.assertTrue(all(value & 0x80000000 for value in pair))
            self.assertEqual(tx.locktime, 0)
            pairs.append(pair)
            context = Pinning(self.c.pin_sig)
            template = Search(context, self.c.script, tx)
            self.assertEqual(template.digest(tx.inputs[1].sequence), legacy_sighash(tx, 1, template.code))
        self.assertEqual(len(set(pairs)), len(counters))
        for bad in (-1, PINNING_SPACE):
            with self.assertRaises(ValueError):
                candidate_tx(self.base(), bad)

    def test_partitions_cover_space_without_overlap(self):
        for total in (29, PINNING_SPACE):
            ranges = [worker_range(total, w, 7) for w in range(7)]
            self.assertEqual(ranges[0][0], 0)
            self.assertEqual(ranges[-1][1], total)
            self.assertTrue(all(a[1] == b[0] for a, b in zip(ranges, ranges[1:])))
        with self.assertRaises(ValueError):
            worker_range(10, 1, 1)

    def test_subset_rank_matches_itertools_exhaustively(self):
        for n, k in ((8, 3), (9, 5), (6, 0), (6, 6)):
            for rank, subset in enumerate(combinations(range(n), k)):
                self.assertEqual(subset_at(n, k, rank), list(subset))
                self.assertEqual(subset_rank(n, subset), rank)
        for p in self.proofs[1:]:
            self.assertEqual(subset_at(150, 9, p['subset_rank']), p['subset'])
        with self.assertRaises(ValueError):
            subset_rank(150, [1, 1])

    def test_assembly_reproduces_published_bytes_and_native_acceptance(self):
        base = deepcopy(self.spend)
        base.inputs[1].script = b''
        tx = assemble_tx(base, self.c, self.preimages, self.proofs[0], self.proofs[1:])
        self.assertEqual(tx.serialize(), self.spend.serialize())
        if VERIFIER.exists():
            with tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp)/'spend.hex'
                path.write_text(tx.serialize().hex())
                result = verify(path, [FIXTURES/(i.txid + '.hex') for i in tx.inputs])
                self.assertTrue(result['valid'])

    def test_assembly_rejects_stale_incomplete_and_wrong_material(self):
        for stage, proof in zip(('pin', 'round1', 'round2'), self.proofs):
            self.assertIs(validate_proof(self.c, self.spend, proof, stage), proof)
            stale = deepcopy(self.spend)
            stale.outputs[0].value -= 1
            with self.assertRaisesRegex(ValueError, 'stale proof'):
                validate_proof(self.c, stale, proof, stage)
        broken = deepcopy(self.proofs[1])
        broken['subset'][0] = broken['subset'][1]
        with self.assertRaises(ValueError):
            validate_proof(self.c, self.spend, broken)
        with self.assertRaisesRegex(ValueError, 'both digest'):
            assemble_tx(self.spend, self.c, self.preimages, self.proofs[0], self.proofs[1:2])
        preimages = dict(self.preimages)
        preimages[next(iter(preimages))] = bytes(20)
        with self.assertRaisesRegex(ValueError, 'HORS preimage'):
            assemble_tx(self.spend, self.c, preimages, self.proofs[0], self.proofs[1:])

    def test_round_find_and_delete_matches_published_trace(self):
        events, _ = execute(self.spend, 1, self.c, detailed=True)
        multis = [e for e in events if e['event'] == 'checkmultisig']
        for rnd, (proof, multi) in enumerate(zip(self.proofs[1:], multis), 1):
            sig, code = stage_context(self.c, f'round{rnd}', proof['subset'])
            self.assertEqual(code.hex(), multi['script_code_hex'])
            self.assertEqual(legacy_sighash(self.spend, 1, code, hash_type=sig[-1]).hex(), proof['digest_hex'])

    def test_resume_continues_without_repeating_completed_candidates(self):
        seen = []
        original = Pinning.keys

        def record(context, digest):
            seen.append(digest)
            return original(context, digest)

        with tempfile.TemporaryDirectory() as tmp, patch('btc_pq.phase4.load_workspace', side_effect=lambda _: self.workspace()):
            with patch.object(Pinning, 'keys', record):
                first = search(tmp, max_candidates=3, max_seconds=10, backend='python')
                second = search(tmp, max_candidates=2, max_seconds=10, backend='python')
            self.assertEqual(first['next_counter'], 3)
            self.assertEqual(second['next_counter'], 5)
            _, code = stage_context(self.c, 'pin')
            self.assertEqual(seen, [legacy_sighash(candidate_tx(self.base(), i), 1, code) for i in range(5)])
            self.assertEqual(second['candidates'], 5)
            with self.assertRaisesRegex(ValueError, 'partition'):
                search(tmp, max_candidates=1, workers=2, backend='python')
            state = json.loads(Path(second['checkpoint']).read_text())
            state['job']['workspace_id'] = 'wrong'
            atomic_json(second['checkpoint'], state)
            with self.assertRaisesRegex(ValueError, 'identity'):
                search(tmp, max_candidates=1, backend='python')

    def test_interruption_preserves_committed_progress(self):
        original = Pinning.keys
        calls = 0

        def interrupt(context, digest):
            nonlocal calls
            calls += 1
            if calls == 3:
                raise KeyboardInterrupt()
            return original(context, digest)

        with tempfile.TemporaryDirectory() as tmp, patch('btc_pq.phase4.load_workspace', side_effect=lambda _: self.workspace()):
            with patch.object(Pinning, 'keys', interrupt):
                with self.assertRaises(KeyboardInterrupt):
                    search(tmp, max_candidates=5, max_seconds=10, backend='python')
            path = next(Path(tmp).glob('search/*/worker-0.json'))
            self.assertEqual(json.loads(path.read_text())['next_counter'], 2)
            resumed = search(tmp, max_candidates=3, max_seconds=10, backend='python')
            self.assertEqual(resumed['next_counter'], 5)
            self.assertEqual(resumed['status'], 'paused')

    def test_checkpoint_lock_prevents_two_writers(self):
        with tempfile.TemporaryDirectory() as tmp:
            with locked(Path(tmp)/'job.lock'):
                with self.assertRaisesRegex(RuntimeError, 'already running'):
                    with locked(Path(tmp)/'job.lock'):
                        self.fail('lock unexpectedly acquired')

    @unittest.skipUnless(SEARCH_BIN.exists(), 'native search binary unavailable')
    def test_native_screen_finds_all_three_known_proofs(self):
        for proof in self.proofs:
            sig, _ = stage_context(self.c, proof['stage'], proof.get('subset'))
            context = Pinning(sig)
            result = native_call(SEARCH_BIN, native_request(context, 'screen',
                digests=[bytes(32).hex(), proof['digest_hex']]), 30)
            self.assertEqual(result['candidates'], 2)
            matching = [e for e in result['der_pass_events'] if e['winning_counter'] == 1
                        and e['key_nonce_hex'] == proof['key_nonce_hex']]
            self.assertEqual(len(matching), 1)

    @unittest.skipUnless(SEARCH_BIN.exists(), 'native search binary unavailable')
    def test_native_pin_stops_after_known_hit_and_counts_it_once(self):
        context = Pinning(self.c.pin_sig)
        template = Search(context, self.c.script, self.spend)
        low = self.spend.inputs[1].sequence & 0x7fffffff
        result = native_call(SEARCH_BIN, native_request(context, 'pin',
            prefix_hex=template.prefix.hex(), code_hex=template.code.hex(), tail_hex=template.tail.hex(),
            counter=low, max_candidates=3, max_seconds=10.0, stop_on_der=True), 30)
        self.assertEqual(result['stop_reason'], 'der_hit')
        self.assertEqual(result['measurement']['candidates'], 1)
        self.assertEqual(result['next_counter'], low + 1)
        self.assertFalse(result['budget_exhausted'])
        self.assertEqual(result['der_pass_events'][0]['key_nonce_hex'], self.proofs[0]['key_nonce_hex'])

    @unittest.skipUnless(SEARCH_BIN.exists(), 'native search binary unavailable')
    def test_both_digest_searches_validate_known_hits_and_save_them(self):
        pin = dict(self.proofs[0], counter=0)
        for rnd in (1, 2):
            rank = self.proofs[rnd]['subset_rank']
            with tempfile.TemporaryDirectory() as tmp, \
                    patch('btc_pq.phase4.load_workspace', return_value=(dict(workspace_id='published'), {}, self.c, self.spend)), \
                    patch('btc_pq.phase4.candidate_tx', return_value=self.spend), \
                    patch('btc_pq.phase4.worker_range', return_value=(rank, rank + 1)), \
                    patch('btc_pq.phase4.build_native', return_value=SEARCH_BIN):
                path = Path(tmp)/'pin.json'
                atomic_json(path, dict(workspace_id='published', proof=pin))
                result = search(tmp, stage=f'round{rnd}', max_candidates=1, pin_path=path)
                self.assertEqual(result['status'], 'hit')
                self.assertEqual(result['next_counter'], rank + 1)
                self.assertEqual(result['hit']['subset'], self.proofs[rnd]['subset'])
                validate_proof(self.c, self.spend, result['hit'], f'round{rnd}')
                saved = list(Path(result['checkpoint']).parent.glob('hit-*.json'))
                self.assertTrue(saved)
                resumed = search(tmp, stage=f'round{rnd}', max_candidates=1, pin_path=path)
                self.assertEqual(resumed['candidates'], 1)

    @unittest.skipUnless(SEARCH_BIN.exists(), 'native search binary unavailable')
    def test_native_search_crosses_sequence_boundary_and_resumes(self):
        with tempfile.TemporaryDirectory() as tmp, patch('btc_pq.phase4.load_workspace', side_effect=lambda _: self.workspace()), \
                patch('btc_pq.phase4.worker_range', return_value=(SEQUENCE_SPACE - 2, SEQUENCE_SPACE + 2)), \
                patch('btc_pq.phase4.build_native', return_value=SEARCH_BIN):
            first = search(tmp, max_candidates=3, max_seconds=10)
            second = search(tmp, max_candidates=3, max_seconds=10)
            self.assertEqual(first['next_counter'], SEQUENCE_SPACE + 1)
            self.assertEqual(second['next_counter'], SEQUENCE_SPACE + 2)
            self.assertEqual(second['candidates'], 4)
            self.assertEqual(second['status'], 'exhausted')


if __name__ == '__main__':
    unittest.main()
