"""Phase 3: published-pipeline vectors and budget/deadline behavior (no node needed)."""
import time
import unittest
from unittest.mock import patch

from btc_pq.bitcoin import Tx, Input, Output, legacy_sighash
from btc_pq.crypto import ec, encode, recover
from btc_pq.phase3 import (Pinning, Search, der_nonzero, der_parts, der_work_bits, is_strict_der,
                           published, validate_published)
from hashlib import sha256


class Phase3Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.validation = validate_published()
        cls.spend, cls.index, cls.parent, cls.construction = published()
        cls.pinning = Pinning(bytes.fromhex(cls.validation['pinning']['sig_nonce_hex']))

    def tx(self):
        return Tx([Input('11'*32, 0, sequence=0xfffffffd),
                   Input('22'*32, 0, sequence=0x80000000)], [Output(9_000, b'\x51')])

    def test_published_pipeline_reproduces_every_check(self):
        v = self.validation
        pin = v['pinning']
        self.assertEqual(pin['z_hex'], '1a4ff1376ee605a8a5248e4ed87dea811eaf2a54a89b7bc7134c90c67843ae23')
        self.assertEqual(pin['key_nonce_recovery_branch'], 0)
        self.assertEqual(pin['sig_puzzle_hex'],
                         '301d020b136a32e061af495ec20443020e5f9b091a78bcb4d2756b58c06d0138')
        self.assertTrue(pin['sig_puzzle_strict_der'])
        self.assertEqual(pin['sig_puzzle_recovery_branch'], 2)
        self.assertEqual(pin['sig_puzzle_z_hex'],
                         '4d350dd901c3b071548c724686f17f22ad1416191d0a1fd0a3cbedbb4ca43640')
        # Deployed script hashes key_nonce with OP_SHA256 (0xa8), not RIPEMD-160.
        self.assertEqual(v['deployed_puzzle_opcode'], '0xa8')
        self.assertFalse(v['ripemd160_key_nonce_strict_der'])
        self.assertEqual(v['script']['bytes'], 9_923)
        self.assertEqual(v['hors_equalverify_checks'], 15)
        r1, r2 = v['digest_rounds']
        self.assertEqual((r1['signed_selections'], r1['bonus_selections']), (8, 1))
        self.assertEqual((r2['signed_selections'], r2['bonus_selections']), (7, 2))
        self.assertEqual(r1['dummy_positions_multisig_order'], [139, 95, 74, 63, 50, 40, 30, 19, 11])
        self.assertEqual(r2['dummy_positions_multisig_order'], [144, 134, 124, 117, 113, 77, 70, 39, 8])
        self.assertEqual(r1['bonus_positions'], [11])
        self.assertEqual(r2['bonus_positions'], [8, 39])

    def test_strict_der_port_and_counts(self):
        v = self.validation
        sigs = [bytes.fromhex(v['pinning']['sig_nonce_hex']),
                bytes.fromhex(v['pinning']['sig_puzzle_hex'])]
        sigs += [bytes.fromhex(r['sig_nonce_hex']) for r in v['digest_rounds']]
        sigs += [bytes.fromhex(r['puzzle_signature_hex']) for r in v['digest_rounds']]
        for sig in sigs:
            self.assertEqual(is_strict_der(sig), ec.is_valid_der_sig(sig))
            self.assertTrue(der_nonzero(sig))
        # Edge cases: negative and padded integers are rejected by both checks.
        base = bytearray(sigs[1])
        for mutation in (4, 16):
            bad = bytearray(base)
            bad[mutation] |= 0x80
            self.assertEqual(is_strict_der(bytes(bad)), ec.is_valid_der_sig(bytes(bad)))
            self.assertFalse(is_strict_der(bytes(bad)))
        self.assertAlmostEqual(der_work_bits(20), 46.425388, places=4)
        self.assertAlmostEqual(der_work_bits(32), 45.425859, places=4)

    def test_search_detects_the_published_hit(self):
        v = self.validation
        z = bytes.fromhex(v['pinning']['z_hex'])
        screened = self.pinning.screen(z)
        self.assertEqual(len(screened), 1)
        branch, key, sig_puzzle = screened[0]
        self.assertEqual(key.hex(), v['pinning']['key_nonce_hex'])
        hit = self.pinning.validate_hit(self.spend, self.index, self.construction.script,
                                        z, branch, key, sig_puzzle)
        self.assertIsNotNone(hit)
        self.assertEqual(hit['key_puzzle_hex'], v['pinning']['key_puzzle_hex'])
        self.assertEqual(hit['sig_puzzle_z_hex'], v['pinning']['sig_puzzle_z_hex'])

    def test_search_templates_match_reference_and_budgets_are_exact(self):
        tx = self.tx()
        search = Search(self.pinning, self.construction.script, tx)
        seen = []

        def probe(digest):
            seen.append(digest)
            self.assertEqual(digest, legacy_sighash(tx, 1, search.code,
                                                    hash_type=self.pinning.sighash_byte))
            return []

        with patch.object(self.pinning, 'screen', side_effect=probe):
            hit, stats = search.pin(7, 3, time.perf_counter() + 10)
        self.assertIsNone(hit)
        self.assertEqual(len(seen), 3)
        self.assertEqual(stats['candidates'], 3)
        self.assertEqual(stats['next_counter'], 10)
        self.assertTrue(stats['budget_exhausted'])
        with patch.object(self.pinning, 'screen', side_effect=probe):
            hit, stats = search.pin(0, 2, time.perf_counter() + 10)
        self.assertEqual(stats['candidates'], 2)

    def test_expired_deadline_tests_no_candidates(self):
        search = Search(self.pinning, self.construction.script, self.tx())
        hit, stats = search.pin(0, 100, time.perf_counter() - 1)
        self.assertIsNone(hit)
        self.assertEqual(stats['candidates'], 0)
        self.assertTrue(stats['budget_exhausted'])

    def test_screen_predicate_counts_key_trials(self):
        # One digest yields one SHA256 trial per valid recovery branch.
        tx = self.tx()
        search = Search(self.pinning, self.construction.script, tx)
        digest = search.digest(0x80000000)
        keys = list(self.pinning.keys(digest))
        self.assertEqual(len(keys), len(self.pinning.branches))
        r, s, _ = der_parts(self.pinning.sig)
        for branch, key in keys:
            matched = [b for b in range(4)
                       if (q := recover(r, s, digest, b)) is not None and encode(q) == key]
            self.assertEqual(matched, [branch])


if __name__ == '__main__':
    unittest.main()
