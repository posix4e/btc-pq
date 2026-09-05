"""Focused algebra/budget checks; saved native/block replays cover Script."""
from itertools import combinations
import time
import unittest
from unittest.mock import patch

from btc_pq.bitcoin import Tx, Input, Output, legacy_sighash
from btc_pq.crypto import ec, encode, recover
from btc_pq.phase2 import Instance, Parameters, Search


class Phase2Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.instance = Instance(Parameters(entries=8,selections=2,puzzle='signature-size-surrogate',signature_bytes=71))

    def tx(self):
        return Tx([Input('11'*32,0),Input('22'*32,1)], [Output(10_000,b'\x51')])

    def test_single_bug_endianness_and_fixed_key(self):
        instance = self.instance
        tx = self.tx()
        self.assertEqual(legacy_sighash(tx,1,instance.script,hash_type=3),b'\x01'+bytes(31))
        z = instance.digest(tx)
        key = instance.key(z)
        self.assertEqual(key,encode(recover(instance.r,1,z,ec.G[1]&1)))
        self.assertTrue(ec.ecdsa_verify(ec.decompress_pubkey(key),int.from_bytes(z,'big'),instance.r,1))

    def test_search_templates_match_reference_across_sequences_and_subsets(self):
        instance = self.instance
        tx = self.tx()
        search = Search(instance,tx,100,time.perf_counter()+10)
        seen = []

        def pin_probe(candidate_tx,z):
            self.assertEqual(z,instance.digest(candidate_tx))
            seen.append(z)
            return b'probe' if len(seen)==3 else None

        with patch.object(instance,'proof',side_effect=pin_probe):
            _, stats = search.pin(7)
        self.assertEqual(stats['candidates'],3)
        self.assertEqual(stats['winning_counter'],9)
        subsets = iter(combinations(range(8),2))

        def subset_probe(candidate_tx,z):
            self.assertEqual(z,instance.digest(candidate_tx,next(subsets)))
            return None

        with patch.object(instance,'proof',side_effect=subset_probe):
            proof, subset, stats = search.subsets()
        self.assertIsNone(proof)
        self.assertIsNone(subset)
        self.assertEqual(stats['candidates'],28)

    def test_candidate_budgets_are_exact_even_below_clock_check_interval(self):
        for phase in ('pin','subsets'):
            search = Search(self.instance,self.tx(),2,time.perf_counter()+10)
            with patch.object(self.instance,'proof',return_value=None):
                with self.assertRaisesRegex(RuntimeError,'budget exhausted'):
                    search.pin(0) if phase=='pin' else search.subsets()
            self.assertEqual(search.progress['candidates'],2)
            self.assertTrue(search.progress['budget_exhausted'])

    def test_expired_deadline_tests_no_candidates(self):
        search = Search(self.instance,self.tx(),100,time.perf_counter()-1)
        with self.assertRaisesRegex(RuntimeError,'budget exhausted'):
            search.pin(0)
        self.assertEqual(search.progress['candidates'],0)

    def test_exact_surrogate_size_and_signature_equation(self):
        instance = Instance(Parameters(entries=2,selections=1,puzzle='signature-size-surrogate',signature_bytes=69))
        for s, accepted in [(1,False),(2**231,True),(2**239-1,True),(2**239,False)]:
            z = (int.from_bytes(b'\x01'+bytes(31),'big')+1-s)%ec.N
            proof = instance.proof(self.tx(),z.to_bytes(32,'big'))
            self.assertEqual(proof is not None,accepted)
            if accepted:
                self.assertEqual(len(proof),69)
                key = ec.decompress_pubkey(instance.key(z.to_bytes(32,'big')))
                self.assertTrue(ec.ecdsa_verify(key,int.from_bytes(b'\x01'+bytes(31),'big'),instance.r,s))


if __name__ == '__main__':
    unittest.main()
