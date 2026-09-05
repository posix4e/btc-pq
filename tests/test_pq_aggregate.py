from copy import deepcopy
import json
import tempfile
import unittest

from btc_pq.bitcoin import Tx
from btc_pq.crypto import ROOT
from btc_pq.pq_aggregate import TOOL, claims, verify

FIXTURES = ROOT/'results/pq-aggregate'


@unittest.skipUnless(TOOL.exists() and (FIXTURES/'2.proof.bin').exists(), 'run python -m btc_pq.pq_aggregate --build')
class AggregateProofTests(unittest.TestCase):
    def test_saved_proof_binds_host_recomputed_transaction(self):
        tx = Tx.parse((FIXTURES/'2.tx.hex').read_text().strip())
        parents = [Tx.parse(raw) for raw in json.loads((FIXTURES/'2.parents.json').read_text())]
        keys = json.loads((FIXTURES/'2.keys.json').read_text())
        proof = FIXTURES/'2.proof.bin'
        self.assertTrue(verify(tx, parents, keys, proof)['valid'])
        changed = deepcopy(tx)
        changed.outputs[0].value -= 1
        self.assertFalse(verify(changed, parents, keys, proof)['valid'])
        # Even perfectly valid proofs only authorize their exact expected keys,
        # messages, and input positions; caller-supplied claims are not trusted.
        swapped = deepcopy(keys)
        swapped.reverse()
        self.assertFalse(verify(tx, parents, swapped, proof)['valid'])
        self.assertFalse(verify(tx, parents, keys, FIXTURES/'2.mutated-proof.bin')['valid'])

    def test_claims_cover_each_input_and_exact_parent(self):
        tx = Tx.parse((FIXTURES/'2.tx.hex').read_text().strip())
        parents = [Tx.parse(raw) for raw in json.loads((FIXTURES/'2.parents.json').read_text())]
        keys = json.loads((FIXTURES/'2.keys.json').read_text())
        original = claims(tx, parents, keys)
        self.assertEqual(original, json.loads((FIXTURES/'2.claims.json').read_text()))
        self.assertNotEqual(original[0]['message'], original[1]['message'])
        with self.assertRaises(ValueError):
            claims(tx, parents[:-1], keys)
        tx.inputs[0].vout += 1
        with self.assertRaises(ValueError):
            claims(tx, parents, keys)


if __name__ == '__main__':
    unittest.main()
