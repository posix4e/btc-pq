from copy import deepcopy
from pathlib import Path
import json
import shutil
import tempfile
import unittest

from btc_pq.bitcoin import Tx
from btc_pq.core import verify
from btc_pq.crypto import ROOT
from btc_pq.covenant_demo import funding, payment, p2mr
from btc_pq.shrincs_build import VERIFIER
from btc_pq.shrincs_demo import auth_script, replay, signed_message, witness
from btc_pq.shrincs_kat import parse_vectors, replay as replay_kat

FIXTURES = ROOT/'results/shrincs-demo'


@unittest.skipUnless(VERIFIER.exists(), 'run btc-pq shrincs-demo --build')
class ShrincsNativeTests(unittest.TestCase):
    def check(self, tx, parents):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            spend = directory/'spend.hex'
            spend.write_text(tx.serialize().hex())
            paths = []
            for index, parent in enumerate(parents):
                p = directory/(str(index)+'.hex')
                p.write_text(parent.serialize().hex())
                paths.append(p)
            return verify(spend, paths, VERIFIER)

    def test_full_message_matches_native_with_annex_and_multiple_inputs(self):
        scripts = [auth_script(bytes([i])*32) for i in (1, 2)]
        trees = [p2mr(script) for script in scripts]
        parents = [funding(tree[0], 'digest-'+str(i)) for i, tree in enumerate(trees)]
        original = payment(parents)
        original_messages = [signed_message(original, parents, i, scripts[i]) for i in range(2)]
        for mutation in ('none', 'version', 'locktime', 'amount', 'other_sequence', 'spent_amount', 'annex'):
            tx, prevs = deepcopy(original), deepcopy(parents)
            annex = b'\x50'+bytes(253) if mutation == 'annex' else None
            if mutation == 'version': tx.version += 1
            if mutation == 'locktime': tx.locktime += 1
            if mutation == 'amount': tx.outputs[0].value += 1
            if mutation == 'other_sequence': tx.inputs[1].sequence -= 1
            if mutation == 'spent_amount':
                prevs[1].outputs[0].value += 1
                tx.inputs[1].txid = prevs[1].txid
            expected = []
            for i in range(2):
                tx.inputs[i].witness = witness(bytes(324), scripts[i], trees[i][1], annex)
                expected.append(signed_message(tx, prevs, i, scripts[i], annex).hex())
            result = self.check(tx, prevs)
            self.assertFalse(result['valid'])  # Message computed; deliberately invalid PQ signature.
            self.assertEqual([r['message_digest'] for r in result['inputs']], expected)
            if mutation != 'none':
                self.assertNotEqual(expected[0], original_messages[0].hex())

    @unittest.skipUnless((FIXTURES/'report.json').exists(), 'generate SHRINCS fixtures first')
    def test_saved_matrix_and_fixture_integrity(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)/'fixtures'
            shutil.copytree(FIXTURES, target)
            result = replay(target)
            self.assertEqual(len(result['cases']), 37)
            self.assertTrue(result['all_expectations_met'])
            report = json.loads((target/'report.json').read_text())
            first = next(iter(report['fixture_sha256']))
            (target/first).write_text('00')
            with self.assertRaisesRegex(ValueError, 'fixture changed'):
                replay(target)

    @unittest.skipUnless((FIXTURES/'report.json').exists(), 'generate SHRINCS fixtures first')
    def test_chunk_boundaries_and_length_dispatch(self):
        report = json.loads((FIXTURES/'report.json').read_text())
        for mode in ('compact-q1', 'recovery'):
            case = next(c for c in report['cases'] if c['name'] == mode+'-valid')
            tx = Tx.parse((FIXTURES/case['spend']).read_text().strip())
            parents = [Tx.parse((FIXTURES/p).read_text().strip()) for p in case['parents']]
            for malformed in (b'', b'\x81', b'\x09', b'\x01\x00'):
                changed = deepcopy(tx)
                changed.inputs[0].witness[-3] = malformed
                self.assertFalse(self.check(changed, parents)['valid'])
            changed = deepcopy(tx)
            changed.inputs[0].witness[0] = bytes(521)
            self.assertFalse(self.check(changed, parents)['valid'])
            for length in (1, 307, 308, 323, 325, 3669, 3679, 3681, 4160):
                changed = deepcopy(tx)
                w = changed.inputs[0].witness
                changed.inputs[0].witness = witness(bytes(length), w[-2], w[-1])
                self.assertFalse(self.check(changed, parents)['valid'], length)

    @unittest.skipUnless((FIXTURES/'upstream-kat.rsp').exists(), 'generate upstream KAT sample first')
    def test_upstream_vectors_and_final_state_boundaries(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'upstream-kat.rsp'
            shutil.copyfile(FIXTURES/'upstream-kat.rsp', path)
            records = parse_vectors(path.read_text())
            self.assertEqual(len(records), 15)
            self.assertIn('q=210', records[-2]['label'])
            self.assertIn('q=211', records[-1]['label'])
            result = replay_kat(path)
            self.assertTrue(result['all_expectations_met'])
            self.assertEqual(result['cases'][-1]['signature_bytes'], 3668)


if __name__ == '__main__':
    unittest.main()
