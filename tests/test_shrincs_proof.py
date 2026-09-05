import json
import unittest
from copy import deepcopy
from pathlib import Path
import subprocess
import tempfile

from btc_pq.crypto import ROOT
from btc_pq.shrincs_proof import REFERENCE, TOOL, authorizations, fixture, native, reference_replay


@unittest.skipUnless(REFERENCE.exists(), 'build the SHRINCS Rust proof verifier')
class ShrincsProofReferenceTests(unittest.TestCase):
    def test_full_vectors_and_negative_controls_match(self):
        with tempfile.TemporaryDirectory() as directory:
            report = reference_replay(Path(directory))
        self.assertEqual(len(report['cases']), 375)
        self.assertEqual(report['negative_controls'], 1875)

    def test_payment_claims_and_maximal_work_invalid_signature(self):
        tx, parents, signatures = fixture('two-inputs-valid')
        original = authorizations(tx, parents, signatures)
        changed = deepcopy(tx)
        changed.outputs[0].value -= 1
        altered = authorizations(changed, parents, signatures)
        self.assertTrue(all(a['message'] != b['message'] for a, b in
                            zip(original['authorizations'], altered['authorizations'])))
        changed = deepcopy(tx)
        changed.inputs[0].txid = '00'*32
        with self.assertRaises(ValueError):
            authorizations(changed, parents, signatures)
        directory = ROOT/'results/shrincs-demo/work-bounds'
        invalid = {name:list(bytes.fromhex((directory/(field+'.hex')).read_text()))
                   for name, field in (('key','pk'), ('message','msg'), ('signature','sig'))}
        result = subprocess.run([str(REFERENCE)], input=json.dumps([invalid]),
                                text=True, capture_output=True, check=True)
        work = json.loads(result.stdout)[0]
        self.assertFalse(work['valid'])
        self.assertEqual(work['compression_blocks'], 4941)
        self.assertEqual(work['wots_attempts'], 2)


@unittest.skipUnless(TOOL.exists() and (ROOT/'results/shrincs-proof/proofs.json').exists(),
                     'generate the three exact SHRINCS proof receipts')
class ShrincsReceiptTests(unittest.TestCase):
    def test_saved_receipts_bind_payment_and_reject_trailing_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            for name in ('compact-q1-valid', 'recovery-valid', 'two-inputs-valid'):
                tx, parents, signatures = fixture(name)
                batch = authorizations(tx, parents, signatures)
                receipt = ROOT/'results/shrincs-proof'/(name+'.receipt.bin')
                self.assertTrue(native('verify', batch, receipt)['valid'])
                changed = deepcopy(tx)
                changed.outputs[0].value -= 1
                altered = authorizations(changed, parents, signatures)
                self.assertFalse(native('verify', altered, receipt, expected=False)['valid'])
                appended = Path(directory)/(name+'.bin')
                appended.write_bytes(receipt.read_bytes()+b'\0')
                self.assertFalse(native('verify', batch, appended, expected=False)['valid'])


if __name__ == '__main__':
    unittest.main()
