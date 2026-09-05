from pathlib import Path
import tempfile
import unittest

from btc_pq.core import verify
from btc_pq.crypto import ROOT
from btc_pq.covenant_demo import funding, payment, p2mr
from btc_pq.shrincs_build import TOOL, VERIFIER
from btc_pq.shrincs_demo import native_tool
from btc_pq.shrincs_kat import parse_vectors


@unittest.skipUnless(TOOL.exists(), 'build the bounded SHRINCS verifier')
class WorkBudgetTests(unittest.TestCase):
    def test_two_final_candidates_reach_the_declared_bound(self):
        directory = ROOT/'results/shrincs-demo/work-bounds'
        paths = [directory/(k+'.hex') for k in ('pk', 'msg', 'sig')]
        result = native_tool('verify-bounded', *paths)
        self.assertFalse(result['valid'])
        self.assertEqual(result['wots_attempts'], 2)
        self.assertEqual(result['compression_blocks'], 4941)
        self.assertEqual(result['compression_blocks'], result['work_bound'])
        self.assertFalse(result['work_exhausted'])
        result = native_tool('verify-bounded', *paths, 4940)
        self.assertFalse(result['valid'])
        self.assertTrue(result['work_exhausted'])
        self.assertLessEqual(result['compression_blocks'], 4940)

    def test_exact_hash_budget_and_sampling_boundary(self):
        records = parse_vectors((ROOT/'results/shrincs-demo/upstream-kat-full.rsp').read_text())
        with tempfile.TemporaryDirectory() as directory:
            paths = [Path(directory)/k for k in ('pk', 'msg', 'sig')]
            for index in (0, 1, 13, 14, 15, 45, 374):
                record = records[index]
                for path, key in zip(paths, ('pk', 'msg', 'sig')):
                    path.write_text(record[key]+'\n')
                result = native_tool('verify-bounded', *paths)
                self.assertTrue(result['valid'])
                actual = result['compression_blocks']
                self.assertLessEqual(actual, result['work_bound'])
                self.assertTrue(native_tool('verify-bounded', *paths, actual)['valid'])
                for cap in (0, 1, actual-1):
                    rejected = native_tool('verify-bounded', *paths, cap)
                    self.assertFalse(rejected['valid'])
                    self.assertTrue(rejected['work_exhausted'])
                    self.assertLessEqual(rejected['compression_blocks'], cap)
                if len(bytes.fromhex(record['sig'])) == 3680:
                    for cap in (0, 1, 2):
                        rejected = native_tool('verify-bounded', *paths, result['work_bound'], cap)
                        self.assertFalse(rejected['valid'])
                        self.assertTrue(rejected['sampling_exhausted'])
                        self.assertEqual(rejected['xof_blocks'], cap)
                    self.assertTrue(native_tool('verify-bounded', *paths, result['work_bound'], 3)['valid'])

    def test_upfront_script_charge_cannot_be_bypassed_by_reuse(self):
        # Explicit test scripts discard the verifier's false result. They prove
        # the work charge applies even to invalid signatures and reused chunks.
        for recovery, allowed, denied in ((False, 1, 2), (True, 3, 4)):
            for repeats, expected in ((allowed, True), (denied, False)):
                if recovery:
                    signature = bytes(3680)
                    chunks = [signature[i:i+520] for i in range(0,3680,520)]
                    clone = bytes([0x57,0x79])*8  # Repeat 7 PICK to copy all 8 chunks.
                    count, cleanup = b'\x58', b'\x6d'*4
                else:
                    chunks = [bytes(324)]
                    clone, count, cleanup = b'\x76', b'\x51', b'\x75'
                check = clone+count+b'\x20'+bytes(32)+b'\xcf\x75'
                script = check*repeats+cleanup+b'\x51'
                output, control = p2mr(script)
                parent = funding(output, f'work-{recovery}-{repeats}')
                tx = payment([parent]); tx.inputs[0].witness = chunks+[script,control]
                with tempfile.TemporaryDirectory() as directory:
                    p, t = Path(directory)/'parent.hex', Path(directory)/'tx.hex'
                    p.write_text(parent.serialize().hex()); t.write_text(tx.serialize().hex())
                    result = verify(t, [p], VERIFIER)
                self.assertEqual(result['valid'], expected, (recovery, repeats, result))
                if not expected:
                    self.assertIn('signature validation', result['inputs'][0]['error'].lower())


if __name__ == '__main__':
    unittest.main()
