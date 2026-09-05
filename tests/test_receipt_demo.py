import ctypes
import json
from pathlib import Path
import tempfile
import unittest

from btc_pq.crypto import ROOT
from btc_pq.receipt_demo import VERIFIER, TARGET, run


@unittest.skipUnless(VERIFIER.exists(), 'build the native receipt transaction checker')
class ReceiptTransactionTests(unittest.TestCase):
    def test_native_payment_and_receipt_mutations(self):
        with tempfile.TemporaryDirectory() as directory:
            for receipts in ('shrincs-proof','shrincs-proof-compressed'):
                report = run(Path(directory)/receipts,receipts=ROOT/'results'/receipts)
                self.assertEqual(len(report['cases']), 16)
                self.assertTrue(report['cases'][0]['result']['group_authorized'])
                self.assertTrue(all(not c['result']['valid'] for c in report['cases'][1:]))

    def test_ffi_binds_image_and_claims_and_rejects_malformed_bytes(self):
        library = TARGET/'release/libbtc_pq_receipt.dylib'
        if not library.exists(): library = TARGET/'release/libbtc_pq_receipt.so'
        verify = ctypes.CDLL(str(library)).btc_pq_receipt_verify
        verify.argtypes = [ctypes.c_void_p,ctypes.c_size_t,ctypes.c_void_p,ctypes.c_void_p]
        verify.restype = ctypes.c_int
        path = ROOT/'results/shrincs-proof'
        proof = (path/'compact-q1-valid.receipt.bin').read_bytes()
        saved = json.loads((path/'execution.json').read_text())['cases'][0]['result']
        image = bytes.fromhex(saved['image_id']); journal = bytes.fromhex(saved['claims_digest'])
        def check(data, expected_image=image, expected_journal=journal):
            buffers = [ctypes.create_string_buffer(value) for value in (data,expected_image,expected_journal)]
            return verify(buffers[0],len(data),buffers[1],buffers[2])
        self.assertEqual(check(proof),1)
        self.assertEqual(check(proof,bytes([image[0]^1])+image[1:]),0)
        self.assertEqual(check(proof,image,bytes([journal[0]^1])+journal[1:]),0)
        for malformed in (b'',b'\0',proof[:-1],proof+b'\0'):
            self.assertEqual(check(malformed),0)
        self.assertEqual(verify(None,0,None,None),0)


if __name__ == '__main__':
    unittest.main()
