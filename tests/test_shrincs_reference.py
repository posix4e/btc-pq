from pathlib import Path
import unittest

from btc_pq.crypto import ROOT
from btc_pq.shrincs_c import CVerifier, LIBRARY
from btc_pq.shrincs_kat import parse_vectors
from btc_pq.shrincs_reference import verify


class ReferenceTests(unittest.TestCase):
    def test_saved_upstream_vectors_and_negative_controls(self):
        records = parse_vectors((ROOT/'results/shrincs-demo/upstream-kat.rsp').read_text())
        for record in records:
            message, signature, key = [bytes.fromhex(record[k]) for k in ('msg', 'sig', 'pk')]
            result = verify(message, signature, key)
            self.assertTrue(result['valid'], record['label'])
            self.assertGreater(result['compression_blocks'], 2000)
            for m, s, p in ((bytes([message[0]^1])+message[1:], signature, key),
                            (message, bytes([signature[0]^1])+signature[1:], key),
                            (message, signature, key[:16]+bytes([key[16]^1])+key[17:]),
                            (message, signature[:-1], key), (message, signature+b'\0', key)):
                self.assertFalse(verify(m, s, p)['valid'], record['label'])

    def test_shape_validation(self):
        for size in (0, 16, 307, 308, 323, 325, 3669, 3679, 3681, 4160):
            self.assertFalse(verify(bytes(32), bytes(size), bytes(32))['valid'])
        self.assertFalse(verify(bytes(32), bytes(324), bytes(31))['valid'])

    def test_complete_vector_set_and_variable_pors_terminal_height(self):
        records = parse_vectors((ROOT/'results/shrincs-demo/upstream-kat-full.rsp').read_text())
        self.assertEqual(len(records), 375)
        heights = set()
        for record in records:
            m, s, p = [bytes.fromhex(record[k]) for k in ('msg', 'sig', 'pk')]
            result = verify(m, s, p)
            self.assertTrue(result['valid'], record['count'])
            if result['mode'] == 'recovery':
                heights.add(result['pors_root_height'])
        self.assertEqual(heights, {16, 17})

    @unittest.skipUnless(LIBRARY.exists(), 'run python -m btc_pq.shrincs_c')
    def test_c_implementation_and_ignored_internal_randomness(self):
        c = CVerifier()
        records = parse_vectors((ROOT/'results/shrincs-demo/upstream-kat.rsp').read_text())
        for record in records:
            m, s, p = [bytes.fromhex(record[k]) for k in ('msg', 'sig', 'pk')]
            self.assertTrue(c.verify(m, s, p))
            self.assertFalse(c.verify(m, s[:-1], p))
            self.assertFalse(c.verify(bytes([m[0]^1])+m[1:], s, p))
        # Internal XMSS WOTS randomness is serialized but not used to hash its
        # already-digested message. A changed byte here is still a valid encoding.
        m, s, p = [bytes.fromhex(records[0][k]) for k in ('msg', 'sig', 'pk')]
        changed = bytearray(s)
        changed[16+1984] ^= 1
        self.assertTrue(c.verify(m, bytes(changed), p))
        self.assertTrue(verify(m, bytes(changed), p)['valid'])


if __name__ == '__main__':
    unittest.main()
