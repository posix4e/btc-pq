from copy import deepcopy
import json
import tempfile
import unittest

from btc_pq.cisa_demo import SOURCE, run, upstream, verify_group


@unittest.skipUnless((SOURCE/'manifest.json').exists(), 'run python -m btc_pq.cisa_demo --fetch')
class CisaTests(unittest.TestCase):
    def test_upstream_wallet_reproduction_and_payment_mutations(self):
        with tempfile.TemporaryDirectory() as directory:
            report = run(directory)
            self.assertEqual(len(report['cases']), 66)
            self.assertTrue(report['all_expectations_met'])
            self.assertTrue(report['published_wallet_vectors_reproduced'])
            self.assertEqual([m['signature_data_bytes'] for m in report['measurements']],
                             [128, 97, 65, 640, 353, 65])

    def test_marker_mode_and_witness_shape(self):
        u = upstream()
        keys = [u.tweak_keypair(u.test_seckey(i)) for i in range(2)]
        parents = [u.TxOut(100000, u.v2_script_pubkey(k[3])) for k in keys]
        tx = u.Tx([u.TxIn(u.test_prevout_txid(i), 0) for i in range(2)], [u.TxOut(199000, b'\x51')])
        _, sigs, aggregate = u.sign_halfagg_group(tx, parents, [(i, k[2], 0) for i, k in enumerate(keys)])
        tx.witnesses = [[sigs[0][:32]], [u.halfagg_final(aggregate)]]
        self.assertTrue(verify_group(tx, parents, 'half'))
        self.assertFalse(verify_group(tx, parents, 'full'))
        for replacement in (b'', tx.witnesses[-1][0][:-1], tx.witnesses[-1][0]+b'\0',
                            tx.witnesses[-1][0][:-1]+b'\xbd'):
            changed = deepcopy(tx)
            changed.witnesses[-1][0] = replacement
            self.assertFalse(verify_group(changed, parents, 'half'))
        tx.witnesses = [[s] for s in sigs]
        self.assertFalse(verify_group(tx, parents, 'plain'))  # Aggregation-mode messages cannot opt out.


if __name__ == '__main__':
    unittest.main()
