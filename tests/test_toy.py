"""Toy opcode, native recovery, actual Script, and search differential checks."""
from itertools import combinations
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from btc_pq.bitcoin import Tx, Input, Output, push, num, legacy_sighash
from btc_pq.core import verify
from btc_pq.crypto import ec, recover, encode, secret
from btc_pq.experiments import write_tx
from btc_pq.toy import ToyInstance, toy_signature, native, search, authorization_bytes
from btc_pq import toy_build


@unittest.skipUnless(toy_build.SEARCH.exists() and toy_build.VERIFIER.exists(),'build experimental tools first')
class ToyTests(unittest.TestCase):
    def key_hit(self,bits=4):
        for i in range(10000):
            key=encode(ec.point_mul(i+1,ec.G))
            if toy_signature(key,bits): return key
        self.fail('test-key gate search exhausted')

    def native_case(self,key,bits,expected,wrong_pubkey=False):
        # Witness carries Q and the puzzle verification public key. Only the
        # hash opcode differs; DER parsing and ECDSA checking are Core's own.
        script=num(bits)+b'\x7e\x7c\xac'
        parent=Tx([Input('00'*32,0)], [Output(10000,script)])
        tx=Tx([Input(parent.txid,0)], [Output(9000,b'\x51')])
        sig=toy_signature(key,bits)
        proof_key=encode(ec.G)
        if sig and not wrong_pubkey:
            z=legacy_sighash(tx,0,script,sig,1)
            proof_key=encode(recover(2,int.from_bytes(sig[7:-1],'big'),z,0))
        tx.inputs[0].script=push(proof_key)+push(key)
        with TemporaryDirectory() as directory:
            parent_file=write_tx(Path(directory)/'parent.hex',parent)
            spend=write_tx(Path(directory)/'spend.hex',tx)
            toy=verify(spend,[parent_file],toy_build.VERIFIER)
            stock=verify(spend,[parent_file])
        self.assertEqual(toy['valid'],expected)
        self.assertFalse(stock['valid'])
        self.assertIn('disabled opcode',stock['inputs'][0]['error'].lower())
        return toy

    def test_opcode_produces_real_der_and_ecdsa_signature(self):
        key=self.key_hit()
        self.native_case(key,4,True)
        rejected=self.native_case(key,4,False,wrong_pubkey=True)
        self.assertNotEqual(rejected['inputs'][0]['error'],'No error')

    def test_opcode_rejects_invalid_target_key_and_failed_gate(self):
        key=self.key_hit()
        self.native_case(key,0,False)
        self.native_case(key,25,False)
        self.native_case(b'\x05'+key[1:],4,False)
        self.native_case(encode(ec.G,'uncompressed'),4,False)
        for i in range(1,100):
            candidate=encode(ec.point_mul(i,ec.G))
            if toy_signature(candidate,4) is None:
                self.native_case(candidate,4,False); break

    def test_native_general_recovery_matches_public_scalar_shortcut(self):
        digests=[n.to_bytes(32,'big') for n in (0,1,ec.N-1,ec.N,ec.N+1,2**256-1)]+[secret(f'toy-test/{i}') for i in range(8)]
        result=native(dict(mode='vectors',bits=4,digests=[d.hex() for d in digests]))
        for z,row in zip(digests,result['vectors'],strict=True):
            q=recover(ec.G[0],1,z,0)
            key=encode(q) if q else b''
            self.assertEqual(row['key_hex'],key.hex())
            self.assertEqual(row['general_recovery_key_hex'],key.hex())
            sig=toy_signature(key,4)
            self.assertEqual(row['signature_hex'],sig.hex() if sig else '')

    def test_first_native_pin_and_subset_hits_match_python_enumeration(self):
        instance=ToyInstance(4,16,3)
        tx=Tx([Input('11'*32,0),Input('22'*32,1,sequence=0x80000000)], [Output(19000,b'\x51')])
        pin=search(instance,tx,'pin',10000,30)
        self.assertTrue(pin['found'])
        probe=Tx.parse(tx.serialize())
        for counter in range(pin['winning_counter']+1):
            probe.inputs[1].sequence=0x80000000|counter
            passes=toy_signature(instance.key(instance.digest(probe)),4) is not None
            self.assertEqual(passes,counter==pin['winning_counter'])
        digest=search(instance,tx,'subset',10000,30)
        self.assertTrue(digest['found'])
        for subset in combinations(range(16),3):
            passes=toy_signature(instance.key(instance.digest(tx,subset)),4) is not None
            if list(subset)==digest['selected_indices']:
                self.assertTrue(passes); break
            self.assertFalse(passes)

    def test_native_candidate_budget_and_subset_exhaustion(self):
        instance=ToyInstance(24,2,1)
        tx=Tx([Input('33'*32,0),Input('44'*32,1,sequence=0x80000000)], [Output(19000,b'\x51')])
        result=search(instance,tx,'pin',2,30)
        self.assertFalse(result['found']); self.assertTrue(result['budget_exhausted'])
        self.assertEqual(result['measurement']['candidates'],2)
        result=search(instance,tx,'subset',10,30)
        self.assertFalse(result['found']); self.assertTrue(result['space_exhausted'])
        self.assertEqual(result['measurement']['candidates'],2)

    def test_frozen_authorization_requires_only_original_preimages(self):
        instance=ToyInstance(4,8,2)
        z=secret('toy/auth/z'); pair=(z,encode(ec.G)); subset=[1,3]
        tx=Tx([Input('55'*32,0),Input('66'*32,1)], [Output(19000,b'\x51')])
        tx.inputs[1].script=instance.witness(pair,pair,subset)
        expected=authorization_bytes(tx,2)
        restricted={i:instance.preimages[i] for i in subset}
        tx.inputs[1].script=instance.witness(pair,pair,subset,restricted)
        self.assertEqual(authorization_bytes(tx,2),expected)
        with self.assertRaises(KeyError):
            instance.witness(pair,pair,[1,4],restricted)


if __name__=='__main__':
    unittest.main()
