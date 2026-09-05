from copy import deepcopy
from pathlib import Path
import tempfile
import unittest

from btc_pq.bitcoin import Input, Output, Tx, num, push
from btc_pq.core import verify
from btc_pq.covenant_build import VERIFIER
from btc_pq.covenant_demo import (BYTE_ENCODING, funding, lamport_script, lamport_witness,
                                  p2mr, payment, run, replay, tagged_hash, tapleaf,
                                  template_hash, test_keys)


class TemplateCoverageTests(unittest.TestCase):
    def test_committed_and_omitted_fields(self):
        tx = Tx([Input('11'*32, 0), Input('22'*32, 1)], [Output(100, b'\x51')])
        digest = template_hash(tx)
        for change in ('output_value', 'output_script', 'sequence', 'version', 'locktime', 'input_count'):
            changed = deepcopy(tx)
            if change == 'output_value': changed.outputs[0].value += 1
            elif change == 'output_script': changed.outputs[0].script = b'\x00'
            elif change == 'sequence': changed.inputs[1].sequence -= 1
            elif change == 'version': changed.version += 1
            elif change == 'locktime': changed.locktime += 1
            else: changed.inputs.append(Input('33'*32, 0))
            self.assertNotEqual(template_hash(changed), digest, change)
        self.assertNotEqual(template_hash(tx, 1), digest)
        self.assertNotEqual(template_hash(tx, annex=b'\x50'), digest)
        changed = deepcopy(tx)
        changed.inputs[0].txid = '44'*32
        changed.inputs[0].vout = 5
        self.assertEqual(template_hash(changed), digest)


@unittest.skipUnless(VERIFIER.exists(), 'run btc-pq covenant-demo --build for native proposal tests')
class NativeCovenantTests(unittest.TestCase):
    def check_spend(self, tx, parent):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            spend, prev = directory/'spend.hex', directory/'parent.hex'
            spend.write_text(tx.serialize().hex())
            prev.write_text(parent.serialize().hex())
            return verify(spend, [prev], VERIFIER)

    def check_script(self, script, witness=()):
        spk, control = p2mr(script)
        parent = funding(spk, 'script-test')
        tx = payment([parent])
        tx.inputs[0].witness = list(witness) + [script, control]
        return self.check_spend(tx, parent)

    def test_all_256_byte_encodings(self):
        script = b''.join(num(i) + BYTE_ENCODING + push(bytes([i])) + b'\x88' for i in range(256)) + b'\x51'
        self.assertTrue(self.check_script(script)['valid'])

    def test_lamport_digest_reconstruction(self):
        # Exercise every byte value through the real native interpreter, with
        # separate one-time keys for every message (no signing-state reuse).
        for start in range(0, 256, 32):
            message = bytes(range(start, start+32))
            keys = test_keys('byte-coverage-'+str(start))
            script = lamport_script(keys)[:-2] + push(message) + b'\x87'
            with self.subTest(start=start):
                self.assertTrue(self.check_script(script, lamport_witness(keys, message))['valid'])

    def test_cat_boundaries_and_branch_semantics(self):
        exact = push(b'a'*260) + push(b'b'*260) + b'\x7e\x82' + num(520) + b'\x87\x77'
        self.assertTrue(self.check_script(exact)['valid'])
        overflow = push(b'a'*260) + push(b'b'*261) + b'\x7e\x75\x51'
        self.assertFalse(self.check_script(overflow)['valid'])
        self.assertFalse(self.check_script(b'\x7e\x51')['valid'])
        self.assertTrue(self.check_script(b'\x00\x63\x7e\x68\x51')['valid'])
        # It must stay disabled in legacy script even with the demo flag.
        parent = funding(b'\x00\x63\x7e\x68\x51', 'legacy-cat')
        self.assertFalse(self.check_spend(payment([parent]), parent)['valid'])

    def test_annex_hash_matches_native(self):
        script = b'\xce\x87'
        parent = funding(p2mr(script)[0], 'annex-test')
        tx = payment([parent])
        annex = b'\x50' + b'a'*253  # exercises CompactSize in the annex hash
        digest = template_hash(tx, annex=annex)
        tx.inputs[0].witness = [digest, script, p2mr(script)[1], annex]
        result = self.check_spend(tx, parent)
        self.assertTrue(result['valid'])
        self.assertEqual(result['inputs'][0]['template_hash'], digest.hex())
        tx.inputs[0].witness[-1] += b'b'
        self.assertFalse(self.check_spend(tx, parent)['valid'])

    def test_p2mr_commitment_and_reserved_branches(self):
        script = b'\x51'
        spk, control = p2mr(script)
        parent = funding(spk, 'control-test')
        tx = payment([parent])
        tx.inputs[0].witness = [script, control]
        self.assertTrue(self.check_spend(tx, parent)['valid'])
        for malformed in (b'', b'\xc0'+control[1:], control+b'\x00', b'\xc1'+bytes(32*129)):
            tx.inputs[0].witness = [script, malformed]
            self.assertFalse(self.check_spend(tx, parent)['valid'])
        # Select the sibling: the same root commits an explicitly failing leaf.
        tx.inputs[0].witness = [b'\x6a', b'\xc1'+tapleaf(script)]
        self.assertFalse(self.check_spend(tx, parent)['valid'])
        # Draft depth-zero behavior is intentionally *not* a secure auth leaf.
        parent = funding(b'\x52\x20'+tapleaf(b'\x6a'), 'depth-zero')
        tx = payment([parent])
        tx.inputs[0].witness = [b'\x6a', b'\xc1']
        self.assertTrue(self.check_spend(tx, parent)['valid'])
        # Future leaf versions retain their upgrade-hook semantics.
        leaf = tapleaf(b'\x6a', 0xc2)
        sibling = tapleaf(b'\x6a')
        root = tagged_hash('TapBranch', b''.join(sorted([leaf, sibling])))
        parent = funding(b'\x52\x20'+root, 'future-leaf')
        tx = payment([parent])
        tx.inputs[0].witness = [b'\x6a', b'\xc3'+sibling]
        self.assertTrue(self.check_spend(tx, parent)['valid'])

    def test_matrix_and_replay(self):
        with tempfile.TemporaryDirectory() as directory:
            result = run(directory)
            self.assertTrue(result['all_expectations_met'])
            self.assertEqual(len(result['cases']), 27)
            self.assertTrue(replay(directory)['all_expectations_met'])
            case = Path(directory)/result['cases'][0]['spend']
            case.write_text('00')
            with self.assertRaisesRegex(ValueError, 'fixture changed'):
                replay(directory)


if __name__ == '__main__':
    unittest.main()
