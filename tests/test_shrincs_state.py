import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from btc_pq.shrincs_build import TOOL
from btc_pq import shrincs_state as wallet


@unittest.skipUnless(TOOL.exists(), 'run btc-pq shrincs-demo --build')
class PersistentStateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)/'signer'
        wallet.create(self.directory)

    def test_restart_idempotence_and_request_binding(self):
        first = wallet.sign(self.directory, bytes(32), 'payment-1')
        second = wallet.sign(self.directory, bytes([1])*32, 'payment-2')
        self.assertEqual((first['q'], second['q']), (1, 2))
        self.assertEqual(wallet.sign(self.directory, bytes(32), 'payment-1'), first)
        self.assertEqual(wallet.read_state(self.directory)['next_q'], 3)
        with self.assertRaisesRegex(ValueError, 'different message'):
            wallet.sign(self.directory, bytes([2])*32, 'payment-1')
        with self.assertRaises(FileExistsError):
            wallet.create(self.directory)

    def test_process_exit_after_reservation_consumes_position(self):
        code = ('import os,sys; from btc_pq.shrincs_state import sign; '
                'sign(sys.argv[1],bytes(32),"interrupted",after_reserve=lambda:os._exit(73))')
        result = subprocess.run([sys.executable, '-c', code, str(self.directory)])
        self.assertEqual(result.returncode, 73)
        state = wallet.read_state(self.directory)
        self.assertEqual(state['next_q'], 2)
        self.assertEqual(state['requests']['interrupted']['status'], 'reserved')
        retried = wallet.sign(self.directory, bytes(32), 'interrupted')
        self.assertEqual(retried['q'], 2)
        self.assertEqual(wallet.read_state(self.directory)['requests']['interrupted']['reservations'], [1, 2])

    def test_concurrent_processes_get_distinct_positions(self):
        code = ('import json,sys; from btc_pq.shrincs_state import sign; '
                'print(json.dumps(sign(sys.argv[1],bytes([int(sys.argv[2])])*32,sys.argv[2])))')
        processes = [subprocess.Popen([sys.executable, '-c', code, str(self.directory), str(i)],
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for i in (1, 2)]
        results = []
        for process in processes:
            stdout, stderr = process.communicate(timeout=60)
            self.assertEqual(process.returncode, 0, stderr)
            results.append(json.loads(stdout))
        self.assertEqual(sorted(r['q'] for r in results), [1, 2])
        self.assertEqual(wallet.read_state(self.directory)['next_q'], 3)

    def test_seed_restore_and_exhaustion_use_recovery(self):
        state = wallet.read_state(self.directory)
        restored = self.directory.parent/'restored'
        info = wallet.create(restored, restore_seed=bytes.fromhex(state['seed']))
        self.assertFalse(info['compact_enabled'])
        recovery = wallet.sign(restored, bytes(32), 'restored-payment')
        self.assertEqual(recovery['mode'], 'recovery')
        self.assertEqual(recovery['public_key'], state['public_key'])
        self.assertEqual(len(bytes.fromhex(recovery['signature'])), 3680)
        # Burn unused earlier positions to test the terminal boundary quickly.
        state['next_q'] = 211
        wallet.durable_json(self.directory/'state.json', state)
        last = wallet.sign(self.directory, bytes([3])*32, 'last-compact')
        exhausted = wallet.sign(self.directory, bytes([4])*32, 'exhausted')
        self.assertEqual((last['q'], len(bytes.fromhex(last['signature']))), (211, 3668))
        self.assertEqual(exhausted['mode'], 'recovery')
        self.assertEqual(wallet.read_state(self.directory)['next_q'], 212)

    def test_corrupt_state_does_not_reinitialize(self):
        (self.directory/'state.json').write_text('{')
        with self.assertRaises(json.JSONDecodeError):
            wallet.sign(self.directory, bytes(32), 'payment')
        self.assertEqual((self.directory/'state.json').read_text(), '{')


if __name__ == '__main__':
    unittest.main()
