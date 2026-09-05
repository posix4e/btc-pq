from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from btc_pq.core import VERIFIER
from btc_pq.holding_demo import create_backup, prepare, restore_backup


class HoldingBackupTests(unittest.TestCase):
    def test_restore_requires_the_funded_commitment(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'backup.json'
            commitment=create_backup(path)
            secret=restore_backup(path,commitment)
            self.assertEqual(len(secret),32)
            original=json.loads(path.read_text())
            self.assertEqual(path.stat().st_mode & 0o777,0o600)
            with self.assertRaises(ValueError):create_backup(path)
            with self.assertRaises(ValueError):restore_backup(path,sha256(b'other output').digest())
            for field,value in [('version',2),('network','main'),('secret','00'*32),('commitment','00'*32)]:
                changed=deepcopy(original);changed[field]=value
                path.write_text(json.dumps(changed))
                with self.assertRaises(ValueError):restore_backup(path,commitment)

    @unittest.skipUnless(VERIFIER.exists() and shutil.which('bitcoind'),'stock Core and native checker required')
    def test_funding_backup_restore_and_unbound_disclosure(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            result=prepare(root/'public',root/'private/backup.json')
            self.assertEqual(len(result['cases']),8)
            self.assertTrue(result['fresh_process_backup_restore'])
            self.assertTrue(result['fresh_node_funding_replay'])
            self.assertTrue(result['remains_unspent_after_10_more_blocks'])
            self.assertFalse(result['secret_bearing_spend_broadcast'])
            verdicts={c['case']:c['native_valid'] for c in result['cases']}
            self.assertFalse(verdicts['wrong_secret'])
            self.assertTrue(verdicts['copied_secret_changed_recipient'])
            secret=json.loads((root/'private/backup.json').read_text())['secret']
            for path in (root/'public').rglob('*'):
                if path.is_file():self.assertNotIn(secret,path.read_text())


if __name__=='__main__':unittest.main()
