import contextlib
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import analyse as entry
from test_contract import fixture

class EntryTests(unittest.TestCase):
    def test_final_origin_result_cli_and_exact_input_hash(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            client, origin, resources = fixture()
            for name, value in [('client', client), ('origin', origin), ('resources', resources)]:
                (root/name).write_text(json.dumps(value))
            args = ['analyse.py', '--client', str(root/'client'), '--origin-result', str(root/'origin'),
                    '--resources', str(root/'resources'), '--output', str(root/'output')]
            with patch.object(sys, 'argv', args):
                entry.main()
            result = json.loads((root/'output').read_text())
            self.assertEqual(result['status'], 'QUALIFIED_PROTOCOL_LATENCY_ONLY')
            self.assertEqual(result['input_sha256']['origin_result'], hashlib.sha256((root/'origin').read_bytes()).hexdigest())
            self.assertFalse(result['performance_claim'])

    def test_obsolete_snapshot_cli_argument_rejected(self):
        with patch.object(sys, 'argv', ['analyse.py', '--origin-proof', 'x']), contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                entry.main()

if __name__ == '__main__':
    unittest.main()
