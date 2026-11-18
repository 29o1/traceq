"""Native OS argument errors stay bounded and never become Rust panics."""
import json
import os
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
CLI = os.fsencode(ROOT / 'cli/traceq')


@unittest.skipUnless(os.name == 'posix', 'raw argv bytes use the POSIX interface')
class NativeArguments(unittest.TestCase):
    def test_invalid_utf8_is_an_argument_error(self):
        for prefix in ([b'stat'], [b'agent-query', b'sample', b'stat']):
            for json_mode in (False, True):
                args = [CLI, *prefix, b'file-\xff.gtsw', *([b'--json'] if json_mode else [])]
                result = subprocess.run(args, capture_output=True, timeout=10)
                self.assertEqual(result.returncode, 2)
                self.assertNotIn(b'panicked', result.stderr)
                if json_mode:
                    self.assertEqual(json.loads(result.stdout), {
                        'error': {'code': 'ARGUMENT', 'message': 'arguments require valid UTF-8'}})
                    self.assertEqual(result.stderr, b'')
                else:
                    self.assertEqual(result.stdout, b'')
                    self.assertEqual(result.stderr, b'traceq: arguments require valid UTF-8\n')


if __name__ == '__main__':
    unittest.main()
