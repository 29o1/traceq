"""Native CLI argument errors and help behavior."""
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
        for prefix in ([b'stat'], [b'context']):
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

    def test_product_help_and_dispatch_exclude_evaluation(self):
        help_text = subprocess.check_output([CLI, b'--help'], timeout=10)
        self.assertNotIn(b'agent-query', help_text)
        result = subprocess.run(
            [CLI, b'agent-query', b'--capabilities', b'--json'],
            capture_output=True, timeout=10,
        )
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stdout)['error']['code'], 'ARGUMENT')

    def test_state_command_help_shows_only_requested_usage(self):
        commands = {
            b'stat': (b'--json', b'full input validation'),
            b'instructions': (b'--mnemonic', b'--gap-reason'),
            b'boundaries': (b'--target-module', b'--reg'),
            b'find-pc': (b'--off', b'--addr', b'--module'),
            b'reg-state': (b'--at-ev', b'--phase', b'--reg'),
            b'mem-access': (b'--range', b'--pc', b'--source-table'),
            b'mem-state': (b'--checkpoint', b'--range-checkpoint', b'--source-runs'),
        }
        for command, options in commands.items():
            with self.subTest(command=command):
                help_text = subprocess.check_output([CLI, command, b'--help'], timeout=10)
                self.assertEqual(help_text, subprocess.check_output([CLI, command, b'-h'], timeout=10))
                usage_commands = {line.split()[1] for line in help_text.splitlines()
                                  if line.startswith(b'traceq ')}
                self.assertEqual(usage_commands, {command})
                for option in options:
                    self.assertIn(option, help_text)


if __name__ == '__main__':
    unittest.main()
