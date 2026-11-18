"""Retired text/GTB inputs never become successful structured queries."""
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / 'cli/traceq'
RETIRED = ('import', 'export', 'taint', 'fold', 'diff', 'calls', 'calltree', 'call-tree')


class RetiredFormats(unittest.TestCase):
    def invoke(self, args):
        return subprocess.run([str(CLI), *map(str, args)], capture_output=True, text=True,
                              timeout=10)

    def test_retired_commands(self):
        help_text = self.invoke(['--help']).stdout
        for command in RETIRED:
            self.assertFalse(any(line.split()[:1] == [command] for line in help_text.splitlines()))
            result = self.invoke([command, 'missing.gtb', '--json'])
            self.assertEqual(result.returncode, 2)
            self.assertEqual(set(json.loads(result.stdout)), {'error'})

    def test_rejects_old_formats_even_for_empty_selection(self):
        with tempfile.TemporaryDirectory(prefix='traceq-retired-') as directory:
            path = Path(directory) / 'input.gtsw'
            # Literal old header identity and a representative text line are
            # independent rejection inputs; no legacy writer is kept in tests.
            # Completed, one-event GTB2 fixture accepted by frozen CLI106.
            # Frozen generation command and old stat output are in round108.
            valid_gtb = bytes.fromhex(
                '3242544700000000484354470200000009000000010006010002020002484354470100000071000000020000000a000000666978747572652e736f02000000783001000000000000000010000000000000240000005b666978747572652e736f5d2030783130303021307830206d6f762078302c2023313b200100000080200000ff0800000024180a00000001000001000000000800000102004843544703000000050000000101011500'
            )
            for data in (valid_gtb, struct.pack('<I', 0x47544232) + bytes(256),
                         b'[module] 0x1000: add x0, x0, #1; x0=0x2\n'):
                path.write_bytes(data)
                for command, args in (
                    ('stat', []), ('instructions', ['--from', '999999', '--limit', '1']),
                    ('context', ['--at-ev', '999999', '--before', '0', '--after', '0']),
                    ('reg-state', ['--at-ev', '0', '--reg', 'x0']),
                    ('mem-state', ['--at-ev', '0', '--range', '0x2000,1']),
                    ('mem-access', ['--range', '0x2000,1']),
                    ('last-writers', ['--range', '0x2000,1']),
                    ('boundaries', ['--from', '999999']),
                    ('find-pc', ['--off', '0']),
                    ('find-value', ['--value', '0']),
                ):
                    with self.subTest(command=command, prefix=data[:8]):
                        result = self.invoke([command, path, *args, '--json'])
                        self.assertNotEqual(result.returncode, 0)
                        self.assertEqual(set(json.loads(result.stdout)), {'error'})

    def test_structured_identity_is_content_based(self):
        with tempfile.TemporaryDirectory(prefix='traceq-retired-') as directory:
            path = Path(directory) / 'capture.gtb'
            header = b'GTSW001\0' + struct.pack('<7Q', 0x1000, 0x100, 0x2000, 32, 1, 2, 64)
            # An empty, completed profile2 stream. Suffix validation still runs
            # even when a selector cannot return any event.
            end = struct.pack('<8Q', 4, 0, 0, 0, 0, 0, 0, 2)
            path.write_bytes(header + end)
            result = self.invoke(['stat', path, '--json'])
            self.assertEqual(result.returncode, 0, result.stdout)
            path.write_bytes(header + end + b'x')
            result = self.invoke(['instructions', path, '--from', '999999', '--json'])
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(set(json.loads(result.stdout)), {'error'})


if __name__ == '__main__':
    unittest.main()
