"""Self-contained evaluation entry checks using a literal trace and no model."""
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

import bench
import query


def fixture(path):
    site = int.from_bytes(b'strh', 'little')
    rows = [
        (8, 0, 0x1000, 0x79000020, 4, site, 0, 0),
        (1, 0, 0x1000, 0x79000020, 0, 0, 0, 1),
        (2, 0, 0x1000, 0x2000, 2, 0xaabb, 0, 1),
        (9, 0, 0x1000, 0, 0, 0, 0, 1),
        (4, 1, 0, 1, 0, 0, 1, 2),
    ]
    path.write_bytes(
        b'GTSW001\0' + struct.pack('<7Q', 0x1000, 4, 0x2000, 2, 1, 2, 64)
        + b''.join(struct.pack('<8Q', *row) for row in rows)
    )


class Entry(unittest.TestCase):
    def test_root_manifest_error_is_recorded(self):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                [bench.EVAL_CLI, 'agent-query', '--manifest', '/', 'sample', 'stat'],
                cwd=directory, capture_output=True, timeout=10,
            )
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertEqual(result.stderr, b'')
            self.assertEqual(json.loads(result.stdout)['error']['code'], 'ADAPTER_CONFIG')
            record = json.loads((Path(directory) / 'queries/calls.jsonl').read_text())
            self.assertEqual(record['failure_origin'], 'adapter')
            self.assertFalse(record['query_execution'])

    def test_packed_rust_adapter_reuses_product_query_and_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / 'fixture.gtsw'
            fixture(path)
            work = bench.pack(root, 'fixture', {'test': {'path': str(path)}}, bench.COMMON)
            self.assertEqual(bench.sha(work / 'traceq'), bench.sha(bench.EVAL_CLI))
            self.assertNotEqual(bench.sha(work / 'traceq'), bench.sha(bench.GT))
            manifest = json.loads((work / 'tools.json').read_text())
            self.assertEqual(manifest['query_policy'], query.capabilities())
            self.assertTrue({'import', 'export', 'taint'}.isdisjoint(manifest['query_policy']['allowed_commands']))
            self.assertFalse((work / 'queries').exists())

            def agent(command, *options):
                return subprocess.run(
                    [work / 'traceq', 'agent-query', 'test', command, *options, '--json'],
                    cwd=work, capture_output=True, timeout=10,
                )

            result = agent('find-value', '--value', '0xaabb', '--write', '--last', '2')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual([r['ev'] for r in json.loads(result.stdout)['data']], [0])
            self.assertEqual(agent('find-value', '--value', '0xaabb', '--last', '257').returncode, 2)
            self.assertEqual(agent('find-value', '--value', '0xaabb', '--last', '2', '--limit', '2').returncode, 2)
            result = agent('context', '--at-ev', '0', '--limit', '0x2')
            expected = subprocess.check_output(
                [bench.GT, 'context', path, '--at-ev', '0', '--limit', '0x2', '--json'], timeout=10,
            )
            self.assertEqual((result.returncode, result.stdout), (0, expected))
            record = json.loads((work / 'queries/calls.jsonl').read_text().splitlines()[-1])
            self.assertEqual(record['execution_path'], 'in_process')


if __name__ == '__main__':
    unittest.main()
