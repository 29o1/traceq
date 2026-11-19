"""Self-contained evaluation entry checks using a literal trace and no model."""
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'evaluation'))

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
    def test_mem_state_source_runs_expand_exactly_and_validate_lengths(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fixture.gtsw'
            fixture(path)
            argv = [ROOT / 'cli/traceq', 'mem-state', path, '--range', '0x2000,2',
                    '--at-ev', '0', '--phase', 'post', '--compact', '--json']
            for provenance in ([], ['--access-source']):
                original = json.loads(subprocess.check_output([*argv, *provenance], timeout=10))
                packed = json.loads(subprocess.check_output([*argv, *provenance, '--source-runs'], timeout=10))
                self.assertEqual(query.expand_mem_state(packed), query.expand_mem_state(original))
                run, = packed['data'][0]['source_runs']
                for invalid_length in (0, 1, 3, True):
                    run[0] = invalid_length
                    with self.assertRaisesRegex(ValueError, 'run|source count'):
                        query.expand_mem_state(packed)

    def test_extended_adapter_check_requires_its_frozen_trace(self):
        result = subprocess.run(
            [sys.executable, Path(__file__).with_name('check_adapter.py')],
            cwd=ROOT, capture_output=True, timeout=10,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn(b'--trace is required', result.stderr)
        self.assertNotIn(b'Traceback', result.stderr)

    def test_model_runner_requires_an_explicit_task_directory(self):
        result = subprocess.run(
            [sys.executable, ROOT / 'evaluation/run_product_evaluation.py'],
            cwd=ROOT, capture_output=True, timeout=10,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn(b'--artifact-dir', result.stderr)
        self.assertNotIn(b'Traceback', result.stderr)

    def test_native_failure_logs_are_separate_from_harness_logs(self):
        from check_adapter import validate_evaluation_logs

        with tempfile.TemporaryDirectory() as directory:
            validate_evaluation_logs((Path(directory) / 'logs').resolve())

    def test_repeat_records_the_packed_query_tool(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / 'fixture.gtsw'
            fixture(path)
            previous = root / 'previous'
            original = bench.pack(previous, 'independent', {'test': {'path': str(path)}}, bench.COMMON)
            (previous / 'grader').mkdir()
            original_manifest = {'product_cli_sha256': 'previous-cli'}
            bench.write(previous / 'manifest.json', original_manifest)

            rust = root / 'rust-repeat'
            with patch.object(bench, 'GT', root / 'absent-product-cli'):
                bench.repeat(rust, previous)
            python = root / 'python-repeat'
            bench.repeat(python, previous, entry='python')

            for run, entry, binary in [(rust, 'rust', bench.EVAL_CLI), (python, 'python', bench.GT)]:
                manifest = json.loads((run / 'manifest.json').read_text())
                self.assertEqual(manifest['query_entry'], entry)
                self.assertEqual(manifest['gt_sha256'], bench.sha(binary))
                self.assertEqual(manifest['frozen_inputs'], {'independent/test': bench.sha(path)})
                if entry == 'python':
                    self.assertEqual(manifest['product_cli_sha256'], manifest['gt_sha256'])
                else:
                    self.assertNotIn('product_cli_sha256', manifest)
            self.assertEqual(json.loads((previous / 'manifest.json').read_text()), original_manifest)
            self.assertEqual(bench.sha(original / 'traceq'), bench.sha(bench.EVAL_CLI))

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
            for options, fmt, index in [
                ((), 'columns-v1', None),
                (('--access-index',), 'columns-v2', 0),
                (('--source-table',), 'columns-v3', None),
                (('--source-table', '--access-index'), 'columns-v3', 0),
            ]:
                result = agent('mem-access', '--range', '0x2000,2', '--compact', *options)
                self.assertEqual(result.returncode, 0, result.stderr)
                doc = json.loads(result.stdout)
                self.assertEqual(doc['meta']['mem_access_format'], fmt)
                row, = query.expand_mem_access(doc)['data']
                self.assertEqual((row['val'], row.get('access_index')), ('0xaabb', index))
                self.assertEqual(row['value_source'], 'store source bits; post callback confirmed')
                if fmt == 'columns-v3':
                    doc['data'][0][-1] = 1
                    with self.assertRaisesRegex(ValueError, 'value_source_ref'):
                        query.expand_mem_access(doc)
            record = json.loads((work / 'queries/calls.jsonl').read_text().splitlines()[-1])
            self.assertEqual(record['execution_path'], 'in_process')


if __name__ == '__main__':
    unittest.main()
