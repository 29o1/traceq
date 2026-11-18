#!/usr/bin/env python3
"""Measure capture observations against native results, outside the solver pack."""
import argparse
import json
from pathlib import Path
import statistics
import time

from bench import LIB, native, native_reference, query, sha, write


def measure(run):
    manifest = json.loads((run / 'manifest.json').read_text())
    if sha(native_reference(run, manifest)) != sha(LIB):
        raise ValueError('This measurement assumes c_transform reads/writes; use the task-specific capture qualification')
    captures = json.loads((run / 'grader/independent-capture.json').read_text())
    checks = []
    for capture in captures:
        trace = run / 'independent/work' / (capture['trace'] + '.gtsw')
        base = int(capture['capture']['data_base'], 0)
        accesses = query(trace, 'mem-access', '--range', hex(base) + ',32', '--limit', 256)['data']
        initial = bytearray(32)
        initial[16:24] = capture['initial'].to_bytes(8, 'little')
        final = bytes.fromhex(capture['native']['buffer'])
        read_facts, write_facts, failures = 0, 0, []
        read_offsets, write_offsets = [], []
        for access in accesses:
            offset, size = int(access['addr'], 0) - base, access['size']
            expected = initial if access['rw'] == 'r' else final
            valid = access.get('known') is True and int(access['val'], 0) == int.from_bytes(expected[offset:offset+size], 'little')
            if not valid:
                failures.append(access)
            if access['rw'] == 'r':
                read_facts += size
                read_offsets.extend(range(offset, offset + size))
            else:
                write_facts += size
                write_offsets.extend(range(offset, offset + size))
        count = min(capture['count'], 8)
        checks.append({'trace': capture['trace'], 'read_bytes_checked': read_facts,
            'write_bytes_checked': write_facts, 'incorrect_accesses': failures,
            'expected_read_bytes_present_exactly_once': sorted(read_offsets) == list(range(16, 16+count)),
            'expected_write_bytes_present_exactly_once': sorted(write_offsets) == list(range(count)) + list(range(8, 12)),
            'capture_preserves_result_and_buffer': capture['capture']['result'] == capture['native']['result'] and capture['capture']['buffer'] == capture['native']['buffer'],
            'reported_gaps': capture['stat']['meta']['capture_gaps'],
            'unknown_reads': capture['stat']['meta']['unknown_reads'],
            'trace_bytes': capture['bytes']})
    # Retain each measured capture. Function timing includes follow/unfollow and
    # stream finalization; process timing additionally includes startup and teardown.
    speed = run / 'capture-speed'
    speed.mkdir(exist_ok=False)
    trials = []
    for i in range(7):
        for mode in ['native', 'trace']:
            started = time.monotonic()
            path = speed / ('sample-%d.gtsw' % i)
            result = native(0x12345678, 8, 0x8877665544332211, mode, path)
            trials.append({'trial': i, 'mode': mode, 'process_seconds': time.monotonic()-started,
                           'target_scope_ms': result['capture_ms'], 'rss_bytes': result['rss_bytes'],
                           'result': result['result'], 'buffer': result['buffer']})
    write(speed / 'trials.json', trials)
    timing = {mode: {key: statistics.median(r[key] for r in trials if r['mode'] == mode)
                    for key in ['process_seconds', 'target_scope_ms', 'rss_bytes']}
              for mode in ['native', 'trace']}
    report = {'independent': {'capture_checks': checks, 'timing_medians': timing, 'timing_trials': 7,
                'speed_scope': 'macOS ARM64, one tiny function invocation; not steady-state throughput'}}
    write(run / 'measurements.json', report)
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--run', type=Path, required=True)
    measure(parser.parse_args().run.resolve())
