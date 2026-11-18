#!/usr/bin/env python3
"""Opt-in whole-libc allocator capture and delayed native survival regression."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import time

from check_invoke import PHONE, ROOT, phone, push, run

REGS = [*[f'x{i}' for i in range(31)], 'sp', 'nzcv', *[f'v{i}' for i in range(32)]]
PATTERN = '363263313b0a'


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def identity(stat):
    pid = int(stat.split(' ', 1)[0])
    fields = stat[stat.rindex(')') + 2:].split()
    return pid, int(fields[19])


def check(out, ndk, sdk, cli):
    out.mkdir(parents=True, exist_ok=False)
    compiler = ndk / 'toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android24-clang++'
    driver = out / 'allocator-check'
    run([compiler, '-std=c++17', '-O2', '-static-libstdc++',
         '-I' + str(ROOT / 'capture/traceq/include'), Path(__file__).with_name('allocator_android.cpp'),
         '-ldl', '-o', driver])
    remote = '/data/local/tmp/traceq-allocator-' + str(time.time_ns())
    phone(['mkdir', '-m', '700', remote])
    push(sdk, remote + '/sdk.so')
    push(driver, remote + '/driver', True)
    boot = phone(['cat', '/proc/sys/kernel/random/boot_id']).stdout.decode().strip()
    deployed = phone(['sha256sum', remote + '/sdk.so']).stdout.decode().split()[0]
    assert deployed == hashlib.sha256(sdk.read_bytes()).hexdigest()
    save(out / 'deployment.json', {'remote': remote, 'boot': boot, 'sdk_sha256': deployed,
                                  'sdk_source': str(sdk), 'driver_sha256': hashlib.sha256(driver.read_bytes()).hexdigest()})
    checks = []
    for case, delay in [('copy', 0), ('allocate', 11)]:
        prefix = remote + '/' + case
        argv = ['/system/bin/timeout', '-v', '-s', 'KILL', '--preserve-status', '40',
                remote + '/driver', remote + '/sdk.so', prefix + '.gtsw', case, str(delay)]
        script = shlex.join(argv) + ' > ' + shlex.quote(prefix + '.stdout')
        script += ' 2> ' + shlex.quote(prefix + '.stderr') + ' &\nwatchdog=$!\n'
        if delay:
            script += 'sleep 1\n'
            script += 'pid=$(sed -n ' + shlex.quote(r's/.*"pid":\([0-9]*\).*/\1/p')
            script += ' ' + shlex.quote(prefix + '.stdout') + ' | head -1)\n'
            for index in range(2):
                if index:
                    script += 'sleep 12\n'
                for name in ('stat', 'status', 'maps'):
                    script += 'cat "/proc/$pid/' + name + '" > '
                    script += shlex.quote(prefix + f'.sample{index}.' + name) + '\n'
        script += 'wait "$watchdog"\nresult=$?\nprintf "%s\\n" "$result" > '
        script += shlex.quote(prefix + '.exit') + '\nexit 0\n'
        (out / (case + '-command.sh')).write_text(script)
        wrapper = phone(['sh', '-c', script])
        (out / (case + '-wrapper.stderr')).write_bytes(wrapper.stderr)
        suffixes = ['stdout', 'stderr', 'exit', 'gtsw']
        if delay:
            suffixes += [f'sample{i}.{name}' for i in range(2) for name in ('stat', 'status', 'maps')]
        for suffix in suffixes:
            run([PHONE, 'pull', '--root', prefix + '.' + suffix, out / (case + '.' + suffix)])
        assert int((out / (case + '.exit')).read_text()) == 0
        rows = [json.loads(line) for line in (out / (case + '.stdout')).read_text().splitlines()]
        before, captured, *late = rows
        expected_identity = before['pid'], before['start_ticks']
        assert expected_identity[1] > 0
        assert (captured['pid'], captured['start_ticks']) == expected_identity
        assert captured['status'] == 0 and captured['capture_status'] == 1 and captured['correct']
        assert captured['buffer'] == PATTERN
        if delay:
            assert len(late) == 2
            previous_ns = captured['monotonic_ns']
            for index, row in enumerate(late):
                assert row['correct'] and (row['pid'], row['start_ticks']) == expected_identity
                assert row['monotonic_ns'] - previous_ns >= 11_000_000_000
                previous_ns = row['monotonic_ns']
                assert identity((out / f'{case}.sample{index}.stat').read_text()) == expected_identity
                status = (out / f'{case}.sample{index}.status').read_text()
                state = next(line.split()[1] for line in status.splitlines() if line.startswith('State:'))
                assert 'TracerPid:\t0' in status and state in ('R', 'S')
                assert remote + '/sdk.so' in (out / f'{case}.sample{index}.maps').read_text()

        def query(command, *options):
            argv = [cli, command, out / (case + '.gtsw'), *options, '--json']
            result = run(argv)
            (out / (case + '-' + command + '.json')).write_bytes(result.stdout)
            return json.loads(result.stdout)

        stat = query('stat')['meta']  # Replay validates END counters and its complete suffix.
        for name, field in [('instructions', 'instructions'), ('reads', 'reads'), ('stores', 'writes'),
                            ('capture_gaps', 'gaps'), ('confirmed_instructions', 'commits')]:
            assert stat[name] == captured[field]
        entries = query('find-pc', '--addr', captured['copy_address'], '--limit', '32')['data']
        boundaries = query('boundaries', '--reg', 'x0', '--limit', '64')['data']
        copy_points = {row['ev'] for row in entries}
        points = list(copy_points)
        malloc_points = set()
        if case == 'allocate':
            malloc = run([cli, 'find-pc', out / (case + '.gtsw'), '--addr', captured['malloc_address'], '--json'])
            (out / (case + '-malloc-entries.json')).write_bytes(malloc.stdout)
            malloc_points = {row['ev'] for row in json.loads(malloc.stdout)['data']}
            points += list(malloc_points)
        points += [row['exit_ev'] for row in boundaries if (row.get('exit_registers') or {}).get('x0') == captured['dest']]
        contexts = query('context', *[x for point in sorted(set(points)) for x in ('--at-ev', str(point))],
                         '--before', '0', '--after', '0', '--limit', str(len(set(points))),
                         *[x for reg in REGS for x in ('--reg', reg)])
        assert contexts['meta']['validation'] == 'full stream through END'
        copy_entry = next(row for row in contexts['data'] if row['ev'] in copy_points
                          and row['pre']['x0'] == captured['dest'] and row['pre']['x2'] == '0x6')
        assert len(copy_entry['pre']) == 65 and all(value is not None for value in copy_entry['pre'].values())
        if case == 'allocate':
            assert any(row['ev'] in malloc_points and row['pre']['x0'] == '0x17700'
                       and all(v is not None for v in row['pre'].values())
                       for row in contexts['data'])
            assert any(row['transfer'] == 'return' and row['exit_ev'] < copy_entry['ev']
                       and row['exit_registers']['x0'] == captured['dest'] for row in boundaries)
        writes = query('mem-access', '--range', captured['dest'] + ',6', '--write', '--limit', '64')
        assert not writes['meta']['truncated']
        values = {}
        base = int(captured['dest'], 0)
        for row in writes['data']:
            assert row['known']
            for offset, value in enumerate(int(row['val'], 0).to_bytes(row['size'], 'little'), int(row['addr'], 0) - base):
                if 0 <= offset < 6:
                    values[offset] = value
        assert bytes(values[i] for i in range(6)).hex() == PATTERN
        after = phone(['sh', '-c', f'if [ -e /proc/{before["pid"]}/stat ]; then cat /proc/{before["pid"]}/stat; else printf "absent\\n"; fi'])
        (out / (case + '.process-after')).write_bytes(after.stdout)
        assert after.stdout.strip() == b'absent'
        checks.append({'case': case, 'complete': True, 'true_write_bytes': 6, 'copy_entry_slots': 65,
                       'identity': expected_identity, 'delayed_native_calls': len(late), 'stats': stat,
                       'report': captured, 'trace_bytes': (out / (case + '.gtsw')).stat().st_size})
    assert phone(['cat', '/proc/sys/kernel/random/boot_id']).stdout.decode().strip() == boot
    assert phone(['sha256sum', remote + '/sdk.so']).stdout.decode().split()[0] == deployed
    save(out / 'result.json', {'pass': True, 'sdk_sha256': deployed, 'checks': checks,
                              'scope': 'Owned standalone libc malloc/copy; no App or SDK unload qualification.'})
    print(out, flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ndk', type=Path, default=os.environ.get('ANDROID_NDK_HOME'))
    parser.add_argument('--library', type=Path, default=ROOT / 'build/traceq-android/libtraceq_capture.so')
    parser.add_argument('--cli', type=Path, default=ROOT / 'cli/traceq')
    parser.add_argument('--out', type=Path, default=ROOT / 'artifacts' / ('allocator-check-' + str(time.time_ns())))
    args = parser.parse_args()
    if args.ndk is None:
        parser.error('--ndk or ANDROID_NDK_HOME is required')
    check(args.out.resolve(), args.ndk.resolve(), args.library.resolve(), args.cli.resolve())
