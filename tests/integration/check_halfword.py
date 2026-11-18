#!/usr/bin/env python3
"""Literal ASM/C halfword atomics, aliases, failed compares and raced old bits."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import struct
import tarfile
import time

from check_invoke import PHONE, ROOT, phone, push, run

REGS = [*[f'x{i}' for i in range(31)], 'sp', 'nzcv', *[f'v{i}' for i in range(32)]]
ATOMIC = {'cash', 'casah', 'casalh', 'caslh', 'swph', 'swpah', 'swpalh', 'swplh'}


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def verify(out, cli, baseline=False):
    reports = [json.loads(line) for line in (out / 'driver.stdout').read_text().splitlines()]
    health = [row for row in reports if 'health' in row]
    trials = [row for row in reports if 'case' in row]
    expected = {(case, pattern, mode) for case in range(20)
                for pattern in (range(1) if case >= 18 else range(3)) for mode in (1, 3)}
    assert len(trials) == len(expected) and {(r['case'], r['pattern'], r['mode']) for r in trials} == expected
    assert len(health) == 3 and len({(r['pid'], r['start_ticks']) for r in health}) == 1
    assert all(row['native_ok'] and row['start_ticks'] > 0 for row in health)
    if not baseline:
        assert all(row['elapsed_ns'] >= 11_000_000_000 for row in health[1:])
    checks = []
    for row in trials:
        name = f'{row["case"]}-{row["pattern"]}-{row["mode"]}'
        trace = out / (name + '.gtsw')

        def query(command, *options, status=0, label=None):
            import subprocess
            args = [str(cli), command, str(trace), *map(str, options), '--json']
            result = subprocess.run(args, capture_output=True, timeout=20)
            (out / (name + '-' + (label or command) + '.json')).write_bytes(result.stdout)
            assert result.returncode == status and not result.stderr, (args, result.returncode, result.stderr)
            return json.loads(result.stdout)

        stat = query('stat')['meta']
        for key, field in [('instructions', 'instructions'), ('reads', 'reads'), ('stores', 'writes'),
                           ('capture_gaps', 'gaps'), ('confirmed_instructions', 'commits')]:
            assert stat[key] == row[field]
        instructions = query('instructions', '--limit', 2000)
        assert not instructions['meta']['truncated']
        atoms = [i for i in instructions['data'] if i['text'].split()[0] in ATOMIC]
        loop = 'contended' in row['name']
        assert len(atoms) == (64 if loop else 1)
        points = [x['ev'] for x in atoms]
        contexts = query('context', *[v for point in points for v in ('--at-ev', point)],
                         '--before', 0, '--after', 0, '--limit', len(points),
                         *[v for reg in REGS for v in ('--reg', reg)])
        assert contexts['meta']['validation'] == 'full stream through END'
        contexts = {x['ev']: x for x in contexts['data']}
        accesses = query('mem-access', '--range', row['address'] + ',2', '--limit', 512, '--access-index')
        assert not accesses['meta']['truncated']
        raw = (out / (name + '.bin')).read_bytes()
        assert len(raw) == (64 * 24 if loop else 8)
        native = struct.unpack('<' + 'Q' * (len(raw) // 8), raw)
        facts = failed = unsupported = 0
        for index, instruction in enumerate(atoms):
            group = contexts[instruction['ev']]
            selected = [a for a in accesses['data'] if a['ev'] == instruction['ev']]
            assert len(group['pre']) == 65 and all(v is not None for v in group['pre'].values())
            if baseline or 'discard' in row['name']:
                assert not selected and group['post'] is None and 'unsupported' in group['gap_reasons']
                unsupported += 1
                continue
            old = native[3 * index] if loop else native[0]
            compare = native[3 * index + 1] if loop else row['compare']
            desired = 0x8000 + index if loop else row['desired']
            cas = instruction['text'].startswith('cas')
            succeeded = not cas or old == compare
            want = [('r', old), *([('w', desired)] if succeeded else [])]
            assert [(a['rw'], int(a['val'], 0)) for a in selected] == want
            assert [a['access_index'] for a in selected] == list(range(len(want)))
            assert all(a['known'] and a['size'] == 2 and a['addr'] == row['address'] for a in selected)
            assert len(group['post']) == 65 and all(v is not None for v in group['post'].values())
            operands = re.findall(r'\b(w\d+|wzr|x\d+|sp)\b', instruction['text'])
            result = operands[0 if cas else 1]
            result = 'x' + result[1:]
            assert int(group['post'][result], 0) == old
            for reg in REGS:
                if reg != result:
                    assert group['post'][reg] == group['pre'][reg], (name, instruction, reg)
            if succeeded:
                assert not group['gap']
                source = selected[-1]['value_source']
                assert ('compare-and-swap' if cas else 'atomic swap') in source
            else:
                assert group['gap_reasons'] == ['unconfirmed_store']
                failed += 1
            facts += len(want)
        if loop:
            assert row['pre_races'] and row['post_races']
            assert facts == (64 + row['successes'] if 'cas' in row['name'] else 128) or baseline
        checks.append({'case': row['name'], 'pattern': row['pattern'], 'mode': row['mode'],
                       'facts': facts, 'ambiguous_failed_compares': failed, 'unsupported': unsupported,
                       'trace_bytes': trace.stat().st_size, 'sdk_total_ns': row['total_ns'], 'stats': stat})
        if not baseline and row['case'] == 0 and row['pattern'] == 0 and row['mode'] == 3:
            for suffix, data in [('truncated', trace.read_bytes()[:-1]), ('suffix', trace.read_bytes() + b'x')]:
                damaged = out / (name + '-' + suffix + '.gtsw')
                damaged.write_bytes(data)
                result = run_error(cli, damaged)
                save(out / (name + '-' + suffix + '-error.json'), result)
    save(out / 'result.json', {'pass': True, 'baseline': baseline, 'checks': checks, 'health': health,
                              'facts': sum(r['facts'] for r in checks),
                              'failed_compares': sum(r['ambiguous_failed_compares'] for r in checks),
                              'scope': 'Owned native ASM/C only; thread-local atomic facts, not a globally serialized memory snapshot.'})


def run_error(cli, trace):
    import subprocess
    r = subprocess.run([str(cli), 'mem-access', str(trace), '--range', '0x1,1', '--offset', '999999', '--json'],
                       capture_output=True, timeout=20)
    doc = json.loads(r.stdout)
    assert r.returncode == 1 and doc['error']['code'] == 'TRACE_ERROR'
    return doc


def check(out, ndk, sdk, cli, baseline):
    out.mkdir(parents=True, exist_ok=False)
    compiler = ndk / 'toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android24-clang'
    fixture = out / 'libhalfword.so'
    driver = out / 'halfword-check'
    files = Path(__file__).resolve().parent
    run([compiler, '-shared', '-fPIC', '-O2', '-march=armv8.1-a+lse', '-mno-outline-atomics',
         files / 'fixtures/halfword_targets.S', files / 'fixtures/halfword_c.c', '-o', fixture])
    run([compiler, '-O2', '-std=c11', '-march=armv8.1-a+lse', '-mno-outline-atomics', '-pthread',
         '-I' + str(ROOT / 'capture/traceq/include'), files / 'halfword_android.c', '-ldl', '-o', driver])
    remote = '/data/local/tmp/traceq-halfword-' + str(time.time_ns())
    phone(['mkdir', '-m', '700', remote])
    for local, name, execute in [(sdk, 'sdk.so', False), (fixture, 'fixture.so', False), (driver, 'driver', True)]:
        push(local, remote + '/' + name, execute)
    boot = phone(['cat', '/proc/sys/kernel/random/boot_id']).stdout.decode().strip()
    args = ['/system/bin/timeout', '-v', '-s', 'KILL', '--preserve-status', '55',
            remote + '/driver', remote + '/sdk.so', remote + '/fixture.so', remote, '0', '20']
    if not baseline:
        args.append('--delayed')
    save(out / 'deployment.json', {'remote': remote, 'boot': boot, 'command': args,
                                  'sha256': {name: hashlib.sha256(local.read_bytes()).hexdigest()
                                             for local, name in [(sdk, 'sdk.so'), (fixture, 'fixture.so'), (driver, 'driver')]}})
    script = shlex.join(args) + ' > ' + shlex.quote(remote + '/driver.stdout')
    script += ' 2> ' + shlex.quote(remote + '/driver.stderr') + '\nstatus=$?\nprintf "%s\\n" "$status" > '
    script += shlex.quote(remote + '/driver.exit') + '\nexit 0\n'
    (out / 'device-command.sh').write_text(script)
    r = phone(['sh', '-c', script])
    (out / 'wrapper.stderr').write_bytes(r.stderr)
    for name in ('driver.stdout', 'driver.stderr', 'driver.exit'):
        run([PHONE, 'pull', '--root', remote + '/' + name, out / name])
    # Transport packaging only; the SDK still writes the unchanged trace format.
    # A failed first capture may leave only a partial trace and no .bin. Retain
    # the archive and tar diagnostics before checking the driver's exit status.
    pack = 'cd ' + shlex.quote(remote) + ' && tar -cf evidence.tar *.gtsw *.bin 2> evidence.stderr; '
    pack += 'status=$?; printf "%s\\n" "$status" > ' + shlex.quote(remote + '/evidence.exit') + '; exit 0'
    phone(['sh', '-c', pack])
    run([PHONE, 'pull', '--root', remote + '/evidence.tar', out / 'evidence.tar'])
    for name in ('evidence.stderr', 'evidence.exit'):
        run([PHONE, 'pull', '--root', remote + '/' + name, out / name])
    with tarfile.open(out / 'evidence.tar') as archive:
        assert all(member.isfile() and re.fullmatch(r'\d+-\d+-\d+\.(gtsw|bin)', member.name)
                   for member in archive.getmembers())
        archive.extractall(out)
    assert phone(['cat', '/proc/sys/kernel/random/boot_id']).stdout.decode().strip() == boot
    assert phone(['sha256sum', remote + '/sdk.so']).stdout.decode().split()[0] == hashlib.sha256(sdk.read_bytes()).hexdigest()
    assert int((out / 'driver.exit').read_text()) == 0
    assert int((out / 'evidence.exit').read_text()) == 0
    verify(out, cli, baseline)
    print(out, flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ndk', type=Path, default=os.environ.get('ANDROID_NDK_HOME'))
    parser.add_argument('--library', type=Path, default=ROOT / 'build/traceq-android/libtraceq_capture.so')
    parser.add_argument('--cli', type=Path, default=ROOT / 'cli/traceq')
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--baseline', action='store_true')
    parser.add_argument('--verify-only', action='store_true')
    args = parser.parse_args()
    if args.verify_only:
        verify(args.out.resolve(), args.cli.resolve(), args.baseline)
    elif args.ndk is None:
        parser.error('--ndk or ANDROID_NDK_HOME is required')
    else:
        check(args.out.resolve(), args.ndk.resolve(), args.library.resolve(), args.cli.resolve(), args.baseline)
