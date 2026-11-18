#!/usr/bin/env python3
"""Opt-in Android Stalker context and slab regression, using the source archive."""
from pathlib import Path
import argparse, hashlib, json, os, platform, shlex, subprocess, time

ROOT = Path(__file__).resolve().parents[2]
PHONE = Path.home() / '.local/bin/revkit-phone'

def run(args, **kwargs):
    return subprocess.run(list(map(str, args)), capture_output=True, timeout=120, **kwargs)

def phone(args):
    result = run([PHONE, 'exec', '--root', '--timeout', '20', *args])
    result.check_returncode()
    return result

def push(source, destination, executable=False):
    data = source.read_bytes()
    script = 'set -eC\ncat > ' + shlex.quote(destination) + '\nchmod ' + ('700' if executable else '600') + ' ' + shlex.quote(destination)
    result = run([PHONE, 'exec', '--root', '--timeout', '100', 'sh', '-c', script], input=data)
    result.check_returncode()
    assert phone(['sha256sum', destination]).stdout.decode().split()[0] == hashlib.sha256(data).hexdigest()

def check(ndk, archive, out):
    out.mkdir(parents=True, exist_ok=False)
    host = 'darwin-x86_64' if platform.system() == 'Darwin' else 'linux-x86_64'
    compiler = ndk / 'toolchains/llvm/prebuilt' / host / 'bin/aarch64-linux-android24-clang'
    fixture, driver = out / 'libgum-vector.so', out / 'gum-vector-check'
    fp_driver = out / 'gum-fp-check'
    slab_driver = out / 'gum-slab-check'
    dense_driver = out / 'gum-dense-check'
    tests = ROOT / 'tests/integration'
    import sys
    sys.path.insert(0, str(ROOT / 'tools'))
    import dependencies
    sdk = dependencies.gum('android-arm64')
    commands = [
        [compiler, '-shared', '-fPIC', tests / 'fixtures/gum_vector_context.S', tests / 'fixtures/gum_fp_context.S',
         tests / 'fixtures/gum_slab_allocation.S', '-o', fixture],
        [compiler, '-O2', '-I' + str(sdk), tests / 'gum_vector_context.c',
         archive, '-ldl', '-llog', '-lm', '-lz', '-o', driver],
        [compiler, '-O2', '-I' + str(sdk), tests / 'gum_fp_context.c',
         archive, '-ldl', '-llog', '-lm', '-lz', '-o', fp_driver],
        [compiler, '-O2', '-I' + str(sdk), tests / 'gum_slab_allocation.c',
         archive, '-Wl,--wrap=gum_memory_allocate', '-Wl,--wrap=gum_memory_allocate_near',
         '-ldl', '-llog', '-lm', '-lz', '-o', slab_driver],
        [compiler, '-O2', '-I' + str(sdk), tests / 'gum_dense_context.c',
         archive, '-ldl', '-llog', '-lm', '-lz', '-o', dense_driver],
    ]
    (out / 'commands.json').write_text(json.dumps([[str(x) for x in c] for c in commands], indent=2) + '\n')
    for index, command in enumerate(commands):
        result = run(command)
        (out / ('build-' + str(index) + '.log')).write_bytes(result.stdout + result.stderr)
        result.check_returncode()
    remote = '/data/local/tmp/traceq-gum-vector-' + str(time.time_ns())
    phone(['mkdir', '-m', '700', remote])
    push(fixture, remote + '/libgum-vector.so')
    push(driver, remote + '/gum-vector-check', True)
    push(fp_driver, remote + '/gum-fp-check', True)
    push(slab_driver, remote + '/gum-slab-check', True)
    push(dense_driver, remote + '/gum-dense-check', True)
    result = run([PHONE, 'exec', '--root', '--timeout', '20', 'timeout', '-k', '2', '10',
                  remote + '/gum-vector-check', remote + '/libgum-vector.so'])
    (out / 'driver.stdout').write_bytes(result.stdout)
    (out / 'driver.stderr').write_bytes(result.stderr)
    rows = [json.loads(line) for line in result.stdout.splitlines() if line.startswith(b'{')]
    valid = (result.returncode == 0 and len(rows) == 3 and [r['seed'] for r in rows] == [1, 7, 163]
             and all(r['callbacks'] >= 2 and r['mismatched_bytes'] == 0 and r['guards']
                     and r['raw_before_match'] and r['raw_after_match'] and r['input_unchanged'] for r in rows))
    summary = {'status': 'vector_pass_FP_pending' if valid else 'fail',
               'exit_code': result.returncode, 'checks': rows,
               'archive_sha256': hashlib.sha256(archive.read_bytes()).hexdigest(),
               'scope': 'Native engine context isolation; no collector trace or App restart.'}
    (out / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    result.check_returncode()
    assert valid, summary
    fp = run([PHONE, 'exec', '--root', '--timeout', '20', 'timeout', '-k', '2', '10',
              remote + '/gum-fp-check', remote + '/libgum-vector.so'])
    (out / 'fp.stdout').write_bytes(fp.stdout)
    (out / 'fp.stderr').write_bytes(fp.stderr)
    fp_rows = [json.loads(line) for line in fp.stdout.splitlines() if line.startswith(b'{')]
    fp.check_returncode()
    assert len(fp_rows) == 1 and fp_rows[0]['pass'], fp_rows
    summary['status'] = 'context_pass_slab_pending'
    summary['FP_environment'] = fp_rows[0]
    (out / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    slab = run([PHONE, 'exec', '--root', '--timeout', '20', 'timeout', '-k', '2', '10',
                remote + '/gum-slab-check', remote + '/libgum-vector.so'])
    (out / 'slab.stdout').write_bytes(slab.stdout)
    (out / 'slab.stderr').write_bytes(slab.stderr)
    slab_rows = [json.loads(line) for line in slab.stdout.splitlines() if line.startswith(b'{')]
    slab.check_returncode()
    assert len(slab_rows) == 1 and slab_rows[0]['pass'], slab_rows
    summary['slab_allocation'] = slab_rows[0]
    dense = run([PHONE, 'exec', '--root', '--timeout', '20', 'timeout', '-k', '2', '10',
                 remote + '/gum-dense-check', remote + '/libgum-vector.so'])
    (out / 'dense.stdout').write_bytes(dense.stdout)
    (out / 'dense.stderr').write_bytes(dense.stderr)
    dense_rows = [json.loads(line) for line in dense.stdout.splitlines() if line.startswith(b'{')]
    dense.check_returncode()
    assert len(dense_rows) == 1 and dense_rows[0]['pass'], dense_rows
    summary['dense_callouts_and_private_stack'] = dense_rows[0]
    summary['status'] = 'pass'
    (out / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print('PASS: three distinct full 32-vector banks survive compiler callbacks')
    print('PASS: FPCR/FPSR survive MINIMAL compiler helpers and FULL callouts')
    print('PASS: code and data slab growth works beyond 32-bit proximity')
    print('PASS: dense long block and512 target-stack bytes remain native')

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--ndk', type=Path, default=Path(os.environ['ANDROID_NDK_HOME']) if os.environ.get('ANDROID_NDK_HOME') else None)
    parser.add_argument('--archive', type=Path, default=ROOT / 'build/traceq-android/gum/libtraceq-gum.a')
    parser.add_argument('--out', type=Path)
    args = parser.parse_args()
    if args.ndk is None: parser.error('provide --ndk or ANDROID_NDK_HOME')
    check(args.ndk.resolve(), args.archive.resolve(),
          (args.out or ROOT / 'artifacts' / ('gum-context-' + str(time.time_ns()))).resolve())
