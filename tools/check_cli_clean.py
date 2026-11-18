#!/usr/bin/env python3
"""Build and test the current CLI sources in a temporary Mac workspace."""
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PACKAGES = ('traceq-cli', 'traceq-core', 'traceq-query', 'traceq-observer', 'traceq-capture')


def run(args, workspace, env):
    print('+ ' + ' '.join(args), flush=True)
    with subprocess.Popen(args, cwd=workspace, env=env, start_new_session=True) as command:
        try:
            status = command.wait(timeout=300)
        except (KeyboardInterrupt, subprocess.TimeoutExpired):
            if command.poll() is None:
                os.killpg(command.pid, signal.SIGKILL)
            command.wait()
            raise
    if status:
        raise subprocess.CalledProcessError(status, args)


def main():
    if platform.system() != 'Darwin':
        sys.exit('check-cli-clean requires macOS')
    files = [Path(name) for name in (
        'Makefile', 'cli/Makefile', 'tools/rust_workspace.py',
        'rust/Cargo.toml', 'rust/Cargo.lock',
    )]
    files.extend(p.relative_to(ROOT) for p in (ROOT / 'tests').glob('test_*.py'))
    for package in PACKAGES:
        directory = ROOT / 'rust' / package
        files.extend(p.relative_to(ROOT) for p in directory.rglob('*')
                     if p.is_file() and p.suffix in ('.rs', '.toml', '.json', '.txt')
                     and 'target' not in p.relative_to(directory).parts)

    with tempfile.TemporaryDirectory(prefix='traceq-cli-clean-') as directory:
        workspace = Path(directory)
        for relative in sorted(files):
            destination = workspace / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, destination)

        print(f'Staged {len(files)} files in {workspace}; project Cargo cache is empty.', flush=True)
        env = dict(os.environ)
        for key in ('CARGO_NET_OFFLINE', 'MAKEFLAGS', 'MFLAGS'):
            env.pop(key, None)
        make = ['make', f'PYTHON={sys.executable}']
        run([*make, 'deps-cli'], workspace, env)
        env['CARGO_NET_OFFLINE'] = 'true'
        run(make, workspace, env)
        run([*make, 'check-cli'], workspace, env)
    print('Clean offline CLI build and regression checks passed.', flush=True)


if __name__ == '__main__':
    main()
