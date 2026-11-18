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
    if (platform.system(), platform.machine()) != ('Darwin', 'arm64'):
        sys.exit('check-cli-clean requires macOS ARM64')
    # Use current worktree contents, but only for paths tracked by Git.
    tracked = subprocess.check_output([
        'git', 'ls-files', '-z', '--', 'Makefile', 'cli/Makefile', 'tests/Makefile',
        'tests/test_*.py', 'tools/rust_workspace.py', 'rust',
    ], cwd=ROOT, timeout=15)
    files = [Path(os.fsdecode(path)) for path in tracked.split(b'\0') if path]

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
