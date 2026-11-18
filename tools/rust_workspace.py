#!/usr/bin/env python3
"""Use a fixed existing toolchain, keeping Cargo/rustup/target state local.

TRACEQ_RUST_TOOLCHAIN may point to a project-local toolchain directory. This
launcher does not install tools or alter rustup defaults/global configuration.
"""
import os
from pathlib import Path
import platform
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
VERSION = '1.95.0'
HOSTS = {
    ('Darwin', 'arm64'): 'aarch64-apple-darwin',
    ('Linux', 'aarch64'): 'aarch64-unknown-linux-gnu',
    ('Linux', 'x86_64'): 'x86_64-unknown-linux-gnu',
}
ANDROID_TARGET = 'aarch64-linux-android'


def main():
    args = sys.argv[1:]
    host = HOSTS.get((platform.system(), platform.machine()))
    label = f'{VERSION}-{host}'
    cache = ROOT / '.deps/rust'
    local = cache / 'toolchain'
    device_toolchain = cache / 'android-rustup/toolchains' / label
    is_device = any(arg.removeprefix('--target=') == ANDROID_TARGET for arg in args)
    preferred = device_toolchain if is_device and device_toolchain.exists() else local
    fallback = Path.home() / '.rustup/toolchains' / label
    toolchain = Path(os.environ.get('TRACEQ_RUST_TOOLCHAIN', preferred if preferred.exists() else fallback))
    tools = toolchain / 'bin'
    if not all((tools / name).is_file() for name in ('cargo', 'rustc', 'rustdoc')):
        sys.exit(f'Missing fixed toolchain: {toolchain}; set TRACEQ_RUST_TOOLCHAIN '
                 f'to an existing {VERSION} toolchain.')
    version = subprocess.check_output([str(tools / 'rustc'), '--version'], text=True, timeout=15)
    if not version.startswith(f'rustc {VERSION} '):
        sys.exit(f'Expected rustc {VERSION}, got {version.strip()}')
    env = os.environ.copy()
    env.update(
        CARGO_HOME=str(cache / 'cargo-home'),
        RUSTUP_HOME=str(cache / 'rustup-home'),
        CARGO_TARGET_DIR=str(cache / 'target'),
        RUSTC=str(tools / 'rustc'),
        RUSTDOC=str(tools / 'rustdoc'),
        RUSTUP_TOOLCHAIN=str(toolchain),
        PATH=str(tools) + os.pathsep + env.get('PATH', ''),
    )
    # Fetch is explicit. Ordinary builds and checks stay offline.
    offline = [] if args[:1] == ['fetch'] else ['--offline']
    return subprocess.call([str(tools / 'cargo'), *offline, *args], cwd=ROOT / 'rust', env=env)


if __name__ == '__main__':
    sys.exit(main())
