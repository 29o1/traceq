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
host = {('Darwin', 'arm64'): 'aarch64-apple-darwin',
        ('Linux', 'aarch64'): 'aarch64-unknown-linux-gnu',
        ('Linux', 'x86_64'): 'x86_64-unknown-linux-gnu'}.get((platform.system(), platform.machine()))
local = ROOT / '.deps/rust/toolchain'
android_local = ROOT / '.deps/rust/android-rustup/toolchains' / ('1.95.0-' + str(host))
android_target = any(arg == 'aarch64-linux-android' or arg == '--target=aarch64-linux-android'
                     for arg in sys.argv[1:])
ios_target = any(arg == 'aarch64-apple-ios' or arg == '--target=aarch64-apple-ios'
                 for arg in sys.argv[1:])
preferred = android_local if (android_target or ios_target) and android_local.exists() else local
toolchain = Path(os.environ.get('TRACEQ_RUST_TOOLCHAIN', str(preferred if preferred.exists() else
    Path.home() / '.rustup/toolchains' / ('1.95.0-' + str(host)))))
for name in ('cargo', 'rustc', 'rustdoc'):
    if not (toolchain / 'bin' / name).is_file():
        sys.exit(f'Missing fixed toolchain: {toolchain}; set TRACEQ_RUST_TOOLCHAIN to an existing 1.95.0 toolchain.')
version = subprocess.check_output([str(toolchain/'bin/rustc'), '--version'], text=True)
if not version.startswith('rustc 1.95.0 '):
    sys.exit(f'Expected rustc 1.95.0, got {version.strip()}')
env = os.environ.copy()
env.update(CARGO_HOME=str(ROOT/'.deps/rust/cargo-home'), RUSTUP_HOME=str(ROOT/'.deps/rust/rustup-home'),
           CARGO_TARGET_DIR=str(ROOT/'.deps/rust/target'), RUSTC=str(toolchain/'bin/rustc'),
           RUSTDOC=str(toolchain/'bin/rustdoc'), RUSTUP_TOOLCHAIN=str(toolchain), PATH=str(toolchain/'bin')+os.pathsep+env.get('PATH',''))
# Network access is explicit: dependency fetch populates only this project's
# Cargo cache/lock. Ordinary builds and checks retain their offline behavior.
offline = [] if sys.argv[1:2] == ['fetch'] else ['--offline']
raise SystemExit(subprocess.call([str(toolchain/'bin/cargo'), *offline, *sys.argv[1:]], cwd=ROOT/'rust', env=env))
