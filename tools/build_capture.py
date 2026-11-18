#!/usr/bin/env python3
"""Build native capture targets in the checkout's build directory."""
import argparse
import os
from pathlib import Path
import platform
import subprocess
import sys

import dependencies

ROOT = Path(__file__).resolve().parents[1]
CAPTURE = ROOT / 'capture/traceq'


def run(args):
    subprocess.run([str(arg) for arg in args], check=True, cwd=ROOT, timeout=300)


def host(with_tests=False):
    if platform.system() != 'Darwin' or platform.machine() != 'arm64':
        raise RuntimeError('traceq-capture host requires macOS ARM64')
    sdk = dependencies.host()
    out = ROOT / 'build/traceq-host'
    out.mkdir(parents=True, exist_ok=True)
    gum_build = out / 'gum-build'
    run([
        'cmake', '-S', CAPTURE, '-B', gum_build, '-DTRACEQ_GUM_ONLY=ON',
        '-DCMAKE_BUILD_TYPE=Release', '-DCMAKE_OSX_ARCHITECTURES=arm64',
        f'-DTRACEQ_GUM_DEVKIT_DIR={sdk}',
    ])
    run(['cmake', '--build', gum_build])
    archive = gum_build / 'gum/libtraceq-gum.a'
    tests = ROOT / 'tests/integration'
    fixtures = tests / 'fixtures'
    run([
        'clang', '-arch', 'arm64', '-dynamiclib', '-O2', '-fno-stack-protector',
        '-fomit-frame-pointer', fixtures / 'targets.S', fixtures / 'extra_targets.S',
        fixtures / 'write_targets.S', fixtures / 'boundary_targets.S', fixtures / 'c_transform.c',
        '-o', out / 'libfixtures.dylib',
    ])
    run([sys.executable, ROOT / 'tools/rust_workspace.py', 'build', '--locked', '--release',
         '-p', 'traceq-capture'])
    rust = ROOT / '.deps/rust/target/release/libtraceq_capture.a'
    compile_flags = [
        'clang++', '-arch', 'arm64', '-std=c++17', '-O2', '-Wall', '-Wextra',
        '-Wno-unused-parameter', '-Wno-deprecated-declarations',
        f'-I{sdk}', '-x', 'objective-c++',
    ]
    link_flags = [
        '-x', 'none', f'-Wl,-force_load,{rust}', archive,
        '-framework', 'Foundation', '-lresolv', '-lm', '-ldl',
    ]
    programs = [('capture_host.mm', 'traceq-capture')]
    if with_tests:
        programs.append(('thread_owner.mm', 'traceq-thread-owner-test'))
    for source, program in programs:
        run([*compile_flags, tests / source, *link_flags, '-o', out / program])
    return out


def android():
    ndk = os.environ.get('ANDROID_NDK_HOME')
    if not ndk or not (toolchain := Path(ndk) / 'build/cmake/android.toolchain.cmake').is_file():
        raise RuntimeError('ANDROID_NDK_HOME must point to an installed NDK')
    sdk = dependencies.gum('android-arm64')
    out = ROOT / 'build/traceq-android'
    args = [
        'cmake', '-S', CAPTURE, '-B', out, '-DCMAKE_BUILD_TYPE=Release',
        f'-DTRACEQ_GUM_DEVKIT_DIR={sdk}', f'-DCMAKE_TOOLCHAIN_FILE={toolchain}',
        '-DANDROID_ABI=arm64-v8a', '-DANDROID_PLATFORM=android-24',
    ]
    out.mkdir(parents=True, exist_ok=True)
    run(args)
    run(['cmake', '--build', out, '--config', 'Release'])
    return out


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('platform', choices=['host', 'android'])
    parser.add_argument('--tests', action='store_true',
                        help='build the host thread-ownership regression executable')
    args = parser.parse_args()
    if args.tests and args.platform != 'host':
        parser.error('--tests applies to the host build')
    print(host(args.tests) if args.platform == 'host' else android())


if __name__ == '__main__':
    main()
