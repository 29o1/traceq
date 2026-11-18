#!/usr/bin/env python3
"""Build the macOS ARM64 native capture fixtures and test executables."""
import argparse
from pathlib import Path
import platform
import sys

TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS.parent.parent / 'tools'))
import dependencies
from build_capture import CAPTURE, ROOT, run


def host(with_tests):
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
    fixtures = TESTS / 'fixtures'
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
        run([*compile_flags, TESTS / source, *link_flags, '-o', out / program])
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tests', action='store_true',
                        help='also build the thread-ownership regression executable')
    print(host(parser.parse_args().tests))


if __name__ == '__main__':
    main()
