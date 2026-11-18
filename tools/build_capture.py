#!/usr/bin/env python3
"""Build the Android ARM64 capture SDK."""
import argparse
import os
from pathlib import Path
import subprocess

import dependencies

ROOT = Path(__file__).resolve().parents[1]
CAPTURE = ROOT / 'capture/traceq'


def run(args):
    subprocess.run([str(arg) for arg in args], check=True, cwd=ROOT, timeout=300)


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
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('platform', choices=['android'])
    parser.parse_args()
    print(android())


if __name__ == '__main__':
    main()
