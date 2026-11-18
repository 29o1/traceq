#!/usr/bin/env python3
"""Check the product source tree exported by Git from a commit or tag."""
import argparse
import io
from pathlib import Path, PurePosixPath
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
PRODUCT_ROOTS = {
    '.gitattributes', '.gitignore', 'LICENSE', 'Makefile', 'README.md', 'README.zh-CN.md', 'SECURITY.md',
    'capture', 'cli', 'dependencies', 'rust', 'tools',
}
REQUIRED = {
    'LICENSE', 'Makefile', 'cli/Makefile', 'rust/Cargo.toml', 'rust/Cargo.lock',
    'rust/traceq-cli/src/main.rs', 'rust/traceq-query/src/lib.rs', 'rust/traceq-core/src/lib.rs',
    'rust/traceq-capture/src/lib.rs', 'rust/traceq-observer/src/lib.rs',
    'capture/traceq/CMakeLists.txt', 'capture/traceq/cmake/TraceqGum.cmake', 'capture/traceq/include/AndroidCapture.h',
    'capture/traceq/vendor/frida-gum-arm64/COPYING', 'capture/traceq/vendor/frida-gum-arm64/gumstalker-arm64.c',
    'capture/traceq/vendor/frida-gum-arm64/gum-devkit-bridge.h',
    'dependencies/gum-devkits.json', 'tools/build_capture.py', 'tools/dependencies.py', 'tools/rust_workspace.py',
}
LOCAL_PARTS = {'.deps', '.git', 'artifacts', 'build', 'evaluation', 'examples', 'experiments', 'target', 'tests'}
LOCAL_SUFFIXES = {'.a', '.dylib', '.gtb', '.gtsc', '.gtsw', '.o', '.pyc', '.so'}


def main(ref):
    commit = subprocess.check_output(
        ['git', 'rev-parse', '--verify', '--end-of-options', f'{ref}^{{commit}}'],
        cwd=ROOT, text=True, timeout=15,
    ).strip()
    archive = subprocess.check_output(['git', 'archive', '--format=tar', commit], cwd=ROOT, timeout=30)
    with tarfile.open(fileobj=io.BytesIO(archive)) as source:
        files = {PurePosixPath(member.name) for member in source if not member.isdir()}
    missing = REQUIRED.difference(path.as_posix() for path in files)
    extra = {path.as_posix() for path in files if (
        path.parts[0] not in PRODUCT_ROOTS
        or LOCAL_PARTS.intersection(path.parts)
        or path.suffix in LOCAL_SUFFIXES
        or path.as_posix() == 'cli/traceq'
        or path.parts[:2] == ('rust', 'traceq-engine')
    )}
    if missing or extra:
        if missing:
            print('Missing product paths: ' + ', '.join(sorted(missing)), file=sys.stderr)
        if extra:
            print('Unexpected release paths: ' + ', '.join(sorted(extra)), file=sys.stderr)
        return 1
    print(f'Product source archive {commit} passed ({len(files)} files).')
    return 0


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ref', nargs='?', default='HEAD', help='commit or tag to check (default: HEAD)')
    sys.exit(main(parser.parse_args().ref))
