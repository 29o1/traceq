#!/usr/bin/env python3
"""Check the product source tree exported by Git from a commit or tag."""
import argparse
import gzip
import io
import os
from pathlib import Path, PurePosixPath
import subprocess
import sys
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PRODUCT_ROOTS = {
    '.gitattributes', '.gitignore', 'LICENSE', 'Makefile', 'README.md', 'README.zh-CN.md', 'SECURITY.md',
    'capture', 'cli', 'dependencies', 'rust', 'tools',
}
REQUIRED = {
    'LICENSE', 'Makefile', 'cli/Makefile', 'rust/Cargo.toml', 'rust/Cargo.lock',
    'rust/traceq-cli/src/main.rs', 'rust/traceq-query/src/lib.rs', 'rust/traceq-core/src/lib.rs',
    'rust/traceq-capture/src/lib.rs', 'rust/traceq-observer/src/lib.rs',
    'rust/traceq-cli/Cargo.toml', 'rust/traceq-query/Cargo.toml', 'rust/traceq-core/Cargo.toml',
    'rust/traceq-capture/Cargo.toml', 'rust/traceq-observer/Cargo.toml',
    'capture/traceq/CMakeLists.txt', 'capture/traceq/cmake/TraceqGum.cmake', 'capture/traceq/include/AndroidCapture.h',
    'capture/traceq/vendor/frida-gum-arm64/COPYING', 'capture/traceq/vendor/frida-gum-arm64/gumstalker-arm64.c',
    'capture/traceq/vendor/frida-gum-arm64/gum-devkit-bridge.h',
    'dependencies/gum-devkits.json', 'tools/build_capture.py', 'tools/dependencies.py', 'tools/rust_workspace.py',
}
LOCAL_PARTS = {'.deps', '.git', 'artifacts', 'build', 'evaluation', 'examples', 'experiments', 'target', 'tests'}
LOCAL_SUFFIXES = {'.a', '.dylib', '.gtb', '.gtsc', '.gtsw', '.o', '.pyc', '.so'}


def product_path(path):
    return (path.parts[0] in PRODUCT_ROOTS
            and not (path.parts[0] == 'rust' and path.parts[2:3] in (('tests',), ('examples',))))


def main(ref, output=None):
    try:
        commit = subprocess.check_output(
            ['git', 'rev-parse', '--verify', '--end-of-options', f'{ref}^{{commit}}'],
            cwd=ROOT, text=True, stderr=subprocess.PIPE, timeout=15,
        ).strip()
    except subprocess.CalledProcessError:
        print(f'Invalid release commit or tag: {ref}', file=sys.stderr)
        return 1
    tree = subprocess.check_output(['git', 'ls-tree', '-r', '-z', '--name-only', commit], cwd=ROOT, timeout=30)
    tracked = [PurePosixPath(os.fsdecode(name)) for name in tree.split(b'\0') if name]
    # Archive attributes can hide nested product inputs, even via .git/info/attributes.
    expected = REQUIRED | {path.as_posix() for path in tracked if product_path(path)}
    archive = subprocess.check_output(['git', 'archive', '--format=tar', commit], cwd=ROOT, timeout=30)
    with tarfile.open(fileobj=io.BytesIO(archive)) as source:
        members = [member for member in source if not member.isdir()]
        files = {PurePosixPath(member.name) for member in members}
    non_files = {member.name for member in members if not member.isfile()}
    missing = expected.difference(path.as_posix() for path in files)
    extra = non_files | {path.as_posix() for path in files if (
        not product_path(path)
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
    if output is not None:
        output = Path(output)
        output.parent.mkdir(parents=True, exist_ok=True)
        staged = None
        try:
            with tempfile.NamedTemporaryFile(dir=output.parent, prefix=output.name + '.',
                                             suffix='.partial', delete=False) as target:
                staged = Path(target.name)
                target.write(gzip.compress(archive, mtime=0))
            os.replace(staged, output)
        finally:
            if staged is not None:
                staged.unlink(missing_ok=True)
        print(f'Wrote {output} from {commit}.')
    return 0


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ref', nargs='?', help='commit or tag to check (checks default to HEAD)')
    parser.add_argument('--output', type=Path, help='atomically save the checked snapshot as a .tar.gz archive')
    args = parser.parse_args()
    if args.output is not None and not args.ref:
        parser.error('export requires an explicit commit or tag (RELEASE_REF in make source-release)')
    sys.exit(main(args.ref or 'HEAD', args.output))
