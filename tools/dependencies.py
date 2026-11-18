#!/usr/bin/env python3
"""Prepare pinned capture SDKs in the checkout's local cache."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import tarfile
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
CACHE = ROOT / '.deps'
GUM_SPEC = ROOT / 'dependencies/gum-devkits.json'


def digest(path):
    fingerprint = hashlib.sha256()
    with path.open('rb') as source:
        for block in iter(lambda: source.read(1024 * 1024), b''):
            fingerprint.update(block)
    return fingerprint.hexdigest()


def verify(path, expected):
    if digest(path) != expected:
        raise RuntimeError(f'checksum mismatch: {path}; existing file retained')


def publish(reader, path, expected=None):
    path.parent.mkdir(parents=True, exist_ok=True)
    # A failed copy or verification keeps its own partial file. The canonical
    # path only appears after verification, including during concurrent builds.
    with tempfile.NamedTemporaryFile(
        dir=path.parent, prefix=f'.{path.name}.', suffix='.partial', delete=False,
    ) as output:
        staged = Path(output.name)
        shutil.copyfileobj(reader, output)
    fingerprint = digest(staged)
    if expected is not None and fingerprint != expected:
        raise RuntimeError(f'checksum mismatch: {staged}; partial file retained')
    try:
        os.link(staged, path)
    except FileExistsError:
        verify(path, fingerprint)
    staged.unlink()


def checked_download(url, path, expected):
    if path.exists():
        verify(path, expected)
        return
    with urllib.request.urlopen(url, timeout=60) as response:
        publish(response, path, expected)


def gum(platform):
    spec = json.loads(GUM_SPEC.read_text())
    item = spec['platforms'][platform]
    devkit = f"frida-gum-{spec['version']}-{platform}"
    dest = CACHE / devkit
    members = item['members']
    if all((dest / name).is_file() for name in members):
        for name, expected in members.items():
            verify(dest / name, expected)
        return dest

    archive = CACHE / f'{devkit}.tar.xz'
    checked_download(item['url'], archive, item['sha256'])
    with tarfile.open(archive, 'r:xz') as package:
        for member in package:
            path = dest / member.name
            if not path.resolve().is_relative_to(dest.resolve()):
                raise RuntimeError('unsafe SDK archive path')
            if member.isdir():
                path.mkdir(parents=True, exist_ok=True)
            elif member.isfile():
                with package.extractfile(member) as source:
                    publish(source, path, members.get(member.name.removeprefix('./')))
            else:
                raise RuntimeError('unsupported SDK archive member')
    for name, expected in members.items():
        verify(dest / name, expected)
    return dest


def host():
    return gum('macos-arm64')


def legacy(source=None, fetch=False, platform=None):
    if platform == 'android':
        raise RuntimeError('Android Gum moved to: tools/dependencies.py gum --platform android-arm64')
    spec = json.loads((ROOT / 'dependencies/traceq-platform-libs.json').read_text())
    results = []
    for item in spec['artifacts']:
        name = item['path']
        if not any(p.lower() in name.lower() for p in spec['active_platforms']):
            continue
        if platform and platform.lower() not in name.lower():
            continue
        target = ROOT / spec['destination'] / name
        expected = item['sha256']
        if target.exists():
            verify(target, expected)
        elif source:
            original = Path(source) / name
            with original.open('rb') as reader:
                publish(reader, target, expected)
        elif fetch:
            base = spec['source_repository'].replace('https://github.com/', 'https://raw.githubusercontent.com/')
            checked_download(f"{base}/{spec['commit']}/{name}", target, expected)
        else:
            raise RuntimeError(f'missing dependency: {target}; use tools/dependencies.py legacy '
                               '--fetch or --source PATH')
        results.append(str(target))
    return results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('kind', choices=['host', 'gum', 'legacy'])
    parser.add_argument('--source', type=Path)
    parser.add_argument('--fetch', action='store_true')
    parser.add_argument('--platform', choices=['android', 'ios', 'android-arm64', 'macos-arm64'])
    args = parser.parse_args()
    if args.kind == 'gum':
        if args.platform not in ('android-arm64', 'macos-arm64'):
            parser.error('gum requires --platform android-arm64 or macos-arm64')
        print(gum(args.platform))
    elif args.kind == 'host':
        print(host())
    else:
        if args.platform not in (None, 'android', 'ios'):
            parser.error('legacy requires --platform ios (also the default)')
        print('\n'.join(legacy(args.source, args.fetch, args.platform)))


if __name__ == '__main__':
    main()
