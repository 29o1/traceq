#!/usr/bin/env python3
"""Prepare pinned capture SDKs; all caches and outputs stay in this checkout."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import tarfile
import urllib.request

ROOT=Path(__file__).resolve().parents[1]
CACHE=ROOT/'.deps'
GUM_SPEC=ROOT/'dependencies/gum-devkits.json'

def digest(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda:f.read(1024*1024),b''):h.update(block)
    return h.hexdigest()

def checked_download(url,path,expected):
    if path.exists():
        if digest(path)!=expected:raise RuntimeError(f'checksum mismatch: {path}; existing file retained')
        return
    path.parent.mkdir(parents=True,exist_ok=True)
    # Keep incomplete artifacts for diagnosis; never replace an existing file.
    with urllib.request.urlopen(url,timeout=60) as response,path.open('xb') as out:
        shutil.copyfileobj(response,out)
    if digest(path)!=expected:raise RuntimeError(f'checksum mismatch: {path}; file retained')

def gum(platform):
    spec=json.loads(GUM_SPEC.read_text())
    item=spec['platforms'][platform]
    archive=CACHE/f"frida-gum-{spec['version']}-{platform}.tar.xz"
    checked_download(item['url'],archive,item['sha256'])
    dest=CACHE/f"frida-gum-{spec['version']}-{platform}"
    dest.mkdir(parents=True,exist_ok=True)
    # Official devkit members are immutable and cannot escape the cache.
    with tarfile.open(archive,'r:xz') as package:
        for member in package.getmembers():
            path=dest/member.name
            if not path.resolve().is_relative_to(dest.resolve()):raise RuntimeError('unsafe SDK archive path')
            if member.isdir():path.mkdir(parents=True,exist_ok=True);continue
            if not member.isfile():raise RuntimeError('unsupported SDK archive member')
            data=package.extractfile(member).read()
            if path.exists():
                if path.read_bytes()!=data:raise RuntimeError(f'SDK member differs: {path}; retained')
            else:
                path.parent.mkdir(parents=True,exist_ok=True)
                with path.open('xb') as out:out.write(data)
    for name,expected in item['members'].items():
        if digest(dest/name)!=expected:raise RuntimeError(f'Gum member checksum mismatch: {name}')
    return dest


def host():
    return gum('macos-arm64')

def legacy(source=None,fetch=False,platform=None):
    if platform=='android':raise RuntimeError('Android Gum moved to: tools/dependencies.py gum --platform android-arm64')
    spec=json.loads((ROOT/'dependencies/traceq-platform-libs.json').read_text())
    results=[]
    for item in spec['artifacts']:
        if not any(p.lower() in item['path'].lower() for p in spec['active_platforms']):continue
        if platform and platform.lower() not in item['path'].lower():continue
        target=ROOT/spec['destination']/item['path']
        if not target.exists():
            if source:
                original=Path(source)/item['path']
                if not original.is_file() or digest(original)!=item['sha256']:raise RuntimeError(f'invalid dependency source: {original}')
                target.parent.mkdir(parents=True,exist_ok=True)
                with original.open('rb') as inp,target.open('xb') as out:shutil.copyfileobj(inp,out)
            elif fetch:
                url=spec['source_repository'].replace('https://github.com/','https://raw.githubusercontent.com/')+'/'+spec['commit']+'/'+item['path']
                checked_download(url,target,item['sha256'])
            else:raise RuntimeError(f'missing dependency: {target}; use tools/dependencies.py legacy --fetch or --source PATH')
        if digest(target)!=item['sha256']:raise RuntimeError(f'checksum mismatch: {target}')
        results.append(str(target))
    return results

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('kind',choices=['host','gum','legacy']);parser.add_argument('--source',type=Path)
    parser.add_argument('--fetch',action='store_true');parser.add_argument('--platform',choices=['android','ios','android-arm64','macos-arm64'])
    args=parser.parse_args()
    if args.kind=='gum':
        if args.platform not in ('android-arm64','macos-arm64'):parser.error('gum requires --platform android-arm64 or macos-arm64')
        print(gum(args.platform))
    else:
        print(host() if args.kind=='host' else '\n'.join(legacy(args.source,args.fetch,args.platform)))
