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
HOST_VERSION='17.26.3'
HOST_SHA256='6491616e05cbe4fc527663d68d4f908266791d8ea7992c3aedc4cbccbc681814'
HOST_URL=f'https://github.com/frida/frida/releases/download/{HOST_VERSION}/frida-gum-devkit-{HOST_VERSION}-macos-arm64.tar.xz'

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

def host():
    archive=CACHE/f'frida-gum-{HOST_VERSION}.tar.xz'
    checked_download(HOST_URL,archive,HOST_SHA256)
    dest=CACHE/f'frida-gum-{HOST_VERSION}'
    dest.mkdir(parents=True,exist_ok=True)
    # Copy regular archive members only. Paths never escape the SDK directory.
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
    return dest

def legacy(source=None,fetch=False,platform=None):
    spec=json.loads((ROOT/'dependencies/traceq-platform-libs.json').read_text())
    results=[]
    for item in spec['artifacts']:
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
    parser=argparse.ArgumentParser();parser.add_argument('kind',choices=['host','legacy']);parser.add_argument('--source',type=Path)
    parser.add_argument('--fetch',action='store_true');parser.add_argument('--platform',choices=['android','ios'])
    args=parser.parse_args()
    print(host() if args.kind=='host' else '\n'.join(legacy(args.source,args.fetch,args.platform)))
