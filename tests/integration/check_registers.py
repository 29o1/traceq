#!/usr/bin/env python3
"""Compile and run the same-context register observer regression."""
import argparse
from pathlib import Path
import platform
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tools'))
import dependencies

def check(out,source=None):
    if platform.system()!='Darwin' or platform.machine()!='arm64':
        raise RuntimeError('register observation check requires macOS ARM64')
    if source is None:
        cargo = [sys.executable, str(ROOT/'tools/rust_workspace.py'), 'test', '--locked']
        subprocess.run([*cargo, '-p', 'traceq-capture'], check=True, timeout=60)
        subprocess.run([*cargo, '--manifest-path', str(ROOT/'tests/observer/Cargo.toml')],
                       check=True, timeout=60)
        return
    sdk=dependencies.host();out.mkdir(parents=True,exist_ok=True)
    command=['clang++','-arch','arm64','-std=c++17','-O2','-DTRACEQ_HOST_LAB',
             '-I'+str(ROOT/'tests/reference/include'),'-I'+str(sdk)]
    if source:command.append('-DTRACEQ_OBSERVER_SOURCE="'+str(source.resolve())+'"')
    binary=out/'register-observation'
    command += [str(ROOT/'tests/reference/register_observation.mm'),str(sdk/'libfrida-gum.a'),
                '-framework','Foundation','-lresolv','-lm','-ldl','-o',str(binary)]
    subprocess.run(command,check=True)
    subprocess.run([str(binary)],check=True)

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,default=ROOT/'build/traceq-register-check')
    p.add_argument('--source',type=Path);a=p.parse_args();check(a.out.resolve(),a.source)
