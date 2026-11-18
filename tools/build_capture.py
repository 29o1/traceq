#!/usr/bin/env python3
"""Build capture targets from this repository without cleaning existing files."""
import argparse
import os
from pathlib import Path
import platform
import subprocess
import dependencies

ROOT=Path(__file__).resolve().parents[1]
CAPTURE=ROOT/'capture/traceq'

def run(args):
    subprocess.run([str(x) for x in args],check=True,cwd=ROOT,timeout=300)

def host(with_tests=False):
    if platform.system()!='Darwin' or platform.machine()!='arm64':
        raise RuntimeError('traceq-capture host currently requires macOS ARM64; make and check-cli are portable')
    sdk=dependencies.host()
    out=ROOT/'build/traceq-host';out.mkdir(parents=True,exist_ok=True)
    gum_build=out/'gum-build'
    run(['cmake','-S',CAPTURE,'-B',gum_build,'-DTRACEQ_GUM_ONLY=ON',
         '-DCMAKE_BUILD_TYPE=Release','-DCMAKE_OSX_ARCHITECTURES=arm64',
         '-DTRACEQ_GUM_DEVKIT_DIR='+str(sdk)])
    run(['cmake','--build',gum_build])
    archive=gum_build/'gum/libtraceq-gum.a'
    tests=ROOT/'tests/integration';fixtures=tests/'fixtures'
    run(['clang','-arch','arm64','-dynamiclib','-O2','-fno-stack-protector','-fomit-frame-pointer',
         fixtures/'targets.S',fixtures/'extra_targets.S',fixtures/'write_targets.S',
         fixtures/'boundary_targets.S',
         fixtures/'c_transform.c','-o',out/'libfixtures.dylib'])
    run(['python3', ROOT/'tools/rust_workspace.py', 'build', '--release', '-p', 'traceq-capture'])
    rust=ROOT/'.deps/rust/target/release/libtraceq_capture.a'
    command=['clang++','-arch','arm64','-std=c++17','-O2','-Wall','-Wextra','-Wno-unused-parameter',
         '-Wno-deprecated-declarations','-DTRACEQ_HOST_LAB','-DTRACEQ_WRITE_STREAM',
         '-I'+str(CAPTURE/'src'),'-I'+str(sdk),'-I'+str(ROOT/'cli/include'),
         '-x','objective-c++',tests/'capture_host.mm','-x','none','-Wl,-force_load,'+str(rust),archive,
         '-framework','Foundation','-lresolv','-lm','-ldl','-o',out/'traceq-capture']
    run(command)
    if with_tests:
        run([tests/'thread_owner.mm' if x==tests/'capture_host.mm' else
             out/'traceq-thread-owner-test' if x==out/'traceq-capture' else x for x in command])
    return out

def device(target,perf=False):
    sdk=dependencies.gum('android-arm64') if target=='android' else None
    if target!='android':dependencies.legacy(platform=target)
    out=ROOT/'build'/('traceq-'+target+('-perf' if perf else ''));out.mkdir(parents=True,exist_ok=True)
    args=['cmake','-S',CAPTURE,'-B',out,'-DCMAKE_BUILD_TYPE=Release',
          '-DTRACEQ_CAPTURE_PERF='+('ON' if perf else 'OFF'),
          '-DTRACEQ_INCLUDE_DIR='+str(ROOT/'cli/include')]
    if target=='android':
        args+=['-DTRACEQ_GUM_DEVKIT_DIR='+str(sdk)]
        ndk=os.environ.get('ANDROID_NDK_HOME')
        if not ndk or not (Path(ndk)/'build/cmake/android.toolchain.cmake').is_file():
            raise RuntimeError('ANDROID_NDK_HOME must point to an installed NDK')
        args+=['-DCMAKE_TOOLCHAIN_FILE='+str(Path(ndk)/'build/cmake/android.toolchain.cmake'),
               '-DANDROID_ABI=arm64-v8a','-DANDROID_PLATFORM=android-24']
    else:
        sdk=subprocess.check_output(['xcrun','--sdk','iphoneos','--show-sdk-path'],text=True).strip()
        args+=['-DCMAKE_SYSTEM_NAME=iOS','-DCMAKE_OSX_SYSROOT='+sdk,
               '-DCMAKE_OSX_ARCHITECTURES=arm64','-DCMAKE_OSX_DEPLOYMENT_TARGET=12.0']
    run(args);run(['cmake','--build',out,'--config','Release'])
    return out

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('platform',choices=['host','android','ios'])
    parser.add_argument('--perf',action='store_true',help='isolated Android capture-probe build')
    parser.add_argument('--tests',action='store_true',help='build host thread-ownership regression executable')
    args=parser.parse_args()
    if args.perf and args.platform!='android':parser.error('--perf currently applies to Android')
    if args.tests and args.platform!='host':parser.error('--tests applies to the host build')
    print(host(args.tests) if args.platform=='host' else device(args.platform,args.perf))
