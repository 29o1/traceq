#!/usr/bin/env python3
"""Opt-in Android invoke regression; uses revkit-phone, without restarting Apps."""
import argparse,json,os,platform,shlex,struct,subprocess,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
PHONE=Path.home()/'.local/bin/revkit-phone'

def run(args,**kwargs):return subprocess.run(list(map(str,args)),capture_output=True,check=True,timeout=120,**kwargs)
def phone(args):return run([PHONE,'exec','--root','--timeout','60',*map(str,args)])
def push(source,destination,executable=False):
    data=source.read_bytes();script='set -eC\ncat > '+shlex.quote(destination)+'\nchmod '+('700' if executable else '600')+' '+shlex.quote(destination)
    run([PHONE,'exec','--root','--timeout','100','sh','-c',script],input=data)
    import hashlib
    assert phone(['sha256sum',destination]).stdout.decode().split()[0]==hashlib.sha256(data).hexdigest()

def check(out,ndk,library,include,cli):
    out.mkdir(parents=True,exist_ok=False);host='darwin-x86_64' if platform.system()=='Darwin' else 'linux-x86_64'
    compiler=ndk/'toolchains/llvm/prebuilt'/host/'bin/aarch64-linux-android24-clang'
    fixture=out/'libinvoke-fixture.so';driver=out/'invoke-check'
    run([compiler,'-shared','-fPIC','-O2','-fno-stack-protector','-fomit-frame-pointer',ROOT/'tests/integration/fixtures/invoke_targets.c','-o',fixture])
    run([str(compiler)+'++','-std=c++17','-O2','-static-libstdc++','-I'+str(include),ROOT/'tests/integration/invoke_android.cpp','-ldl','-o',driver])
    remote='/data/local/tmp/traceq-invoke-'+str(time.time_ns());phone(['mkdir','-m','700',remote])
    for source,name,executable in [(library,'libtraceq_capture.so',False),(fixture,'libinvoke-fixture.so',False),(driver,'invoke-check',True)]:push(source,remote+'/'+name,executable)
    try:
        result=phone([remote+'/invoke-check',remote+'/libtraceq_capture.so',remote+'/libinvoke-fixture.so',remote])
    except subprocess.CalledProcessError as error:
        (out/'driver.stdout').write_bytes(error.stdout or b'');(out/'driver.stderr').write_bytes(error.stderr or b'')
        raise
    (out/'driver.stdout').write_bytes(result.stdout);(out/'driver.stderr').write_bytes(result.stderr)
    rows=[json.loads(line) for line in result.stdout.splitlines()];assert len(rows)==36
    checks=[];mask=(1<<64)-1
    for row in rows:
        seed=int(row['seed'],0);kind=row['kind']
        expected=(seed+454)&mask if kind=='integer' else (seed^0x5a) if kind=='triple' else None
        want=struct.pack('<d',11.) if kind=='floating' else expected.to_bytes(8,'little');assert row['buffer']==want.hex()
        if kind=='integer':assert int(row['result'],0)==expected^0x55667788
        if kind=='floating':assert row['fp']==12.
        if kind=='triple':assert [int(x,0) for x in row['triple']]==[(seed+i)&mask for i in [1,2,3]]
        mode=row['observation']
        if mode:
            path=out/(kind+'-'+str(row['seed_index'])+'-'+str(mode)+'.gtsw');run([PHONE,'pull','--root',remote+'/'+path.name,path])
            def query(cmd,*args):return json.loads(run([cli,cmd,path,*args,'--json']).stdout)
            stat=query('stat')['meta']
            assert stat['instructions']==row['instructions'] and stat['reads']==row['reads'] and stat['stores']==row['writes'] and stat['capture_gaps']==row['gaps']
            assert stat['external_execution']=='followed_without_instruction_records'
            registers=['x0','x1','x2','x3','x4','x5','x6','x7','sp'] if kind=='integer' else ['d0','s1','d2','x0','x1'] if kind=='floating' else ['x0','x1','x8']
            selectors=[x for reg in registers for x in ['--reg',reg]]
            entry=query('context','--at-ev','0','--before','0','--after','0',*selectors)
            assert entry['meta']['validation']=='full stream through END' and len(entry['data'])==1
            pre={key:int(value,0) for key,value in entry['data'][0]['pre'].items()}
            assert pre['x1']==int(row['data_base'],0)
            if kind=='integer':
                assert pre['x0']==seed and [pre['x'+str(i)] for i in range(2,8)]==list(range(1,7))
                stack=query('mem-access','--range',hex(pre['sp'])+',16','--read')
                assert not stack['meta']['truncated']
                observed={}
                for access in stack['data']:
                    assert access['known']
                    start=int(access['addr'],0);value=int(access['val'],0).to_bytes(access['size'],'little')
                    observed.update((start+i,b) for i,b in enumerate(value))
                assert bytes(observed[pre['sp']+i] for i in range(16))==struct.pack('<QQ',7,8)
            elif kind=='floating':
                assert [pre[r] for r in ['d0','s1','d2','x0']]==[0x4000000000000000,0x40400000,0x3ff0000000000000,4]
            else:assert pre['x0']==seed and pre['x8']!=0
            writers=query('last-writers','--range',row['data_base']+',8')['data'];assert len(writers)==8
            for i,w in enumerate(writers):
                if w['known']:assert int(w['value'],0)==want[i]
                else:assert w['value'] is None
                assert w['last_observed_write'] is not None and int(w['last_observed_write']['value'],0)==want[i]
            if kind!='floating':assert stat['capture_gaps']==0 and all(w['known'] for w in writers)
        checks.append({'kind':kind,'seed_index':row['seed_index'],'observation':mode,'native_oracle':True})
    summary={'status':'pass','cases':len(checks),'captures':sum(bool(r['observation']) for r in rows),'checks':checks,'remote':remote,'error_recovery':'Driver rejects missing path/module/callback/report and invalid mode; target not called on errors, valid native/capture remains usable.'}
    (out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n');print('PASS',len(checks),'ABI cases,',summary['captures'],'captures and error recovery')
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--ndk',type=Path,default=Path(os.environ['ANDROID_NDK_HOME']) if os.environ.get('ANDROID_NDK_HOME') else None);p.add_argument('--library',type=Path,default=ROOT/'build/traceq-android/libtraceq_capture.so');p.add_argument('--include',type=Path,default=ROOT/'capture/traceq/src');p.add_argument('--cli',type=Path,default=ROOT/'cli/traceq');p.add_argument('--out',type=Path);a=p.parse_args()
    if a.ndk is None:p.error('provide --ndk or ANDROID_NDK_HOME')
    check((a.out or ROOT/'artifacts'/('invoke-check-'+str(time.time_ns()))).resolve(),a.ndk.resolve(),a.library.resolve(),a.include.resolve(),a.cli.resolve())
