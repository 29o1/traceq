#!/usr/bin/env python3
"""CLZ/RBIT register observations, native byte oracles and truthful gaps."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import time
from check_multiply import flags

from rust_classifier import archive as classifier_archive
ROOT=Path(__file__).resolve().parents[2]
FIXTURES=Path(__file__).resolve().parent/'fixtures'
MASK=(1<<64)-1
REGS=[*[f'x{i}' for i in range(31)],'sp','nzcv',*[f'v{i}' for i in range(32)]]
INPUTS=[0,1,1<<63,1<<31,0xfedcba9876543210,MASK]

def operation(kind,value,bits):
    value&=(1<<bits)-1
    return bits-value.bit_length() if kind=='clz' else int(f'{value:0{bits}b}'[::-1],2)

def scalar_cases():
    for kind in ['clz','rbit']:
        for flavor in ['', 'zero', 'discard', 'alias']:
            for bits in [64,32]:
                yield kind,flavor,bits,f'bitops_{kind}_{flavor}{bits}' if flavor else f'bitops_{kind}{bits}'

def vector_cases():
    for kind in ['clz','rbit']:
        for shape,lanes,bits in ([('8b',8,8),('16b',16,8),('4h',4,16),('8h',8,16),('2s',2,32),('4s',4,32)] if kind=='clz' else [('8b',8,8),('16b',16,8)]):
            yield kind,lanes,bits,False,f'bitops_{kind}_{shape}'
        yield kind,16,8,True,f'bitops_{kind}_vector_alias'

def vector_expected(kind,value,lanes,bits):
    return sum(operation(kind,value>>(i*bits),bits)<<(i*bits) for i in range(lanes))

def c_expected(seed,initial,count):
    x=seed
    for i in range(count):
        value=x^initial^i
        x=operation('rbit',value,64)^operation('clz',value,64)
    return x,b''.join(v.to_bytes(8,'little') for v in [seed,initial,initial,x]).hex()

def run(args):
    r=subprocess.run(list(map(str,args)),capture_output=True,text=True,timeout=30)
    if r.returncode:raise AssertionError((list(map(str,args)),r.returncode,r.stdout[-2000:],r.stderr[-2000:]))
    return r.stdout

def check(out,runner,cli):
    out.mkdir(parents=True,exist_ok=False)
    sys.path.insert(0,str(ROOT/'tools'));import dependencies
    sdk=dependencies.host();classifier=out/'bitops-classification'
    run(['clang++','-arch','arm64','-std=c++17','-O2','-DTRACEQ_HOST_LAB',
         '-I'+str(sdk),
         FIXTURES.parent/'bitops_classification.mm',classifier_archive(),sdk/'libfrida-gum.a','-framework','Foundation',
         '-lresolv','-lm','-ldl','-o',classifier])
    print(run([classifier]).strip(),flush=True)
    asm=out/'libbitops.dylib';run(['clang','-dynamiclib',FIXTURES/'bitops_targets.S','-o',asm])
    def query(path,cmd,*args):return json.loads(run([cli,cmd,path,*args,'--json']))
    def invoke(lib,fn,mode,path,seed,count,initial,all_data=False):
        return json.loads(run([runner,lib,fn,mode,path,hex(seed),count,hex(initial),*(['--all-data'] if all_data else [])]))
    records=[];reg_args=[p for reg in REGS for p in ['--reg',reg]];initial=0x0123456789abcdef
    for kind,flavor,bits,fn in scalar_cases():
        for n,seed in enumerate(INPUTS):
            value=MASK if flavor=='discard' else operation(kind,0 if flavor=='zero' else seed,bits)
            want=b''.join(v.to_bytes(8,'little') for v in [seed,value,initial,initial]).hex()
            native=invoke(asm,fn,'native',out/'unused',seed,1,initial)
            assert int(native['result'],0)==value and native['buffer']==want
            for mode in ['trace-chunks','trace-fast']:
                path=out/f'{fn}-{n}-{mode}.gtsw';cap=invoke(asm,fn,mode,path,seed,1,initial)
                assert cap['ok'] and cap['buffer']==want and cap['result']==native['result']
                stat=query(path,'stat')['meta'];assert stat['capture_gaps']==0 and stat['reads']==1 and stat['stores']==3,stat
                ev=4+int(flavor=='alias')
                row=query(path,'context','--at-ev',ev,'--before',0,'--after',0,*reg_args)['data'][0]
                pre,post=row['pre'],row['post'];assert len(pre)==len(post)==65 and all(v is not None for v in [*pre.values(),*post.values()])
                assert row['completion']=='confirmed' and not row['gap'] and row['memory']==[]
                assert int(pre['x8'],0)==(seed if flavor=='alias' else MASK) and int(pre['x9'],0)==seed
                assert int(post['x8'],0)==value and int(pre['nzcv'],0)==flags(seed,1)
                assert all(pre[r]==post[r] for r in REGS if r!='x8')
                writers=query(path,'last-writers','--range',cap['data_base']+',32','--limit',32)['data']
                assert [r['known'] for r in writers]==[i<16 or i>=24 for i in range(32)]
                assert all(int(r['value'],0)==bytes.fromhex(want)[i] for i,r in enumerate(writers) if r['known'])
                records.append(dict(kind='scalar',function=fn,input=n,mode=mode))
        print(fn,'OK',flush=True)
    for kind,lanes,bits,alias,fn in vector_cases():
        for n,initial in enumerate(INPUTS):
            seed=0x123456789abcdef0;value=vector_expected(kind,initial,lanes,bits)
            want=(seed.to_bytes(8,'little')+value.to_bytes(16,'little')+bytes(8)).hex()
            native=invoke(asm,fn,'native',out/'unused',seed,1,initial)
            assert native['buffer']==want and int(native['result'],0)==value&MASK,(fn,initial,native,hex(value))
            for mode in ['trace-chunks','trace-fast']:
                path=out/f'{fn}-{n}-{mode}.gtsw';cap=invoke(asm,fn,mode,path,seed,1,initial)
                assert cap['ok'] and cap['buffer']==want and cap['result']==native['result']
                stat=query(path,'stat')['meta'];assert stat['capture_gaps']==0 and stat['reads']==1 and stat['stores']==2,stat
                row=query(path,'context','--at-ev',4+int(alias),'--before',0,'--after',0,*reg_args)['data'][0]
                pre,post=row['pre'],row['post'];assert len(pre)==len(post)==65 and all(v is not None for v in [*pre.values(),*post.values()])
                assert row['completion']=='confirmed' and not row['gap'] and row['memory']==[]
                assert int(pre['v0'],0)==(initial if alias else (1<<128)-1) and int(pre['v1'],0)==initial
                assert int(post['v0'],0)==value and int(pre['nzcv'],0)==flags(seed,1)
                assert all(pre[r]==post[r] for r in REGS if r!='v0')
                writers=query(path,'last-writers','--range',cap['data_base']+',32','--limit',32)['data']
                assert [r['known'] for r in writers]==[i<24 for i in range(32)]
                assert all(int(r['value'],0)==bytes.fromhex(want)[i] for i,r in enumerate(writers) if r['known'])
                records.append(dict(kind='vector',function=fn,input=n,mode=mode))
        print(fn,'OK',flush=True)
    for opt in ['-O1','-O2']:
        lib=out/f'libbitops-c{opt}.dylib';run(['clang','-dynamiclib',opt,'-fno-stack-protector','-fomit-frame-pointer',FIXTURES/'bitops_c.c','-o',lib])
        for n,(seed,initial,count) in enumerate([(0,0,1),(MASK,MASK,7),(1<<63,0x0123456789abcdef,31),(0xfedcba9876543210,0,0)]):
            value,want=c_expected(seed,initial,count);native=invoke(lib,'bitops_c','native',out/'unused',seed,count,initial,True)
            assert int(native['result'],0)==value and native['buffer']==want
            for mode in ['trace-chunks','trace-fast']:
                path=out/f'c-{opt}-{n}-{mode}.gtsw';cap=invoke(lib,'bitops_c',mode,path,seed,count,initial,True)
                assert cap['result']==native['result'] and cap['buffer']==want
                stat=query(path,'stat')['meta'];assert stat['capture_gaps']==0,stat
                instructions=query(path,'instructions','--limit',4096);assert not instructions['meta']['truncated']
                bitops={name:sum(r['text'].startswith(name+' ') for r in instructions['data']) for name in ['clz','rbit']}
                if count and opt=='-O2':assert bitops['clz'],'expected compiler-generated CLZ'
                # The compiler may implement the C reversal with shifts/masks
                # and REV. Exact RBIT observations are covered by the assembly.
                records.append(dict(kind='compiled-c',optimization=opt,input=n,mode=mode,instructions=stat['instructions'],bitops=bitops))
    for mode in ['trace-chunks','trace-fast']:
        for fn in ['bitops_gap','bitops_unknown']:
            path=out/f'{fn}-{mode}.gtsw';cap=invoke(asm,fn,mode,path,0x1234,1,1)
            native=invoke(asm,fn,'native',out/'unused',0x1234,1,1);assert cap['result']==native['result'] and cap['buffer']==native['buffer']
            stat=query(path,'stat')['meta']
            if fn=='bitops_gap':
                assert stat['capture_gaps']==1 and stat['unsupported_mnemonics']=={'st3':1}
                writers=query(path,'last-writers','--range',cap['data_base']+',8')['data']
                assert all(not r['known'] and r['value'] is None and r['last_observed_write'] is not None for r in writers)
                assert bytes(int(r['last_observed_write']['value'],0) for r in writers)==(0x1234).to_bytes(8,'little')
            else:
                assert stat['capture_gaps']==0 and stat['unknown_reads']==1
                hits=query(path,'find-value','--value',0,'--read');assert not hits['data'] and hits['meta']['skipped_unknown_reads']==1
            records.append(dict(kind='unknown-gap-guard',function=fn,mode=mode))
    (out/'summary.json').write_text(json.dumps({'status':'pass','count':len(records),'checks':records},indent=2)+'\n')
    print('PASS',len(records),'targeted captures',flush=True)

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path);p.add_argument('--runner',type=Path,default=ROOT/'build/traceq-host/traceq-capture');p.add_argument('--cli',type=Path,default=ROOT/'cli/traceq');a=p.parse_args()
    check((a.out or ROOT/'artifacts'/f'bitops-{time.time_ns()}').resolve(),a.runner.resolve(),a.cli.resolve())
