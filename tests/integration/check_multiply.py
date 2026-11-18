#!/usr/bin/env python3
"""Scalar multiplication snapshots and independent compiled-C behavior."""
import argparse
import json
from pathlib import Path
import subprocess
import time

ROOT=Path(__file__).resolve().parents[2]
FIXTURES=Path(__file__).resolve().parent/'fixtures'
MASK=(1<<64)-1
NAMES=['umull','smull','umaddl','smaddl','umsubl','smsubl','umnegl','smnegl','umulh','smulh',
       'mul64','mul32','madd64','madd32','msub64','msub32','mneg64','mneg32','umull_zero','smaddl_zero']
INPUTS=[(0,0),(0xffffffff80000000,0x7fffffff),(MASK,MASK),(0x8000000000000001,0xfedcba9887654321)]
REGS=[*[f'x{i}' for i in range(31)],'sp','nzcv',*[f'v{i}' for i in range(32)]]

def signed(n,bits):
    n&=(1<<bits)-1
    return n-(1<<bits) if n>>(bits-1) else n

def expected(op,a,b):
    acc=(a+b)&MASK
    if op=='umull_zero':return 0
    if op=='smaddl_zero':return (signed(a,32)*signed(b,32))&MASK
    if op in ('umulh','smulh'):
        return (((a*b) if op=='umulh' else signed(a,64)*signed(b,64))>>64)&MASK
    if op.endswith(('32','64')):
        bits=int(op[-2:]);kind=op[:-2];product=a*b
    else:
        bits=64;kind=op[1:];product=signed(a,32)*signed(b,32) if op[0]=='s' else (a&0xffffffff)*(b&0xffffffff)
    value=acc+product if kind in ('madd','maddl') else acc-product if kind in ('msub','msubl') else -product if kind in ('mneg','mnegl') else product
    return value&((1<<bits)-1)

def flags(a,b):
    d=(a-b)&MASK
    return ((d>>63)<<31)|(int(d==0)<<30)|(int(a>=b)<<29)|(int(bool((a^b)&(a^d)&(1<<63)))<<28)

def c_expected(name,a,b,count):
    buf=bytearray(32);buf[16:24]=b.to_bytes(8,'little')
    if name=='multiply_c':
        acc=a;buf[:8]=a.to_bytes(8,'little');buf[8:16]=b.to_bytes(8,'little')
        for i in range(count):
            u=(acc&0xffffffff)*(b&0xffffffff);s=signed(acc,32)*signed(b,32);high=(acc*b)>>64
            acc=((u+s+high)&MASK)^i
        buf[24:32]=acc.to_bytes(8,'little');return acc,buf.hex()
    for i in range(20):buf[i]=(a+i)&255
    for i in range(count):buf[i%20]^=i&255
    return buf[0],buf.hex()

def run(args):
    r=subprocess.run(list(map(str,args)),capture_output=True,text=True,timeout=30)
    if r.returncode:raise AssertionError((args,r.stdout[-1000:],r.stderr[-1000:]))
    return r.stdout

def check(out,runner,cli,section='all'):
    out.mkdir(parents=True,exist_ok=False)
    asm=out/'libmultiply.dylib';run(['clang','-dynamiclib',FIXTURES/'multiply_targets.S','-o',asm])
    def query(path,cmd,*args):return json.loads(run([cli,cmd,path,*args,'--json']))
    def invoke(lib,fn,mode,path,a,count,b,all_data=False):
        return json.loads(run([runner,lib,fn,mode,path,hex(a),count,hex(b),*(['--all-data'] if all_data else [])]))
    records=[];args=[part for reg in REGS for part in ('--reg',reg)]
    for op in (NAMES if section in ('all','scalar') else []):
        for n,(a,b) in enumerate(INPUTS):
            value=expected(op,a,b);want=b''.join(v.to_bytes(8,'little') for v in [a,b,b,value]).hex()
            native=invoke(asm,'multiply_'+op,'native',out/'unused',a,1,b)
            assert int(native['result'],0)==value and native['buffer']==want,(op,n,native,value)
            for mode in ['trace-chunks','trace-fast']:
                path=out/f'{op}-{n}-{mode}.gtsw';cap=invoke(asm,'multiply_'+op,mode,path,a,1,b)
                assert cap['ok'] and cap['buffer']==want and int(cap['result'],0)==value
                stat=query(path,'stat')['meta'];assert (stat['instructions'],stat['reads'],stat['stores'],stat['capture_gaps'])==(11,1,3,0),(op,stat)
                row=query(path,'context','--at-ev',7,'--before',0,'--after',0,*args)['data'][0]
                assert row['completion']=='confirmed' and not row['gap'] and not row['memory']
                pre,post=row['pre'],row['post'];assert len(pre)==len(post)==65 and all(v is not None for v in [*pre.values(),*post.values()])
                assert int(pre['x8'],0)==a and int(pre['x9'],0)==b and int(pre['x10'],0)==(a+b)&MASK
                assert int(pre['x11'],0)==MASK and int(post['x11'],0)==value,(op,n,row)
                assert int(pre['nzcv'],0)==flags(a,b) and pre['nzcv']==post['nzcv']
                assert all(pre[r]==post[r] for r in REGS if r!='x11'),(op,n)
                writers=query(path,'last-writers','--range',cap['data_base']+',32','--limit',32)['data']
                assert [r['known'] for r in writers]==[i<16 or i>=24 for i in range(32)]
                for i,r in enumerate(writers):
                    if r['known']:assert int(r['value'],0)==bytes.fromhex(want)[i]
                records.append(dict(kind='assembly',op=op,input=n,mode=mode,passed=True))
        print(op,'OK',flush=True)
    # SIMD shares UMULL's ID. Check its now-supported vector form independently.
    for mode in (['trace-chunks','trace-fast'] if section in ('all','vector') else []):
        path=out/f'vector-{mode}.gtsw';cap=invoke(asm,'multiply_vector_gap',mode,path,0xab,1,0)
        native=invoke(asm,'multiply_vector_gap','native',out/'unused',0xab,1,0)
        assert cap['result']==native['result'] and cap['buffer']==native['buffer']
        stat=query(path,'stat')['meta'];assert stat['unsupported_mnemonics']=={}
        row=query(path,'context','--at-ev',3,'--before',0,'--after',0,*args)['data'][0]
        assert row['completion']=='confirmed' and not row['gap'] and not row['memory']
        pre,post=row['pre'],row['post'];assert len(pre)==len(post)==65
        assert int(post['v2'],0)==int.from_bytes(b'\x06\x00'*8,'little')
        assert all(pre[r]==post[r]for r in REGS if r!='v2')
        writers=query(path,'last-writers','--range',cap['data_base']+',8')['data']
        assert all(r['known']for r in writers)
        assert bytes(int(r['value'],0)for r in writers)==(0xab).to_bytes(8,'little')
        records.append(dict(kind='vector-supported',mode=mode,passed=True))
    for opt in (['-O1','-O2'] if section in ('all','c') else []):
        lib=out/f'libmultiply-c{opt}.dylib';run(['clang','-dynamiclib',opt,'-fno-stack-protector','-fomit-frame-pointer',FIXTURES/'multiply_c.c','-o',lib])
        for name in ['multiply_c','multiply_indexed']:
            for n,(a,b,count) in enumerate([(0,0,0),(0xffffffff80000000,0xfedcba9887654321,7),(MASK,MASK,31)]):
                value,buf=c_expected(name,a,b,count);native=invoke(lib,name,'native',out/'unused',a,count,b,all_data=True)
                assert int(native['result'],0)==value and native['buffer']==buf,(opt,name,n,native,value,buf)
                for mode in ['trace-chunks','trace-fast']:
                    path=out/f'{name}-{opt}-{n}-{mode}.gtsw';cap=invoke(lib,name,mode,path,a,count,b,all_data=True)
                    assert cap['result']==native['result'] and cap['buffer']==buf
                    stat=query(path,'stat')['meta']
                    assert stat['capture_gaps']==0,(opt,name,stat)
                    region=cap['data_base']+(',32' if name=='multiply_c' else ',20')
                    writers=query(path,'last-writers','--range',region,'--limit',32)['data']
                    want_known=[i<16 or i>=24 for i in range(32)] if name=='multiply_c' else [True]*20
                    assert [r['known'] for r in writers]==want_known
                    for i,r in enumerate(writers):
                        if r['known']:assert int(r['value'],0)==bytes.fromhex(buf)[i]
                        if r['last_observed_write'] is not None:
                            assert int(r['last_observed_write']['value'],0)==bytes.fromhex(buf)[i]
                    records.append(dict(kind='compiled-c',optimization=opt,function=name,input=n,mode=mode,passed=True,
                                        instructions=stat['instructions'],remaining_gaps=stat['unsupported_mnemonics']))
    (out/'summary.json').write_text(json.dumps(dict(checks=records,count=len(records)),indent=2)+'\n');print('PASS',len(records),'targeted captures',flush=True)

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path);p.add_argument('--runner',type=Path,default=ROOT/'build/traceq-host/traceq-capture');p.add_argument('--cli',type=Path,default=ROOT/'cli/traceq');p.add_argument('--section',choices=['all','scalar','vector','c'],default='all');a=p.parse_args()
    check((a.out or ROOT/'artifacts'/f'multiply-{time.time_ns()}').resolve(),a.runner.resolve(),a.cli.resolve(),a.section)
