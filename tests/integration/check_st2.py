#!/usr/bin/env python3
"""ST2 interleaving/lane facts from native bytes and all65 actual snapshots."""
import argparse,json,time
from pathlib import Path
from check_bitops import run,REGS
ROOT=Path(__file__).resolve().parents[2];FIX=Path(__file__).resolve().parent/'fixtures'
MASK=(1<<64)-1

def cases():
    for shape,element,width in [('8b',1,8),('16b',1,16),('4h',2,8),('8h',2,16),('2s',4,8),('4s',4,16),('2d',8,16)]:
        for form in ['base','imm','reg']:yield f'st2_{shape}_{form}',element,width,-1,form
    for letter,element,high in [('b',1,15),('h',2,7),('s',4,3),('d',8,1)]:
        for lane in [0,high]:
            for form in ['base','imm','reg']:yield f'st2_{letter}{lane}_{form}',element,element,lane,form
    yield 'st2_wrap',1,16,-1,'wrap'
    yield 'st2_sp',1,16,-1,'sp'
    yield 'st2_unaligned',2,8,-1,'unaligned'
    yield 'st2_alias',4,16,-1,'alias'
    yield 'st2_outside',1,16,-1,'outside'

def payload(seed,initial,count,element,width,lane):
    a=seed.to_bytes(8,'little')+count.to_bytes(8,'little');b=initial.to_bytes(8,'little')+seed.to_bytes(8,'little')
    if lane>=0:return a[lane*element:(lane+1)*element]+b[lane*element:(lane+1)*element]
    return b''.join(source[i:i+element] for i in range(0,width,element) for source in [a,b])

def check(out,runner,cli):
    out.mkdir(parents=True,exist_ok=False);lib=out/'libst2.dylib';run(['clang','-arch','arm64','-dynamiclib',FIX/'st2_targets.S','-o',lib])
    def query(path,cmd,*args):return json.loads(run([cli,cmd,path,*args,'--json']))
    def invoke(module,fn,mode,path,seed,count,initial,all_data=False):return json.loads(run([runner,module,fn,mode,path,hex(seed),count,hex(initial),*(['--all-data'] if all_data else [])]))
    regs=[p for r in REGS for p in ['--reg',r]];checks=[]
    for fn,element,width,lane,form in cases():
        for n,(seed,initial,count) in enumerate([(0, MASK,1),(0xfedcba9876543210,0x0123456789abcdef,7)]):
            raw=payload(seed,initial,count,element,width,lane);expected=bytearray(32);expected[16:24]=initial.to_bytes(8,'little');offset=int(form=='unaligned')
            if form=='outside':expected[:8]=seed.to_bytes(8,'little')
            else:expected[offset:offset+len(raw)]=raw
            native=invoke(lib,fn,'native',out/'unused',seed,count,initial);assert native['buffer']==expected.hex() and int(native['result'],0)==seed,(fn,n,native,expected.hex())
            for mode in ['trace-chunks','trace-fast']:
                path=out/f'{fn}-{n}-{mode}.gtsw';cap=invoke(lib,fn,mode,path,seed,count,initial,form=='sp')
                assert cap['ok'] and cap['buffer']==expected.hex() and cap['result']==native['result']
                instructions=query(path,'instructions','--limit',100);assert not instructions['meta']['truncated']
                hints=[r for r in instructions['data'] if r['text'].startswith('st2 ')];assert len(hints)==1
                row=query(path,'context','--at-ev',hints[0]['ev'],'--before',0,'--after',0,*regs)['data'][0]
                assert row['completion']=='confirmed' and len(row['pre'])==len(row['post'])==65 and all(x is not None for x in [*row['pre'].values(),*row['post'].values()])
                pre,post=row['pre'],row['post'];want=dict(pre)
                if form in ['imm','reg','alias']:
                    step=width*2 if form=='imm' else 7 if form=='reg' else int(pre['x8'],0)
                    assert int(post['x8'],0)==(int(pre['x8'],0)+step)&MASK;want['x8']=post['x8']
                assert post==want,'ST2 changed source registers/NZCV/unrelated state'
                stat=query(path,'stat')['meta'];writers=query(path,'last-writers','--range',cap['data_base']+',32','--limit',32)['data']
                if form=='outside':
                    assert stat['capture_gaps']==1 and stat['gap_reasons']['outside_data_range']==1 and not stat['unsupported_mnemonics'] and row['memory']==[] and row['gap']
                    assert all(not r['known'] for r in writers)
                    assert bytes(int(r['last_observed_write']['value'],0) for r in writers[:8])==seed.to_bytes(8,'little')
                else:
                    assert stat['capture_gaps']==0 and not row['gap'],stat
                    base=int(pre['sp' if form=='sp' else 'x8'],0)
                    assert len(row['memory'])==2
                    for i,access in enumerate(row['memory']):
                        assert access['rw']=='w' and access['known'] and access['size']==width and int(access['addr'],0)==base+i*width
                        assert int(access['val'],0).to_bytes(width,'little')==raw[i*width:(i+1)*width]
                    known=[offset<=i<offset+len(raw) for i in range(32)]
                    assert [r['known'] for r in writers]==known
                    assert all(int(r['value'],0)==expected[i] for i,r in enumerate(writers) if r['known'])
                checks.append({'function':fn,'input':n,'mode':mode,'all65':True,'bytes_and_writers':True})
        print(fn,'PASS',flush=True)
    for opt in ['-O1','-O3']:
        module=out/f'libst2-c{opt}.dylib';run(['clang','-arch','arm64','-dynamiclib',opt,'-fno-stack-protector','-fomit-frame-pointer',FIX/'st2_c.c','-o',module])
        for count in [0,1,7,16]:
            seed=0x123456789abcdef0;initial=0x0123456789abcdef;want=bytearray(32);want[16:24]=initial.to_bytes(8,'little')
            for i in range(count):want[2*i]=(seed+i)&255;want[2*i+1]=(initial+i*3)&255
            native=invoke(module,'st2_c','native',out/'unused',seed,count,initial);assert native['buffer']==want.hex() and int(native['result'],0)==seed^initial
            for mode in ['trace-chunks','trace-fast']:
                path=out/f'c-{opt}-{count}-{mode}.gtsw';cap=invoke(module,'st2_c',mode,path,seed,count,initial,True)
                assert cap['ok'] and cap['buffer']==want.hex() and cap['result']==native['result']
                rows=query(path,'last-writers','--range',cap['data_base']+',32','--limit',32)['data']
                for i,row in enumerate(rows):
                    if row['known']:assert i<count*2 and int(row['value'],0)==want[i]
                stat=query(path,'stat')['meta'];assert stat['capture_gaps']==0 and [r['known'] for r in rows]==[i<count*2 for i in range(32)],stat
                instructions=query(path,'instructions','--limit',1000);assert not instructions['meta']['truncated']
                checks.append({'kind':'ordinary-c','optimization':opt,'count':count,'mode':mode,'unsupported':stat['unsupported_mnemonics'],'st2':sum(x['text'].startswith('st2 ') for x in instructions['data'])})
    (out/'summary.json').write_text(json.dumps({'status':'pass','count':len(checks),'checks':checks},indent=2)+'\n');print('PASS',len(checks),'targeted captures',flush=True)
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path);p.add_argument('--runner',type=Path,default=ROOT/'build/traceq-host/traceq-capture');p.add_argument('--cli',type=Path,default=ROOT/'cli/traceq');a=p.parse_args();check((a.out or ROOT/'artifacts'/f'st2-{time.time_ns()}').resolve(),a.runner.resolve(),a.cli.resolve())
