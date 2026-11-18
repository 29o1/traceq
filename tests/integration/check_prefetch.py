#!/usr/bin/env python3
"""Architectural prefetch hints preserve state and create no load/store facts."""
import argparse
import json
from pathlib import Path
import time
from check_bitops import run,REGS
from check_multiply import flags
ROOT=Path(__file__).resolve().parents[2];FIX=Path(__file__).resolve().parent/'fixtures'
NAMES=['base','store','exec','reg','shift','uxtw','sxtw','sxtx','unscaled_pos','unscaled_neg','unmapped','unnamed','forward','backward']
INPUTS=[0,(1<<64)-1,0x123456789abcdef0]

def c_expected(seed,initial,count):
    data=bytearray(32);data[16:24]=initial.to_bytes(8,'little');acc=seed;written=set()
    for i in range(count):
        at=(i*7)&31;data[at]^=acc&255;written.add(at);acc=(acc>>1)^(data[at]+i)
    return acc,data.hex(),written

def check(out,runner,cli):
    out.mkdir(parents=True,exist_ok=False);lib=out/'libprefetch.dylib'
    run(['clang','-dynamiclib',FIX/'prefetch_targets.S',FIX/'bitops_targets.S','-o',lib])
    def query(path,cmd,*args):return json.loads(run([cli,cmd,path,*args,'--json']))
    def invoke(module,fn,mode,path,seed,count,initial):return json.loads(run([runner,module,fn,mode,path,hex(seed),count,hex(initial)]))
    regs=[p for reg in REGS for p in ['--reg',reg]];records=[];initial=0x0123456789abcdef
    def hint_rows(path):
        instructions=query(path,'instructions','--limit',4096);assert not instructions['meta']['truncated']
        return [r for r in instructions['data'] if r['text'].startswith(('prfm ','prfum '))]
    def contexts(path,hints):
        assert 0<len(hints)<=64
        rows=query(path,'context',*[p for row in hints for p in ['--at-ev',row['ev']]],'--before',0,'--after',0,'--limit',64,*regs)['data']
        assert len(rows)==len(hints)
        for row in rows:
            assert row['completion']=='confirmed' and not row['gap'] and row['memory']==[]
            assert len(row['pre'])==len(row['post'])==65 and all(v is not None for v in row['pre'].values())
            assert row['pre']==row['post'],'hint changed registers or NZCV'
        return rows
    for name in NAMES:
        for n,seed in enumerate(INPUTS):
            fn='prefetch_'+name;want=(seed.to_bytes(8,'little')+bytes(8)+initial.to_bytes(8,'little')+bytes(8)).hex()
            native=invoke(lib,fn,'native',out/'unused',seed,1,initial);assert native['buffer']==want and int(native['result'],0)==seed
            for mode in ['trace-chunks','trace-fast']:
                path=out/f'{name}-{n}-{mode}.gtsw';cap=invoke(lib,fn,mode,path,seed,1,initial)
                assert cap['ok'] and cap['result']==native['result'] and cap['buffer']==want
                stat=query(path,'stat')['meta'];assert stat['capture_gaps']==stat['reads']==stat['unknown_reads']==0 and stat['stores']==1,stat
                hints=hint_rows(path);assert len(hints)==1;row=contexts(path,hints)[0];assert int(row['pre']['nzcv'],0)==flags(seed,1)
                writers=query(path,'last-writers','--range',cap['data_base']+',32','--limit',32)['data']
                assert [r['known'] for r in writers]==[i<8 for i in range(32)]
                assert all(int(r['value'],0)==bytes.fromhex(want)[i] for i,r in enumerate(writers) if r['known'])
                memory=query(path,'mem-state','--range',cap['data_base']+',32','--at-ev',row['ev'],'--phase','post','--limit',32)['data']
                assert [r['known'] for r in memory]==[i<8 for i in range(32)],'hint invented data knowledge'
                hits=query(path,'find-value','--value',0,'--read');assert not hits['data'] and hits['meta']['skipped_unknown_reads']==0
                records.append({'kind':'assembly','form':name,'input':n,'mode':mode,'all_65_unchanged':True,'writer_preserved':True})
        print(name,'OK',flush=True)
    for opt in ['-O1','-O2']:
        module=out/f'libprefetch-c{opt}.dylib';run(['clang','-dynamiclib',opt,'-fno-stack-protector','-fomit-frame-pointer',FIX/'prefetch_c.c','-o',module])
        for n,(seed,initial,count) in enumerate([(0,0,0),(1,0,1),((1<<64)-1,0xfedcba9876543210,7),(0x123456789abcdef0,0x0123456789abcdef,31)]):
            value,want,written=c_expected(seed,initial,count);native=invoke(module,'prefetch_c','native',out/'unused',seed,count,initial)
            assert int(native['result'],0)==value and native['buffer']==want
            for mode in ['trace-chunks','trace-fast']:
                path=out/f'c-{opt}-{n}-{mode}.gtsw';cap=invoke(module,'prefetch_c',mode,path,seed,count,initial)
                assert cap['buffer']==want and cap['result']==native['result']
                stat=query(path,'stat')['meta'];assert stat['capture_gaps']==0 and stat['reads']==stat['stores']==count,stat
                hints=hint_rows(path);contexts(path,hints)
                writers=query(path,'last-writers','--range',cap['data_base']+',32','--limit',32)['data']
                assert [r['known'] for r in writers]==[i in written for i in range(32)]
                assert all(int(r['value'],0)==bytes.fromhex(want)[i] for i,r in enumerate(writers) if r['known'])
                records.append({'kind':'compiled-c','optimization':opt,'input':n,'mode':mode,'hints':len(hints),'known_writers':len(written)})
    for mode in ['trace-chunks','trace-fast']:
        for fn in ['bitops_gap','bitops_unknown']:
            path=out/f'{fn}-{mode}.gtsw';cap=invoke(lib,fn,mode,path,0x1234,1,1)
            if fn=='bitops_gap':
                stat=query(path,'stat')['meta'];assert stat['capture_gaps']==1 and stat['unsupported_mnemonics']=={'st3':1}
                writers=query(path,'last-writers','--range',cap['data_base']+',8')['data'];assert all(not r['known'] and r['value'] is None and r['last_observed_write'] is not None for r in writers)
                assert bytes(int(r['last_observed_write']['value'],0) for r in writers)==(0x1234).to_bytes(8,'little')
            else:
                stat=query(path,'stat')['meta'];assert stat['capture_gaps']==0 and stat['unknown_reads']==1
                hits=query(path,'find-value','--value',0,'--read');assert not hits['data'] and hits['meta']['skipped_unknown_reads']==1
            records.append({'kind':'unknown-gap-guard','function':fn,'mode':mode})
    (out/'summary.json').write_text(json.dumps({'status':'pass','count':len(records),'checks':records},indent=2)+'\n');print('PASS',len(records),'targeted captures',flush=True)

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path);p.add_argument('--runner',type=Path,default=ROOT/'build/traceq-host/traceq-capture');p.add_argument('--cli',type=Path,default=ROOT/'cli/traceq');a=p.parse_args()
    check((a.out or ROOT/'artifacts'/f'prefetch-{time.time_ns()}').resolve(),a.runner.resolve(),a.cli.resolve())
