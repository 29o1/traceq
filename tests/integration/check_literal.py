#!/usr/bin/env python3
"""Literal-load addresses, completed values, full snapshots and unknowns."""
import argparse
import json
from pathlib import Path
import subprocess
import time
from check_multiply import c_expected

ROOT=Path(__file__).resolve().parents[2]
FIXTURES=Path(__file__).resolve().parent/'fixtures'
MASK=(1<<64)-1
LOW=0x7ff8123480000001
HIGH=0xfedcba987fc12345
REGS=[*[f'x{i}' for i in range(31)],'sp','nzcv',*[f'v{i}' for i in range(32)]]
FORMS={'w':4,'x':8,'sw':4,'s':4,'d':8,'q':16,'wzr':4,'xzr':8,'swzr':4}

def run(args):
    r=subprocess.run(list(map(str,args)),capture_output=True,text=True,timeout=30)
    if r.returncode:raise AssertionError((args,r.returncode,r.stdout[-1000:],r.stderr[-1000:]))
    return r.stdout

def query(cli,path,cmd,*args):return json.loads(run([cli,cmd,path,*args,'--json']))

def cases():
    for direction in ['forward','backward']:
        for payload in ['zero','bits']:
            for form in ['w','x','sw','s','d','q']:
                yield f'literal_{form}_{direction}_{payload}',form,direction,0 if payload=='zero' else LOW,0 if payload=='zero' else HIGH
    yield 'literal_s_nan','s','forward',0x7fc12345,0
    for direction in ['forward','backward']:
        for form in ['wzr','xzr','swzr']:
            yield f'literal_{form}_{direction}',form,direction,0 if direction=='backward' else LOW,0

def expected(form,low,high,seed,initial):
    size=FORMS[form];value=(low|(high<<64))&((1<<(size*8))-1)
    result=MASK
    if form in ['w','x']:result=value
    if form=='sw':result=value if value<1<<31 else value|((MASK>>32)<<32)
    buf=bytearray(32);buf[:8]=seed.to_bytes(8,'little');buf[16:24]=initial.to_bytes(8,'little')
    if form in ['s','d','q']:buf[16:32]=value.to_bytes(16,'little')
    else:buf[8:16]=result.to_bytes(8,'little')
    return result,buf.hex(),value

def literal_address(row):
    word=int(row['opcode'],0);assert word&0x3b000000==0x18000000,row
    imm=(word>>5)&0x7ffff
    if imm&0x40000:imm-=1<<19
    return (int(row['pc'],0)+4*imm)&MASK

def validate(cli,path,cap,form,direction,low,high,seed,initial,restricted=False):
    result,buf,value=expected(form,low,high,seed,initial)
    assert cap['ok'] and int(cap['result'],0)==result and cap['buffer']==buf,(form,cap,buf)
    stat=query(cli,path,'stat')['meta']
    ins=query(cli,path,'instructions','--limit',100)['data']
    loads=[r for r in ins if r['text'].startswith(('ldr ','ldrsw ')) and '[' not in r['text']]
    assert len(loads)==1,loads
    row=query(cli,path,'context','--at-ev',loads[0]['ev'],'--before',0,'--after',0,
              *[p for reg in REGS for p in ['--reg',reg]])['data'][0]
    assert row['completion']=='confirmed',row
    address=literal_address(row)
    assert (address<int(row['pc'],0))==(direction=='backward'),row
    assert len(row['pre'])==len(row['post'])==65
    assert all(v is not None for v in [*row['pre'].values(),*row['post'].values()])
    assert int(row['pre']['x8'],0)==MASK and int(row['pre']['v31'],0)==(1<<128)-1
    changed='v31' if form in ['s','d','q'] else 'x8' if form in ['w','x','sw'] else None
    assert all(row['pre'][r]==row['post'][r] for r in REGS if r!=changed),row
    if changed:assert int(row['post'][changed],0)==(value if changed=='v31' else result),row
    if restricted:
        assert stat['capture_gaps']==1 and stat['gap_reasons']['outside_data_range']==1,stat
        assert row['gap_reasons']==['outside_data_range'] and not row['memory'],row
        writers=query(cli,path,'last-writers','--range',cap['data_base']+',8')['data']
        assert all(not r['known'] and r['last_observed_write'] is not None for r in writers),writers
    else:
        assert not stat['capture_gaps'] and not row['gap'],stat
        assert len(row['memory'])==1,row
        memory=row['memory'][0];unknown=form.endswith('zr')
        assert memory['rw']=='r' and int(memory['addr'],0)==address and memory['size']==FORMS[form]
        assert memory['known']==(not unknown) and memory['val']==(None if unknown else hex(value)),memory
        assert stat['unknown_reads']==int(unknown),stat
        hit=query(cli,path,'find-value','--value',hex(0 if unknown else value),'--read','--limit',100)
        if unknown:assert hit['data']==[] and hit['meta']['skipped_unknown_reads']==1,hit
        else:assert any(r['ev']==row['ev'] and int(r['addr'],0)==address for r in hit['data']),hit
        # A read supplies bytes to mem-state, without manufacturing a writer.
        pool=query(cli,path,'mem-state','--range',hex(address)+','+str(FORMS[form]),'--at-ev',row['ev'])['data']
        assert all(r['known']==(not unknown) for r in pool),pool
        if not unknown:assert [int(r['value'],0) for r in pool]==list(value.to_bytes(FORMS[form],'little'))
        writers=query(cli,path,'last-writers','--range',hex(address)+','+str(FORMS[form]))['data']
        assert all(not r['known'] and r['last_observed_write'] is None for r in writers),writers
    return dict(form=form,direction=direction,event=row['ev'],width=FORMS[form],
                address=hex(address),gaps=stat['capture_gaps'],unknown_reads=stat['unknown_reads'],all_65_slots_checked=True)

def check(out,runner,cli):
    out.mkdir(parents=True,exist_ok=False)
    lib=out/'libliteral.dylib';run(['clang','-dynamiclib',FIXTURES/'literal_targets.S','-o',lib])
    seed,initial=0x89abcdef12345678,0x0123456789abcdef
    def invoke(lib,fn,mode,path,count=7,all_data=True):
        return json.loads(run([runner,lib,fn,mode,path,hex(seed),count,hex(initial),*(['--all-data'] if all_data else [])]))
    records=[]
    for fn,form,direction,low,high in cases():
        native=invoke(lib,fn,'native',out/'unused')
        value,buf,_=expected(form,low,high,seed,initial)
        assert int(native['result'],0)==value and native['buffer']==buf,(fn,native,buf)
        for mode in ['trace-chunks','trace-fast']:
            path=out/f'{fn}-{mode}.gtsw';cap=invoke(lib,fn,mode,path)
            facts=validate(cli,path,cap,form,direction,low,high,seed,initial)
            records.append(dict(kind='assembly',function=fn,mode=mode,**facts))
    print('literal forms and zero-register unknowns OK',flush=True)
    for form in ['x','sw','q']:
        fn=f'literal_{form}_forward_bits'
        for mode in ['trace-chunks','trace-fast']:
            path=out/f'restricted-{form}-{mode}.gtsw';cap=invoke(lib,fn,mode,path,all_data=False)
            facts=validate(cli,path,cap,form,'forward',LOW,HIGH,seed,initial,restricted=True)
            records.append(dict(kind='restricted-data',mode=mode,**facts))
    for mode in ['trace-chunks','trace-fast']:
        path=out/f'prefetch-{mode}.gtsw';cap=invoke(lib,'literal_prefetch',mode,path)
        native=invoke(lib,'literal_prefetch','native',out/'unused')
        assert cap['buffer']==native['buffer'] and cap['result']==native['result']
        stat=query(cli,path,'stat')['meta'];assert not stat['unsupported_mnemonics'] and stat['capture_gaps']==0 and stat['reads']==0,stat
        writers=query(cli,path,'last-writers','--range',cap['data_base']+',8')['data']
        assert all(r['known'] and r['last_observed_write'] is not None for r in writers)
        assert bytes(int(r['value'],0) for r in writers)==seed.to_bytes(8,'little')
        records.append(dict(kind='prefetch-hint',mode=mode))
    for opt in ['-O1','-O2']:
        lib=out/f'libc{opt}.dylib';run(['clang','-dynamiclib',opt,'-fno-stack-protector','-fomit-frame-pointer',FIXTURES/'multiply_c.c','-o',lib])
        for n,count in enumerate([0,7,31]):
            value,buf=c_expected('multiply_indexed',seed,initial,count)
            native=invoke(lib,'multiply_indexed','native',out/'unused',count)
            assert int(native['result'],0)==value and native['buffer']==buf
            for mode in ['trace-chunks','trace-fast']:
                path=out/f'c-{opt}-{n}-{mode}.gtsw';cap=invoke(lib,'multiply_indexed',mode,path,count)
                assert cap['buffer']==buf and int(cap['result'],0)==value
                stat=query(cli,path,'stat')['meta'];assert stat['capture_gaps']==0,stat
                writers=query(cli,path,'last-writers','--range',cap['data_base']+',20')['data']
                assert all(r['known'] for r in writers) and [int(r['value'],0) for r in writers]==list(bytes.fromhex(buf)[:20])
                rows=query(cli,path,'instructions','--limit',4096)
                assert not rows['meta']['truncated']
                literals=[r for r in rows['data'] if r['text'].startswith('ldr ') and '[' not in r['text']]
                if opt=='-O2':assert literals,'expected the compiler-generated literal load'
                for ins in literals:
                    row=query(cli,path,'context','--at-ev',ins['ev'],'--before',0,'--after',0)['data'][0]
                    assert row['completion']=='confirmed' and not row['gap'] and len(row['memory'])==1
                    assert row['memory'][0]['known'] and int(row['memory'][0]['addr'],0)==literal_address(row)
                records.append(dict(kind='compiled-c',optimization=opt,count=count,mode=mode,literal_loads=len(literals),gaps=stat['capture_gaps']))
    (out/'summary.json').write_text(json.dumps(dict(count=len(records),checks=records),indent=2)+'\n')
    print('PASS',len(records),'targeted captures',flush=True)

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path)
    p.add_argument('--runner',type=Path,default=ROOT/'build/traceq-host/traceq-capture')
    p.add_argument('--cli',type=Path,default=ROOT/'cli/traceq');a=p.parse_args()
    check((a.out or ROOT/'artifacts'/f'literal-{time.time_ns()}').resolve(),a.runner.resolve(),a.cli.resolve())
