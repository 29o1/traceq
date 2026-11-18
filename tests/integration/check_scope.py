#!/usr/bin/env python3
"""Native cross-image calls, callbacks, tail exits and CLI provenance checks."""
import argparse
import json
from pathlib import Path
import subprocess
import time

ROOT=Path(__file__).resolve().parents[2]
HERE=Path(__file__).resolve().parent

def run(args):
    return subprocess.run(list(map(str,args)),capture_output=True,text=True,check=True,timeout=30)

def query(path,command,*args):
    return json.loads(run([ROOT/'cli/traceq',command,path,*args,'--json']).stdout)

def check(out):
    out.mkdir(parents=True,exist_ok=False)
    run(['clang','-dynamiclib','-O2',HERE/'fixtures/cross_external.c','-install_name','@loader_path/libexternal.dylib','-o',out/'libexternal.dylib'])
    run(['clang','-dynamiclib',HERE/'fixtures/cross_scope.S',out/'libexternal.dylib','-o',out/'libscope.dylib'])
    rows=[]
    for function,mode in [('cross_target',0),('cross_target',1),('cross_target',2),('cross_target',3),('cross_tail',1),('cross_direct',1)]:
        name=function+'-'+str(mode);seed=0x1234
        command=[ROOT/'build/traceq-host/traceq-capture',out/'libscope.dylib',function]
        native=json.loads(run([*command,'native',out/'unused',hex(seed),str(mode),'0']).stdout)
        expected=[seed if mode in (0,3) else seed^(0xa5 if mode==2 else 0x5a),seed+3 if mode==2 else seed]
        if function=='cross_target':expected+=[expected[0],seed+7]
        else:expected=[expected[0],0,0,0]
        assert native['buffer']==b''.join(n.to_bytes(8,'little') for n in expected).hex()
        assert int(native['result'],16)==seed+7
        for capture_mode in ['trace-chunks','trace-fast']:
            path=out/(name+'-'+capture_mode+'.gtsw')
            capture=json.loads(run([*command,capture_mode,path,hex(seed),str(mode),'0','--all-data','--follow-external']).stdout)
            assert capture['buffer']==native['buffer'] and capture['result']==native['result']
            stat=query(path,'stat');boundaries=query(path,'boundaries','--limit','20')
            assert stat['meta']['boundary_capture'] and not stat['meta']['unpositioned_gap']
            assert stat['meta']['external_execution']=='followed_without_instruction_records'
            spans=boundaries['data'];assert not boundaries['meta']['truncated']
            if function=='cross_target':
                assert len(spans)==(3 if mode==2 else 2)
                first=spans[0];assert first['transfer']=='call' and first['target']['module']=='libexternal.dylib'
                assert int(first['exit_registers']['x0'],16)==seed
                assert first['exit_registers']['x1']==capture['data_base']
                assert first['reentry_matches_expected_return']==(mode!=2)
                assert spans[-1]['transfer']=='return' and spans[-1]['status']=='no_reentry_observed'
                assert stat['meta']['capture_gaps']==(2 if mode==2 else 1)
                if mode==2:
                    assert spans[1]['transfer']=='return' and spans[1]['status']=='reentered'
                    assert spans[1]['target']['module']=='libexternal.dylib'
                else:assert int(first['reentry_registers']['x0'],16)==seed+7
                writers=query(path,'last-writers','--range',capture['data_base']+',32','--limit','32')
                assert [r['known'] for r in writers['data']]==[i>=16 for i in range(32)]
                assert all(r['last_observed_write'] is not None for r in writers['data'])
                # All three external effects have an unobserved interval. Even
                # same-value writes must not turn unchanged bytes into provenance.
                for row in writers['data']:
                    first_gap=row['last_observed_write']['first_located_gap']
                    if row['known']:
                        assert first_gap is None
                    else:
                        assert first_gap['reasons']==['outside_code_range']
                        span=next(s for s in spans if s['exit_ev']==first_gap['ev'])
                        assert first_gap['scope_exit']['target']==span['target']
                        assert first_gap['scope_exit']['reentry_ev']==span['reentry_ev']
                        assert first_gap['scope_exit']['memory_effects']=='unobserved'
                at_exit=query(path,'last-writers','--range',capture['data_base']+',8','--at-seq',str(first['exit_ev']))
                assert all(r['last_observed_write']['first_located_gap']['scope_exit']['reentry_ev'] is None for r in at_exit['data'])

                prior=bytes(int(r['last_observed_write']['value'],16) for r in writers['data'][:16])
                assert prior==seed.to_bytes(8,'little')+(seed+3 if mode==2 else seed).to_bytes(8,'little')
                assert writers['data'][0]['last_observed_write']['gaps_since']==(2 if mode==2 else 1)
                # A later load can restore the byte value without restoring its writer.
                last=stat['meta']['instructions']-1
                state=query(path,'mem-state','--range',capture['data_base']+',8','--at-ev',str(last),'--phase','pre')
                assert all(r['known'] for r in state['data'])
                assert bytes(int(r['value'],16) for r in state['data'])==expected[0].to_bytes(8,'little')
                historical=query(path,'last-writers','--range',capture['data_base']+',8','--at-seq',str(first['exit_ev']-1))
                assert all(r['known'] and r['last_observed_write']['gaps_since']==0 for r in historical['data'])
                page=query(path,'boundaries','--limit','1','--offset','1')
                assert page['data']==spans[1:2]
                selected=query(path,'boundaries','--from',str(first['exit_ev']),'--to',str(first['exit_ev']),'--reg','x0')
                assert len(selected['data'])==1 and list(selected['data'][0]['exit_registers'])==['x0']
                (out/(name+'-'+capture_mode+'-writers.json')).write_text(json.dumps(writers,indent=2)+'\n')
            else:
                assert len(spans)==1 and spans[0]['transfer']=='branch' and spans[0]['status']=='no_reentry_observed'
                assert stat['meta']['capture_gaps']==1
            (out/(name+'-'+capture_mode+'-boundaries.json')).write_text(json.dumps(boundaries,indent=2)+'\n')
            rows.append({'case':name,'mode':capture_mode,'boundaries':len(spans),'gaps':stat['meta']['capture_gaps'],'native_match':True})
            print(name,capture_mode,'OK',flush=True)
    (out/'summary.json').write_text(json.dumps({'checks':rows,'count':len(rows)},indent=2)+'\n')

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path);a=p.parse_args();check((a.out or ROOT/'artifacts'/('scope-check-'+str(time.time_ns()))).resolve())
