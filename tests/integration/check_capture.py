#!/usr/bin/env python3
"""Run the merged capture -> query chain using only repository-local assets."""
from pathlib import Path
import hashlib
import json
import struct
import subprocess
import sys
import time

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
sys.path.insert(0,str(HERE/'fixtures'))
from expectations import CASES,expected,writes,last_writers

GT=ROOT/'cli/traceq'
BUILD=ROOT/'build/traceq-host'

def invoke(args):
    result=subprocess.run([str(x) for x in args],capture_output=True,text=True,timeout=30)
    if result.returncode:raise AssertionError(f'{args}: {result.returncode}: {result.stdout[:500]} {result.stderr[:500]}')
    return json.loads(result.stdout)

def decoded(path):
    data=path.read_bytes()
    assert data[:8]==b'GTSW001\0' and len(data)%64==0
    code,code_size,base,length,tid,profile,width=struct.unpack_from('<7Q',data,8)
    records=[struct.unpack_from('<8Q',data,n) for n in range(64,len(data),64)]
    assert records[-1][0]==4
    pcs=[r[2]-code for r in records if r[0]==1]
    stores=[dict(seq=r[1],pc=r[2]-code,offset=r[3]-base,size=r[4],value=r[5]+(r[6]<<64)) for r in records if r[0]==2]
    gaps=[r for r in records if r[0]==3]
    return pcs,stores,gaps

def main():
    out=ROOT/'artifacts'/('capture-check-'+str(time.time_ns()));out.mkdir(parents=True)
    results=[]
    for case in CASES:
        answer=expected(case)
        args=[BUILD/'traceq-capture',BUILD/'libfixtures.dylib',case['function']]
        inputs=[hex(case['seed']),str(case['count']),str(case['initial'])]
        native=invoke([*args,'native',out/'unused',*inputs])
        assert int(native['result'],0)==answer['result'] and native['buffer']==answer['buffer'],case['id']
        path=out/(case['id']+'.gtsw')
        capture=invoke([*args,'writes',path,*inputs])
        assert capture['ok'] and capture['buffer']==native['buffer'] and capture['result']==native['result'],case['id']
        pcs,stores,gaps=decoded(path)
        assert pcs==[r['pc'] for r in answer['events']],case['id']
        want=writes(answer)
        if case.get('partial'):
            assert len(gaps)==1 and gaps[0][1]==1
            want=[r for r in want if r['seq']!=1]
        else:assert not gaps,case['id']
        assert stores==want,case['id']
        query=invoke([GT,'last-writers',path,'--range',capture['data_base']+',32','--limit','32','--json'])
        actual=[(r['writer_seq'],int(r['pc_offset'],0),int(r['value'],0)) if r['known'] else None for r in query['data']]
        assert actual==last_writers(answer,partial=case.get('partial',False)),case['id']
        assert query['meta']['capture_gaps']==len(gaps)
        (out/(case['id']+'.json')).write_text(json.dumps({'native':native,'capture':capture,'query':query},indent=2)+'\n')
        results.append({'case':case['id'],'partial':case.get('partial',False),'passed':True})
    summary={'cases':results,'supported_cases':sum(not c.get('partial') for c in CASES),
             'partial_cases':sum(bool(c.get('partial')) for c in CASES),'structured_capture_chain_passed':True,
             'binaries':{str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest()
                         for p in [GT,BUILD/'traceq-capture',BUILD/'libfixtures.dylib']}}
    (out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    print(f"PASS: {len(results)} capture cases, native results, write facts, byte provenance, and structured capture chain")
    print(out)

if __name__=='__main__':main()
