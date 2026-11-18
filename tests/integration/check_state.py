#!/usr/bin/env python3
"""Independent state/read checks and an ordinary C input-to-output case."""
import hashlib
import json
from pathlib import Path
import re
import struct
import sys
import time

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
sys.path.insert(0,str(HERE))
from check_capture import invoke,BUILD,GT
from expectations import CASES,expected,last_writers,writes

def decode(path):
    raw=path.read_bytes();assert raw[:8]==b'GTSW001\0' and len(raw)%64==0
    code,_,base,_,_,profile,_=struct.unpack_from('<7Q',raw,8);assert profile==2
    state={};groups=[];g=None;gaps=[]
    def key(slot):return f'x{slot}' if slot<31 else 'sp' if slot==31 else 'nzcv' if slot==32 else f'v{slot-33}'
    for offset in range(64,len(raw),64):
        kind,seq,pc,address,size,low,high,detail=struct.unpack_from('<8Q',raw,offset)
        value=low+(high<<64)
        if kind==1:
            g=dict(pc=pc-code,seq=seq,pre=state.copy(),post=None,committed=False,memory=[]);groups.append(g)
        elif kind in (5,6):
            name=key(address)
            if kind==5:g['pre'][name]=value
            else:
                if g['post'] is None:g['post']=g['pre'].copy()
                g['post'][name]=value
            state[name]=value
        elif kind in (2,7):g['memory'].append(dict(rw='w' if kind==2 else 'r',offset=address-base,size=size,value=value if detail else None))
        elif kind==3:state={};gaps.append((seq,detail))
        elif kind==9:
            g['committed']=True
            if g['post'] is None:g['post']=g['pre'].copy()
        elif kind==4:assert seq==len(groups)
    return groups,gaps

def capture(out,name,function,seed,count,initial,mode='trace'):
    path=out/(name+'.gtsw')
    data=invoke([BUILD/'traceq-capture',BUILD/'libfixtures.dylib',function,mode,path,hex(seed),str(count),hex(initial)])
    return path,data

def run():
    out=ROOT/'artifacts'/('state-check-'+str(time.time_ns()));out.mkdir(parents=True)
    validations=[]
    for case in CASES:
        path,c=capture(out,case['id'],case['function'],case['seed'],case['count'],case['initial'])
        want=expected(case);assert c['buffer']==want['buffer'] and int(c['result'],0)==want['result'],case['id']
        groups,gaps=decode(path);assert [g['pc'] for g in groups]==[e['pc'] for e in want['events']]
        assert gaps==([(1,1)] if case.get('partial') else [])
        checked=0
        for actual,event in zip(groups,want['events']):
            if not(case.get('partial') and actual['seq']==1):assert actual['memory']==event.get('memory',[]),(case['id'],actual,event)
            for phase in ('pre','post'):
                if phase=='post' and not actual['committed']:continue
                for reg,value in event.get(phase,{}).items():
                    assert actual[phase].get(reg)==value,(case['id'],actual['seq'],phase,reg,actual[phase].get(reg),value)
                    checked+=1
        q=invoke([GT,'last-writers',path,'--range',c['data_base']+',32','--limit','32','--json'])
        got=[(r['writer_seq'],int(r['pc_offset'],0),int(r['value'],0)) if r['known'] else None for r in q['data']]
        assert got==last_writers(want,partial=case.get('partial',False))
        # Terminal RET has a real pre snapshot, with no invented post snapshot.
        ret=len(groups)-1
        query=invoke([GT,'reg-state',path,'--at-ev',str(ret),'--phase','pre','--reg','x0','--json'])
        assert int(query['data'][0]['val'],0)==want['result']
        query=invoke([GT,'reg-state',path,'--at-ev',str(ret),'--phase','post','--reg','x0','--json'])
        assert not query['data'][0]['known']
        validations.append(dict(case=case['id'],state_facts=checked,passed=True,gaps=gaps))
        print('state:',case['id'],flush=True)
    c_cases=[]
    for n,(seed,count,initial) in enumerate([(0x12345678,4,0x8877665544332211),(0,8,0xffffffffffffffff),(0xffffffff,1,0x80),(9,0,7)]):
        name=f'c-transform-{n}';path,c=capture(out,name,'c_transform',seed,count,initial)
        native=invoke([BUILD/'traceq-capture',BUILD/'libfixtures.dylib','c_transform','native',out/'unused',hex(seed),str(count),hex(initial)])
        buf=bytearray(32);buf[16:24]=initial.to_bytes(8,'little');state=seed&0xffffffff;intermediates=[]
        for i in range(min(count,8)):
            state=((state^buf[16+i])*33+17)&0xffffffff;buf[i]=(state>>3)&255;intermediates.append(state)
        buf[8:12]=state.to_bytes(4,'little')
        assert c['result']==native['result']==hex(state) and c['buffer']==native['buffer']==buf.hex()
        groups,gaps=decode(path);assert not gaps
        accesses=[(g,m) for g in groups for m in g['memory']]
        reads=[m for g,m in accesses if m['rw']=='r'];assert reads==[dict(rw='r',offset=16+i,size=1,value=buf[16+i]) for i in range(min(count,8))]
        write_bytes={}
        for g,m in accesses:
            if m['rw']=='w':
                for i in range(m['size']):write_bytes[m['offset']+i]=(m['value']>>(8*i))&255
        assert write_bytes=={i:buf[i] for i in [*range(min(count,8)),*range(8,12)]}
        query=invoke([GT,'mem-access',path,'--range',c['data_base']+',32','--limit','64','--json'])
        c_cases.append(dict(case=name,seed=seed,count=count,initial=initial,result=state,passed=True))
        if n==0:
            first_read=next(r for r in query['data'] if r['rw']=='r')
            first_write=next(r for r in query['data'] if r['rw']=='w' and int(r['addr'],0)==int(c['data_base'],0))
            fragment=invoke([GT,'instructions',path,'--from',str(first_read['ev']),'--to',str(first_write['ev']),'--json'])
            states=[]
            for instruction in fragment['data']:
                names=list(dict.fromkeys(re.findall(r'\b[wx]\d+\b',instruction['text'])))
                args=[item for name in names for item in ('--reg',name)]
                if not args:continue
                pre=invoke([GT,'reg-state',path,'--at-ev',str(instruction['ev']),'--phase','pre',*args,'--json'])
                post=invoke([GT,'reg-state',path,'--at-ev',str(instruction['ev']),'--phase','post',*args,'--json'])
                states.append(dict(instruction=instruction,pre=pre,post=post))
            last_store=next(g for g,m in reversed(accesses) if m['rw']=='w')
            memory=invoke([GT,'mem-state',path,'--range',c['data_base']+',12','--at-ev',str(last_store['seq']),'--json'])
            for row in memory['data']:
                i=int(row['address'],0)-int(c['data_base'],0)
                if i in write_bytes:assert row['known'] and int(row['value'],0)==buf[i]
                else:assert not row['known']
            chain={'capture':c,'input_byte':first_read,'output_byte':first_write,'expected_first_state':intermediates[0],
                   'instructions':fragment,'states':states,'memory':memory}
            (out/'c-evidence.json').write_text(json.dumps(chain,indent=2)+'\n')
        print('C:',name,flush=True)
    # A sign-extended destination preserves the accessed byte; a discarded load
    # reports its address/width with an unknown value instead of guessing zero.
    path,c=capture(out,'signed-discard','signed_discard_read',0,1,0x80)
    assert int(c['result'],0)==0xffffffffffffff80
    q=invoke([GT,'mem-access',path,'--range',c['data_base']+',32','--read','--json'])
    assert q['data'][0]['val']=='0x80' and q['data'][0]['size']==1
    assert q['data'][1]['val'] is None and not q['data'][1]['known']
    assert q['meta']['unknown_reads']==1 and q['meta']['capture_gaps']==0
    path,c=capture(out,'outside-call','outside_call',0x123456789abcdef0,1,0)
    assert c['buffer'][:16]=='f0debc9a78563412'
    q=invoke([GT,'last-writers',path,'--range',c['data_base']+',24','--limit','24','--json'])
    assert q['meta']['capture_gaps']==1
    assert [r['known'] for r in q['data']]==[i==16 for i in range(24)]
    summary={'state_cases':validations,'c_cases':c_cases,
             'boundary_cases':['signed/discarded load','out-of-range helper call'],
             'binary_sha256':{str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in (GT,BUILD/'traceq-capture',BUILD/'libfixtures.dylib')}}
    (out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    print('PASS:',len(validations),'state cases,',len(c_cases),'C inputs, 2 boundary cases')
    print(out)

if __name__=='__main__':run()
