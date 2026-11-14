"""Independent hand expectations. Never imported by the capture executable."""
from extended_expectations import CASES as PREVIOUS, expected as prior_expected

CASES=[*PREVIOUS,
    dict(id='fp-finite',function='fp_store_bits',seed=0x3ff000003f800000,count=1,initial=0),
    dict(id='fp-nan-bits',function='fp_store_bits',seed=0x7ff80000ffc12345,count=1,initial=0),
    dict(id='store-writeback',function='store_writeback',seed=0x123456789abcdef0,count=7,initial=0),
    dict(id='store-writeback-zero',function='store_writeback',seed=0,count=0,initial=0),
    dict(id='store-buffer-flush',function='store_loop',seed=0,count=2048,initial=0),
    dict(id='unsupported-st1',function='unsupported_store',seed=0xab,count=1,initial=0,partial=True)]

def expected(case):
    if case['function'] in {c['function'] for c in PREVIOUS}: return prior_expected(case)
    events=[];buf=bytearray(32);buf[16:24]=case['initial'].to_bytes(8,'little')
    def step(pc,stores=()):
        memory=[]
        for off,size,value in stores:
            value &= (1<<(size*8))-1
            buf[off:off+size]=value.to_bytes(size,'little')
            memory.append(dict(rw='w',offset=off,size=size,value=value))
        events.append(dict(pc=pc,memory=memory))
    seed=case['seed'];count=case['count'];result=seed
    if case['function']=='fp_store_bits':
        step(0);step(4,[(0,8,seed)]);step(8);step(12,[(8,4,seed)]);step(16,[(16,8,0)]);step(20)
    elif case['function']=='store_writeback':
        step(0);step(4,[(16,8,seed),(24,8,count)]);step(8,[(16,8,0)]);step(12,[(4,4,seed)]);step(16);step(20)
        result=seed^count
    elif case['function']=='store_loop':
        step(0)
        for i in range(count): step(4,[(0,8,i)]);step(8);step(12);step(16)
        step(20);step(24);result=count
    elif case['function']=='unsupported_store':
        step(0);step(4,[(0,16,int.from_bytes(bytes([3])*16,'little'))]);step(8,[(20,1,seed)]);step(12)
    else:raise ValueError(case)
    return dict(events=events,buffer=buf.hex(),result=result)

def writes(answer):
    return [dict(seq=i,pc=e['pc'],offset=m['offset'],size=m['size'],value=m['value'])
            for i,e in enumerate(answer['events']) for m in e.get('memory',[]) if m['rw']=='w']

def last_writers(answer,at=None,partial=False):
    rows=[None]*32
    for i,event in enumerate(answer['events']):
        if at is not None and i>at:break
        if partial and i==1:
            rows=[None]*32
            continue
        for m in event.get('memory',[]):
            if m['rw']=='w':
                for k in range(m['size']):rows[m['offset']+k]=(i,event['pc'],(m['value']>>(8*k))&255)
    return rows
