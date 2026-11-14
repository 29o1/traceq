"""Independent semantic expectations for the new instruction mechanisms."""
from base_expectations import CASES as ORIGINAL_CASES,expected as original_expected,MASK,subtract_flags

CASES=[*ORIGINAL_CASES,
    dict(id='pair-zero',function='pair_writeback',seed=0,count=7,initial=0),
    dict(id='pair-wide',function='pair_writeback',seed=MASK,count=3,initial=0),
    dict(id='simd-zero',function='simd_bytes',seed=0,count=1,initial=0),
    dict(id='simd-lanes',function='simd_bytes',seed=0xff807f1200fe55aa,count=1,initial=0),
    dict(id='indexed-wrap',function='indexed_bytes',seed=250,count=8,initial=0),
    dict(id='indexed-wide',function='indexed_bytes',seed=0x123456789abcdef0,count=16,initial=0),
    dict(id='loop-long',function='state_loop',seed=123,count=1024,initial=7)]

def expected(case):
    if case['function'] in ('arithmetic_branch','memory_overlap','state_loop'):
        return original_expected(case)
    regs={'x0':case['seed'],'x2':case['count']};buf=bytearray(32);buf[16:24]=case['initial'].to_bytes(8,'little');events=[]
    def step(pc,updates=None,memory=None):
        pre=regs.copy()
        for reg,value in (updates or {}).items():regs[reg]=value & ((1<<(128 if reg.startswith('v') else 64))-1)
        events.append(dict(pc=pc,pre=pre,post=regs.copy(),memory=memory or []))
    def write(offset,size,value):
        value&=(1<<(8*size))-1;buf[offset:offset+size]=value.to_bytes(size,'little')
        return dict(rw='w',offset=offset,size=size,value=value)
    def read(offset,size):return dict(rw='r',offset=offset,size=size,value=int.from_bytes(buf[offset:offset+size],'little'))
    if case['function']=='pair_writeback':
        step(0,memory=[write(0,8,regs['x0']),write(8,8,regs['x2'])])
        step(4)  # Pointer value is runtime-specific; its writeback is tested by later addresses.
        m=[read(0,8),read(8,8)];step(8,{'x3':m[0]['value'],'x4':m[1]['value']},m)
        step(12,memory=[write(16,8,regs['x3'])]);step(16,memory=[write(24,8,regs['x4'])])
        step(20,{'x0':regs['x3']^regs['x4']});step(24)
    elif case['function']=='simd_bytes':
        first=bytes([0x12]*16);second=case['seed'].to_bytes(8,'little')*2
        xor=bytes(a^b for a,b in zip(first,second));added=bytes((v+0x12)&255 for v in xor)
        step(0,{'v0':int.from_bytes(first,'little')})
        step(4,{'v1':int.from_bytes(second,'little')})
        step(8,{'v2':int.from_bytes(xor,'little')})
        step(12,memory=[write(0,16,regs['v2'])])
        step(16,{'v3':int.from_bytes(xor,'little')},[read(0,16)])
        step(20,{'v4':int.from_bytes(added,'little')})
        step(24,memory=[write(16,16,regs['v4'])])
        step(28,{'x0':int.from_bytes(added[:8],'little')});step(32)
    elif case['function']=='indexed_bytes':
        step(0,{'x4':0});step(4,{'x6':0})
        for i in range(case['count']):
            step(8,{'x3':regs['x0']+i})
            step(12,memory=[write(i,1,regs['x3'])])
            m=read(i,1);step(16,{'x5':m['value']},[m])
            step(20,{'x6':regs['x6']+regs['x5']})
            step(24,{'x4':i+1});step(28,{'nzcv':subtract_flags(i+1,case['count'])});step(32)
        step(36,memory=[write(24,8,regs['x6'])]);step(40,{'x0':regs['x6']});step(44)
    else:raise ValueError(case['function'])
    events[-1]['post']={}
    return dict(events=events,result=regs['x0'],buffer=buf.hex())
