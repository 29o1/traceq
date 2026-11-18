#!/usr/bin/env python3
"""SHA-256 state observation: independent scalar rounds/schedule and native hashes.
Operand roles: https://arm-software.github.io/acle/neon_intrinsics/advsimd.html#sha256
"""
import argparse,hashlib,json,subprocess,sys,time
from pathlib import Path
from check_simd import run,REGS
from rust_classifier import archive as classifier_archive
ROOT=Path(__file__).resolve().parents[2];MASK=(1<<64)-1;U32=(1<<32)-1

def ror(x,n):return ((x>>n)|(x<<(32-n)))&U32
def small0(x):return ror(x,7)^ror(x,18)^(x>>3)
def small1(x):return ror(x,17)^ror(x,19)^(x>>10)
def lanes(x):return [(x>>(32*i))&U32 for i in range(4)]
def pack(x):return sum((v&U32)<<(32*i) for i,v in enumerate(x))
def expected(op,d,n,m=0):
 left,right,wk=lanes(d),lanes(n),lanes(m)
 if op=='sha256su0':return pack([(left[i]+small0((left[1:]+right[:1])[i]))&U32 for i in range(4)])
 if op=='sha256su1':
  out=[];extra=right[1:]+wk[:1]
  for i in range(4):out.append((left[i]+extra[i]+small1(wk[i+2] if i<2 else out[i-2]))&U32)
  return pack(out)
 state=(left+right) if op=='sha256h' else (right+left)
 for word in wk:
  a,b,c,d,e,f,g,h=state;t1=(h+(ror(e,6)^ror(e,11)^ror(e,25))+((e&f)^((~e)&g))+word)&U32;t2=((ror(a,2)^ror(a,13)^ror(a,22))+((a&b)^(a&c)^(b&c)))&U32
  state=[(t1+t2)&U32,a,b,c,(d+t1)&U32,e,f,g]
 return pack(state[:4] if op=='sha256h' else state[4:])

def decoded(word):
 three={0x5e004000:'sha256h',0x5e005000:'sha256h2',0x5e006000:'sha256su1'};op=three.get(word&0xffe0fc00)
 if (word&0xfffffc00)==0x5e282800:op='sha256su0'
 return None if op is None else (op,word&31,(word>>5)&31,(word>>16)&31)

def verify(row):
 parsed=decoded(int(row['opcode'],0))
 if parsed is None:return False
 op,d,n,m=parsed;assert row['completion']=='confirmed' and not row['gap'] and row['memory']==[]
 assert len(row['pre'])==len(row['post'])==65 and all(x is not None for x in [*row['pre'].values(),*row['post'].values()])
 pre={k:int(v,0) for k,v in row['pre'].items()};post={k:int(v,0) for k,v in row['post'].items()};want=dict(pre);want['v'+str(d)]=expected(op,pre['v'+str(d)],pre['v'+str(n)],pre['v'+str(m)]);assert post==want,(op,pre,post,want)
 return True

def cases():
 for bank in [(0,1,2),(29,30,31)]:
  for op in ['sha256h','sha256h2','sha256su0','sha256su1']:
   aliases=[(bank[0],bank[1],bank[2]),(bank[1],bank[1],bank[2])]
   if op!='sha256su0':aliases += [(bank[2],bank[1],bank[2]),(bank[0],bank[1],bank[1]),(bank[1],bank[1],bank[1])]
   for d,n,m in aliases:yield dict(op=op,d=d,n=n,m=m,bank=bank)

def assembly(c,name):
 d,n,m=c['d'],c['n'],c['m'];zero,a,b=c['bank'];op=c['op'];instruction=f'{op} q{d}, q{n}, v{m}.4s' if op in ['sha256h','sha256h2'] else f'{op} v{d}.4s, v{n}.4s'+('' if op=='sha256su0' else f', v{m}.4s')
 setup=['ldr x9, [x1, #16]','eor x10, x0, x9','mvn x11, x0',f'fmov d{a}, x0',f'mov v{a}.d[1], x10',f'fmov d{b}, x9',f'mov v{b}.d[1], x11',f'movi v{zero}.16b, #165','cmp x0, x2']
 return '.p2align 2\n.globl _'+name+'\n.globl _'+name+'_end\n_'+name+':\n    '+'\n    '.join(setup+[instruction,f'str q{d}, [x1]',f'umov x0, v{d}.d[0]','ret'])+'\n_'+name+'_end:\n'

def check(out,runner,cli):
 out.mkdir(parents=True,exist_ok=False);sys.path.insert(0,str(ROOT/'tools'));import dependencies;sdk=dependencies.host()
 classifier=out/'sha256-classification';run(['clang++','-arch','arm64','-std=c++17','-O2','-DTRACEQ_HOST_LAB','-I'+str(ROOT/'cli/include'),'-I'+str(sdk),ROOT/'tests/integration/sha256_classification.mm',classifier_archive(),sdk/'libfrida-gum.a','-framework','Foundation','-lresolv','-lm','-ldl','-o',classifier]);print(run([classifier]).strip(),flush=True)
 specs=list(cases());source=out/'sha256.S';source.write_text('.text\n'+''.join(assembly(c,'sha256_'+str(i)) for i,c in enumerate(specs)));lib=out/'libsha256.dylib';run(['clang','-arch','arm64','-march=armv8-a+crypto','-dynamiclib',source,'-o',lib])
 def invoke(lib,name,mode,path,seed,count,initial):return json.loads(run([runner,lib,name,mode,path,hex(seed),count,hex(initial)]))
 def q(path,cmd,*args):return json.loads(run([cli,cmd,path,*map(str,args),'--json']))
 regs=[x for r in REGS for x in ['--reg',r]];checks=[]
 for i,c in enumerate(specs):
  for k,(seed,initial) in enumerate([(0,0),(MASK,MASK),(0xfedcba9876543210,0x0123456789abcdef),(0xdeadbeef1337c0de,0xf102030407cafe09)]):
   zero,a,b=c['bank'];values={zero:int.from_bytes(bytes([165])*16,'little'),a:seed|((seed^initial)<<64),b:initial|((seed^MASK)<<64)};value=expected(c['op'],values[c['d']],values[c['n']],values[c['m']]);want=value.to_bytes(16,'little')+initial.to_bytes(8,'little')+bytes(8);name='sha256_'+str(i)
   native=invoke(lib,name,'native',out/'unused',seed,7,initial);assert native['buffer']==want.hex() and int(native['result'],0)==value&MASK,(c,k,native,want.hex())
   for mode in ['trace-chunks','trace-fast']:
    path=out/f'{i}-{k}-{mode}.gtsw';cap=invoke(lib,name,mode,path,seed,7,initial);assert cap['ok'] and cap['buffer']==want.hex() and cap['result']==native['result'];row=q(path,'context','--at-ev',9,'--before',0,'--after',0,*regs)['data'][0];assert verify(row)
    stat=q(path,'stat')['meta'];assert stat['capture_gaps']==0 and not stat['unsupported_mnemonics'];checks.append(dict(case=c,input=k,mode=mode,all65=True,native_bytes=True))
  print('assembly',i,c['op'],'PASS',flush=True)
 for opt in ['-O1','-O3']:
  module=out/('libsha256-c'+opt+'.dylib');run(['clang','-arch','arm64','-march=armv8-a+crypto','-dynamiclib',opt,'-fno-stack-protector','-fomit-frame-pointer',ROOT/'tests/integration/fixtures/sha256_c.c','-o',module])
  for count in [0,3,15]:
   seed=0xdeadbeef1337c0de;initial=0xf102030407cafe09;message=bytes(((seed>>(8*(i&7)))^(initial>>(8*((i+3)&7)))^i)&255 for i in range(count));want=hashlib.sha256(message).digest();native=invoke(module,'sha256_c','native',out/'unused',seed,count,initial);assert native['buffer']==want.hex() and int(native['result'],0)==seed^initial
   for mode in ['trace-chunks','trace-fast']:
    path=out/f'c-{opt}-{count}-{mode}.gtsw';cap=invoke(module,'sha256_c',mode,path,seed,count,initial);assert cap['ok'] and cap['buffer']==want.hex() and cap['result']==native['result'];context=q(path,'context','--at-ev',0,'--before',0,'--after',4096,'--limit',4096,*regs);assert not context['meta']['truncated'] and context['meta']['validation']=='full stream through END';verified=sum(verify(row) for row in context['data']);assert verified==56,verified
    writers=q(path,'last-writers','--range',cap['data_base']+',32','--limit',32)['data']
    for n,w in enumerate(writers):
     if w['known']:assert int(w['value'],0)==want[n]
     else:assert w['value'] is None
    checks.append(dict(kind='ordinary-c-intrinsics',optimization=opt,count=count,mode=mode,verified_sha256=verified,native_hash=True))
 (out/'summary.json').write_text(json.dumps({'status':'pass','assembly_cases':len(specs),'captures':len(checks),'checks':checks},indent=2)+'\n');print('PASS',len(checks),'targeted SHA256 captures',flush=True)
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--runner',type=Path,default=ROOT/'build/traceq-host/traceq-capture');p.add_argument('--cli',type=Path,default=ROOT/'cli/traceq');p.add_argument('--out',type=Path,required=True);a=p.parse_args();check(a.out.resolve(),a.runner.resolve(),a.cli.resolve())
