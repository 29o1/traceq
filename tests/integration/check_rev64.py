#!/usr/bin/env python3
"""REV64 observations against independent byte/element permutation and native C.
Roles: https://arm-software.github.io/acle/neon_intrinsics/advsimd.html#reverse-elements
"""
import argparse,json,sys
from pathlib import Path
from check_simd import run,REGS
from rust_classifier import archive as classifier_archive
ROOT=Path(__file__).resolve().parents[2];HERE=Path(__file__).resolve().parent
MASK=(1<<64)-1
SHAPES=[('8b',8,1,'b8'),('16b',16,1,'b16'),('4h',8,2,'h4'),('8h',16,2,'h8'),('2s',8,4,'s2'),('4s',16,4,'s4')]
PATTERNS=[(0,0),(MASK,MASK),(0xfedcba9876543210,0x0123456789abcdef),(0x8000000000000001,0x7ff8123456789abc)]
def reverse(value,width,element):
 raw=value.to_bytes(16,'little');out=bytearray(16)
 for base in range(0,width,8):out[base:base+8]=b''.join(raw[base+i:base+i+element] for i in range(8-element,-1,-element))
 return int.from_bytes(out,'little')
def decoded(word):
 if word&0xbf3ffc00!=0x0e200800 or (word>>22)&3>=3:return None
 return (word&31,(word>>5)&31,16 if word&(1<<30) else 8,1<<((word>>22)&3))
def verify(row):
 op=decoded(int(row['opcode'],0))
 if op is None:return False
 d,n,width,element=op;assert row['completion']=='confirmed' and not row['gap'] and row['memory']==[]
 assert len(row['pre'])==len(row['post'])==65 and all(v is not None for v in [*row['pre'].values(),*row['post'].values()])
 pre={k:int(v,0) for k,v in row['pre'].items()};post={k:int(v,0) for k,v in row['post'].items()};wanted=dict(pre);wanted['v'+str(d)]=reverse(pre['v'+str(n)],width,element);assert post==wanted,(op,row,wanted);return True
def specs():
 for bank in [(0,1,2),(29,31,30)]:
  for shape,width,element,label in SHAPES:
   for alias in [False,True]:yield dict(shape=shape,width=width,element=element,label=label,bank=bank,d=bank[1] if alias else bank[0],n=bank[1])
def assembly(c,name):
 z,a,b=c['bank'];d,n=c['d'],c['n'];setup=['ldr x9, [x1, #16]','eor x10, x0, x9','mvn x11, x0',f'fmov d{a}, x0',f'mov v{a}.d[1], x10',f'fmov d{b}, x9',f'mov v{b}.d[1], x11',f'movi v{z}.16b, #165','cmp x0, x2']
 return '.p2align 2\n.globl _'+name+'\n.globl _'+name+'_end\n_'+name+':\n    '+'\n    '.join(setup+[f'rev64 v{d}.{c["shape"]}, v{n}.{c["shape"]}',f'str q{d}, [x1]',f'umov x0, v{d}.d[0]','ret'])+'\n_'+name+'_end:\n'
def check(out,runner,cli):
 out.mkdir(parents=True,exist_ok=False);sys.path.insert(0,str(ROOT/'tools'));import dependencies;sdk=dependencies.host();classifier=out/'rev64-classification'
 run(['clang++','-arch','arm64','-std=c++17','-O2','-DTRACEQ_HOST_LAB','-I'+str(sdk),HERE/'rev64_classification.mm',classifier_archive(),sdk/'libfrida-gum.a','-framework','Foundation','-lresolv','-lm','-ldl','-o',classifier]);print(run([classifier]).strip(),flush=True)
 cases=list(specs());assert len(cases)==len({(c['shape'],c['d'],c['n']) for c in cases})==24
 frozen=[]
 for c in cases:
  for seed,initial in PATTERNS:frozen.append(dict(case=c,seed=seed,initial=initial,result=hex(reverse(seed|((seed^initial)<<64),c['width'],c['element']))))
 (out/'frozen-oracles.json').write_text(json.dumps({'assembly':frozen,'source':'Python byte/element permutation;64bitdestupper64zero;all expectedvalues frozenbeforecaptures.'},indent=2)+'\n')
 src=out/'rev64.S';src.write_text('.text\n'+''.join(assembly(c,'rev64_'+str(i)) for i,c in enumerate(cases)));lib=out/'librev64.dylib';run(['clang','-arch','arm64','-dynamiclib',src,'-o',lib]);checks=[];regs=[x for r in REGS for x in ['--reg',r]]
 def invoke(module,fn,mode,path,seed,count,initial,all_data=False):return json.loads(run([runner,module,fn,mode,path,hex(seed),count,hex(initial),*(['--all-data'] if all_data else [])]))
 def q(path,command,*args):return json.loads(run([cli,command,path,*map(str,args),'--json']))
 for i,c in enumerate(cases):
  for k,(seed,initial) in enumerate(PATTERNS):
   value=int(frozen[i*len(PATTERNS)+k]['result'],0);want=value.to_bytes(16,'little')+initial.to_bytes(8,'little')+bytes(8);name='rev64_'+str(i);native=invoke(lib,name,'native',out/'unused',seed,7,initial);assert native['buffer']==want.hex() and int(native['result'],0)==value&MASK
   for mode in ['trace-chunks','trace-fast']:
    path=out/f'{i}-{k}-{mode}.gtsw';cap=invoke(lib,name,mode,path,seed,7,initial);assert cap['ok'] and cap['buffer']==want.hex() and cap['result']==native['result'];row=q(path,'context','--at-ev',9,'--before',0,'--after',0,*regs)['data'][0];assert verify(row);stat=q(path,'stat')['meta'];assert stat['capture_gaps']==0 and not stat['unsupported_mnemonics'];writers=q(path,'last-writers','--range',cap['data_base']+',32','--limit',32)['data'];assert [w['known'] for w in writers]==[j<16 for j in range(32)];assert all(int(w['value'],0)==want[j] for j,w in enumerate(writers) if w['known']);checks.append(dict(kind='assembly',case=c,input=k,mode=mode,all65=True,native_bytes=True))
  print('assembly',i,c['shape'],'PASS',flush=True)
 for opt in ['-O1','-O3']:
  module=out/('librev64-c'+opt+'.dylib');run(['clang','-arch','arm64','-dynamiclib',opt,'-fno-stack-protector','-fomit-frame-pointer',HERE/'fixtures/rev64_c.c','-o',module])
  for shape,width,element,label in SHAPES:
   for seed,initial,count in [(0,0,0),(0xfedcba9876543210,0x0123456789abcdef,1),(MASK,0x8000000000000001,5)]:
    want=bytearray(32);want[16:24]=initial.to_bytes(8,'little')
    if count:want[:width]=reverse(initial,width,element).to_bytes(16,'little')[:width]
    name='rev64_'+label+'_c';native=invoke(module,name,'native',out/'unused',seed,count,initial,True);assert native['buffer']==want.hex() and int(native['result'],0)==seed^initial
    for mode in ['trace-chunks','trace-fast']:
     path=out/f'c-{opt}-{label}-{count}-{mode}.gtsw';cap=invoke(module,name,mode,path,seed,count,initial,True);assert cap['ok'] and cap['buffer']==want.hex() and cap['result']==native['result'];context=q(path,'context','--at-ev',0,'--before',0,'--after',4096,'--limit',4096,*regs);assert not context['meta']['truncated'];verified=sum(verify(row) for row in context['data']);stat=q(path,'stat')['meta'];assert 'rev64' not in stat['unsupported_mnemonics'];writers=q(path,'last-writers','--range',cap['data_base']+',32','--limit',32)['data'];assert [w['known'] for w in writers]==[bool(count and j<width) for j in range(32)]
     for j,w in enumerate(writers):
      if w['known']:assert int(w['value'],0)==want[j]
      else:assert w['value'] is None
     checks.append(dict(kind='ordinary-c-intrinsics',optimization=opt,shape=shape,count=count,mode=mode,verified_rev64=verified,native_bytes=True))
 (out/'summary.json').write_text(json.dumps({'status':'pass','assembly_distinct_configurations':24,'captures':len(checks),'checks':checks},indent=2)+'\n');print('PASS',len(checks),'targeted REV64 captures',flush=True)
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--runner',type=Path,default=ROOT/'build/traceq-host/traceq-capture');p.add_argument('--cli',type=Path,default=ROOT/'cli/traceq');p.add_argument('--out',type=Path,required=True);a=p.parse_args();check(a.out.resolve(),a.runner.resolve(),a.cli.resolve())
