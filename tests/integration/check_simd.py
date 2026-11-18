#!/usr/bin/env python3
"""Register-only SIMD facts: independent lane math, native bytes and all65 slots."""
import argparse,json,subprocess,time,sys
from pathlib import Path
from rust_classifier import archive as classifier_archive
ROOT=Path(__file__).resolve().parents[2]
MASK=(1<<64)-1
REGS=[*[f'x{i}' for i in range(31)],'sp','nzcv',*[f'v{i}' for i in range(32)]]

def run(args):
 r=subprocess.run(list(map(str,args)),capture_output=True,text=True,timeout=40)
 if r.returncode:raise AssertionError((list(map(str,args)),r.returncode,r.stdout[-2000:],r.stderr[-2000:]))
 return r.stdout

def cases():
 shapes=[('8b',64,8),('16b',128,8),('4h',64,16),('8h',128,16),('2s',64,32),('4s',128,32),('2d',128,64),('d',64,64)]
 for shape,bits,element in shapes:
  for alias in [False,True]:
   for zero in [False,True]:yield dict(op='cmeq',shape=shape,bits=bits,element=element,alias=alias,zero=zero,shift=0)
   for shift in [0,1,element-1]:yield dict(op='shl',shape=shape,bits=bits,element=element,alias=alias,zero=False,shift=shift)
 for op in ['ushll','ushll2']:
  for element in [8,16,32]:
   for shift in [0,1,element-1]:
    for alias in [False,True]:yield dict(op=op,element=element,shift=shift,alias=alias)
 for op in ['xtn','xtn2']:
  for element in [8,16,32]:
   for alias in [False,True]:yield dict(op=op,element=element,shift=0,alias=alias)

def expected(case,a,b,prior):
 op=case['op'];element=case['element'];mask=(1<<element)-1
 if op=='cmeq':return sum((mask if (a>>(i*element))&mask==(0 if case['zero'] else (b>>(i*element))&mask) else 0)<<(i*element) for i in range(case['bits']//element))
 if op=='shl':return sum(((((a>>(i*element))&mask)<<case['shift'])&mask)<<(i*element) for i in range(case['bits']//element))
 if op.startswith('ushll'):
  start=64 if op.endswith('2') else 0
  return sum((((a>>(start+i*element))&mask)<<case['shift'])<<(i*element*2) for i in range(64//element))
 narrowed=sum(((a>>(i*element*2))&mask)<<(i*element) for i in range(64//element))
 return ((prior&MASK)|(narrowed<<64)) if op=='xtn2' else narrowed

def assembly(case,name):
 op=case['op'];element=case['element'];d=1 if case['alias'] else 0
 def v(reg,shape):return 'd'+str(reg) if shape=='d' else 'v'+str(reg)+'.'+shape
 if op in ['cmeq','shl']:
  dst,src=v(d,case['shape']),v(1,case['shape']);third=('#0' if case['zero'] else v(2,case['shape'])) if op=='cmeq' else '#'+str(case['shift']);instruction=f'{op} {dst}, {src}, {third}'
 elif op.startswith('ushll'):
  letter={8:'b',16:'h',32:'s'}[element];dstletter={8:'h',16:'s',32:'d'}[element];n=(128 if op.endswith('2') else 64)//element
  instruction=f'{op} v{d}.{64//element}{dstletter}, v1.{n}{letter}, #{case["shift"]}'
 else:
  letter={8:'b',16:'h',32:'s'}[element];srcletter={8:'h',16:'s',32:'d'}[element];n=(128 if op.endswith('2') else 64)//element
  instruction=f'{op} v{d}.{n}{letter}, v1.{64//element}{srcletter}'
 setup=['ldr x9, [x1, #16]','eor x10, x0, x9','mvn x11, x0','fmov d1, x0','mov v1.d[1], x10','fmov d2, x9','mov v2.d[1], x11','movi v0.16b, #165','cmp x0, x2']
 return '.p2align 2\n.globl _'+name+'\n.globl _'+name+'_end\n_'+name+':\n    '+'\n    '.join(setup+[instruction,f'str q{d}, [x1]',f'umov x0, v{d}.d[0]','ret'])+'\n_'+name+'_end:\n'

def check(out,runner,cli):
 out.mkdir(parents=True,exist_ok=False)
 sys.path.insert(0,str(ROOT/'tools'));import dependencies
 sdk=dependencies.host();classifier=out/'simd-classification'
 run(['clang++','-arch','arm64','-std=c++17','-O2','-DTRACEQ_HOST_LAB','-I'+str(ROOT/'cli/include'),'-I'+str(sdk),ROOT/'tests/integration/simd_classification.mm',classifier_archive(),sdk/'libfrida-gum.a','-framework','Foundation','-lresolv','-lm','-ldl','-o',classifier]);print(run([classifier]).strip(),flush=True)
 specs=list(cases());source=out/'simd.S';source.write_text('.text\n'+''.join(assembly(c,'simd_'+str(i)) for i,c in enumerate(specs)));lib=out/'libsimd.dylib';run(['clang','-arch','arm64','-dynamiclib',source,'-o',lib])
 def invoke(lib,name,mode,path,seed,count,initial):return json.loads(run([runner,lib,name,mode,path,hex(seed),count,hex(initial)]))
 def query(path,cmd,*args):return json.loads(run([cli,cmd,path,*map(str,args),'--json']))
 regs=[a for r in REGS for a in ['--reg',r]];checks=[]
 for i,case in enumerate(specs):
  for k,(seed,initial) in enumerate([(0,0),(MASK,MASK),(0xfedcba9876543210,0x0123456789abcdef)]):
   a=seed|((seed^initial)<<64);b=initial|((seed^MASK)<<64);prior=a if case['alias'] else int.from_bytes(bytes([165])*16,'little');value=expected(case,a,b,prior);want=value.to_bytes(16,'little')+initial.to_bytes(8,'little')+bytes(8);fn='simd_'+str(i)
   native=invoke(lib,fn,'native',out/'unused',seed,7,initial);assert native['buffer']==want.hex() and int(native['result'],0)==value&MASK,(case,k,native,want.hex())
   for mode in ['trace-chunks','trace-fast']:
    path=out/f'{i}-{k}-{mode}.gtsw';captured=invoke(lib,fn,mode,path,seed,7,initial);assert captured['ok'] and captured['buffer']==want.hex() and captured['result']==native['result']
    row=query(path,'context','--at-ev',9,'--before',0,'--after',0,*regs)['data'][0];assert row['completion']=='confirmed' and not row['gap'] and row['memory']==[]
    assert len(row['pre'])==len(row['post'])==65 and all(v is not None for v in [*row['pre'].values(),*row['post'].values()]);pre={r:int(v,0) for r,v in row['pre'].items()};post={r:int(v,0) for r,v in row['post'].items()};target='v'+str(1 if case['alias'] else 0);want_post=dict(pre);want_post[target]=value;assert post==want_post,(case,k,pre,post,want_post)
    assert pre['v1']==a and pre['v2']==b and pre[target]==prior
    stat=query(path,'stat')['meta'];assert stat['capture_gaps']==0 and not stat['unsupported_mnemonics'],(case,stat)
    writers=query(path,'last-writers','--range',captured['data_base']+',32','--limit',32)['data'];assert [w['known'] for w in writers]==[n<16 for n in range(32)];assert all(int(w['value'],0)==want[n] for n,w in enumerate(writers) if w['known'])
    checks.append({'case':case,'input':k,'mode':mode,'all65_effects':True,'native_bytes':True})
  print(i,case,'PASS',flush=True)
 for opt in ['-O1','-O3']:
  module=out/('libsimd-c'+opt+'.dylib');run(['clang','-arch','arm64','-dynamiclib',opt,'-fno-stack-protector','-fomit-frame-pointer',ROOT/'tests/integration/fixtures/simd_c.c','-o',module])
  for kind in ['widen','narrow','compare']:
   for count in [0,1,8]:
    seed=0xfedcba9876543210;initial=0x1067442333102210;raw=initial.to_bytes(8,'little')+bytes(8);want=bytearray(32);want[16:24]=raw[:8]
    for i in range(count):
     if kind=='widen':want[i*2:i*2+2]=(raw[i]<<3).to_bytes(2,'little')
     elif kind=='narrow':want[i]=raw[2*i]
     else:want[i]=255 if raw[i]==seed&255 else 0
    name='simd_'+kind+'_c';native=invoke(module,name,'native',out/'unused',seed,count,initial);assert native['buffer']==want.hex() and int(native['result'],0)==seed^initial
    for mode in ['trace-chunks','trace-fast']:
     path=out/f'c-{opt}-{kind}-{count}-{mode}.gtsw';cap=invoke(module,name,mode,path,seed,count,initial);assert cap['ok'] and cap['buffer']==want.hex() and cap['result']==native['result'];stat=query(path,'stat')['meta']
     writers=query(path,'last-writers','--range',cap['data_base']+',32','--limit',32)['data']
     for n,w in enumerate(writers):
      if w['known']:assert int(w['value'],0)==want[n]
      else:assert w['value'] is None
     checks.append({'kind':'ordinary-c','operation':kind,'optimization':opt,'count':count,'mode':mode,'gaps':stat['capture_gaps'],'unsupported':stat['unsupported_mnemonics']})
 (out/'summary.json').write_text(json.dumps({'status':'pass','assembly_cases':len(specs),'captures':len(checks),'checks':checks},indent=2)+'\n');print('PASS',len(checks),'targeted captures',flush=True)
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--runner',type=Path,default=ROOT/'build/traceq-host/traceq-capture');p.add_argument('--cli',type=Path,default=ROOT/'cli/traceq');p.add_argument('--out',type=Path,default=ROOT/'artifacts'/('simd-'+str(time.time_ns())));a=p.parse_args();check(a.out.resolve(),a.runner.resolve(),a.cli.resolve())
