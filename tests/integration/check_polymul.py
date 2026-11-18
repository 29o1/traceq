#!/usr/bin/env python3
"""Polynomial multiply observation: independent carryless math, assembly, C pipelines.
Operand roles: https://arm-software.github.io/acle/neon_intrinsics/advsimd.html#polynomial-multiply
"""
import argparse,ctypes,json,re,subprocess,sys
from pathlib import Path
from check_simd import run,REGS
from rust_classifier import archive as classifier_archive
ROOT=Path(__file__).resolve().parents[2];HERE=Path(__file__).resolve().parent
MASK=(1<<64)-1
OPS=['pmull8','pmull8hi','pmull64','pmull64hi']
def instruction(op,d,n,m=0):
 high=op.endswith('hi');wide=op.startswith('pmull64');dst='1q' if wide else '8h';src=('2d' if high else '1d') if wide else ('16b' if high else '8b')
 return f"{'pmull2' if high else 'pmull'} v{d}.{dst}, v{n}.{src}, v{m}.{src}"
def specs():
 for bank in [(0,1,2),(29,30,31)]:
  z,a,b=bank
  for op in OPS:
   for d,n,m in [(z,a,b),(a,a,b),(b,a,b),(z,a,a),(a,a,a),(z,b,a)]:yield dict(op=op,d=d,n=n,m=m,bank=bank)
def carryless(a,b):
 result=0
 while b:
  if b&1:result^=a
  b>>=1;a<<=1
 return result
def expected(op,d,n,m=0):
 width=64 if op.startswith('pmull64') else 8
 if op.endswith('hi'):n>>=64;m>>=64
 result=0;mask=(1<<width)-1
 for lane in range(64//width):result|=carryless((n>>(lane*width))&mask,(m>>(lane*width))&mask)<<(lane*width*2)
 return result
def assembly(c,name):
 z,a,b=c['bank'];d,n,m=c['d'],c['n'],c['m']
 setup=['ldr x9, [x1, #16]','eor x10, x0, x9','mvn x11, x0',f'fmov d{a}, x0',f'mov v{a}.d[1], x10',f'fmov d{b}, x9',f'mov v{b}.d[1], x11',f'movi v{z}.16b, #165','cmp x0, x2']
 return '.p2align 2\n.globl _'+name+'\n.globl _'+name+'_end\n_'+name+':\n    '+'\n    '.join(setup+[instruction(c['op'],d,n,m),f'str q{d}, [x1]',f'umov x0, v{d}.d[0]','ret'])+'\n_'+name+'_end:\n'
def check(out,runner,cli):
 out.mkdir(parents=True,exist_ok=False);sys.path.insert(0,str(ROOT/'tools'));import dependencies;sdk=dependencies.host()
 classifier=out/'polymul-classification';run(['clang++','-arch','arm64','-std=c++17','-O2','-DTRACEQ_HOST_LAB','-I'+str(ROOT/'capture/traceq/src'),'-I'+str(ROOT/'cli/include'),'-I'+str(sdk),HERE/'polymul_classification.mm',classifier_archive(),sdk/'libfrida-gum.a','-framework','Foundation','-lresolv','-lm','-ldl','-o',classifier]);print(run([classifier]).strip(),flush=True)
 # Check the algebraic oracle against a separate untraced assembly library.
 oracle_source=out/'native-oracle.S';oracle_source.write_text('.text\n'+''.join('.p2align 2\n.globl _oracle_'+op+'\n_oracle_'+op+':\n ldr q1,[x0]\n ldr q2,[x0,#16]\n '+instruction(op,0,1,2)+'\n str q0,[x1]\n ret\n' for op in OPS));oracle_lib=out/'libnative-oracle.dylib';run(['clang','-arch','arm64','-march=armv8-a+crypto','-dynamiclib',oracle_source,'-o',oracle_lib]);native=ctypes.CDLL(str(oracle_lib));functions={}
 for op in OPS:
  function=getattr(native,'oracle_'+op);function.argtypes=[ctypes.c_void_p,ctypes.c_void_p];function.restype=None;functions[op]=function
 def hardware(op,n,m):
  src=ctypes.create_string_buffer(n.to_bytes(16,'little')+m.to_bytes(16,'little'));dst=ctypes.create_string_buffer(16);functions[op](src,dst);return int.from_bytes(dst.raw,'little')
 patterns=[(0,0),(MASK,MASK),(0xfedcba9876543210,0x0123456789abcdef),(0x8000000000000001,0x7ff8123456789abc)]
 cases=list(specs());assert len(cases)==len({(c['op'],c['d'],c['n'],c['m']) for c in cases}),"duplicate assembly configurations";frozen=[]
 for c in cases:
  for seed,initial in patterns:
   z,a,b=c['bank'];v={z:int.from_bytes(bytes([165])*16,'little'),a:seed|((seed^initial)<<64),b:initial|((seed^MASK)<<64)};frozen.append(dict(case=c,seed=seed,initial=initial,result=hex(expected(c['op'],0,v[c['n']],v[c['m']]))));assert int(frozen[-1]['result'],0)==hardware(c['op'],v[c['n']],v[c['m']])
 c_expected={};c_returns={};seed=0xdeadbeef1337c0de;initial=0xf102030407cafe09
 for count in [0,1,3,7]:
  a=seed|(initial<<64);b=initial|((seed^MASK)<<64)
  for i in range(count):
   olda,oldb=a,b;a=expected('pmull64',0,olda,oldb)^expected('pmull8',0,olda,oldb);b=expected('pmull64hi',0,olda,oldb)^expected('pmull8hi',0,olda,oldb)
  c_expected[count]=(a.to_bytes(16,'little')+b.to_bytes(16,'little')).hex();c_returns[count]=seed^initial
 (out/'frozen-native-oracles.json').write_text(json.dumps({'assembly':frozen,'c_pipeline':c_expected,'c_returns':c_returns,'source':'Independent carryless polynomial product oracle, crosschecked with separate untraced assembly; outputs frozen before capture.'},indent=2)+'\n')
 def verify(row):
  opcode=row['text'].split()[0]
  if opcode not in ['pmull','pmull2']:return False
  parts=re.findall(r'v(\d+)\.(8h|8b|16b|1q|1d|2d)',row['text']);assert len(parts)==3,row
  d,n,m=[int(x[0]) for x in parts];op=('pmull64' if parts[0][1]=='1q' else 'pmull8')+('hi' if opcode=='pmull2' else '')
  assert row['completion']=='confirmed' and not row['gap'] and row['memory']==[]
  assert len(row['pre'])==len(row['post'])==65 and all(v is not None for v in [*row['pre'].values(),*row['post'].values()])
  pre={k:int(v,0) for k,v in row['pre'].items()};post={k:int(v,0) for k,v in row['post'].items()};want=dict(pre);want['v'+str(d)]=expected(op,0,pre['v'+str(n)],pre['v'+str(m)]);assert post==want,(op,row,want);return True
 def invoke(lib,name,mode,path,seed,count,initial,all_data=False):return json.loads(run([runner,lib,name,mode,path,hex(seed),count,hex(initial),*(['--all-data'] if all_data else [])]))
 def q(path,cmd,*args):return json.loads(run([cli,cmd,path,*map(str,args),'--json']))
 regs=[x for r in REGS for x in ['--reg',r]];checks=[];source=out/'polymul.S';source.write_text('.text\n'+''.join(assembly(c,'polymul_'+str(i)) for i,c in enumerate(cases)));lib=out/'libpolymul.dylib';run(['clang','-arch','arm64','-march=armv8-a+crypto','-dynamiclib',source,'-o',lib])
 for i,c in enumerate(cases):
  for k,(seed,initial) in enumerate(patterns):
   value=int(frozen[i*len(patterns)+k]['result'],0);want=value.to_bytes(16,'little')+initial.to_bytes(8,'little')+bytes(8);name='polymul_'+str(i);native_row=invoke(lib,name,'native',out/'unused',seed,7,initial);assert native_row['buffer']==want.hex() and int(native_row['result'],0)==value&MASK
   for mode in ['trace-chunks','trace-fast']:
    path=out/f'{i}-{k}-{mode}.gtsw';cap=invoke(lib,name,mode,path,seed,7,initial);assert cap['ok'] and cap['buffer']==want.hex() and cap['result']==native_row['result'];row=q(path,'context','--at-ev',9,'--before',0,'--after',0,*regs)['data'][0];assert verify(row);stat=q(path,'stat')['meta'];assert stat['capture_gaps']==0 and not stat['unsupported_mnemonics'];writers=q(path,'last-writers','--range',cap['data_base']+',32','--limit',32)['data'];assert [w['known'] for w in writers]==[n<16 for n in range(32)];assert all(int(w['value'],0)==want[n] for n,w in enumerate(writers) if w['known']);checks.append(dict(kind='assembly',case=c,input=k,mode=mode,all65=True,native_bytes=True))
  print('assembly',i,c['op'],'PASS',flush=True)
 for opt in ['-O1','-O3']:
  module=out/('libpolymul-c'+opt+'.dylib');run(['clang','-arch','arm64','-march=armv8-a+crypto','-dynamiclib',opt,'-fno-stack-protector','-fomit-frame-pointer',HERE/'fixtures/polymul_c.c','-o',module])
  for count in [0,1,3,7]:
   seed=0xdeadbeef1337c0de;initial=0xf102030407cafe09;want=bytes.fromhex(c_expected[count]);native_row=invoke(module,'polymul_mix_c','native',out/'unused',seed,count,initial,True);assert native_row['buffer']==want.hex() and int(native_row['result'],0)==c_returns[count]
   for mode in ['trace-chunks','trace-fast']:
    path=out/f'c-{opt}-{count}-{mode}.gtsw';cap=invoke(module,'polymul_mix_c',mode,path,seed,count,initial,True);assert cap['ok'] and cap['buffer']==want.hex() and cap['result']==native_row['result'];context=q(path,'context','--at-ev',0,'--before',0,'--after',4096,'--limit',4096,*regs);assert not context['meta']['truncated'] and context['meta']['validation']=='full stream through END';verified=sum(verify(row) for row in context['data']);assert (verified==0 if count==0 else verified>=4*count),(opt,count,verified);stat=q(path,'stat')['meta'];assert not any(op in stat['unsupported_mnemonics'] for op in ['pmull','pmull2'])
    writers=q(path,'last-writers','--range',cap['data_base']+',32','--limit',32)['data']
    for n,w in enumerate(writers):
     if w['known']:assert int(w['value'],0)==want[n]
     else:assert w['value'] is None
    checks.append(dict(kind='ordinary-c-intrinsics',optimization=opt,count=count,mode=mode,verified_polynomial=verified,native_oracle=True))
 (out/'summary.json').write_text(json.dumps({'status':'pass','assembly_cases':len(cases),'captures':len(checks),'checks':checks},indent=2)+'\n');print('PASS',len(checks),'targeted polynomial captures',flush=True)
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--runner',type=Path,default=ROOT/'build/traceq-host/traceq-capture');p.add_argument('--cli',type=Path,default=ROOT/'cli/traceq');p.add_argument('--out',type=Path,default=ROOT/'artifacts'/('polymul-check-'+str(__import__('time').time_ns())));a=p.parse_args();check(a.out.resolve(),a.runner.resolve(),a.cli.resolve())
