#!/usr/bin/env python3
"""SHA1 observation: independent untraced assembly oracles and C pipelines.
Operand roles: https://arm-software.github.io/acle/neon_intrinsics/advsimd.html#sha1
"""
import argparse,ctypes,json,re,subprocess,sys
from pathlib import Path
from check_simd import run,REGS
from rust_classifier import archive as classifier_archive
ROOT=Path(__file__).resolve().parents[2];HERE=Path(__file__).resolve().parent
MASK=(1<<64)-1
OPS=['sha1c','sha1p','sha1m','sha1h','sha1su0','sha1su1']

def instruction(op,d,n,m):
 if op in OPS[:3]:return f'{op} q{d}, s{n}, v{m}.4s'
 if op=='sha1h':return f'{op} s{d}, s{n}'
 return f'{op} v{d}.4s, v{n}.4s'+('' if op=='sha1su1' else f', v{m}.4s')
def specs():
 for bank in [(0,1,2),(29,30,31)]:
  z,n,m=bank
  for op in OPS:
   z,n,m=bank
   aliases=[(z,n,m),(n,n,m)]
   if op not in ['sha1h','sha1su1']:aliases += [(m,n,m),(z,n,n),(n,n,n)]
   for d,n,m in aliases:yield dict(op=op,d=d,n=n,m=m,bank=bank)
def assembly(c,name):
 z,a,b=c['bank'];d,n,m=c['d'],c['n'],c['m']
 setup=['ldr x9, [x1, #16]','eor x10, x0, x9','mvn x11, x0',f'fmov d{a}, x0',f'mov v{a}.d[1], x10',f'fmov d{b}, x9',f'mov v{b}.d[1], x11',f'movi v{z}.16b, #165','cmp x0, x2']
 return '.p2align 2\n.globl _'+name+'\n.globl _'+name+'_end\n_'+name+':\n    '+'\n    '.join(setup+[instruction(c['op'],d,n,m),f'str q{d}, [x1]',f'umov x0, v{d}.d[0]','ret'])+'\n_'+name+'_end:\n'
def check(out,runner,cli):
 out.mkdir(parents=True,exist_ok=False);sys.path.insert(0,str(ROOT/'tools'));import dependencies;sdk=dependencies.host()
 classifier=out/'sha1-classification';run(['clang++','-arch','arm64','-std=c++17','-O2','-DTRACEQ_HOST_LAB','-I'+str(ROOT/'cli/include'),'-I'+str(sdk),HERE/'sha1_classification.mm',classifier_archive(),sdk/'libfrida-gum.a','-framework','Foundation','-lresolv','-lm','-ldl','-o',classifier]);print(run([classifier]).strip(),flush=True)
 # This helper has no traceq dependency and executes without instrumentation.
 oracle_source=out/'native-oracle.S';oracle_source.write_text('.text\n'+''.join('.p2align 2\n.globl _oracle_'+op+'\n_oracle_'+op+':\n ldr q0,[x0]\n ldr q1,[x0,#16]\n ldr q2,[x0,#32]\n '+instruction(op,0,1,2)+'\n str q0,[x1]\n ret\n' for op in OPS));oracle_lib=out/'libnative-oracle.dylib';run(['clang','-arch','arm64','-march=armv8-a+crypto','-dynamiclib',oracle_source,'-o',oracle_lib]);native=ctypes.CDLL(str(oracle_lib));functions={}
 for op in OPS:
  f=getattr(native,'oracle_'+op);f.argtypes=[ctypes.c_void_p,ctypes.c_void_p];f.restype=None;functions[op]=f
 def expected(op,d,n,m=0):
  src=ctypes.create_string_buffer(d.to_bytes(16,'little')+n.to_bytes(16,'little')+m.to_bytes(16,'little'));dst=ctypes.create_string_buffer(16);functions[op](src,dst);return int.from_bytes(dst.raw,'little')
 patterns=[(0,0),(MASK,MASK),(0xfedcba9876543210,0x0123456789abcdef),(0x8000000000000001,0x7ff8123456789abc)]
 cases=list(specs());assert len(cases)==len({(c['op'],c['d'],c['n'],c['m']) for c in cases}),"duplicate assembly configurations";frozen=[]
 for c in cases:
  for seed,initial in patterns:
   z,a,b=c['bank'];v={z:int.from_bytes(bytes([165])*16,'little'),a:seed|((seed^initial)<<64),b:initial|((seed^MASK)<<64)};frozen.append(dict(case=c,seed=seed,initial=initial,result=hex(expected(c['op'],v[c['d']],v[c['n']],v[c['m']]))))
 c_expected={};c_returns={};seed=0xdeadbeef1337c0de;initial=0xf102030407cafe09
 for count in [0,1,3,7]:
  a=seed|(initial<<64);b=initial|((seed^MASK)<<64);w=count|(0xfedcba9876543210<<64);e=(seed^initial)&0xffffffff
  for i in range(count):
   a=expected('sha1c',a,e,w);a=expected('sha1p',a,e,b);b=expected('sha1m',b,e,a);e=expected('sha1h',0,e)&0xffffffff;w=expected('sha1su0',w,a,b);w=expected('sha1su1',w,a)
  c_expected[count]=(a.to_bytes(16,'little')+b.to_bytes(16,'little')).hex();c_returns[count]=seed^initial^e
 (out/'frozen-native-oracles.json').write_text(json.dumps({'assembly':frozen,'c_pipeline':c_expected,'c_returns':c_returns,'source':'Separate untraced assembly helper with exacttyped pointers;expected outputs savedbefore anytrace capture.'},indent=2)+'\n')
 def verify(row):
  parts=row['text'].replace(',',' ').split();op=parts[0]
  if op not in OPS:return False
  regs=[int(re.fullmatch(r'[qvs](\d+)(?:\.4s)?',x).group(1)) for x in parts[1:]];d,n=regs[:2];m=regs[2] if len(regs)==3 else 0
  assert row['completion']=='confirmed' and not row['gap'] and row['memory']==[]
  assert len(row['pre'])==len(row['post'])==65 and all(v is not None for v in [*row['pre'].values(),*row['post'].values()])
  pre={k:int(v,0) for k,v in row['pre'].items()};post={k:int(v,0) for k,v in row['post'].items()};want=dict(pre);want['v'+str(d)]=expected(op,pre['v'+str(d)],pre['v'+str(n)],pre['v'+str(m)]);assert post==want,(op,row,want);return True
 def invoke(lib,name,mode,path,seed,count,initial,all_data=False):return json.loads(run([runner,lib,name,mode,path,hex(seed),count,hex(initial),*(['--all-data'] if all_data else [])]))
 def q(path,cmd,*args):return json.loads(run([cli,cmd,path,*map(str,args),'--json']))
 regs=[x for r in REGS for x in ['--reg',r]];checks=[];source=out/'sha1.S';source.write_text('.text\n'+''.join(assembly(c,'sha1_'+str(i)) for i,c in enumerate(cases)));lib=out/'libsha1.dylib';run(['clang','-arch','arm64','-march=armv8-a+crypto','-dynamiclib',source,'-o',lib])
 for i,c in enumerate(cases):
  for k,(seed,initial) in enumerate(patterns):
   value=int(frozen[i*len(patterns)+k]['result'],0);want=value.to_bytes(16,'little')+initial.to_bytes(8,'little')+bytes(8);name='sha1_'+str(i);native_row=invoke(lib,name,'native',out/'unused',seed,7,initial);assert native_row['buffer']==want.hex() and int(native_row['result'],0)==value&MASK
   for mode in ['trace-chunks','trace-fast']:
    path=out/f'{i}-{k}-{mode}.gtsw';cap=invoke(lib,name,mode,path,seed,7,initial);assert cap['ok'] and cap['buffer']==want.hex() and cap['result']==native_row['result'];row=q(path,'context','--at-ev',9,'--before',0,'--after',0,*regs)['data'][0];assert verify(row);stat=q(path,'stat')['meta'];assert stat['capture_gaps']==0 and not stat['unsupported_mnemonics'];writers=q(path,'last-writers','--range',cap['data_base']+',32','--limit',32)['data'];assert [w['known'] for w in writers]==[n<16 for n in range(32)];assert all(int(w['value'],0)==want[n] for n,w in enumerate(writers) if w['known']);checks.append(dict(kind='assembly',case=c,input=k,mode=mode,all65=True,native_bytes=True))
  print('assembly',i,c['op'],'PASS',flush=True)
 for opt in ['-O1','-O3']:
  module=out/('libsha1-c'+opt+'.dylib');run(['clang','-arch','arm64','-march=armv8-a+crypto','-dynamiclib',opt,'-fno-stack-protector','-fomit-frame-pointer',HERE/'fixtures/sha1_c.c','-o',module])
  for count in [0,1,3,7]:
   seed=0xdeadbeef1337c0de;initial=0xf102030407cafe09;want=bytes.fromhex(c_expected[count]);native_row=invoke(module,'sha1_mix_c','native',out/'unused',seed,count,initial,True);assert native_row['buffer']==want.hex() and int(native_row['result'],0)==c_returns[count]
   for mode in ['trace-chunks','trace-fast']:
    path=out/f'c-{opt}-{count}-{mode}.gtsw';cap=invoke(module,'sha1_mix_c',mode,path,seed,count,initial,True);assert cap['ok'] and cap['buffer']==want.hex() and cap['result']==native_row['result'];context=q(path,'context','--at-ev',0,'--before',0,'--after',4096,'--limit',4096,*regs);assert not context['meta']['truncated'] and context['meta']['validation']=='full stream through END';verified=sum(verify(row) for row in context['data']);assert (verified==0 if count==0 else verified>=3*count),(opt,count,verified);stat=q(path,'stat')['meta'];assert not any(op in stat['unsupported_mnemonics'] for op in OPS)
    writers=q(path,'last-writers','--range',cap['data_base']+',32','--limit',32)['data']
    for n,w in enumerate(writers):
     if w['known']:assert int(w['value'],0)==want[n]
     else:assert w['value'] is None
    checks.append(dict(kind='ordinary-c-intrinsics',optimization=opt,count=count,mode=mode,verified_sha1=verified,native_oracle=True))
 (out/'summary.json').write_text(json.dumps({'status':'pass','assembly_cases':len(cases),'captures':len(checks),'checks':checks},indent=2)+'\n');print('PASS',len(checks),'targeted SHA1 captures',flush=True)
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--runner',type=Path,default=ROOT/'build/traceq-host/traceq-capture');p.add_argument('--cli',type=Path,default=ROOT/'cli/traceq');p.add_argument('--out',type=Path,required=True);a=p.parse_args();check(a.out.resolve(),a.runner.resolve(),a.cli.resolve())
