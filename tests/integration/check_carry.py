#!/usr/bin/env python3
"""Scalar carry state observations checked with independent arbitrary integers.
A64 source: https://documentation-service.arm.com/static/68da52dfbd7cab51328c0622
"""
import argparse,json,sys
from pathlib import Path
from check_simd import run,REGS
from rust_classifier import archive as classifier_archive
ROOT=Path(__file__).resolve().parents[2];HERE=Path(__file__).resolve().parent
MASK=(1<<64)-1;OPS=['adc','adcs','sbc','sbcs','ngc','ngcs']
def calculate(a,b,carry,width,subtract):
 mask=(1<<width)-1;a&=mask;b&=mask;borrow=1-carry
 total=a-b-borrow if subtract else a+b+carry;result=total&mask
 signed=lambda v:v-(1<<width) if v>>(width-1) else v
 signed_total=signed(a)-signed(b)-borrow if subtract else signed(a)+signed(b)+carry
 flags=((result>>(width-1))<<31)|(int(result==0)<<30)|(int(a>=b+borrow if subtract else total>mask)<<29)|(int(not -(1<<(width-1))<=signed_total<(1<<(width-1)))<<28)
 return result,flags
def decoded(word):
 if word&0x1fe0fc00!=0x1a000000:return None
 return dict(d=word&31,n=(word>>5)&31,m=(word>>16)&31,width=64 if word>>31 else 32,subtract=bool(word&(1<<30)),flags=bool(word&(1<<29)))
def verify(row):
 op=decoded(int(row['opcode'],0))
 if op is None:return False
 assert row['completion']=='confirmed' and not row['gap'] and row['memory']==[]
 assert len(row['pre'])==len(row['post'])==65 and all(v is not None for v in [*row['pre'].values(),*row['post'].values()])
 pre={k:int(v,0) for k,v in row['pre'].items()};post={k:int(v,0) for k,v in row['post'].items()};a=0 if op['n']==31 else pre['x'+str(op['n'])];b=0 if op['m']==31 else pre['x'+str(op['m'])];value,flags=calculate(a,b,(pre['nzcv']>>29)&1,op['width'],op['subtract']);wanted=dict(pre)
 if op['d']!=31:wanted['x'+str(op['d'])]=value
 if op['flags']:wanted['nzcv']=(pre['nzcv']&~0xf0000000)|flags
 assert post==wanted,(op,row,wanted);return True

def specs():
 for width in [32,64]:
  for op in OPS:
   if op.startswith('ngc'):aliases=[(11,31,9),(9,31,9),(31,31,9),(11,31,31)]
   else:
    aliases=[(11,8,9),(8,8,9),(9,8,9),(11,8,8),(8,8,8),(31,8,9),(11,8,31)]
    if op.startswith('adc'):aliases += [(11,31,9),(11,31,31)]
   for d,n,m in aliases:yield dict(op=op,width=width,d=d,n=n,m=m,high=False)
   high=[(29,31,30),(30,31,29)] if op.startswith('ngc') else [(29,29,30),(30,29,30)]
   for d,n,m in high:yield dict(op=op,width=width,d=d,n=n,m=m,high=True)
def patterns(width):
 mask=(1<<width)-1;sign=1<<(width-1)
 for a,b,c in [(0,0,0),(mask,mask,1),(sign-1,0,1),(sign,1,0),(sign,mask,0)]:
  yield ((0xbadcafe0<<32)|a if width==32 else a),((0x12345678<<32)|b if width==32 else b),c

def expected(c,seed,initial,carry):
 registers={8:seed,9:initial,11:seed^MASK,29:seed,30:initial,31:0};value,flags=calculate(registers[c['n']],registers[c['m']],carry,c['width'],c['op'].startswith(('sbc','ngc')));stored=0 if c['d']==31 else value;pre=0x60000000 if carry else 0x80000000;post_flags=flags if c['op'].endswith('s') else pre
 return stored,stored.to_bytes(8,'little')+post_flags.to_bytes(8,'little')+initial.to_bytes(8,'little')+bytes(8)
def assembly(c,name):
 prefix='x' if c['width']==64 else 'w';reg=lambda n:prefix+('zr' if n==31 else str(n));operands=[reg(c['d']),reg(c['m'])] if c['op'].startswith('ngc') else [reg(c[k]) for k in ['d','n','m']]
 setup=['stp x29, x30, [sp, #-16]!','ldr x30, [x1, #16]','mov x29, x0','cmp x2, #1'] if c['high'] else ['ldr x9, [x1, #16]','mov x8, x0','mvn x11, x0','cmp x2, #1']
 outreg='xzr' if c['d']==31 else 'x'+str(c['d']);body=setup+[c['op']+' '+', '.join(operands),'mrs x10, nzcv',f'stp {outreg}, x10, [x1]',f'mov x0, {outreg}']+(['ldp x29, x30, [sp], #16'] if c['high'] else [])+['ret']
 return '.p2align 2\n.globl _'+name+'\n.globl _'+name+'_end\n_'+name+':\n    '+'\n    '.join(body)+'\n_'+name+'_end:\n'
def check(out,runner,cli):
 out.mkdir(parents=True,exist_ok=False);sys.path.insert(0,str(ROOT/'tools'));import dependencies;sdk=dependencies.host();classifier=out/'carry-classification'
 run(['clang++','-arch','arm64','-std=c++17','-O2','-DTRACEQ_HOST_LAB','-I'+str(sdk),HERE/'carry_classification.mm',classifier_archive(),sdk/'libfrida-gum.a','-framework','Foundation','-lresolv','-lm','-ldl','-o',classifier]);print(run([classifier]).strip(),flush=True)
 cases=list(specs());assert len(cases)==len({(c['op'],c['width'],c['d'],c['n'],c['m']) for c in cases})==104
 frozen=[]
 for c in cases:
  for seed,initial,carry in patterns(c['width']):
   value,buf=expected(c,seed,initial,carry);frozen.append(dict(case=c,seed=seed,initial=initial,carry=carry,result=hex(value),buffer=buf.hex()))
 (out/'frozen-oracles.json').write_text(json.dumps({'assembly':frozen,'source':'Arbitraryinteger arithmetic andsignedbounds;carryfrompreNZCV,Wdestzeroextended,ZRdiscard,onlySformswriteflags.'},indent=2)+'\n');source=out/'carry.S';source.write_text('.text\n'+''.join(assembly(c,'carry_'+str(i)) for i,c in enumerate(cases)));lib=out/'libcarry.dylib';run(['clang','-arch','arm64','-dynamiclib',source,'-o',lib]);regs=[x for r in REGS for x in ['--reg',r]];checks=[];encodings=set()
 def invoke(module,name,mode,path,seed,count,initial):return json.loads(run([runner,module,name,mode,path,hex(seed),count,hex(initial),'--all-data']))
 def q(path,command,*args):return json.loads(run([cli,command,path,*map(str,args),'--json']))
 for i,c in enumerate(cases):
  for k,(seed,initial,carry) in enumerate(patterns(c['width'])):
   oracle=frozen[i*5+k];native=invoke(lib,'carry_'+str(i),'native',out/'unused',seed,carry,initial);assert native['buffer']==oracle['buffer'] and int(native['result'],0)==int(oracle['result'],0),(c,k,native,oracle)
   for mode in ['trace-chunks','trace-fast']:
    path=out/f'{i}-{k}-{mode}.gtsw';cap=invoke(lib,'carry_'+str(i),mode,path,seed,carry,initial);assert cap['ok'] and cap['buffer']==oracle['buffer'] and cap['result']==native['result'];row=q(path,'context','--at-ev',4,'--before',0,'--after',0,*regs)['data'][0];assert verify(row)
    if k==0 and mode=='trace-fast':assert int(row['opcode'],0) not in encodings;encodings.add(int(row['opcode'],0))
    stat=q(path,'stat')['meta'];assert stat['capture_gaps']==0 and not stat['unsupported_mnemonics'];writers=q(path,'last-writers','--range',cap['data_base']+',32','--limit',32)['data'];assert [w['known'] for w in writers]==[j<16 for j in range(32)]
    for j,w in enumerate(writers):
     if w['known']:assert int(w['value'],0)==bytes.fromhex(oracle['buffer'])[j]
     else:assert w['value'] is None
    checks.append(dict(kind='assembly',case=c,input=k,mode=mode,all65=True,native_bytes_flags=True))
  print('assembly',i,c['op'],c['width'],'PASS',flush=True)
 for opt in ['-O1','-O3']:
  module=out/('libcarry-c'+opt+'.dylib');run(['clang','-arch','arm64','-dynamiclib',opt,'-fno-stack-protector','-fomit-frame-pointer',HERE/'fixtures/carry_c.c','-o',module])
  for op in ['add','sub','neg']:
   for seed,initial,count in [(0,0,0),(MASK,MASK,1),(0x8000000000000001,0x7ff8123456789abc,7),(0xfedcba9876543210,0x0123456789abcdef,3)]:
    a=(seed<<64)|initial;b=(count<<64)|(seed^initial);value=(a+b if op=='add' else a-b if op=='sub' else -a)&((1<<128)-1);wanted=value.to_bytes(16,'little')+initial.to_bytes(8,'little')+bytes(8);name='carry_'+op+'_c';native=invoke(module,name,'native',out/'unused',seed,count,initial);assert native['buffer']==wanted.hex() and int(native['result'],0)==value>>64
    for mode in ['trace-chunks','trace-fast']:
     path=out/f'c-{opt}-{op}-{count}-{seed}-{mode}.gtsw';cap=invoke(module,name,mode,path,seed,count,initial);assert cap['ok'] and cap['buffer']==wanted.hex() and cap['result']==native['result'];context=q(path,'context','--at-ev',0,'--before',0,'--after',4096,'--limit',4096,*regs);assert not context['meta']['truncated'];verified=sum(verify(row) for row in context['data']);stat=q(path,'stat')['meta'];assert not any(x in stat['unsupported_mnemonics'] for x in OPS);writers=q(path,'last-writers','--range',cap['data_base']+',32','--limit',32)['data']
     for j,w in enumerate(writers):
      if w['known']:assert int(w['value'],0)==wanted[j]
      else:assert w['value'] is None
     checks.append(dict(kind='ordinary-c-wideinteger',optimization=opt,operation=op,count=count,mode=mode,verified_carry=verified,native_bytes=True))
 assert len(encodings)==104
 (out/'summary.json').write_text(json.dumps({'status':'pass','distinct_assembly_encodings':len(encodings),'captures':len(checks),'checks':checks},indent=2)+'\n');print('PASS',len(checks),'targeted carry captures',flush=True)
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--runner',type=Path,default=ROOT/'build/traceq-host/traceq-capture');p.add_argument('--cli',type=Path,default=ROOT/'cli/traceq');p.add_argument('--out',type=Path,required=True);a=p.parse_args();check(a.out.resolve(),a.runner.resolve(),a.cli.resolve())
