#!/usr/bin/env python3
"""LD1/ST1 native byte facts, full register effects and truthful data-range gaps."""
import argparse,json,subprocess,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
MASK=(1<<64)-1
REGS=[*[f'x{i}' for i in range(31)],'sp','nzcv',*[f'v{i}' for i in range(32)]]

def run(args):
 r=subprocess.run(list(map(str,args)),capture_output=True,text=True,timeout=40)
 if r.returncode:raise AssertionError((list(map(str,args)),r.returncode,r.stdout[-2000:],r.stderr[-2000:]))
 return r.stdout

def cases():
 for kind in ['ld1','st1']:
  for n in range(1,5):
   for i,(shape,width) in enumerate([('8b',8),('16b',16),('4h',8),('8h',16),('2s',8),('4s',16),('1d',8),('2d',16)]):
    yield dict(kind=kind,n=n,shape=shape,width=width,lane=-1,form=['base','imm','reg'][(n+i)%3])
  for letter,width,high in [('b',1,15),('h',2,7),('s',4,3),('d',8,1)]:
   for lane in [0,high]:
    for form in ['base','imm','reg']:yield dict(kind=kind,n=1,shape=letter,width=width,lane=lane,form=form)
  for form in ['wrap','sp','unaligned','alias','outside']:
   yield dict(kind=kind,n=4 if form=='wrap' else 2,shape='16b',width=16,lane=-1,form=form)

def asm(case,name):
 kind,n,shape,width,lane,form=[case[k] for k in ['kind','n','shape','width','lane','form']]
 regs=[(30+i)%32 for i in range(n)] if form=='wrap' else list(range(n))
 setup=['ldr x9, [x1, #16]','stp x0, x9, [x1]','mvn x10, x0','stp x2, x10, [x1, #16]','mvn x10, x9','eor x11, x0, x9','stp x10, x11, [x1, #32]','add x10, x0, x2','sub x11, x9, x2','stp x10, x11, [x1, #48]','fmov d0, x0','mov v0.d[1], x2','fmov d1, x9','mov v1.d[1], x0','mvn x10, x0','fmov d2, x10','mov v2.d[1], x9','fmov d3, x2','mvn x10, x9','mov v3.d[1], x10','cmp x0, x2','mov x8, x1']
 if form=='wrap':setup+=['mov v30.16b, v0.16b','mov v31.16b, v1.16b','mov v0.16b, v2.16b','mov v1.16b, v3.16b']
 if form in ['sp','outside']:setup+=['sub sp, sp, #64','ldp q16, q17, [x1]','ldp q18, q19, [x1, #32]','stp q16, q17, [sp]','stp q18, q19, [sp, #32]']
 if form=='unaligned':setup+=['add x8, x8, #1']
 if form=='reg':setup+=['mov x10, #7']
 vectors=', '.join('v'+str(i)+'.'+shape for i in regs)
 instruction=kind+' {'+vectors+'}'+('['+str(lane)+']' if lane>=0 else '')+', ['+('sp' if form in ['sp','outside'] else 'x8')+']'
 if form=='imm':instruction+=', #'+str(n*width)
 if form=='reg':instruction+=', x10'
 if form=='alias':instruction+=', x8'
 tail=[]
 if kind=='ld1':
  for i,reg in enumerate(regs):tail+=['str q'+str(reg)+', [x1, #'+str(64+i*16)+']']
 elif form in ['sp','outside']:tail+=['ldp q16, q17, [sp]','ldp q18, q19, [sp, #32]','stp q16, q17, [x1]','stp q18, q19, [x1, #32]']
 if form in ['sp','outside']:tail+=['add sp, sp, #64']
 return '.p2align 2\n.globl _'+name+'\n.globl _'+name+'_end\n_'+name+':\n    '+'\n    '.join(setup+[instruction]+tail+['ret'])+'\n_'+name+'_end:\n'

def check(out,runner,cli):
 out.mkdir(parents=True,exist_ok=False);specs=list(cases());source=out/'targets.S';source.write_text('.text\n'+''.join(asm(c,'structure_'+str(i)) for i,c in enumerate(specs)));lib=out/'libstructure.dylib';run(['clang','-arch','arm64','-dynamiclib',source,'-o',lib])
 def invoke(lib,fn,mode,path,seed,count,initial,all_data=True):return json.loads(run([runner,lib,fn,mode,path,hex(seed),count,hex(initial),'--buffer-size','128',*(['--all-data'] if all_data else [])]))
 def query(path,cmd,*args):return json.loads(run([cli,cmd,path,*args,'--json']))
 reg_args=[a for reg in REGS for a in ['--reg',reg]];checks=[]
 for i,c in enumerate(specs):
  for k,(seed,initial,count) in enumerate([(0,MASK,1),(0xfedcba9876543210,0x0123456789abcdef,7)]):
   words=[seed,initial,count,seed^MASK,initial^MASK,seed^initial,(seed+count)&MASK,(initial-count)&MASK]
   data=b''.join(x.to_bytes(8,'little') for x in words);want=bytearray(data+bytes(64));n=c['n'];width=c['width'];lane=c['lane'];form=c['form'];offset=int(form=='unaligned')
   vectors=[seed.to_bytes(8,'little')+count.to_bytes(8,'little'),initial.to_bytes(8,'little')+seed.to_bytes(8,'little'),(seed^MASK).to_bytes(8,'little')+initial.to_bytes(8,'little'),count.to_bytes(8,'little')+(initial^MASK).to_bytes(8,'little')]
   if c['kind']=='st1':
    payload=b''.join(v[(lane*width if lane>=0 else 0):(lane*width if lane>=0 else 0)+width] for v in vectors[:n]);want[offset:offset+len(payload)]=payload
   else:
    payload=bytes(want[offset:offset+n*width])
    for r in range(n):
     v=bytearray(vectors[r]) if lane>=0 else bytearray(16)
     begin=lane*width if lane>=0 else 0;v[begin:begin+width]=payload[r*width:(r+1)*width];want[64+r*16:80+r*16]=v
   fn='structure_'+str(i);native=invoke(lib,fn,'native',out/'unused',seed,count,initial)
   assert native['buffer']==want.hex() and int(native['result'],0)==seed,(c,k,native,want.hex())
   for mode in ['trace-chunks','trace-fast']:
    path=out/f'{i}-{k}-{mode}.gtsw';cap=invoke(lib,fn,mode,path,seed,count,initial,form!='outside');assert cap['ok'] and cap['buffer']==want.hex() and cap['result']==native['result']
    instructions=query(path,'instructions','--limit','200');assert not instructions['meta']['truncated'];hints=[r for r in instructions['data'] if r['text'].startswith(c['kind']+' ')];assert len(hints)==1
    row=query(path,'context','--at-ev',str(hints[0]['ev']),'--before','0','--after','0',*reg_args)['data'][0]
    assert row['completion']=='confirmed' and len(row['pre'])==len(row['post'])==65 and all(v is not None for v in [*row['pre'].values(),*row['post'].values()])
    pre,post=row['pre'],row['post'];expected=dict(pre);base=int(pre['sp' if form in ['sp','outside'] else 'x8'],0)
    if form in ['imm','reg','alias']:expected['x8']=hex((int(pre['x8'],0)+(n*width if form=='imm' else 7 if form=='reg' else int(pre['x8'],0)))&MASK)
    if c['kind']=='ld1':
     for r in range(n):expected['v'+str((30+r)%32 if form=='wrap' else r)]=hex(int.from_bytes(want[64+r*16:80+r*16],'little'))
    assert {r:int(v,0) for r,v in post.items()}=={r:int(v or '0',0) for r,v in expected.items()},(c,pre,post,expected)
    stat=query(path,'stat')['meta'];assert not stat['unpositioned_gap']
    if form=='outside':assert row['gap'] and row['memory']==[] and 'outside_data_range' in row['gap_reasons']
    else:
     assert not row['gap'] and stat['capture_gaps']==0,(c,stat)
     assert len(row['memory'])==n
     for r,access in enumerate(row['memory']):assert access['known'] and access['rw']==('r' if c['kind']=='ld1' else 'w') and access['size']==width and int(access['addr'],0)==base+r*width and int(access['val'],0).to_bytes(width,'little')==payload[r*width:(r+1)*width],(c,access,payload.hex())
    writers=query(path,'last-writers','--range',cap['data_base']+',128','--limit','128')['data'];assert len(writers)==128
    for b,w in enumerate(writers):
     if w['known']:assert int(w['value'],0)==want[b]
     else:assert w['value'] is None
    checks.append({'case':c,'input':k,'mode':mode,'all65':True,'native_bytes':True,'memory_facts':True})
  print(i,c['kind'],c['shape'],n,form,'PASS',flush=True)
 for opt in ['-O1','-O3']:
  module=out/('libstructure-c'+opt+'.dylib');run(['clang','-arch','arm64','-dynamiclib',opt,'-fno-stack-protector','-fomit-frame-pointer',Path(__file__).resolve().parent/'fixtures/structure_c.c','-o',module])
  for count in [0,1,7,64]:
   seed=0x123456789abcdef0;initial=0x0123456789abcdef
   want=bytearray(128);want[:64]=bytes(((seed+i*13)^(initial>>((i%8)*8)))&255 for i in range(64));want[64:64+count]=want[:count]
   native=invoke(module,'structure_c','native',out/'unused',seed,count,initial);assert native['buffer']==want.hex() and int(native['result'],0)==seed^initial
   for mode in ['trace-chunks','trace-fast']:
    path=out/f'c-{opt}-{count}-{mode}.gtsw';cap=invoke(module,'structure_c',mode,path,seed,count,initial);assert cap['ok'] and cap['buffer']==want.hex() and cap['result']==native['result']
    stat=query(path,'stat')['meta'];assert stat['instructions']>0 and stat['stores']>0
    writers=query(path,'last-writers','--range',cap['data_base']+',128','--limit','128')['data'];assert len(writers)==128
    for b,w in enumerate(writers):
     if w['known']:assert int(w['value'],0)==want[b]
     else:assert w['value'] is None
    checks.append({'kind':'ordinary-c','optimization':opt,'count':count,'mode':mode,'gaps':stat['capture_gaps'],'unsupported':stat['unsupported_mnemonics'],'capture_ms':cap['capture_ms']})
 (out/'summary.json').write_text(json.dumps({'status':'pass','cases':len(specs),'captures':len(checks),'checks':checks},indent=2)+'\n');print('PASS',len(checks),'targeted captures',flush=True)
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--runner',type=Path,default=ROOT/'build/traceq-host/traceq-capture');p.add_argument('--cli',type=Path,default=ROOT/'cli/traceq');p.add_argument('--out',type=Path,default=ROOT/'artifacts'/('structure-'+str(time.time_ns())));a=p.parse_args();check(a.out.resolve(),a.runner.resolve(),a.cli.resolve())
