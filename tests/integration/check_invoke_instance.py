#!/usr/bin/env python3
"""Opt-in Android module-instance regression; all phone I/O uses revkit-phone."""
import argparse,hashlib,json,os,platform,shlex,struct,subprocess,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
PHONE=Path.home()/'.local/bin/revkit-phone'
def run(args,**kw):return subprocess.run(list(map(str,args)),capture_output=True,check=True,timeout=120,**kw)
def phone(args):return run([PHONE,'exec','--root','--timeout','60',*args])
def push(source,remote,executable=False):
 data=source.read_bytes();run([PHONE,'exec','--root','--timeout','100','sh','-c','set -eC\ncat > '+shlex.quote(remote)+'\nchmod '+('700' if executable else '600')+' '+shlex.quote(remote)],input=data)
 assert phone(['sha256sum',remote]).stdout.decode().split()[0]==hashlib.sha256(data).hexdigest()
def elfword(raw,va):
 off=struct.unpack_from('<Q',raw,32)[0];size,count=struct.unpack_from('<HH',raw,54)
 for i in range(count):
  typ,_,pos,start,_,length,_,_=struct.unpack_from('<II6Q',raw,off+i*size)
  if typ==1 and start<=va and va+4<=start+length:return struct.unpack_from('<I',raw,pos+va-start)[0]
 raise AssertionError('opcode outside ELF')
def check(out,ndk,library,cli,probe=False):
 out.mkdir(parents=True,exist_ok=False);host='darwin-x86_64' if platform.system()=='Darwin' else 'linux-x86_64';cc=ndk/'toolchains/llvm/prebuilt'/host/'bin/aarch64-linux-android24-clang';fixture=ROOT/'tests/integration/fixtures/invoke_instance.c';include=ROOT/'capture/traceq/src'
 for image,tag in [('a','0x13579bdfu'),('b','0x2468ace0u')]:
  (out/image).mkdir();run([cc,'-shared','-fPIC','-O2','-fno-stack-protector','-fomit-frame-pointer','-Wl,-soname,libtraceq-instance.so','-DINSTANCE_TAG='+tag,fixture,'-o',out/image/'libtraceq-instance.so'])
 driver=out/'instance-check';run([str(cc)+'++','-std=c++17','-O2','-static-libstdc++','-I'+str(include),ROOT/'tests/integration/invoke_instance_android.cpp','-ldl','-o',driver])
 remote='/data/local/tmp/traceq-instance-'+str(time.time_ns());phone(['mkdir','-m','700',remote]);phone(['mkdir',remote+'/a',remote+'/b'])
 for source,name,exe in [(library,'collector.so',False),(driver,'instance-check',True),(out/'a/libtraceq-instance.so','a/libtraceq-instance.so',False),(out/'b/libtraceq-instance.so','b/libtraceq-instance.so',False)]:push(source,remote+'/'+name,exe)
 try:r=phone([remote+'/instance-check',remote+'/collector.so',remote+'/a/libtraceq-instance.so',remote+'/b/libtraceq-instance.so',remote])
 except subprocess.CalledProcessError as e:
  (out/'driver.stdout').write_bytes(e.stdout or b'');(out/'driver.stderr').write_bytes(e.stderr or b'');raise
 (out/'driver.stdout').write_bytes(r.stdout);(out/'driver.stderr').write_bytes(r.stderr);rows=[json.loads(x) for x in r.stdout.splitlines()];assert len(rows)==(18 if probe else 42)
 regs=[*['x'+str(i) for i in range(31)],'sp','nzcv',*['v'+str(i) for i in range(32)]];selectors=[x for reg in regs for x in ['--reg',reg]];checks=[]
 for x in rows:
  value=int(x['seed'],0)^[0x13579bdf,0x2468ace0][x['image']];expected=[]
  for i in range(8):value=((value*33+17)&((1<<64)-1))^i;expected.append((value>>(i&7))&255)
  assert int(x['result'],0)==value and x['bytes']==bytes(expected).hex()
  if not x['observation']:continue
  path=out/(x['label']+'.gtsw');run([PHONE,'pull','--root',remote+'/'+path.name,path])
  def q(cmd,*args):return json.loads(run([cli,cmd,path,*map(str,args),'--json']).stdout)
  stat=q('stat')['meta'];assert (stat['instructions'],stat['reads'],stat['stores'],stat['capture_gaps'])==(x['instructions'],x['reads'],x['writes'],x['gaps'])
  assert x['target_inside_selected']==(int(x['target'],0)>=int(x['code_base'],0) and int(x['target'],0)-int(x['code_base'],0)<x['code_size'])
  if not x['target_inside_selected']:assert x['selector']=='name' and stat['instructions']==0;checks.append({'label':x['label'],'expected_name_ambiguity':True});continue
  n=stat['instructions'];assert n>0 and not stat['unpositioned_gap'];raw=(out/('a' if not x['image'] else 'b')/'libtraceq-instance.so').read_bytes()
  ctx=q('context','--at-ev',0,'--before',0,'--after',n-1,'--limit',n,*selectors);assert ctx['meta']['validation']=='full stream through END' and len(ctx['data'])==n
  for row in ctx['data']:
   assert len(row['pre'])==65 and all(v is not None for v in row['pre'].values());assert int(row['opcode'],0)==elfword(raw,int(row['pc'],0)-int(x['module_base'],0))
   if row['completion']=='confirmed':assert len(row['post'])==65 and all(v is not None for v in row['post'].values())
   else:assert row['post'] is None
  assert int(ctx['data'][0]['pre']['x0'],0)==int(x['seed'],0) and int(ctx['data'][0]['pre']['x1'],0)==int(x['output'],0)
  assert int(ctx['data'][-1]['pre']['x0'],0)==value
  writers=q('last-writers','--range',hex(int(x['output'],0)-16)+',64','--limit',64);assert len(writers['data'])==64
  for i,w in enumerate(writers['data']):
   if 16<=i<24:
    assert w['last_observed_write'] is not None and int(w['last_observed_write']['value'],0)==expected[i-16]
    if w['known']:assert int(w['value'],0)==expected[i-16]
    else:assert w['value'] is None
   else:assert not w['known'] and w['value'] is None and w['last_observed_write'] is None
  (out/(x['label']+'-context.json')).write_text(json.dumps(ctx)+'\n');checks.append({'label':x['label'],'all65_elf_oracle':True,'instructions':n,'gaps':stat['capture_gaps']})
 if not probe:assert sum(x['selector']=='at' and x['observation']>0 for x in rows)==18
 assert any(not x['target_inside_selected'] and x['observation']>0 for x in rows if x['selector']=='name')
 summary={'status':'probe_confirmed' if probe else 'pass','rows':rows,'checks':checks,'remote':remote,'scope':'Independent native scalar oracles for two DSOs and3seeds; full65/ELF/END, output bytes/redzones, unwritten-byte unknown, address/error/recovery guards. Name mismatch is an intentional diagnostic, not qualified capture.'};(out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n');print(summary['status'],len(rows),'calls',len(checks),'captures')
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--ndk',type=Path,required=True);p.add_argument('--library',type=Path,required=True);p.add_argument('--cli',type=Path,default=ROOT/'cli/traceq');p.add_argument('--out',type=Path,required=True);p.add_argument('--probe',action='store_true');a=p.parse_args();check(a.out.resolve(),a.ndk.resolve(),a.library.resolve(),a.cli.resolve(),a.probe)
