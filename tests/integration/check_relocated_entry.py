#!/usr/bin/env python3
"""Bounded Android relocation evidence check through the formal SDK C ABI."""
from pathlib import Path
import argparse,hashlib,json,shlex,subprocess,sys,time
ROOT=Path(__file__).resolve().parents[2]
PHONE=Path('/Users/fanjiahao05/.local/bin/revkit-phone')
def run(args,**kw):return subprocess.run(list(map(str,args)),capture_output=True,timeout=120,**kw)
def phone(args,**kw):
 r=run([PHONE,'exec','--root','--timeout','60',*args],**kw);r.check_returncode();return r

def push(f,dst):
 blob=f.read_bytes();script='set -eC\ncat > '+shlex.quote(dst)+'\nchmod 700 '+shlex.quote(dst)
 phone(['sh','-c',script],input=blob);assert phone(['sha256sum',dst]).stdout.decode().split()[0]==hashlib.sha256(blob).hexdigest()

def check(out,ndk,library,expanded,observation=3,smoke=False):
 out.mkdir(parents=True,exist_ok=False);sys.path.insert(0,str(ROOT/'tools'));import dependencies
 sdk=dependencies.gum('android-arm64');cc=ndk/'toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android24-clang';tests=ROOT/'tests/integration'
 commands=[[cc,'-shared','-fPIC',tests/'fixtures/relocated_entry.S',tests/'fixtures/relocated_algorithm.c','-O2','-fno-stack-protector','-fomit-frame-pointer','-o',out/'librelocated.so'],[cc,'-O2','-I'+str(sdk),'-I'+str(ROOT/'capture/traceq/include'),tests/'relocated_entry.c',tests/'fixtures/relocated_adapter.S',ROOT/'build/traceq-android/gum/libtraceq-gum.a','-ldl','-llog','-lm','-lz','-o',out/'driver']]
 (out/'commands.json').write_text(json.dumps([[str(x)for x in c]for c in commands],indent=2)+'\n')
 for i,c in enumerate(commands):
  r=run(c);(out/('build-'+str(i)+'.stderr')).write_bytes(r.stderr);r.check_returncode()
 remote='/data/local/tmp/traceq-relocated-'+str(time.time_ns());phone(['mkdir','-m','700',remote])
 for f,n in [(library,'sdk.so'),(out/'librelocated.so','fixture.so'),(out/'driver','driver')]:push(f,remote+'/'+n)
 args=['timeout','-k','2','20',remote+'/driver',remote+'/sdk.so',remote+'/fixture.so',remote,str(int(expanded)),str(observation)]
 if smoke:args.append('smoke')
 r=phone(args);(out/'driver.stdout').write_bytes(r.stdout);(out/'driver.stderr').write_bytes(r.stderr)
 rows=[json.loads(x)for x in r.stdout.splitlines()];assert len(rows)==(3 if smoke else 9) and all(row['pass']for row in rows)
 checks=[]
 for row in rows:
  name=row['case']+'-'+str(row['seed_index']);trace=out/(name+'.gtsw')
  r=run([PHONE,'pull','--root',remote+'/'+name+'.gtsw',trace]);r.check_returncode()
  def query(label,cmd,*args):
   r=run([ROOT/'cli/traceq',cmd,trace,*map(str,args),'--json']);(out/(name+'-'+label+'.json')).write_bytes(r.stdout);r.check_returncode();return json.loads(r.stdout)
  stat=query('stat','stat')['meta'];assert [stat[k]for k in ['instructions','reads','stores','capture_gaps','confirmed_instructions']]==[row[k]for k in ['instructions','reads','writes','gaps','commits']]
  first=query('entry','context','--at-ev',0,'--before',0,'--after',0,'--reg','sp','--reg','x0','--reg','x1','--limit',1)['data'][0]
  base=int(row['trampoline'],0);want_pc=base if expanded else int(row['target'],0)+16
  assert int(first['pc'],0)==want_pc and int(first['pre']['sp'],0)==int(row['entry_sp'],0)-(0 if expanded or row['case']=='relocated_carry' else 64)
  assert first['pre']['x1']==row['output_address']
  if expanded or row['case']!='relocated_carry':assert first['pre']['x0']==row['seed']
  stores=query('early-stores','mem-access','--range',hex(int(row['entry_sp'],0)-64)+',48','--write','--to',10,'--limit',32)['data']
  if expanded:
   assert stat['code_scope']=='explicit_ranges' and stat['code_envelope_only'] and len(stat['code_ranges'])==2
   if row['case']!='relocated_carry':assert len(stores)==(6 if row['case']=='relocated_spill' else 2)
   expected=[int(row['seed'],0),int(row['output_address'],0),2,3,5,7]
   for i,access in enumerate(stores if row['case']!='relocated_carry' else []):assert access['known'] and int(access['addr'],0)==int(row['entry_sp'],0)-64+i*8 and int(access['val'],0)==expected[i]
  elif row['case']!='relocated_carry':assert not stores
  if row['case']=='relocated_carry':
   reads=query('input-read','mem-access','--range',hex(int(row['output_address'],0)+16)+',8','--read','--limit',32)['data']
   assert len(reads)==int(expanded)
   if expanded:assert reads[0]['known'] and int(reads[0]['val'],0)==int(row['initial'],0)
   wide=int(row['initial'],0)+(int(row['initial'],0)^int(row['seed'],0))
   assert int(row['result'],0)==(int(row['seed'],0)+row['count']+(wide>>64))&((1<<64)-1)
  checks.append({'case':name,'native_result_and_whole_guarded_output':True,'entry_PC':first['pc'],'entry_SP':first['pre']['sp'],'independent_expected_SP':row['entry_sp'],'early_real_stack_stores':len(stores),'trace_bytes':trace.stat().st_size,'instructions':row['instructions']})
 result={'pass':True,'expanded':expanded,'observation':observation,'cases':checks,'SDK_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'remote':remote,'scope':'Two ASM relocation mechanisms and one optimized ordinary C algorithm; frozen or formal SDK. Actual Stalker input trampoline PCs, hardware SP reference and early stores. No App/ABI-specific product logic.'}
 (out/'summary.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);p.add_argument('--ndk',type=Path,required=True);p.add_argument('--library',type=Path,required=True);p.add_argument('--expanded',action='store_true');p.add_argument('--observation',type=int,choices=[1,2,3],default=3);p.add_argument('--smoke',action='store_true');a=p.parse_args();check(a.out.resolve(),a.ndk.resolve(),a.library.resolve(),a.expanded,a.observation,a.smoke)
