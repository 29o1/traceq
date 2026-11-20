"""Disjoint scope metadata, hull holes and explicit state cutoffs on both transports."""
from pathlib import Path
import json,struct,subprocess,time,unittest
ROOT=Path(__file__).resolve().parents[1];CLI=ROOT/'cli/traceq';MASK=(1<<64)-1
class ScopeRangeChecks(unittest.TestCase):
 @classmethod
 def setUpClass(cls):cls.out=ROOT/'artifacts'/('scope-range-unit-'+str(time.time_ns()));cls.out.mkdir(parents=True);cls.n=0
 def site(self,pc,text,word):
  a,b,c=struct.unpack('<3Q',text.ljust(24,b'\0'));return (8,0,pc,word,len(text),a,b,c)
 def pre(self,ev,pc):return [(5,ev,pc,i,8 if i<33 else 16,0x2000 if i==0 else 0,0,1) for i in range(65)]
 def records(self):
  prefix=[(13,0,0,3,2,1,0,0),(14,0,0x1000,0x100,0,0,0,0),(14,1,0x3000,0x100,0,0,0,0),self.site(0x1000,b'br x0',0xd61f0000),self.site(0x3000,b'add x1, x1, #1',0x91000421)]
  return prefix+[(1,0,0x1000,0xd61f0000,0,0,0,0)]+self.pre(0,0x1000)+[(11,0,0x1000,0x2000,2,0,0,1),(3,0,0x1000,0,0,0,0,6),(1,1,0x3000,0x91000421,0,0,0,1)]+self.pre(1,0x3000)+[(12,1,0x3000,0,0,0,0,1),(9,1,0x3000,0,0,0,0,1),(4,2,0,0,1,0,1,2)]
 def artifact(self,records,chunked):
  type(self).n+=1;p=self.out/(str(self.n)+'.gtsw');data=bytearray((b'GTSC001\0' if chunked else b'GTSW001\0')+struct.pack('<7Q',0x1000,0x2100,0x5000,64,1,2,64))
  if not chunked:data+=b''.join(struct.pack('<8Q',*e) for e in records)
  else:
   for first in range(0,len(records),3):
    block=records[first:first+3];raw=bytearray();seq=pc=0
    for e in block:
     def zz(n):n&=MASK;return ((n<<1)^(MASK if n>>63 else 0))&MASK
     fields=[zz(e[1]-seq),zz(e[2]-pc),*e[3:]];seq,pc=e[1:3];widths=[(x.bit_length()+7)//8 for x in fields];raw+=bytes([e[0]])+struct.pack('<I',sum(x<<(4*i) for i,x in enumerate(widths)));raw+=b''.join(x.to_bytes(n,'little') for x,n in zip(fields,widths))
    data+=b'GTBL001\0'+struct.pack('<II',len(block),len(raw))+raw
  p.write_bytes(data);return p
 def q(self,path,cmd,*args,ok=True):
  r=subprocess.run([str(CLI),cmd,str(path),*map(str,args),'--json'],capture_output=True,text=True,timeout=10);j=json.loads(r.stdout);self.assertEqual(r.returncode==0,ok,(r.stdout,r.stderr));return j
 def test_hole_is_outside_even_inside_envelope(self):
  for chunked in [False,True]:
   p=self.artifact(self.records(),chunked);q=self.q(p,'stat');self.assertEqual(q['meta']['code_ranges'],[{'base':'0x1000','size':256},{'base':'0x3000','size':256}]);self.assertTrue(q['meta']['code_envelope_only']);self.assertEqual(q['meta']['capture_gaps'],1)
   b=self.q(p,'boundaries')['data'][0];self.assertEqual(b['target']['address'],'0x2000');self.assertEqual(b['status'],'reentered');self.assertEqual(b['reentry_ev'],1)
   w=self.q(p,'last-writers','--range','0x5000,8');self.assertEqual(w['meta']['as_of_ev'],1);self.assertEqual(w['meta']['state_position'],'after_recorded_accesses_at_event');self.assertFalse(any(x['known'] for x in w['data']))
 def test_invalid_metadata_and_hole_instructions_rejected(self):
  base=self.records();cases=[]
  for index,field,value in [(0,3,5),(0,4,1),(0,4,65),(1,2,0),(1,2,0x1004),(1,3,0),(1,3,2),(1,4,1),(2,1,2),(2,2,0x1080),(2,2,0x3002),(2,3,252),(2,3,MASK-3)]:
   rows=list(base);x=list(rows[index]);x[field]=value;rows[index]=tuple(x);cases.append(rows)
  cases += [base[:2]+base[3:],base[:3]+[base[1]]+base[3:],base[:4]+[base[1]]+base[4:],base[:3]+[self.site(0x2000,b'br x0',0xd61f0000)]+base[3:]]
  for kind,pc in [(1,0x2000),(11,0x3000)]:
   rows=list(base);index=next(i for i,e in enumerate(rows) if e[0]==kind);x=list(rows[index]);x[2 if kind==1 else 3]=pc;rows[index]=tuple(x);cases.append(rows)
  for chunked in [False,True]:
   for rows in cases:
    p=self.artifact(rows,chunked)
    for cmd,args in [('stat',[]),('context',['--at-ev',0]),('find-value',['--value',0]),('find-value',['--bytes','00'])]:self.assertEqual(set(self.q(p,cmd,*args,ok=False)),{'error'})
 def test_full_suffix_validation_and_no_empty_cutoff(self):
  for chunked in [False,True]:
   for damage in ['truncate','suffix']:
    p=self.artifact(self.records(),chunked);data=p.read_bytes();p.write_bytes(data[:-1] if damage=='truncate' else data+b'x');self.assertEqual(self.q(p,'instructions','--to',0,'--limit',1,ok=False)['error']['code'],'TRACE_ERROR')
   p=self.artifact([(13,0,0,1,0,1,0,0),(4,0,0,0,0,0,0,2)],chunked);q=self.q(p,'last-writers','--range','0x5000,8');self.assertIsNone(q['meta']['as_of_ev']);self.assertNotIn('code_ranges',q['meta'])
 def test_cached_interval_switches_and_exact_instruction_tail(self):
  pcs=[0x1000,0x10fc,0x3000,0x30fc,0x1000,0x3000,0x10fc,0x30fc]
  prefix=[(13,0,0,3,2,1,0,0),(14,0,0x1000,0x100,0,0,0,0),(14,1,0x3000,0x100,0,0,0,0)]
  for pc in sorted(set(pcs)):prefix.append(self.site(pc,b'nop',0xd503201f))
  rows=list(prefix)
  for ev,pc in enumerate(pcs):
   rows.append((1,ev,pc,0xd503201f,0,0,0,1))
   if ev==0:rows+=self.pre(ev,pc)
   rows.append((9,ev,pc,0,0,0,0,1))
  rows.append((4,len(pcs),0,0,0,0,len(pcs),2))
  for chunked in [False,True]:
   p=self.artifact(rows,chunked);q=self.q(p,'instructions','--limit',len(pcs));self.assertEqual([int(x['pc'],0) for x in q['data']],pcs)
   for invalid_pc in [0x10fd,0x10ff,0x1100,0x2000,0x30fd,0x3100]:
    damaged=list(rows);damaged.insert(len(prefix),self.site(invalid_pc,b'nop',0xd503201f));self.q(self.artifact(damaged,chunked),'stat',ok=False)
 def test_unexecuted_site_requires_an_aligned_pc(self):
  for chunked in (False, True):
   for pc, valid in ((0x1004, True), (0x1005, False)):
    with self.subTest(chunked=chunked, pc=hex(pc)):
     path = self.artifact([self.site(pc, b'nop', 0xd503201f), (4,0,0,0,0,0,0,2)], chunked)
     result = self.q(path, 'stat', ok=valid)
     if valid:
      self.assertEqual((result['data'][0]['sites'], result['meta']['instructions']), (1, 0))
     else:
      self.assertEqual(result['error']['code'], 'TRACE_ERROR')
 def test_single_range_alignment_uses_instruction_pc(self):
  for chunked in (False,True):
   for pc in (0x1004,0x1005,0x1104):
    with self.subTest(chunked=chunked,pc=hex(pc)):
     rows=[self.site(pc,b'nop',0xd503201f),(1,0,pc,0xd503201f,0,0,0,0),(4,1,0,0,0,0,0,2)]
     path=self.artifact(rows,chunked)
     data=bytearray(path.read_bytes())
     struct.pack_into('<2Q',data,8,0x1001,0x100)
     path.write_bytes(data)
     result=self.q(path,'instructions',ok=pc==0x1004)
     if pc==0x1004:
      self.assertEqual([(row['pc'],row['off']) for row in result['data']],[('0x1004','0x3')])
     else:
      self.assertEqual(result['error']['code'],'TRACE_ERROR')
 def test_implicit_range_cannot_end_inside_an_instruction(self):
  pc=0x1004
  rows=[self.site(pc,b'nop',0xd503201f),(1,0,pc,0xd503201f,0,0,0,0),(4,1,0,0,0,0,0,2)]
  for chunked in (False,True):
   path=self.artifact(rows,chunked)
   data=bytearray(path.read_bytes())
   struct.pack_into('<Q',data,16,8)
   path.write_bytes(data)
   self.assertEqual(self.q(path,'stat')['meta']['instructions'],1)
   struct.pack_into('<Q',data,16,7)
   path.write_bytes(data)
   self.assertEqual(self.q(path,'instructions','--offset',100,ok=False)['error']['code'],'TRACE_ERROR')
 def test_scope_features_keep_prefix_order_and_legacy_site_order(self):
  pc=0x1000;site=self.site(pc,b'nop',0xd503201f);body=[(1,0,pc,0xd503201f,0,0,0,1)]+self.pre(0,pc)+[(9,0,pc,0,0,0,0,1),(4,1,0,0,0,0,1,2)]
  for chunked in [False,True]:
   # Existing single-range streams permit their feature after SITE metadata.
   legacy=self.artifact([site,(13,0,0,1,0,1,0,0)]+body,chunked);self.assertEqual(self.q(legacy,'stat')['meta']['instructions'],1)
   late=[site,(13,0,0,3,2,1,0,0),(14,0,0x1000,0x100,0,0,0,0),(14,1,0x3000,0x100,0,0,0,0)]+body
   self.q(self.artifact(late,chunked),'stat',ok=False)
   duplicate=self.records();duplicate.insert(3,duplicate[0]);self.q(self.artifact(duplicate,chunked),'stat',ok=False)
 def test_maximum_64_range_prefix_and_repeated_switches(self):
  bases=[0x1000+index*0x100 for index in range(64)];pcs=[bases[0],bases[-1],bases[0],bases[-1]]
  rows=[(13,0,0,3,64,1,0,0)]+[(14,index,base,4,0,0,0,0) for index,base in enumerate(bases)]
  rows+=[self.site(pc,b'nop',0xd503201f) for pc in sorted(set(pcs))]
  for ev,pc in enumerate(pcs):
   rows.append((1,ev,pc,0xd503201f,0,0,0,1))
   if ev==0:rows+=self.pre(ev,pc)
   rows.append((9,ev,pc,0,0,0,0,1))
  rows.append((4,len(pcs),0,0,0,0,len(pcs),2))
  for chunked in [False,True]:
   p=self.artifact(rows,chunked);data=bytearray(p.read_bytes());struct.pack_into('<Q',data,16,bases[-1]+4-bases[0]);p.write_bytes(data)
   q=self.q(p,'stat');self.assertEqual(len(q['meta']['code_ranges']),64);self.assertEqual(q['meta']['instructions'],4)
if __name__=='__main__':unittest.main()
