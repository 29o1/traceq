"""State timing, delta propagation and gap semantics of execution profile 2."""
import json
from pathlib import Path
import struct
import subprocess
import time
import unittest

ROOT=Path(__file__).resolve().parents[1]

class StateStreamChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.out=ROOT/'artifacts'/('state-unit-'+str(time.time_ns()));cls.out.mkdir(parents=True);cls.n=0

    def artifact(self,events):
        type(self).n+=1;path=self.out/(str(self.n)+'.gtsw')
        header=b'GTSW001\0'+struct.pack('<7Q',0x1000,0x100,0x2000,32,1,2,64)
        sites=[]
        for pc in sorted({e[2] for e in events if e[0]==1}):
            text=b'add x0, x0, #1';part=text.ljust(24,b'\0');a,b,c=struct.unpack('<3Q',part)
            sites.append((8,0,pc,0x91000400,len(text),a,b,c))
        path.write_bytes(header+b''.join(struct.pack('<8Q',*e) for e in sites+events));return path

    def query(self,path,cmd='reg-state',args=None,ok=True):
        options=['--at-ev','0','--reg','x0'] if args is None else args
        r=subprocess.run([str(ROOT/'cli/traceq'),cmd,str(path),*options,'--json'],capture_output=True,text=True,timeout=10)
        data=json.loads(r.stdout);self.assertEqual(r.returncode==0,ok,data);return data

    def base(self):
        return [(1,0,0x1000,0x91000400,0,0,0,1),(5,0,0x1000,0,8,1,0,1),
                (6,0,0x1000,0,8,2,0,1),(9,0,0x1000,0,0,0,0,1),
                (1,1,0x1004,0x91000400,0,0,0,0),
                (1,2,0x1008,0x91000400,0,0,0,1),(9,2,0x1008,0,0,0,0,1),
                (4,3,0,0,0,0,2,2)]

    def test_pre_post_and_unchanged_delta(self):
        p=self.artifact(self.base())
        self.assertEqual(self.query(p)['data'][0]['val'],'0x1')
        self.assertEqual(self.query(p,args=['--at-ev','0','--phase','post','--reg','x0'])['data'][0]['val'],'0x2')
        self.assertEqual(self.query(p,args=['--at-ev','2','--phase','post','--reg','x0'])['data'][0]['val'],'0x2')

    def test_branch_post_and_unobserved_register_stay_unknown(self):
        p=self.artifact(self.base())
        self.assertFalse(self.query(p,args=['--at-ev','1','--phase','post','--reg','x0'])['data'][0]['known'])
        self.assertFalse(self.query(p,args=['--at-ev','2','--reg','x1'])['data'][0]['known'])

    def test_gap_breaks_register_inheritance(self):
        events=self.base();events.insert(5,(3,1,0x1004,0,0,0,0,1));events[-1]=(4,3,0,0,1,0,2,2)
        self.assertFalse(self.query(self.artifact(events),args=['--at-ev','2','--reg','x0'])['data'][0]['known'])

    def test_future_gap_does_not_erase_historical_write(self):
        events=self.base();events.insert(2,(2,0,0x1000,0x2000,1,0xab,0,1))
        events.insert(6,(3,1,0x1004,0,0,0,0,1));events[-1]=(4,3,0,1,1,0,2,2)
        q=self.query(self.artifact(events),'last-writers',['--range','0x2000,1','--at-seq','0'])
        self.assertEqual(q['data'][0]['value'],'0xab')

    def test_external_call_gap_is_located_and_invalidates_prior_state(self):
        events=self.base();events.insert(2,(2,0,0x1000,0x2000,1,0xab,0,1))
        events.insert(6,(3,1,0x1004,0,0,0,0,6));events[-1]=(4,3,0,1,1,0,2,2)
        path=self.artifact(events)
        stat=self.query(path,'stat',[])['meta']
        self.assertEqual(stat['gap_reasons']['outside_code_range'],1)
        self.assertEqual(stat['gap_reasons']['unsupported'],0)
        self.assertFalse(stat['unpositioned_gap'])
        gaps=self.query(path,'instructions',['--gaps'])
        self.assertEqual([row['ev'] for row in gaps['data']],[1])
        self.assertFalse(self.query(path,args=['--at-ev','2','--reg','x0'])['data'][0]['known'])
        self.assertFalse(self.query(path,'last-writers',['--range','0x2000,1'])['data'][0]['known'])
        evidence=self.query(path,'last-writers',['--range','0x2000,1'])['data'][0]['last_observed_write']
        self.assertEqual((evidence['value'],evidence['writer_seq'],evidence['gaps_since'],evidence['latest_gap_ev']),('0xab',0,1,1))
        historical=self.query(path,'last-writers',['--range','0x2000,1','--at-seq','0'])
        self.assertEqual(historical['data'][0]['value'],'0xab')

    def test_missing_completion_does_not_look_like_valid_end(self):
        events=self.base();events.pop(-2);events[-1]=(4,3,0,0,0,0,1,2)
        self.assertIn('completion',self.query(self.artifact(events),ok=False)['error']['message'])

    def test_unknown_read_value_is_not_zero(self):
        events=self.base();events.insert(2,(7,0,0x1000,0x2000,8,0,0,0));events[-1]=(4,3,0,0,0,1,2,2)
        q=self.query(self.artifact(events),'mem-access',['--range','0x2000,8','--read'])
        self.assertFalse(q['data'][0]['known']);self.assertIsNone(q['data'][0]['val'])

    def test_incomplete_capture_produces_no_state_answer(self):
        q=self.query(self.artifact(self.base()[:-1]),ok=False)
        self.assertNotIn('data',q);self.assertIn('truncated',q['error']['message'])

    def test_code_bytes_must_match_metadata(self):
        events=self.base();events[0]=(1,0,0x1000,0xdeadbeef,0,0,0,1)
        self.query(self.artifact(events),ok=False)

    def test_stat_discovers_scope_without_external_capture_metadata(self):
        q=self.query(self.artifact(self.base()),'stat',[])
        self.assertEqual(q['data'][0]['profile'],2)
        self.assertEqual(q['meta']['data_base'],'0x2000')
        self.assertEqual(q['meta']['code_size'],256)

    def boundary_events(self):
        name=b'external.so';a,b,c=struct.unpack('<3Q',name.ljust(24,b'\0'))
        events=[(13,0,0,1,0,0,0,0),(10,0,0x3000,0x100,len(name),a,b,c),
                (1,0,0x1000,0x91000400,0,0,0,0)]
        events.extend((5,0,0x1000,i,8 if i<33 else 16,1,0,1) for i in range(65))
        events.extend([(11,0,0x1000,0x3010,1,0x1004,0,1),(3,0,0x1000,0,0,0,0,6),
                       (1,1,0x1004,0x91000400,0,0,0,0)])
        events.extend((5,1,0x1004,i,8 if i<33 else 16,9 if i==0 else 1,0,1) for i in range(65))
        events.extend([(12,1,0x1004,0,0,0,0,1),(11,1,0x1004,0x5000,3,0,0,1),
                       (4,2,0,0,1,0,0,2)])
        return events

    def test_scope_boundaries_reentry_and_open_terminal_return(self):
        path=self.artifact(self.boundary_events())
        q=self.query(path,'boundaries',['--reg','x0'])
        self.assertTrue(q['meta']['boundary_capture'])
        first,last=q['data']
        self.assertEqual(first['target']['module'],'external.so')
        self.assertEqual(first['target']['offset'],'0x10')
        self.assertEqual(first['exit_registers'],{'x0':'0x1'})
        self.assertEqual(first['reentry_registers'],{'x0':'0x9'})
        self.assertTrue(first['reentry_matches_expected_return'])
        self.assertEqual(last['status'],'no_reentry_observed')
        self.assertIsNone(last['reentry_registers'])
        self.assertIsNone(last['target']['module'])
        for args in [['--at-ev','0'],['--range','0x2000,1'],['--phase','post']]:
            self.assertEqual(self.query(path,'boundaries',args,ok=False)['error']['code'],'ARGUMENT')

    def test_scope_boundary_cannot_hide_missing_gap_or_reentry(self):
        for kind in (3,12,4):
            events=[e for e in self.boundary_events() if e[0]!=kind]
            self.query(self.artifact(events),'boundaries',[],ok=False)

    def test_old_stream_reports_boundary_capture_unavailable(self):
        q=self.query(self.artifact(self.base()),'boundaries',[])
        self.assertFalse(q['meta']['boundary_capture'])
        self.assertEqual(q['data'],[])

    def test_context_merges_windows_and_preserves_pre_post(self):
        path=self.artifact(self.base())
        q=self.query(path,'context',['--at-ev','2','--at-ev','0','--at-ev','0','--before','1','--after','1','--reg','x0'])
        self.assertEqual([r['ev'] for r in q['data']],[0,1,2])
        self.assertEqual(q['meta']['requested_events'],[0,2])
        self.assertEqual(q['data'][0]['pre'],{'x0':'0x1'})
        self.assertEqual(q['data'][0]['post'],{'x0':'0x2'})
        self.assertIsNone(q['data'][1]['post'])
        self.assertEqual(q['data'][2]['pre'],{'x0':'0x2'})
        page=self.query(path,'context',['--at-ev','0','--at-ev','2','--limit','1','--offset','1'])
        self.assertEqual([r['ev'] for r in page['data']],[1]);self.assertTrue(page['meta']['truncated'])
        self.assertIn('--offset 2',page['meta']['next'])

    def test_context_reads_gaps_and_unknown_values(self):
        events=self.base();events.insert(2,(7,0,0x1000,0x2000,8,0,0,0))
        events.insert(6,(3,1,0x1004,0,0,0,0,1));events[-1]=(4,3,0,0,1,1,2,2)
        q=self.query(self.artifact(events),'context',['--at-ev','0','--at-ev','1','--at-ev','2','--before','0','--after','0'])
        self.assertIsNone(q['data'][0]['memory'][0]['val']);self.assertFalse(q['data'][0]['memory'][0]['known'])
        self.assertEqual(q['data'][1]['gap_reasons'],['unsupported'])
        self.assertIsNone(q['data'][2]['pre']['x0'])

    def test_context_auto_keeps_simd_high_bits_and_alias_views(self):
        events=self.base();events.insert(2,(5,0,0x1000,33,16,1,2,1));events.insert(4,(6,0,0x1000,33,16,1,3,1))
        path=self.artifact(events)
        q=self.query(path,'context',['--at-ev','0','--before','0','--after','0'])
        self.assertEqual(q['data'][0]['pre']['v0'],'0x20000000000000001')
        self.assertEqual(q['data'][0]['post']['v0'],'0x30000000000000001')
        explicit=self.query(path,'context',['--at-ev','0','--reg','d0','--reg','w0','--reg','xzr'])
        self.assertEqual(explicit['data'][0]['pre'],{'d0':'0x1','w0':'0x1','xzr':'0x0'})

    def test_context_includes_boundary_and_validates_entire_stream(self):
        path=self.artifact(self.boundary_events())
        q=self.query(path,'context',['--at-ev','0','--after','1','--reg','x0'])
        self.assertEqual(q['data'][0]['scope_exit']['target']['module'],'external.so')
        self.assertEqual(q['data'][1]['scope_reentry'],{'exit_ev':0})
        truncated=self.artifact(self.boundary_events()[:-1])
        self.query(truncated,'context',['--at-ev','0','--before','0','--after','0','--limit','1'],ok=False)
        for args in [[],['--at-ev','2'],['--at-ev','0','--before','4097'],['--at-ev','0','--after','-1']]:
            self.query(path,'context',args,ok=False)

    def test_context_global_gap_keeps_unknown_state_and_constant_zero(self):
        events=self.base();events.insert(-1,(3,3,0,0,0,0,0,4));events[-1]=(4,3,0,0,1,0,2,2)
        q=self.query(self.artifact(events),'context',['--at-ev','0','--before','0','--after','0','--reg','x0','--reg','xzr'])
        self.assertTrue(q['meta']['unpositioned_gap'])
        self.assertEqual(q['data'][0]['pre'],{'x0':None,'xzr':'0x0'})
        self.assertEqual(q['data'][0]['post'],{'x0':None,'xzr':'0x0'})

if __name__=='__main__':unittest.main()
