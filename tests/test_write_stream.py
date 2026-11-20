"""Behavioral checks for byte provenance, scope gaps and incomplete artifacts."""
from pathlib import Path
import json,struct,subprocess,time,unittest
def compare_facts(expected_pcs,actual_pcs,expected_stores,actual_stores):
    result=dict(correct=0,wrong=0,unknown=0,extra=0)
    def check(want,got):
        result['unknown' if got is None else 'correct' if want==got else 'wrong']+=1
    for i,pc in enumerate(expected_pcs):check(pc,actual_pcs[i] if i<len(actual_pcs) else None)
    result['extra']+=max(0,len(actual_pcs)-len(expected_pcs))
    # Match by instruction sequence and ordinal, so a missing store cannot shift
    # all subsequent facts or disappear from the fixed expected denominator.
    def keyed(rows):
        counts={};out={}
        for row in rows:
            seq=row['seq'];n=counts.get(seq,0);counts[seq]=n+1;out[seq,n]=row
        return out
    want=keyed(expected_stores);got=keyed(actual_stores)
    for key,row in want.items():
        for field in ('pc','offset','size','value'):check(row[field],got.get(key,{}).get(field))
    result['extra']+=len(got.keys()-want.keys())
    return result

ROOT=Path(__file__).resolve().parents[1]
GT=ROOT/'cli/traceq'

class StreamChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.out=ROOT/'artifacts'/('query-checks-'+str(time.time_ns()));cls.out.mkdir(parents=True)
        cls.counter=0

    def artifact(self,events,raw_suffix=b'',*,code_base=0x1000):
        type(self).counter+=1
        path=self.out/(str(self.counter)+'.gtsw')
        data=b'GTSW001\0'+struct.pack('<7Q',code_base,0x100,0x2000,32,1,1,64)
        path.write_bytes(data+b''.join(struct.pack('<8Q',*e) for e in events)+raw_suffix)
        return path

    def query(self,path,*args,ok=True):
        r=subprocess.run([str(GT),'last-writers',str(path),'--range','0x2000,32','--limit','32','--json',*args],
                         capture_output=True,text=True,timeout=10)
        data=json.loads(r.stdout)
        self.assertEqual(r.returncode==0,ok,r.stdout+r.stderr)
        return data

    def base(self):
        return [(1,0,0x1000,0,0,0,0,0),(2,0,0x1000,0x2000,8,0x1122334455667788,0,1),
                (1,1,0x1004,0,0,0,0,0),(2,1,0x1004,0x2002,2,0xaabb,0,1),
                (1,2,0x1008,0,0,0,0,0),(2,2,0x1008,0x2002,2,0xaabb,0,1),
                (4,3,0,3,0,0,0,1)]

    def test_overlap_and_same_value_write_have_distinct_latest_writer(self):
        rows=self.query(self.artifact(self.base()))['data']
        self.assertEqual([rows[i]['writer_seq'] for i in range(8)],[0,0,2,2,0,0,0,0])
        self.assertEqual(rows[2]['value'],'0xbb');self.assertFalse(rows[8]['known'])
        self.assertIsNone(rows[8]['writer_seq']);self.assertIsNone(rows[8]['value'])

    def test_single_range_alignment_uses_instruction_pc(self):
        for start in (0x1004, 0x1005, 0x1104):
            with self.subTest(pc=hex(start)):
                events = [(kind, seq, pc + start - 0x1000 if pc else pc, *rest)
                          for kind, seq, pc, *rest in self.base()]
                result = self.query(self.artifact(events, code_base=0x1001), ok=start == 0x1004)
                if start == 0x1004:
                    self.assertEqual(result['data'][0]['pc'], '0x1004')
                    self.assertEqual(result['data'][0]['value'], '0x88')
                else:
                    self.assertEqual(result['error']['code'], 'FORMAT')

    def test_state_cutoff_is_explicit_for_default_historical_empty_and_paged_results(self):
        path=self.artifact(self.base())
        for at,options in [(2,[]),(0,['--at-seq','0']),(1,['--at-seq','1'])]:
            q=self.query(path,*options)
            self.assertEqual(q['meta']['as_of_ev'],at)
            self.assertEqual(q['meta']['state_position'],'after_recorded_accesses_at_event')
            page=self.query(path,*options,'--limit','2','--offset','1')
            self.assertEqual(page['meta']['as_of_ev'],at);self.assertEqual(page['data'],q['data'][1:3])
        self.assertEqual(set(self.query(path,'--at-seq','3',ok=False)),{'error'})
        empty=self.query(self.artifact([(4,0,0,0,0,0,0,1)]))
        self.assertIsNone(empty['meta']['as_of_ev']);self.assertFalse(any(r['known'] for r in empty['data']))
        self.assertEqual(set(self.query(self.artifact(self.base(),b'x'),'--at-seq','0',ok=False)),{'error'})

    def test_historical_query_selects_earlier_same_value_write(self):
        rows=self.query(self.artifact(self.base()),'--at-seq','1')['data']
        self.assertEqual(rows[2]['writer_seq'],1)

    def test_gap_invalidates_old_writers_then_new_store_recovers_one_byte(self):
        events=self.base()[:2]+[(1,1,0x1004,0,0,0,0,0),(3,1,0x1004,0,0,0,0,1),
            (1,2,0x1008,0,0,0,0,0),(2,2,0x1008,0x2003,1,0xff,0,1),(4,3,0,2,1,0,0,1)]
        q=self.query(self.artifact(events))
        self.assertEqual([r['known'] for r in q['data']],[i==3 for i in range(32)])
        self.assertEqual(q['meta']['capture_gaps'],1)

    def test_exclusive_gap_without_dynamic_position_invalidates_past_query(self):
        events=self.base()[:-1]+[(3,3,0,0,0,0,0,4),(4,3,0,3,1,0,0,1)]
        q=self.query(self.artifact(events),'--at-seq','0')
        self.assertFalse(any(r['known'] for r in q['data']))
        self.assertEqual(q['meta']['selected_gaps'],1)

    def test_gap_data_fields_are_checked_after_historical_and_empty_selection(self):
        for global_gap in (False,True):
            events=self.base()[:-1]
            events.append((3,3 if global_gap else 2,0 if global_gap else 0x1008,0,0,0,0,4 if global_gap else 1))
            gap=len(events)-1
            events.append((4,3,0,3,1,0,0,1))
            valid=self.query(self.artifact(events),'--at-seq','0')
            self.assertEqual(valid['data'][0]['known'],not global_gap)
            for field in range(3,7):
                damaged=list(events);record=list(damaged[gap]);record[field]=1;damaged[gap]=tuple(record)
                path=self.artifact(damaged)
                for options in ([],['--at-seq','0','--limit','1'],['--at-seq','0','--offset','32']):
                    with self.subTest(global_gap=global_gap,field=field,options=options):
                        result=self.query(path,*options,ok=False)
                        self.assertEqual(result['error']['code'],'FORMAT')
                        self.assertEqual(set(result),{'error'})

    def test_vector_high_half_survives_query(self):
        events=[(1,0,0x1000,0,0,0,0,0),(2,0,0x1000,0x2000,16,0x11,0x8877665544332211,1),(4,1,0,1,0,0,0,1)]
        q=self.query(self.artifact(events))
        self.assertEqual([int(r['value'],0) for r in q['data'][8:16]],[0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88])

    def test_pagination_keeps_range_and_unknowns(self):
        q=self.query(self.artifact(self.base()),'--limit','3','--offset','6')
        self.assertEqual(len(q['data']),3);self.assertTrue(q['meta']['truncated'])
        self.assertIn('--offset 9',q['meta']['next']);self.assertFalse(q['data'][2]['known'])

    def test_missing_footer_never_returns_plausible_partial_answer(self):
        q=self.query(self.artifact(self.base()[:-1]),ok=False)
        self.assertEqual(q['error']['code'],'TRUNCATED');self.assertNotIn('data',q)

    def test_truncated_frame_is_rejected(self):
        q=self.query(self.artifact(self.base()[:-1],b'\x04'*9),ok=False)
        self.assertEqual(q['error']['code'],'TRUNCATED')

    def test_footer_counter_mismatch_is_rejected(self):
        events=self.base();events[-1]=(4,3,0,4,0,0,0,1)
        self.assertEqual(self.query(self.artifact(events),ok=False)['error']['code'],'FORMAT')

    def test_trailing_bytes_are_rejected(self):
        self.assertEqual(self.query(self.artifact(self.base(),b'x'),ok=False)['error']['code'],'FORMAT')

    def test_out_of_scope_store_is_rejected(self):
        events=self.base();events[1]=(2,0,0x1000,0x201f,8,1,0,1)
        self.assertEqual(self.query(self.artifact(events),ok=False)['error']['code'],'FORMAT')

    def test_invalid_cli_is_one_json_error(self):
        q=self.query(self.artifact(self.base()),'--limit','-1',ok=False)
        self.assertEqual(q['error']['code'],'ARGUMENT')

    def test_missing_and_wrong_values_keep_evaluation_denominator(self):
        want=[dict(seq=0,pc=0,offset=0,size=8,value=123)]
        good=compare_facts([0],[0],want,want)
        missing=compare_facts([0],[0],want,[])
        bad=compare_facts([0],[0],want,[dict(want[0],value=124)])
        self.assertEqual(good['correct'],5)
        self.assertEqual(missing['unknown'],4)
        self.assertEqual(missing['correct']+missing['unknown'],5)
        self.assertEqual(bad['wrong'],1)

if __name__=='__main__':unittest.main()
