"""Known numeric observations -> event/address -> context, across both transports."""
import json
from pathlib import Path
import shlex
import struct
import subprocess
import time
import unittest

ROOT=Path(__file__).resolve().parents[1]
CLI=ROOT/'cli/traceq'
WIDE=(0x22<<64)|0x11
MASK=(1<<64)-1

def frame(kind,ev,addr=0,size=0,low=0,high=0,detail=1):
    return (kind,ev,0x1000+4*ev,addr,size,low,high,detail)

class FindValueChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.out=ROOT/'artifacts'/f'find-value-unit-{time.time_ns()}'
        cls.out.mkdir(parents=True);cls.counter=0

    def events(self,global_gap=False):
        e=[frame(1,0,0x91000400),frame(5,0,0,8),frame(5,0,1,8,0x100000001),
           frame(5,0,64,16,0x11,0x22),frame(6,0,0,8,0x5a),
           frame(7,0,0x2000,1,detail=0),frame(2,0,0x2001,1),frame(2,0,0x2008,16,0x11,0x22),frame(9,0),
           frame(1,1,0x91000400),frame(7,1,0x2001,1,0x5a),frame(2,1,0x2018,8,0x5a),frame(9,1),
           frame(1,2,0x91000400,detail=0),frame(3,2),
           frame(1,3,0x91000400),frame(7,3,0x2020,8,0x5a,detail=0),frame(6,3,2,8,0x5a),
           frame(2,3,0x2020,1,0x5a),frame(9,3)]
        if global_gap:e.append((3,4,0,0,0,0,0,4))
        e.append((4,4,0,4,2 if global_gap else 1,3,3,2))
        return e

    def artifact(self,events=None,chunked=False):
        type(self).counter+=1
        path=self.out/f"value's sample {self.counter}.gtsw"
        events=self.events() if events is None else events
        sites=[]
        for pc in sorted({e[2] for e in events if e[0]==1}):
            text=b'add x0, x0, #1';a,b,c=struct.unpack('<3Q',text.ljust(24,b'\0'))
            sites.append((8,0,pc,0x91000400,len(text),a,b,c))
        records=sites+events
        header=(b'GTSC001\0' if chunked else b'GTSW001\0')+struct.pack('<7Q',0x1000,0x100,0x2000,0x100,1,2,64)
        if not chunked:body=b''.join(struct.pack('<8Q',*e) for e in records)
        else:
            body=b''
            # Tiny independent blocks force state/match propagation over boundaries.
            for first in range(0,len(records),3):
                block=records[first:first+3];encoded=b'';prev_seq=prev_pc=0
                def zz(n):n&=MASK;return ((n<<1) ^ (MASK if n>>63 else 0))&MASK
                for e in block:
                    fields=[zz(e[1]-prev_seq),zz(e[2]-prev_pc),*e[3:]];prev_seq,prev_pc=e[1:3]
                    widths=[(v.bit_length()+7)//8 for v in fields]
                    encoded+=bytes([e[0]])+struct.pack('<I',sum(n<<(4*i) for i,n in enumerate(widths)))
                    encoded+=b''.join(v.to_bytes(n,'little') for v,n in zip(fields,widths))
                body+=b'GTBL001\0'+struct.pack('<II',len(block),len(encoded))+encoded
        path.write_bytes(header+body);return path

    def query(self,path,*args,ok=True,positional=False):
        argv=[str(CLI),'find-value',*([str(args[0]),str(path),*map(str,args[1:])] if positional else [str(path),*map(str,args)]),'--json']
        r=subprocess.run(argv,capture_output=True,text=True,timeout=10);data=json.loads(r.stdout)
        self.assertEqual(r.returncode==0,ok,(argv,r.stdout,r.stderr));return data

    def test_zero_and_unknown_are_distinct(self):
        for chunked in (False,True):
            path=self.artifact(chunked=chunked);q=self.query(path,'--value',0)
            self.assertEqual([(r['ev'],r['kind']) for r in q['data']],[(0,'reg'),(0,'mem')])
            self.assertEqual(q['meta']['skipped_unknown_reads'],2)
            self.assertEqual(self.query(path,'--value',0,'--read')['data'],[])
            writes=self.query(path,'--value',0,'--write')['data']
            self.assertEqual([(r['addr'],r['size']) for r in writes],[('0x2001',1)])
            current=json.loads(subprocess.check_output([str(CLI),'last-writers',str(path),'--range','0x2001,1','--json']))['data'][0]
            self.assertFalse(current['known'])
            self.assertEqual(current['last_observed_write']['value'],'0x0')

    def test_register_phases_are_observations_not_accesses(self):
        path=self.artifact();q=self.query(path,'0x5a',positional=True)
        regs=[r for r in q['data'] if r['kind']=='reg']
        self.assertEqual([(r['ev'],r['reg'],r['phase']) for r in regs],[(0,'x0','post'),(3,'x2','post')])
        self.assertTrue(all('rw' not in r and 'addr' not in r for r in regs))
        self.assertEqual(q['meta']['total'],5)
        self.assertEqual(len(self.query(path,'--value','0x5a','--read')['data']),1)
        self.assertEqual(len(self.query(path,'--value','0x5a','--write')['data']),2)
        filtered=self.query(path,'--value','0x5a','--from',1,'--to',1)
        self.assertEqual([r['rw'] for r in filtered['data']],['r','w'])

    def test_numeric_memory_search_limits_memory_rows_and_keeps_continuation(self):
        for chunked in (False, True):
            path = self.artifact(chunked=chunked)
            args = ['--value', '0x5a']
            all_hits = self.query(path, *args)
            wanted = [row for row in all_hits['data'] if row['kind'] == 'mem']
            full = self.query(path, *args, '--memory')
            self.assertEqual(full['data'], wanted)
            self.assertEqual({row['rw'] for row in wanted}, {'r', 'w'})
            self.assertEqual(full['meta']['skipped_unknown_reads'], all_hits['meta']['skipped_unknown_reads'])
            self.assertEqual(full['meta']['scans'], 1)

            page = self.query(path, *args, '--memory', '--limit', 2)
            self.assertEqual(page['data'], wanted[:2])
            self.assertEqual(page['meta']['total'], len(wanted))
            argv = shlex.split(page['meta']['next'])
            self.assertIn('--memory', argv)
            following = json.loads(subprocess.check_output([str(CLI), *argv[1:]], timeout=10))
            self.assertEqual(following['data'], wanted[2:])
            tail = self.query(path, *args, '--memory', '--last', 1)
            self.assertEqual(tail['data'], wanted[-1:])
            self.assertEqual(self.query(path, '--bytes', '5a', '--memory', ok=False)['error']['code'], 'ARGUMENT')

    def test_full_width_and_slot_64(self):
        for chunked in (False,True):
            path=self.artifact(chunked=chunked);q=self.query(path,'--value',hex(WIDE))
            self.assertEqual([(r['kind'],r['size']) for r in q['data']],[('reg',16),('mem',16)])
            self.assertEqual(q['data'][0]['reg'],'v31');self.assertEqual(q['data'][0]['phase'],'pre')
            self.assertTrue(all(r['val']==hex(WIDE) for r in q['data']))
            for partial in [0x11,0x22,1]:self.assertEqual(self.query(path,'--value',hex(partial))['data'],[])
            self.assertEqual(self.query(path,'--value','0x100000001')['data'][0]['reg'],'x1')
            self.assertEqual(self.query(path,'--value',str(WIDE))['data'],q['data'])

    def test_batch_pagination_and_tail_per_value(self):
        path=self.artifact(chunked=True);values=['--value','0x5a','--value','0','--value','0x5a']
        full=self.query(path,*values,'--limit',20);q=self.query(path,*values,'--limit',1)
        self.assertEqual(q['meta']['total'],7);self.assertEqual(len(q['meta']['values']),2)
        self.assertEqual([v['total'] for v in q['meta']['values']],[5,2]);self.assertEqual(q['meta']['shown'],2)
        pages=[]
        while True:
            pages.extend(q['data'])
            if not q['meta']['truncated']:break
            argv=shlex.split(q['meta']['next']);argv[0]=str(CLI)
            q=json.loads(subprocess.check_output(argv,text=True))
        def identity(row):return json.dumps(row,sort_keys=True)
        self.assertEqual(sorted(map(identity,pages)),sorted(map(identity,full['data'])))
        tail=self.query(path,*values,'--last',1)
        self.assertEqual([(r['ev'],r['val']) for r in tail['data']],[(0,'0x0'),(3,'0x5a')])
        self.assertTrue(tail['meta']['truncated']);self.assertEqual(tail['meta']['next'],'')
        self.assertEqual(self.query(path,*values,'--offset',100)['data'],[])

    def test_context_round_trip(self):
        path=self.artifact(chunked=True);q=self.query(path,'--value','0x5a','--write','--context',1)
        argv=shlex.split(q['meta']['context_command']);argv[0]=str(CLI)
        ctx=json.loads(subprocess.check_output(argv,text=True))
        self.assertEqual(q['context']['ev'],1);self.assertEqual(q['context']['rows'],ctx['data'])
        focus=next(r for r in ctx['data'] if r['focus']);hit=q['data'][0]
        evidence=focus['memory'][hit['access_index']]
        self.assertEqual((evidence['addr'],evidence['val'],evidence['size'],evidence['rw']),(hit['addr'],hit['val'],hit['size'],hit['rw']))
        self.assertEqual(q['meta']['scans'],2)
        empty=self.query(path,'--value','0xffff','--context',1)
        self.assertNotIn('context',empty);self.assertEqual(empty['meta']['context_command'],'')

    def test_register_hit_context_includes_even_unused_simd_slot(self):
        path=self.artifact();q=self.query(path,'--value',hex(WIDE),'--context',1)
        argv=shlex.split(q['meta']['context_command']);argv[0]=str(CLI)
        ctx=json.loads(subprocess.check_output(argv,text=True))
        self.assertEqual(q['context']['rows'],ctx['data'])
        self.assertEqual(ctx['data'][0]['pre']['v31'],hex(WIDE))
        self.assertEqual(ctx['meta']['register_selection'],'explicit')

    def test_global_gap_suppresses_registers_without_corrupting_pages(self):
        for chunked in (False,True):
            path=self.artifact(self.events(global_gap=True),chunked)
            full=self.query(path,'--value','0x5a')
            self.assertEqual(full['meta']['total'],3);self.assertTrue(full['meta']['register_matches_suppressed'])
            self.assertTrue(all(r['kind']=='mem' for r in full['data']))
            page=self.query(path,'--value','0x5a','--limit',1,'--offset',1)
            self.assertEqual(page['data'],full['data'][1:2])
            self.assertEqual(self.query(path,'--value','0x5a','--last',1)['data'],full['data'][-1:])
            q=self.query(path,'--value','0x5a','--context',1)
            for g in q['context']['rows']:
                self.assertTrue(all(v is None for v in g['pre'].values()))
            self.assertEqual(q['context']['rows'][1]['memory'][0]['val'],'0x5a')

    def test_128_bit_maximum_and_invalid_arguments(self):
        events=self.events();events[2]=frame(5,0,1,8,MASK) # GPR all bits, no narrowing.
        events[3]=frame(5,0,64,16,MASK,MASK)
        path=self.artifact(events)
        self.assertEqual(self.query(path,'--value',hex((1<<128)-1))['data'][0]['reg'],'v31')
        for args in [[],['--value'],['--value','-1'],['--value','0x'],['--value',str(1<<128)],
                     ['--value','1','--read','--write'],['--value','1','--last','0'],
                     ['--value','1','--last','1','--limit','1'],['--value','1','--limit','0'],
                     ['--value','1','--limit','4097'],['--value','1','--context','0'],
                     ['--value','1','--context','201'],
                     [part for value in range(65) for part in ('--value',str(value))],
                     ['--value','1','--value','2','--limit','4096'],
                     ['--value','1','--from','2','--to','1'],['--value','1','--reg','x0']]:
            with self.subTest(args=args):self.assertEqual(self.query(path,*args,ok=False)['error']['code'],'ARGUMENT')

    def test_full_validation_after_hits_and_window(self):
        for chunked in (False,True):
            for damage in ['truncate','trailing']:
                path=self.artifact(chunked=chunked);data=path.read_bytes();path.write_bytes(data[:-1] if damage=='truncate' else data+b'x')
                for args in [['--limit',1],['--last',1],['--to',0,'--context',1],['--memory','--offset',99]]:
                    q=self.query(path,'--value','0x5a',*args,ok=False);self.assertEqual(set(q),{'error'})
                    self.assertEqual(q['error']['code'],'TRACE_ERROR')

    def test_fixed_and_chunked_match_and_text_output(self):
        a,b=self.artifact(),self.artifact(chunked=True)
        left=self.query(a,'--value','0x5a','--value',hex(WIDE),'--context',2)
        right=self.query(b,'--value','0x5a','--value',hex(WIDE),'--context',2)
        for obj in [left,right]:obj['meta'].pop('context_command')
        self.assertEqual(left,right)
        text=subprocess.check_output([str(CLI),'find-value','0x5a',str(a),'--context','1'],text=True)
        self.assertIn('"phase":"post"',text);self.assertIn('context:',text)


    def test_wide_observation_masks_reset_between_instructions(self):
        other=(0xabcdef01<<64)|0x9988776655443322
        events=self.events()
        at=next(i for i,e in enumerate(events) if e[0]==7 and e[1]==1)
        events[at:at]=[frame(5,1,64,16,other&MASK,other>>64)]
        at=next(i for i,e in enumerate(events) if e[0]==9 and e[1]==1)
        events[at:at]=[frame(6,1,64,16,WIDE&MASK,WIDE>>64)]
        for chunked in (False,True):
            path=self.artifact(events,chunked)
            q=self.query(path,'--value',hex(WIDE),'--value',hex(other),'--limit',20)
            regs=[(r['ev'],r['phase'],r['val']) for r in q['data'] if r['kind']=='reg' and r['reg']=='v31']
            self.assertEqual(regs,[(0,'pre',hex(WIDE)),(1,'pre',hex(other)),(1,'post',hex(WIDE))])
            tail=self.query(path,'--value',hex(WIDE),'--last',1,'--context',1)
            self.assertEqual((tail['data'][0]['ev'],tail['data'][0]['phase']),(1,'post'))
            focus=next(r for r in tail['context']['rows'] if r['focus'])
            self.assertEqual((focus['pre']['v31'],focus['post']['v31']),(hex(other),hex(WIDE)))

    def test_gap_invalidates_prior_post_observation_and_context_inherits(self):
        events=[frame(1,0,0x91000400),frame(5,0,0,8,1),frame(6,0,0,8,0x5a),
                frame(3,0),frame(6,0,1,8,0x5a),frame(9,0),
                frame(1,1,0x91000400),frame(9,1),(4,2,0,0,1,0,2,2)]
        for chunked in (False,True):
            path=self.artifact(events,chunked)
            q=self.query(path,'--value','0x5a','--context',1)
            self.assertEqual([(r['ev'],r['reg'],r['phase']) for r in q['data']],[(0,'x1','post')])
            self.assertEqual(self.query(path,'--value','0')['data'],[])
            self.assertEqual([(r['ev'],r['reg'],r['phase']) for r in self.query(path,'--value',1)['data']],[(0,'x0','pre')])
            inherited=next(r for r in q['context']['rows'] if r['ev']==1)
            self.assertEqual(inherited['pre']['x1'],'0x5a')
            self.assertEqual(inherited['post']['x1'],'0x5a')


    def byte_artifact(self,groups,chunked=False,global_gap=False):
        events=[]
        for ev,accesses in enumerate(groups):
            events += [frame(1,ev,0x91000400),frame(5,ev,0,8,0x12345678)]
            for access in accesses:
                if access=='gap':events.append(frame(3,ev));continue
                rw,addr,data,known=access
                bits=int.from_bytes(data,'little');events.append(frame(7 if rw=='r' else 2,ev,addr,len(data),bits&MASK,bits>>64,int(known)))
            events.append(frame(9,ev))
        if global_gap:events.append((3,len(groups),0,0,0,0,0,4))
        events.append((4,len(groups),0,sum(e[0]==2 for e in events),sum(e[0]==3 for e in events),sum(e[0]==7 for e in events),len(groups),2))
        return self.artifact(events,chunked)

    def test_byte_offsets_vector_spans_and_context(self):
        data=bytes(range(64));accesses=[('r',0x2000+i,data[i:i+16],True) for i in range(0,64,16)]
        for chunked in (False,True):
            path=self.byte_artifact([accesses],chunked)
            for begin,end in [(0,8),(0,16),(0,64),(12,40),(15,17)]:
                q=self.query(path,'--bytes',data[begin:end].hex(),'--read','--context',1)
                self.assertEqual(len(q['data']),1);row=q['data'][0]
                self.assertEqual((row['ev'],row['addr'],row['size'],row['access_index'],row['byte_offset'],row['last_access_index']),(0,hex(0x2000+begin),end-begin,begin//16,begin%16,(end-1)//16))
                self.assertEqual(row['access_size'],16);self.assertNotIn('val',row);self.assertEqual(row['bytes'],data[begin:end].hex())
                self.assertEqual(q['meta']['matching'],'recorded_memory_byte_subsequence');self.assertNotIn('values',q['meta'])
                argv=shlex.split(q['meta']['context_command']);argv[0]=str(CLI);ctx=json.loads(subprocess.check_output(argv,text=True))
                self.assertEqual(q['context']['rows'],ctx['data']);self.assertEqual(q['meta']['scans'],2)
                memory=ctx['data'][0]['memory'][row['access_index']:row['last_access_index']+1]
                observed=b''.join(int(a['val'],0).to_bytes(a['size'],'little') for a in memory)
                self.assertEqual(observed[row['byte_offset']:row['byte_offset']+row['size']],data[begin:end])
            self.assertEqual(self.query(path,'--value',hex(int.from_bytes(data[:8],'little')),'--read')['data'],[])
            self.assertEqual(len(self.query(path,'--value',hex(int.from_bytes(data[:16],'little')),'--read')['data']),1)
            self.assertEqual(self.query(path,'--bytes',data[:8][::-1].hex(),'--read')['data'],[])

    def test_byte_spans_stop_at_unknown_gaps_directions_and_events(self):
        a=('r',0x2000,b'abcd',True);b=('r',0x2004,b'efgh',True)
        cases=[[[a,('r',0x2004,b'\0'*4,False),('r',0x2008,b'efgh',True)]],[[a,('r',0x2010,b'efgh',True)]],[[a],[b]],[[a,('w',0x2004,b'efgh',True)]],[[a,'gap',b]]]
        for chunked in (False,True):
            for groups in cases:
                path=self.byte_artifact(groups,chunked)
                self.assertEqual(self.query(path,'--bytes',b'abcdefgh'.hex())['data'],[])
                self.assertEqual(len(self.query(path,'--bytes',b'abcd'.hex(),'--read')['data']),1)
                for w in self.query(path,'--bytes','00000000')['data']:self.fail(('unknown bytes matched',w))
        path=self.byte_artifact([cases[0][0]])
        self.assertEqual(self.query(path,'--bytes','00000000','--read')['meta']['skipped_unknown_reads'],1)

    def test_byte_pattern_batch_overlap_pagination_and_tail(self):
        for chunked in (False,True):
            path=self.byte_artifact([[('w',0x2000,b'\xaa'*4,True)]],chunked)
            args=['--bytes','aaaa','--bytes','aa','--bytes','0xAAaa']
            full=self.query(path,*args,'--limit',20);self.assertEqual(full['meta']['total'],7)
            self.assertEqual([p['total'] for p in full['meta']['patterns']],[3,4]);self.assertEqual(len(full['meta']['patterns']),2)
            q=self.query(path,*args,'--limit',1);hits=[]
            while True:
                hits+=q['data']
                if not q['meta']['truncated']:break
                argv=shlex.split(q['meta']['next']);argv[0]=str(CLI);q=json.loads(subprocess.check_output(argv,text=True))
            identity=lambda r:json.dumps(r,sort_keys=True)
            self.assertEqual(sorted(map(identity,hits)),sorted(map(identity,full['data'])))
            tail=self.query(path,*args,'--last',1);self.assertEqual([(r['addr'],r['bytes']) for r in tail['data']],[('0x2002','aaaa'),('0x2003','aa')]);self.assertEqual(tail['meta']['next'],'')
            self.assertEqual(self.query(path,*args,'--read')['data'],[])
            self.assertEqual(self.query(path,*args,'--from',1)['data'],[])

    def test_byte_zero_known_is_distinct_from_unknown_and_registers(self):
        for chunked in (False,True):
            path=self.byte_artifact([[('r',0x2000,bytes(8),False),('w',0x2010,bytes(1),True)]],chunked,True)
            q=self.query(path,'--bytes','00');self.assertEqual([(r['rw'],r['addr']) for r in q['data']],[('w','0x2010')]);self.assertTrue(q['meta']['unpositioned_gap']);self.assertEqual(q['meta']['skipped_unknown_reads'],1)
            self.assertEqual(self.query(path,'--bytes','78563412')['data'],[])
            self.assertEqual(self.query(path,'--bytes','0000')['data'],[])
            self.assertEqual(self.query(path,'--bytes','00','--read')['data'],[])
            context=self.query(path,'--bytes','00','--context',1)['context']['rows'];self.assertTrue(all(v is None for v in context[0]['pre'].values()))

    def test_byte_pattern_argument_errors(self):
        path=self.byte_artifact([[('r',0x2000,b'abcd',True)]])
        bad=[['--bytes'],['--bytes',''],['--bytes','x0'],['--bytes','0x'],['--bytes','0'],['--bytes','abc'],['--bytes','0g'],['--bytes','aa'*65],['--bytes','aa','--value',1],['--bytes','aa','--read','--write'],['--bytes','aa','--last',1,'--limit',1],['--bytes','aa','--context',0],['--bytes','aa','--offset','-1'],['--bytes','aa','--from',2,'--to',1],[part for i in range(65) for part in ['--bytes',bytes([i]).hex()]]]
        for args in bad:
            with self.subTest(args=args):self.assertEqual(self.query(path,*args,ok=False)['error']['code'],'ARGUMENT')
        args=[part for i in range(64) for part in ['--bytes',bytes([i]).hex()]]
        self.assertEqual(len(self.query(path,*args,'--limit',64)['meta']['patterns']),64)
        self.assertEqual(self.query(path,*args,'--limit',65,ok=False)['error']['code'],'ARGUMENT')

    def test_byte_full_validation_and_transport_text_equivalence(self):
        groups=[[('r',0x2000,b'abcdefgh',True),('r',0x2008,b'ijklmnop',True)]]
        left=self.byte_artifact(groups);right=self.byte_artifact(groups,True)
        args=['--bytes',b'defghijkl'.hex(),'--context',1];a=self.query(left,*args);b=self.query(right,*args)
        for q in (a,b):q['meta'].pop('context_command')
        self.assertEqual(a,b)
        text=subprocess.check_output([str(CLI),'find-value',str(left),*map(str,args)],text=True);self.assertIn('"byte_offset":3',text);self.assertIn('context:',text)
        for chunked in (False,True):
            for damage in ['truncate','trailing']:
                path=self.byte_artifact(groups,chunked);data=path.read_bytes();path.write_bytes(data[:-1] if damage=='truncate' else data+b'x')
                for filters in [['--limit',1],['--last',1],['--to',0,'--context',1]]:
                    q=self.query(path,'--bytes',b'abcdefgh'.hex(),*filters,ok=False);self.assertEqual(set(q),{'error'});self.assertEqual(q['error']['code'],'TRACE_ERROR')

    def test_byte_maximum_span_coordinates(self):
        # The stream contract permits at most4 accesses per instruction.
        for chunked in (False,True):
            data=bytes(range(64));accesses=[('r',0x2000+i,data[i:i+16],True) for i in range(0,64,16)]
            path=self.byte_artifact([accesses],chunked)
            for begin in [0,15]:
                row=self.query(path,'--bytes',data[begin:].hex(),'--read')['data'][0]
                self.assertEqual((row['addr'],row['size'],row['byte_offset'],row['access_size'],row['access_index'],row['last_access_index']),(hex(0x2000+begin),64-begin,begin,16,0,3))
            invalid=self.byte_artifact([accesses+[('r',0x2040,b'x',True)]],chunked)
            self.assertEqual(self.query(invalid,'--bytes','00',ok=False)['error']['code'],'TRACE_ERROR')

    def test_byte_runs_span_events_ring_capacity_and_endpoint_context(self):
        data=bytes(range(96))
        groups=[[('w',0x2000+i,data[i:i+16],True),('r',0x2080,b'X',True)] for i in range(0,96,16)]
        for chunked in (False,True):
            path=self.byte_artifact(groups,chunked)
            pattern=data[15:79].hex()
            self.assertEqual(self.query(path,'--bytes',pattern,'--write')['data'],[])
            q=self.query(path,'--bytes',pattern,'--write','--across-events','--context',1)
            self.assertEqual(q['meta']['total'],1);row=q['data'][0]
            self.assertEqual((row['ev'],row['last_ev'],row['addr'],row['size']),(0,4,'0x200f',64))
            self.assertEqual((row['access_index'],row['last_access_index'],row['byte_offset'],row['access_size']),(0,0,15,16))
            self.assertEqual((row['pc'],row['last_pc']),('0x1000','0x1010'))
            self.assertEqual([r['ev'] for r in q['context']['rows']],[0,1,3,4,5])
            self.assertEqual([r['ev'] for r in q['context']['rows'] if r['focus']],[0,4])
            argv=shlex.split(q['meta']['context_command']);argv[0]=str(CLI)
            self.assertEqual(q['context']['rows'],json.loads(subprocess.check_output(argv))['data'])
            self.assertEqual((q['context']['last_ev'],q['meta']['scans']),(4,2))
            self.assertFalse(q['meta']['cross_event_matches_suppressed'])
            self.assertEqual(self.query(path,'--bytes',pattern,'--write','--across-events','--from',1)['data'],[])
            self.assertEqual(self.query(path,'--bytes',pattern,'--write','--across-events','--to',3)['data'],[])

    def test_byte_runs_break_on_uncertainty_overlap_and_selected_discontinuity(self):
        a=('w',0x2000,b'abcd',True);b=('w',0x2004,b'efgh',True)
        for chunked in (False,True):
            good=[[a],[('r',0x2080,b'X',True)],[b]]
            path=self.byte_artifact(good,chunked)
            self.assertEqual(len(self.query(path,'--bytes',b'abcdefgh'.hex(),'--write','--across-events')['data']),1)
            self.assertEqual(self.query(path,'--bytes',b'abcdefgh'.hex(),'--across-events')['data'],[])
            cases=[[[a],['gap'],[b]],[[a],[('r',0x2003,b'X',True)],[b]],
                   [[a],[('r',0x2080,b'X',False)],[b]],[[a],[('w',0x2080,b'X',True)],[b]],
                   [[a],[('w',0x2003,b'efgh',True)]],
                   [[a],[('w',0x2005,b'efgh',True)]],[[a,'gap',b]]]
            for groups in cases:
                path=self.byte_artifact(groups,chunked)
                with self.subTest(groups=groups):
                    self.assertEqual(self.query(path,'--bytes',b'abcdefgh'.hex(),'--write','--across-events')['data'],[])
            # Read selection uses the same boundaries, with stores as the other direction.
            groups=[[('r',0x2000,b'abcd',True)],[('w',0x2080,b'X',True)],[('r',0x2004,b'efgh',True)]]
            path=self.byte_artifact(groups,chunked)
            self.assertEqual(len(self.query(path,'--bytes',b'abcdefgh'.hex(),'--read','--across-events')['data']),1)
            groups[1]=[('w',0x2000,b'X',True)];path=self.byte_artifact(groups,chunked)
            self.assertEqual(self.query(path,'--bytes',b'abcdefgh'.hex(),'--read','--across-events')['data'],[])

    def test_byte_runs_batch_completion_order_pages_and_last(self):
        groups=[[('w',0x2000+i,b'a',True)] for i in range(6)]
        for chunked in (False,True):
            path=self.byte_artifact(groups,chunked)
            args=['--bytes','6161','--bytes','61','--bytes','0x6161','--write','--across-events']
            full=self.query(path,*args,'--limit',20)
            self.assertEqual([p['total'] for p in full['meta']['patterns']],[5,6])
            self.assertEqual([(r['ev'],r['last_ev'],r['bytes']) for r in full['data'][:3]],[(0,0,'61'),(0,1,'6161'),(1,1,'61')])
            page=self.query(path,*args,'--limit',1);rows=[]
            while True:
                rows+=page['data']
                if not page['meta']['truncated']:break
                self.assertIn('--across-events',page['meta']['next'])
                argv=shlex.split(page['meta']['next']);argv[0]=str(CLI);page=json.loads(subprocess.check_output(argv))
            identity=lambda r:json.dumps(r,sort_keys=True)
            self.assertEqual(sorted(map(identity,rows)),sorted(map(identity,full['data'])))
            tail=self.query(path,*args,'--last',1)
            self.assertEqual([(r['ev'],r['last_ev']) for r in tail['data']],[(4,5),(5,5)])
            self.assertEqual(self.query(path,*args,'--offset',999)['data'],[])

    def test_byte_runs_unpositioned_gap_keeps_independent_local_pages(self):
        groups=[[('w',0x2000,b'a',True)],[('w',0x2001,b'b',True)],
                [('w',0x2002,b'abab',True)],
                [('w',0x2006,b'a',True),('r',0x2080,b'X',True),('w',0x2007,b'b',True)],
                [('w',0x2020,b'ab',True)]]
        for chunked in (False,True):
            path=self.byte_artifact(groups,chunked,True)
            args=['--bytes','6162','--write','--across-events']
            full=self.query(path,*args)
            self.assertEqual([(r['ev'],r['last_ev'],r['addr']) for r in full['data']],[(2,2,'0x2002'),(2,2,'0x2004'),(4,4,'0x2020')])
            self.assertTrue(full['meta']['cross_event_matches_suppressed'])
            self.assertEqual(self.query(path,*args,'--limit',1,'--offset',2)['data'],full['data'][2:])
            self.assertEqual(self.query(path,*args,'--last',1)['data'],full['data'][-1:])
            self.assertEqual(full['meta']['total'],3)

    def test_byte_runs_full_validation_empty_pages_and_invalid_modes(self):
        for chunked in (False,True):
            groups=[[('w',0x2000,b'a',True)],[('w',0x2001,b'b',True)]]
            path=self.byte_artifact(groups,chunked)
            self.assertEqual(self.query(path,'--value',1,'--across-events',ok=False)['error']['code'],'ARGUMENT')
            for damage in ('truncate','trailing','end_count'):
                path=self.byte_artifact(groups,chunked);data=path.read_bytes()
                if damage=='end_count':
                    # Independently rebuild with a wrong END write count; works for both transports.
                    ev=[frame(1,0,0x91000400),frame(2,0,0x2000,1,0x61),frame(9,0),(4,1,0,2,0,0,1,2)]
                    path=self.artifact(ev,chunked)
                else:path.write_bytes(data[:-1] if damage=='truncate' else data+b'x')
                for filters in (['--limit',1],['--offset',999],['--last',1],['--from',99,'--context',1]):
                    q=self.query(path,'--bytes','6162','--write','--across-events',*filters,ok=False)
                    self.assertEqual(set(q),{'error'});self.assertEqual(q['error']['code'],'TRACE_ERROR')

    def test_byte_runs_all_patterns_and_maximum_bounded_page(self):
        groups=[[('w',0x2000+64*i+16*j,b'a'*16,True) for j in range(4)] for i in range(4)]
        args=[part for length in range(1,65) for part in ('--bytes','61'*length)]
        path=self.byte_artifact(groups,True)
        q=self.query(path,*args,'--across-events','--write','--limit',64)
        self.assertEqual((q['meta']['shown'],q['meta']['total']),(4096,sum(257-n for n in range(1,65))))
        self.assertEqual([p['total'] for p in q['meta']['patterns']],list(range(256,192,-1)))
        tail=self.query(path,*args,'--across-events','--last',1)
        self.assertEqual(len(tail['data']),64)
        self.assertTrue(all(r['last_ev']==3 and int(r['addr'],0)+r['size']==0x2100 for r in tail['data']))

if __name__=='__main__':unittest.main()
