"""State timing, delta propagation and gap semantics of execution profile 2."""
import json
import copy
import shlex
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

    def artifact(self,events,chunked=False,codes=None):
        type(self).n+=1;path=self.out/(str(self.n)+'.gtsw')
        header=(b'GTSC001\0' if chunked else b'GTSW001\0')+struct.pack('<7Q',0x1000,0x100,0x2000,32,1,2,64)
        sites=[]
        for pc in sorted({e[2] for e in events if e[0]==1}):
            opcode,text=(codes or {}).get(pc,(0x91000400,b'add x0, x0, #1'));part=text.ljust(24,b'\0');a,b,c=struct.unpack('<3Q',part)
            sites.append((8,0,pc,opcode,len(text),a,b,c))
        records=sites+events
        if not chunked:body=b''.join(struct.pack('<8Q',*e) for e in records)
        else:
            body=b'';mask=(1<<64)-1
            for first in range(0,len(records),3):
                block=records[first:first+3];encoded=b'';seq=pc=0
                for e in block:
                    def zz(n):n&=mask;return ((n<<1)^(mask if n>>63 else 0))&mask
                    values=[zz(e[1]-seq),zz(e[2]-pc),*e[3:]];seq,pc=e[1:3]
                    widths=[(v.bit_length()+7)//8 for v in values]
                    encoded+=bytes([e[0]])+struct.pack('<I',sum(w<<(4*i) for i,w in enumerate(widths)))
                    encoded+=b''.join(v.to_bytes(w,'little') for v,w in zip(values,widths))
                body+=b'GTBL001\0'+struct.pack('<II',len(block),len(encoded))+encoded
        path.write_bytes(header+body);return path

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

    def test_memory_selector_errors_show_range_repair_without_accepting_aliases(self):
        events=self.base();events.insert(2,(2,0,0x1000,0x2000,1,0xab,0,1));events[-1]=(4,3,0,1,0,0,2,2)
        for chunked in [False,True]:
            path=self.artifact(events,chunked)
            for command in ['mem-access','mem-state','last-writers']:
                extra=['--at-ev','0'] if command=='mem-state' else []
                for bad in [[],['--addr','0x2000','--len','1'],['--addr','0x2000','--size','1'],
                            ['--len','1'],['--size','1'],['--range','0x2000,1','--addr','0x2000']]:
                    with self.subTest(chunked=chunked,command=command,options=bad):
                        argv=[str(ROOT/'cli/traceq'),command,str(path),*bad,*extra]
                        result=subprocess.run([*argv,'--json'],capture_output=True,text=True,timeout=10)
                        self.assertEqual(result.returncode,2);self.assertEqual(result.stderr,'')
                        error=json.loads(result.stdout);self.assertEqual(set(error),{'error'})
                        self.assertEqual(error['error']['code'],'ARGUMENT')
                        message=error['error']['message']
                        self.assertIn('--range BASE,LEN',message);self.assertIn('LEN is bytes',message)
                        example=shlex.split(message.split('e.g. ')[1])
                        self.assertEqual(example,['--range','0x1000,16'])
                        # Replace the example address with this trace's data buffer.
                        self.query(path,command,[example[0],'0x2000,'+example[1].split(',')[1],*extra])
                        text=subprocess.run(argv,capture_output=True,text=True,timeout=10)
                        self.assertEqual(text.returncode,2);self.assertEqual(text.stdout,'')
                        self.assertEqual(text.stderr,command+': '+message+'\n')
                repaired=self.query(path,command,['--range','0x2000,1',*extra])
                self.assertTrue(repaired['data']);self.assertEqual(repaired['data'][0]['value' if command!='mem-access' else 'val'],'0xab')
            pc=self.query(path,'find-pc',['--addr','0x1000'])
            self.assertEqual([row['ev'] for row in pc['data']],[0])

    def test_last_writers_reports_state_cutoff_including_empty_and_paged_queries(self):
        events=self.base();events.insert(2,(2,0,0x1000,0x2000,1,0xab,0,1))
        events.insert(-2,(2,2,0x1008,0x2000,1,0xcd,0,1));events[-1]=(4,3,0,2,0,0,2,2)
        path=self.artifact(events)
        for at,options in [(2,[]),(0,['--at-seq','0']),(1,['--at-ev','1'])]:
            q=self.query(path,'last-writers',['--range','0x2000,8',*options])
            self.assertEqual(q['meta']['as_of_ev'],at)
            self.assertEqual(q['meta']['state_position'],'after_recorded_accesses_at_event')
            self.assertEqual(q['data'][0]['value'],'0xcd' if at==2 else '0xab')
            self.assertEqual(q['data'][0]['writer_seq'],2 if at==2 else 0)
            paged=self.query(path,'last-writers',['--range','0x2000,8','--limit','2','--offset','1',*options])
            self.assertEqual(paged['meta']['as_of_ev'],at)
            self.assertEqual(paged['data'],q['data'][1:3])
        invalid=self.query(path,'last-writers',['--range','0x2000,8','--at-seq','3'],ok=False)
        self.assertEqual(set(invalid),{'error'})
        empty=self.query(self.artifact([(4,0,0,0,0,0,0,2)]),'last-writers',['--range','0x2000,8'])
        self.assertIsNone(empty['meta']['as_of_ev']);self.assertFalse(any(r['known'] for r in empty['data']))
        for data in [path.read_bytes()[:-1],path.read_bytes()+b'x']:
            path.write_bytes(data)
            self.assertEqual(set(self.query(path,'last-writers',['--range','0x2000,8','--at-seq','0'],ok=False)),{'error'})

    def test_find_pc_module_offsets_keep_capture_offsets_and_page_in_trace_order(self):
        name = b'module.so'
        fields = struct.unpack('<3Q', name.ljust(24, b'\0'))
        metadata = [(13, 0, 0, 1, 0, 1, 0, 0), (10, 0, 0xf00, 0x200, len(name), *fields)]
        for chunked in (False, True):
            path = self.artifact([*metadata, *self.base()], chunked)
            args = ['--module', name.decode(), '--off', '0x108', '--off', '0x100']
            full = self.query(path, 'find-pc', args)
            self.assertEqual([(r['ev'], r['module_offset'], r['off']) for r in full['data']],
                             [(0, '0x100', '0x0'), (2, '0x108', '0x8')])
            self.assertEqual(full['meta']['module'], 'module.so')
            self.assertEqual(full['meta']['module_base'], '0xf00')
            absolute = self.query(path, 'find-pc', ['--addr', '0x1000', '--addr', '0x1008'])
            self.assertEqual(absolute['data'], [{k: v for k, v in row.items() if k != 'module_offset'}
                                               for row in full['data']])
            page = self.query(path, 'find-pc', [*args, '--limit', '1'])
            self.assertEqual(page['data'], full['data'][:1])
            self.assertEqual(page['meta']['total'], 2)
            next_argv = shlex.split(page['meta']['next'])
            result = subprocess.run([str(ROOT/'cli/traceq'), *next_argv[1:]],
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertEqual(json.loads(result.stdout)['data'], full['data'][1:])
            empty = self.artifact([*metadata, (4, 0, 0, 0, 0, 0, 0, 2)], chunked)
            self.assertEqual(self.query(empty, 'find-pc', args)['data'], [])

    def test_find_pc_module_selector_errors_follow_complete_validation(self):
        name = b'module.so'
        fields = struct.unpack('<3Q', name.ljust(24, b'\0'))
        metadata = [(13, 0, 0, 1, 0, 1, 0, 0), (10, 0, 0xf00, 0x200, len(name), *fields)]
        for chunked in (False, True):
            path = self.artifact([*metadata, *self.base()], chunked)
            duplicated = (10, 0, 0x2000, 0x200, len(name), *fields)
            ambiguous = self.artifact([*metadata, duplicated, *self.base()], chunked)
            missing = ['--module', 'missing.so', '--off', '0x100']
            args = ['--module', 'module.so', '--off', '0x100']
            for source, options, message in [
                (path, missing, 'absent from trace metadata'),
                (path, [*args, '--off', '0x200'], 'outside recorded module'),
                (path, [*args, '--addr', '0x1000'], 'cannot mix with --addr'),
                (ambiguous, args, 'multiple recorded instances'),
            ]:
                error = self.query(source, 'find-pc', options, ok=False)['error']
                self.assertEqual(error['code'], 'ARGUMENT')
                self.assertIn(message, error['message'])
            raw = path.read_bytes()
            for damaged in (raw[:-1], raw+b'x'):
                path.write_bytes(damaged)
                for selectors in (args, missing):
                    error = self.query(path, 'find-pc', [*selectors, '--offset', '99'], ok=False)['error']
                    self.assertEqual(error['code'], 'TRACE_ERROR')

    def test_memory_commands_reject_ignored_time_filters(self):
        path = self.artifact(self.compact_events(), chunked=True)
        args = ['--range','0x2000,1']
        pre = self.query(path,'mem-state',[*args,'--checkpoint','2:pre'])
        self.assertFalse(pre['data'][0]['data'][0]['known'])
        after = self.query(path,'last-writers',[*args,'--at-seq','2'])
        self.assertEqual(after['data'][0]['value'],'0x55')
        for command, options in [
            ('last-writers',['--at-ev','2','--phase','pre']),
            ('last-writers',['--from','2']),
            ('mem-access',['--at-ev','2']),
            ('mem-access',['--phase','pre']),
        ]:
            result = self.query(path,command,[*args,*options],ok=False)
            self.assertEqual(result['error']['code'],'ARGUMENT')

    def test_empty_trace_range_checks_follow_full_validation(self):
        for chunked in [False,True]:
            path = self.artifact([(4,0,0,0,0,0,0,2)],chunked)
            original = path.read_bytes()
            for command in ['mem-access','last-writers']:
                outside = ['--range','0x9999,4','--offset','99']
                self.assertEqual(self.query(path,command,outside,ok=False)['error']['code'],'ARGUMENT')
                for bad in [original[:-1],original+b'x']:
                    path.write_bytes(bad)
                    self.assertEqual(self.query(path,command,outside,ok=False)['error']['code'],'TRACE_ERROR')
                path.write_bytes(original)

    def test_last_writers_does_not_probe_an_option_value_as_a_trace_path(self):
        path = self.artifact(self.compact_events(),chunked=True)
        (self.out/'1').write_text('an unrelated numeric filename')
        result = subprocess.run([str(ROOT/'cli/traceq'),'last-writers','--limit','1',str(path),
                                 '--range','0x2000,8','--compact','--json'],
                                cwd=self.out,capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stdout)
        self.assertEqual(json.loads(result.stdout)['meta']['shown'],1)

    def compact_events(self):
        def pre(ev,pc):return [(5,ev,pc,i,8 if i<33 else 16,0,0,1) for i in range(65)]
        name=b'external.so';a,b,c=struct.unpack('<3Q',name.ljust(24,b'\0'))
        return [(13,0,0,1,0,1,0,0),(10,0,0x3000,0x100,len(name),a,b,c),
                (1,0,0x1000,0x91000400,0,0,0,1),*pre(0,0x1000),
                (2,0,0x1000,0x2000,8,0x1122334455667700,0,1),(9,0,0x1000,0,0,0,0,1),
                (1,1,0x1004,0x91000400,0,0,0,0),(11,1,0x1004,0x3010,1,0x1008,0,1),(3,1,0x1004,0,0,0,0,6),
                (1,2,0x1008,0x91000400,0,0,0,1),*pre(2,0x1008),(12,2,0x1008,1,0,0,0,1),
                (2,2,0x1008,0x2000,1,0x55,0,1),(9,2,0x1008,0,0,0,0,1),
                (1,3,0x100c,0x91000400,0,0,0,0),(3,3,0x100c,0,0,0,0,1),
                (1,4,0x1010,0x91000400,0,0,0,1),*pre(4,0x1010),
                (2,4,0x1010,0x2002,2,0xaabb,0,1),(9,4,0x1010,0,0,0,0,1),
                (1,5,0x1014,0x91000400,0,0,0,0),(11,5,0x1014,0x5000,3,0,0,1),(4,6,0,3,2,0,3,2)]

    def assert_compact_expands(self,compact,default):
        expanded=copy.deepcopy(compact);table=expanded['meta'].pop('located_gaps')
        self.assertEqual(len(table),len({json.dumps(g,sort_keys=True) for g in table}))
        for row in expanded['data']:
            evidence=row['last_observed_write']
            if evidence is None:continue
            ref=evidence.pop('first_located_gap_ref')
            if ref is not None:self.assertIs(type(ref),int);self.assertTrue(0<=ref<len(table))
            evidence['first_located_gap']=table[ref] if ref is not None else None
        if expanded['meta']['next']:
            argv=shlex.split(expanded['meta']['next']);self.assertIn('--compact',argv)
            self.assertEqual([x for x in argv if x!='--compact'],shlex.split(default['meta']['next']))
            expanded['meta']['next']=default['meta']['next']
        self.assertEqual(expanded,default)

    def expand_writer_runs(self, document):
        meta = dict(document['meta'])
        self.assertEqual(meta.pop('last_writers_format'), 'runs-v1')
        meta['next'] = meta['next'].replace(' --runs ', ' --compact ')
        data = []
        for run in document['data']:
            source = run['last_observed_write']
            if source is None:
                self.assertFalse(run['known'])
                values = [None] * run['size']
            else:
                values = list(bytes.fromhex(source['data_hex']))
                self.assertEqual(len(values), run['size'])
            for offset, value in enumerate(values):
                row = {'address': hex(int(run['address'], 0) + offset), 'known': run['known'],
                       'value': None, 'writer_seq': None, 'pc': None, 'last_observed_write': None}
                if source is not None:
                    history = {k: v for k, v in source.items() if k != 'data_hex'}
                    history['value'] = hex(value)
                    row['last_observed_write'] = history
                    if run['known']:
                        row.update({k: history[k] for k in ('value', 'writer_seq', 'pc', 'pc_offset')})
                data.append(row)
        self.assertEqual(meta['shown'], len(data))
        return {'data': data, 'meta': meta}

    def test_writer_runs_roundtrip_for_cutoffs_and_byte_pagination(self):
        for chunked in (False, True):
            path = self.artifact(self.compact_events(), chunked)
            base = ['--range', '0x2000,16']
            for cutoff in (0, 1, 2, 3, 4, 5):
                args = [*base, '--at-seq', str(cutoff)]
                runs = self.query(path, 'last-writers', [*args, '--runs'])
                compact = self.query(path, 'last-writers', [*args, '--compact'])
                self.assertEqual(self.expand_writer_runs(runs), compact)
                if cutoff == 0:
                    self.assertEqual([(row['size'], row['known']) for row in runs['data']], [(8, True), (8, False)])
                    self.assertEqual(runs['data'][0]['last_observed_write']['data_hex'], '0077665544332211')
                    self.assertIsNone(runs['data'][1]['last_observed_write'])

            args = [*base, '--at-seq', '0', '--limit', '3', '--offset', '2']
            first = self.query(path, 'last-writers', [*args, '--runs'])
            self.assertEqual(self.expand_writer_runs(first), self.query(path, 'last-writers', [*args, '--compact']))
            self.assertEqual([(row['address'], row['size']) for row in first['data']], [('0x2002', 3)])
            next_args = shlex.split(first['meta']['next'])
            result = subprocess.run([str(ROOT/'cli/traceq'), *next_args[1:]],
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stdout)
            second = json.loads(result.stdout)
            self.assertEqual(second['meta']['last_writers_format'], 'runs-v1')
            self.assertEqual([(row['address'], row['size']) for row in second['data']], [('0x2005', 3)])

    def test_writer_runs_keep_unpositioned_gaps_and_validate_empty_pages(self):
        for chunked in (False, True):
            events = self.compact_events()
            events.insert(-1, (3, 6, 0, 0, 0, 0, 0, 4))
            events[-1] = (4, 6, 0, 3, 3, 0, 3, 2)
            path = self.artifact(events, chunked)
            args = ['--range', '0x2000,16', '--at-seq', '0']
            runs = self.query(path, 'last-writers', [*args, '--runs'])
            self.assertTrue(runs['meta']['unpositioned_gap'])
            self.assertTrue(all(not row['known'] for row in runs['data']))
            self.assertEqual(self.expand_writer_runs(runs), self.query(path, 'last-writers', [*args, '--compact']))
            raw = path.read_bytes()
            empty = [*args, '--runs', '--offset', '16']
            self.assertEqual(self.query(path, 'last-writers', empty)['data'], [])
            for damage in (raw[:-1], raw + b'x'):
                path.write_bytes(damage)
                self.assertEqual(self.query(path, 'last-writers', empty, ok=False)['error']['code'], 'TRACE_ERROR')

    def test_compact_gap_references_preserve_cutoffs_overwrites_and_all_facts(self):
        for chunked in [False,True]:
            path=self.artifact(self.compact_events(),chunked)
            for at in [None,0,1,2,3,4,5]:
                args=['--range','0x2000,16','--limit','16',*(['--at-seq',str(at)] if at is not None else [])]
                default=self.query(path,'last-writers',args);compact=self.query(path,'last-writers',[*args,'--compact'])
                self.assert_compact_expands(compact,default)
                if at is None:
                    self.assertEqual([g['ev'] for g in compact['meta']['located_gaps']],[3,1])
                    self.assertEqual(compact['meta']['located_gaps'][1]['scope_exit']['target']['address'],'0x3010')
                    self.assertEqual(compact['meta']['located_gaps'][1]['scope_exit']['reentry_ev'],2)
                    self.assertEqual([r['known'] for r in compact['data']],[i in [2,3] for i in range(16)])
                    self.assertEqual(compact['data'][2]['value'],'0xbb');self.assertIsNone(compact['data'][8]['last_observed_write'])

    def test_compact_pages_have_local_references_and_keep_mode(self):
        for chunked in [False,True]:
            path=self.artifact(self.compact_events(),chunked);args=['--range','0x2000,8','--limit','2']
            full=self.query(path,'last-writers',['--range','0x2000,8','--limit','8']);page=self.query(path,'last-writers',[*args,'--compact']);rows=[]
            self.assertEqual([g['ev'] for g in page['meta']['located_gaps']],[3,1])
            while True:
                default=self.query(path,'last-writers',[*args,'--offset',str(len(rows))]);self.assert_compact_expands(page,default);rows.extend(default['data'])
                if not page['meta']['truncated']:break
                argv=shlex.split(page['meta']['next']);argv[0]=str(ROOT/'cli/traceq')
                page=json.loads(subprocess.check_output(argv,text=True))
                if len(rows)==2:self.assertEqual(page['meta']['located_gaps'],[])
                if len(rows)==4:self.assertEqual([g['ev'] for g in page['meta']['located_gaps']],[1])
            self.assertEqual(rows,full['data'])

    def test_compact_empty_global_gap_and_invalid_suffix_are_conservative(self):
        for chunked in [False,True]:
            empty=self.query(self.artifact([(4,0,0,0,0,0,0,2)],chunked),'last-writers',['--range','0x2000,8','--compact'])
            self.assertEqual(empty['meta']['located_gaps'],[]);self.assertIsNone(empty['meta']['as_of_ev'])
            events=self.compact_events();events.insert(-1,(3,6,0,0,0,0,0,4));events[-1]=(4,6,0,3,3,0,3,2)
            path=self.artifact(events,chunked);args=['--range','0x2000,16','--limit','16']
            default=self.query(path,'last-writers',args);compact=self.query(path,'last-writers',[*args,'--compact']);self.assert_compact_expands(compact,default)
            self.assertTrue(compact['meta']['unpositioned_gap']);self.assertFalse(any(r['known'] for r in compact['data']))
            original=path.read_bytes()
            for damaged in [original[:-1],original+b'x']:
                path.write_bytes(damaged);bad=self.query(path,'last-writers',['--range','0x2000,8','--at-seq','0','--limit','1','--compact'],ok=False)
                self.assertEqual(set(bad),{'error'});self.assertEqual(bad['error']['code'],'TRACE_ERROR')

    def test_compact_is_limited_to_profile_two_json_last_writers(self):
        path=self.artifact(self.compact_events())
        for command in ['stat','instructions','reg-state']:
            self.assertEqual(self.query(path,command,['--compact'],ok=False)['error']['code'],'ARGUMENT')
        result=subprocess.run([str(ROOT/'cli/traceq'),'last-writers',str(path),'--range','0x2000,8','--compact'],capture_output=True,text=True)
        self.assertEqual(result.returncode,2);self.assertEqual(result.stdout,'');self.assertIn('--json',result.stderr)
        legacy=self.out/'profile-one.gtsw'
        legacy.write_bytes(b'GTSW001\0'+struct.pack('<7Q',0x1000,0x100,0x2000,32,1,1,64)+struct.pack('<8Q',4,0,0,0,0,0,0,1))
        for mode in ('--compact', '--runs'):
            bad=self.query(legacy,'last-writers',['--range','0x2000,8',mode],ok=False)
            self.assertEqual(set(bad),{'error'});self.assertEqual(bad['error']['code'],'ARGUMENT')

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

    def memory_access_events(self):
        events=self.compact_events()
        events.insert(next(i for i,e in enumerate(events) if e[0]==2),
                      (7,0,0x1000,0x2000,16,0x0123456789abcdef,0xfedcba9876543210,1))
        events.insert(next(i for i,e in enumerate(events) if e[0]==2 and e[1]==2),
                      (7,2,0x1008,0x2008,8,0,0,0))
        events[-1]=(4,6,0,3,2,2,3,2)
        return events

    def atomic_access_artifact(self,chunked=False,global_gap=False):
        events=[(1,0,0x1000,0xb8200020,0,0,0,1),(5,0,0x1000,0,8,7,0,1),(5,0,0x1000,1,8,0x2000,0,1),
                (7,0,0x1000,0x2000,4,13,0,1),(2,0,0x1000,0x2000,4,20,0,1),
                (6,0,0x1000,0,8,13,0,1),(9,0,0x1000,0,0,0,0,1),
                (1,1,0x1004,0xb9000020,0,0,0,1),(2,1,0x1004,0x2000,4,99,0,1),(9,1,0x1004,0,0,0,0,1)]
        if global_gap:events.append((3,2,0,0,0,0,0,4))
        events.append((4,2,0,2,int(global_gap),1,2,2))
        return self.artifact(events,chunked,{0x1000:(0xb8200020,b'ldadd w0, w0, [x1]'),0x1004:(0xb9000020,b'str w0, [x1]')})

    def test_atomic_write_sources_and_mixed_compact_pages(self):
        for chunked in [False,True]:
            path=self.atomic_access_artifact(chunked)
            full=self.query(path,'mem-access',['--range','0x2000,4'])
            self.assertEqual([(r['rw'],r['val'])for r in full['data']],[('r','0xd'),('w','0x14'),('w','0x63')])
            self.assertIn('returned old bits',full['data'][1]['value_source'])
            self.assertEqual(full['data'][2]['value_source'],'store source bits; post callback confirmed')
            for filters in [[],['--write'],['--read'],['--limit','1','--offset','1'],['--limit','1','--offset','2'],['--offset','99']]:
                args=['--range','0x2000,4',*filters];named=self.query(path,'mem-access',args);packed=self.query(path,'mem-access',[*args,'--compact'])
                self.assert_mem_access_expands(packed,named)
                if filters in [[],['--write']]:
                    self.assertNotIn('mem_access_format',packed['meta']);self.assertEqual(packed['meta']['compact_fallback'],'mixed_write_sources')
                else:self.assertEqual(packed['meta']['mem_access_format'],'columns-v1')
            context=self.query(path,'context',['--at-ev','0','--before','0','--after','0'])
            self.assertEqual([m['value_source']for m in context['data'][0]['memory']],[r['value_source']for r in full['data'][:2]])

    def test_atomic_read_write_temporal_state_and_full_validation(self):
        for chunked in [False,True]:
            path=self.atomic_access_artifact(chunked)
            pre=self.query(path,'mem-state',['--range','0x2000,4','--at-ev','0','--phase','pre'])
            self.assertTrue(all(not r['known'] for r in pre['data']))
            post=self.query(path,'mem-state',['--range','0x2000,4','--at-ev','0','--phase','post'])
            self.assertEqual([r['value']for r in post['data']],['0x14','0x0','0x0','0x0'])
            last=self.query(path,'last-writers',['--range','0x2000,4','--at-seq','0'])
            self.assertEqual([r['value']for r in last['data']],['0x14','0x0','0x0','0x0'])
            gap=self.query(self.atomic_access_artifact(chunked,True),'mem-state',['--range','0x2000,4','--at-ev','0','--phase','post'])
            self.assertTrue(all(not r['known']for r in gap['data']))
            for damage in ('truncate','suffix'):
                path=self.atomic_access_artifact(chunked);data=path.read_bytes();path.write_bytes(data[:-1]if damage=='truncate'else data+b'x')
                q=self.query(path,'mem-access',['--range','0x2000,4','--offset','99','--compact'],ok=False)
                self.assertEqual(set(q),{'error'});self.assertEqual(q['error']['code'],'TRACE_ERROR')

    def test_mem_access_indices_precede_filtering_and_survive_paging(self):
        for chunked in (False, True):
            path = self.atomic_access_artifact(chunked)
            args = ['--range', '0x2000,4', '--range', '0x2001,1', '--write', '--access-index']
            named = self.query(path, 'mem-access', args)
            self.assertEqual([(row['ev'], row['access_index']) for row in named['data']], [(0, 1), (1, 0)])
            mixed = self.query(path, 'mem-access', [*args, '--compact'])
            self.assertEqual(mixed['meta']['compact_fallback'], 'mixed_write_sources')
            self.assertEqual(mixed['data'], named['data'])

            first = self.query(path, 'mem-access', [*args, '--compact', '--limit', '1'])
            self.assertEqual(first['meta']['mem_access_format'], 'columns-v2')
            self.assertEqual(first['meta']['columns'][-1], 'access_index')
            self.assertEqual(first['data'][0][-1], 1)
            next_argv = shlex.split(first['meta']['next'])
            self.assertIn('--access-index', next_argv)
            result = subprocess.run([str(ROOT/'cli/traceq'), *next_argv[1:]],
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stdout)
            second = json.loads(result.stdout)
            self.assertEqual(second['data'][0][-1], 0)
            self.assertFalse(second['meta']['truncated'])

            raw = path.read_bytes()
            for damaged in (raw[:-1], raw + b'x'):
                path.write_bytes(damaged)
                error = self.query(path, 'mem-access', [*args, '--offset', '99', '--compact'], ok=False)['error']
                self.assertEqual(error['code'], 'TRACE_ERROR')

    def assert_mem_access_expands(self,packed,named):
        columns=['ev','pc','off','rw','addr','size','known','val']
        write_sources={r['value_source'] for r in named['data'] if r['rw']=='w'}
        expected_meta=self.compact_page_meta(packed,named)
        if len(write_sources)>1:
            expected_meta['compact_fallback']='mixed_write_sources'
            self.assertEqual(packed['data'],named['data'])
        else:
            expected_meta.update(
                mem_access_format='columns-v1',
                columns=columns,
                value_sources={
                    'r':next((r['value_source'] for r in named['data'] if r['rw']=='r'),
                             'load destination bits after completion'),
                    'w':next(iter(write_sources),'store source bits; post callback confirmed'),
                },
            )
            self.assertEqual(packed['data'],[[row[c] for c in columns] for row in named['data']])
        self.assertEqual(packed['meta'],expected_meta)
        return named

    def compact_page_meta(self,packed,named):
        meta=dict(named['meta'])
        if meta['next']:
            argv=shlex.split(packed['meta']['next'])
            self.assertIn('--compact',argv)
            self.assertEqual([a for a in argv if a!='--compact'],shlex.split(meta['next']))
            meta['next']=packed['meta']['next']
        return meta

    def test_mem_access_compact_preserves_wide_unknown_filtered_and_paged_facts(self):
        for chunked in [False,True]:
            path=self.artifact(self.memory_access_events(),chunked)
            for options in [[],['--read'],['--write'],['--from','2','--to','4']]:
                args=['--range','0x2004,8',*options]
                full=self.query(path,'mem-access',[*args,'--limit','10'])
                packed=self.query(path,'mem-access',[*args,'--limit','10','--compact'])
                self.assert_mem_access_expands(packed,full)
                if not options:
                    self.assertEqual(len(full['data']),3)
                    self.assertEqual(full['data'][0]['val'],'0xfedcba98765432100123456789abcdef')
                    self.assertEqual(full['data'][0]['addr'],'0x2000')
                    self.assertEqual(full['data'][0]['size'],16)
                    self.assertFalse(full['data'][-1]['known']);self.assertIsNone(full['data'][-1]['val'])
                    self.assertEqual(full['meta']['capture_gaps'],2)
                page=self.query(path,'mem-access',[*args,'--limit','1','--compact']);all_rows=[]
                while True:
                    named=self.query(path,'mem-access',[*args,'--limit','1','--offset',str(len(all_rows))])
                    all_rows+=self.assert_mem_access_expands(page,named)['data']
                    if not page['meta']['truncated']:break
                    argv=shlex.split(page['meta']['next']);r=subprocess.run([str(ROOT/'cli/traceq'),*argv[1:]],capture_output=True,text=True,timeout=10)
                    self.assertEqual(r.returncode,0,r.stdout);page=json.loads(r.stdout)
                self.assertEqual(all_rows,full['data'])

    def test_mem_access_multiple_ranges_return_one_ordered_union(self):
        for chunked in [False, True]:
            path = self.artifact(self.memory_access_events(), chunked)
            ranges = ['--range', '0x200c,2', '--range', '0x2000,1', '--range', '0x200d,2']
            full = self.query(path, 'mem-access', ranges)
            broad = self.query(path, 'mem-access', ['--range', '0x2000,16'])
            self.assertEqual(full['data'], broad['data'][:4])
            self.assertEqual(full['meta']['total'], 4)
            self.assertEqual([(r['ev'], r['rw'], r['size']) for r in full['data']],
                             [(0, 'r', 16), (0, 'w', 8), (2, 'r', 8), (2, 'w', 1)])
            unknown = self.query(path, 'mem-access', [*ranges, '--read', '--from', '2'])
            self.assertEqual(unknown['data'], [full['data'][2]])
            self.assertIsNone(unknown['data'][0]['val'])

            args = [*ranges, '--limit', '2']
            first = self.query(path, 'mem-access', [*args, '--compact'])
            self.assert_mem_access_expands(first, self.query(path, 'mem-access', args))
            self.assertEqual(first['meta']['total'], 4)
            next_argv = shlex.split(first['meta']['next'])
            result = subprocess.run([str(ROOT/'cli/traceq'), *next_argv[1:]],
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stdout)
            second = json.loads(result.stdout)
            named = self.query(path, 'mem-access', [*args, '--offset', '2'])
            self.assert_mem_access_expands(second, named)
            self.assertEqual(named['data'], full['data'][2:])
            self.assertFalse(second['meta']['truncated'])

            single = ['--range', '0x2000,1']
            self.assertEqual(self.query(path, 'mem-access', single * 64),
                             self.query(path, 'mem-access', single))
            over = self.query(path, 'mem-access', single * 65, ok=False)
            self.assertEqual(over['error']['code'], 'ARGUMENT')

    def test_mem_access_multiple_ranges_validate_even_when_outside_and_empty(self):
        for chunked in [False, True]:
            path = self.artifact(self.memory_access_events(), chunked)
            raw = path.read_bytes()
            valid = ['--range', '0x2000,1', '--range', '0x200d,2', '--offset', '99']
            outside = [*valid, '--range', '0x9999,1']
            self.assertEqual(self.query(path, 'mem-access', valid)['data'], [])
            self.assertEqual(self.query(path, 'mem-access', outside, ok=False)['error']['code'], 'ARGUMENT')
            for damage in [raw[:-1], raw + b'x']:
                path.write_bytes(damage)
                for args in [valid, outside]:
                    error = self.query(path, 'mem-access', [*args, '--compact'], ok=False)
                    self.assertEqual(error['error']['code'], 'TRACE_ERROR')

    def test_mem_access_compact_validates_empty_pages_and_corrupt_suffix(self):
        for chunked in [False,True]:
            path=self.artifact(self.memory_access_events(),chunked);original=path.read_bytes()
            for page in [['--offset','99'],['--read','--from','5']]:
                args=['--range','0x2000,16',*page]
                self.assert_mem_access_expands(self.query(path,'mem-access',[*args,'--compact']),self.query(path,'mem-access',args))
                for damaged in [original[:-1],original+b'x']:
                    path.write_bytes(damaged)
                    q=self.query(path,'mem-access',[*args,'--compact'],ok=False)
                    self.assertEqual(set(q),{'error'});self.assertEqual(q['error']['code'],'TRACE_ERROR')
                path.write_bytes(original)
            empty=self.artifact([(4,0,0,0,0,0,0,2)],chunked)
            args=['--range','0x2000,1']
            self.assert_mem_access_expands(self.query(empty,'mem-access',[*args,'--compact']),self.query(empty,'mem-access',args))
        self.assertEqual(self.query(path,'mem-access',['--range','0x2000,16','--limit','0','--compact'],ok=False)['error']['code'],'ARGUMENT')
        r=subprocess.run([str(ROOT/'cli/traceq'),'mem-access',str(path),'--range','0x2000,16','--compact'],capture_output=True,text=True,timeout=10)
        self.assertEqual(r.returncode,2);self.assertEqual(r.stdout,'');self.assertIn('--json',r.stderr)

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
        left_page=self.query(path,'boundaries',['--reg','x0','--from','0','--to','0'])
        right_page=self.query(path,'boundaries',['--reg','x0','--from','1','--to','1'])
        self.assertEqual(left_page['data'],[first])
        self.assertEqual(right_page['data'],[last])
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

    def test_context_capture_metadata_is_complete_on_selected_and_empty_pages(self):
        expected={'instructions':6,'reads':1,'unknown_reads':1,'stores':3,
                  'confirmed_instructions':3,'capture_gaps':2,'scope_exits':2,'scope_reentries':1,
                  'code_base':'0x1000','code_size':256,'data_base':'0x2000','data_size':32,
                  'scope':'observations within declared single-thread code/data ranges'}
        for chunked in [False,True]:
            events=self.compact_events()
            at=next(i for i,e in enumerate(events) if e[0]==2)
            events.insert(at,(7,0,0x1000,0x2010,8,0,0,0))
            events[-1]=(4,6,0,3,2,1,3,2)
            path=self.artifact(events,chunked)
            for offset in [0,1,99]:
                args=['--at-ev','0','--at-ev','5','--before','0','--after','0',
                      '--reg','x0','--reg','x1','--limit','1','--offset',str(offset)]
                for compact in [False,True]:
                    q=self.query(path,'context',args+(['--compact'] if compact else []))
                    for key,value in expected.items():self.assertEqual(q['meta'][key],value,(key,offset,compact))
                    self.assertEqual(q['meta']['total'],2)
                    self.assertEqual(q['meta']['shown'],0 if offset==99 else 1)
                    if offset==0:
                        row=q['data'][0] if not compact else dict(zip(q['meta']['columns'],q['data'][0]))
                        self.assertEqual(row['pre'],{'x0':'0x0','x1':'0x0'} if not compact else ['0x0','0x0'])
                    if offset==1:
                        row=q['data'][0] if not compact else dict(zip(q['meta']['columns'],q['data'][0]))
                        self.assertIsNone(row['post'])

    def test_mem_state_sixteen_byte_lanes_partial_overwrite_and_completion(self):
        for chunked in [False,True]:
            events=self.base()
            events[3:3]=[(7,0,0x1000,0x2000,16,0x0807060504030201,0x100f0e0d0c0b0a09,1),
                         (2,0,0x1000,0x2007,2,0xbbaa,0,1)]
            events[-1]=(4,3,0,1,0,1,2,2)
            path=self.artifact(events,chunked)
            args=['--range','0x2001,16','--at-ev','0','--phase','post']
            q=self.query(path,'mem-state',args)
            expected=['0x2','0x3','0x4','0x5','0x6','0x7','0xaa','0xbb',
                      '0xa','0xb','0xc','0xd','0xe','0xf','0x10',None]
            self.assertEqual([b['value'] for b in q['data']],expected)
            for b in q['data'][:-1]:
                self.assertEqual((b['known'],b['observed_ev'],b['pc'],b['pc_offset']),(True,0,'0x1000','0x0'))
            pre=self.query(path,'mem-state',['--range','0x2001,16','--at-ev','1','--phase','pre'])
            self.assertEqual(pre['data'],q['data'])
            post=self.query(path,'mem-state',['--range','0x2001,16','--at-ev','1','--phase','post'])
            self.assertFalse(any(b['known'] for b in post['data']))
            initial=self.query(path,'mem-state',['--range','0x2001,16','--at-ev','0','--phase','pre'])
            self.assertFalse(any(b['known'] for b in initial['data']))
            path.write_bytes(path.read_bytes()+b'x')
            bad=self.query(path,'mem-state',[*args,'--offset','999'],ok=False)
            self.assertEqual(set(bad),{'error'})

    def test_mem_state_checkpoints_keep_order_values_sources_and_completion(self):
        points=[(2,'pre'),(0,'post'),(0,'pre'),(1,'post'),(0,'post')]
        for chunked in [False,True]:
            events=self.base();events.insert(3,(7,0,0x1000,0x2000,16,0x0807060504030201,0x100f0e0d0c0b0a09,1))
            events[-1]=(4,3,0,0,0,1,2,2);path=self.artifact(events,chunked)
            args=['--range','0x2000,16','--limit','16']+[a for ev,phase in points for a in ['--checkpoint',str(ev)+':'+phase]]
            q=self.query(path,'mem-state',args)
            self.assertEqual(q['meta']['memory_format'],'checkpoints-v1')
            self.assertEqual((q['meta']['total'],q['meta']['shown'],q['meta']['checkpoints']),(80,80,5))
            self.assertFalse(q['meta']['truncated'])
            self.assertEqual([(r['ev'],r['phase'])for r in q['data']],points)
            for point,row in zip(points,q['data']):
                single=self.query(path,'mem-state',['--range','0x2000,16','--at-ev',str(point[0]),'--phase',point[1],'--limit','16'])
                self.assertEqual(row['data'],single['data'])
                for key,value in single['meta'].items():
                    if key not in ['total','shown','truncated','next','phase']:self.assertEqual(q['meta'][key],value)
            self.assertEqual([int(b['value'],0)for b in q['data'][0]['data']],list(range(1,17)))
            self.assertEqual(q['data'][1]['data'][8]['value'],'0x9')
            self.assertEqual(q['data'][1]['data'][8]['observed_ev'],0)
            self.assertEqual(q['data'][1]['data'][8]['pc'],'0x1000')
            self.assertTrue(all(not b['known']for b in q['data'][2]['data']))
            self.assertTrue(all(not b['known']for b in q['data'][3]['data']))
            self.assertEqual(q['data'][3]['instruction_completion'],'unobserved')

    def test_mem_state_access_source_uses_the_latest_access_and_exact_ordinal(self):
        for chunked in [False,True]:
            events=self.base()
            events[3:3]=[(7,0,0x1000,0x2000,2,0x2211,0,1),
                         (2,0,0x1000,0x2001,1,0x33,0,1)]
            events[-1]=(4,3,0,1,0,1,2,2)
            path=self.artifact(events,chunked)
            args=['--range','0x2000,3','--checkpoint','0:post','--checkpoint','1:post','--access-source']
            named=self.query(path,'mem-state',args)
            first,unobserved=[f['data'] for f in named['data']]
            self.assertEqual([(b['value'],b['observed_rw'],b['observed_access_index']) for b in first[:2]],
                             [('0x11','r',0),('0x33','w',1)])
            for b in [*first[2:],*unobserved]:
                self.assertFalse(b['known'])
                self.assertNotIn('observed_rw',b)
                self.assertNotIn('observed_access_index',b)
            packed=self.query(path,'mem-state',[*args,'--compact'])
            self.assertEqual(packed['meta']['mem_state_format'],'hex-v2')
            self.assertEqual(packed['meta']['source_columns'],
                             ['observed_ev','pc_index','observed_rw','observed_access_index'])
            self.assertEqual(packed['data'][0]['data']['sources'],[[0,0,'r',0],[0,0,'w',1],None])
            self.assertEqual(packed['data'][1]['data']['sources'],[None]*3)
            raw=path.read_bytes()
            for damage in [raw[:-1],raw+b'x']:
                path.write_bytes(damage)
                bad=self.query(path,'mem-state',[*args,'--compact','--offset','9'],ok=False)
                self.assertEqual(bad['error']['code'],'TRACE_ERROR')

    def assert_compact_memory_roundtrip(self,path,args):
        named=self.query(path,'mem-state',args)
        packed=self.query(path,'mem-state',[*args,'--compact'])
        expected_meta=self.compact_page_meta(packed,named)
        checkpoints=named['meta'].get('memory_format')=='checkpoints-v1'
        rows=[group['data'] for group in named['data']] if checkpoints else [named['data']]
        pcs=list(dict.fromkeys((b['pc'],b['pc_offset']) for page in rows for b in page if b['known']))
        table=[{'pc':pc,'pc_offset':offset} for pc,offset in pcs]
        expected_meta.update(mem_state_format='hex-v1',source_columns=['observed_ev','pc_index'],pc_table=table)
        self.assertEqual(packed['meta'],expected_meta)

        frames=[group['data'] for group in packed['data']] if checkpoints else packed['data']
        self.assertEqual(len(frames),len(rows))
        for frame,page in zip(frames,rows):
            sources=[[b['observed_ev'],pcs.index((b['pc'],b['pc_offset']))] if b['known'] else None
                     for b in page]
            base,length=map(lambda n:int(n,0),args[args.index('--range')+1].split(','))
            offset=int(args[args.index('--offset')+1]) if '--offset' in args else 0
            self.assertEqual(frame,{
                'address':hex(base+min(offset,length)),
                'size':len(page),
                'data_hex':''.join(f"{int(b['value'],0):02x}" if b['known'] else '00' for b in page),
                'sources':sources,
            })
        if checkpoints:
            self.assertEqual([{**group,'data':None} for group in packed['data']],
                             [{**group,'data':None} for group in named['data']])
        return packed,named

    def test_mem_state_compact_preserves_128bit_values_overlap_zero_and_unknown_sources(self):
        for chunked in [False,True]:
            events=self.base();events[3:3]=[(7,0,0x1000,0x2000,16,0x0807060504030200,0x100f0e0d0c0b0a09,1),
                                          (2,0,0x1000,0x2007,2,0xbbaa,0,1)]
            events[-1]=(4,3,0,1,0,1,2,2);path=self.artifact(events,chunked)
            packed,named=self.assert_compact_memory_roundtrip(path,['--range','0x2000,17','--at-ev','0','--phase','post'])
            self.assertEqual(packed['data'][0]['data_hex'],'00020304050607aabb0a0b0c0d0e0f1000')
            self.assertEqual(packed['data'][0]['sources'][:16],[[0,0]]*16)
            self.assertIsNone(packed['data'][0]['sources'][16])
            self.assertTrue(named['data'][0]['known']);self.assertEqual(named['data'][0]['value'],'0x0')
            self.assertFalse(named['data'][-1]['known'])
            for ev,phase in [(0,'pre'),(1,'pre'),(1,'post'),(2,'post')]:
                self.assert_compact_memory_roundtrip(path,['--range','0x2000,17','--at-ev',str(ev),'--phase',phase])

    def test_mem_state_compact_checkpoint_pages_keep_order_sources_and_local_tables(self):
        for chunked in [False,True]:
            path=self.artifact(self.compact_events(),chunked)
            points=['4:post','0:post','5:pre','0:post','1:post']
            args=['--range','0x2000,16','--limit','3']+[v for point in points for v in ['--checkpoint',point]]
            for offset in range(0,19,3):
                packed,named=self.assert_compact_memory_roundtrip(path,[*args,'--offset',str(offset)])
                self.assertEqual([str(x['ev'])+':'+x['phase']for x in packed['data']],points)
                self.assertEqual(packed['meta']['shown'],sum(r['data']['size']for r in packed['data']))
                used={s[1]for row in packed['data']for s in row['data']['sources']if s is not None}
                self.assertEqual(used,set(range(len(packed['meta']['pc_table']))))
            packed,named=self.assert_compact_memory_roundtrip(path,['--range','0x2000,16','--at-ev','4','--limit','3','--offset','99'])
            self.assertEqual(packed['data'][0]['size'],0);self.assertEqual(named['data'],[])
            self.assertEqual(packed['meta']['pc_table'],[])

    def test_mem_state_multiple_ranges_share_checkpoint_order_and_page_offsets(self):
        ranges=['0x2003,2','0x2000,4','0x2003,2']
        for chunked in (False,True):
            path=self.atomic_access_artifact(chunked)
            common=['--checkpoint','1:post','--checkpoint','0:post','--limit','2','--access-source']
            args=[arg for r in ranges for arg in ('--range',r)]+common
            first=self.query(path,'mem-state',args)
            self.assertEqual(first['meta']['memory_format'],'ranges-checkpoints-v1')
            self.assertEqual((first['meta']['total'],first['meta']['shown'],first['meta']['range_count']),(16,12,3))
            self.assertEqual(first['data'][0],first['data'][2])
            command=shlex.split(first['meta']['next'])
            command[0]=str(ROOT/'cli/traceq')
            second=json.loads(subprocess.check_output(command,text=True,timeout=10))
            self.assertEqual((second['meta']['total'],second['meta']['shown'],second['meta']['next']),(16,4,''))
            for grouped, offset in ((first,'0'),(second,'2')):
                for group, selected_range in zip(grouped['data'],ranges):
                    single=self.query(path,'mem-state',['--range',selected_range,*common,'--offset',offset])
                    self.assertEqual(group['range_base'],single['meta']['range_base'])
                    self.assertEqual(group['range_size'],single['meta']['range_size'])
                    self.assertEqual(group['data'],single['data'])
            packed=self.query(path,'mem-state',[*args,'--compact'])
            self.assertEqual(packed['meta']['mem_state_format'],'hex-v2')
            self.assertEqual(packed['data'][1]['data'][0]['data']['data_hex'],'6300')
            oversize=['--range','0x2000,4096','--range','0x3000,4096','--at-ev','0','--limit','4096']
            self.assertEqual(self.query(path,'mem-state',oversize,ok=False)['error']['code'],'ARGUMENT')
            invalid=['--range','0x1000,1','--range','0x2000,1','--at-ev','0','--offset','99']
            self.assertEqual(self.query(path,'mem-state',invalid,ok=False)['error']['code'],'ARGUMENT')
            raw=path.read_bytes()
            for damage in (raw[:-1],raw+b'x'):
                path.write_bytes(damage)
                self.assertEqual(self.query(path,'mem-state',[*args,'--offset','99'],ok=False)['error']['code'],'TRACE_ERROR')
                self.assertEqual(self.query(path,'mem-state',invalid,ok=False)['error']['code'],'TRACE_ERROR')

    def test_mem_state_range_checkpoints_select_only_requested_pairs(self):
        first=['--range','0x2000,4','--range-checkpoint','1:post']
        second=['--range','0x2003,2','--range-checkpoint','0:post','--range-checkpoint','1:pre']
        args=[*first,*second,'--limit','1','--access-source']
        for chunked in (False,True):
            path=self.atomic_access_artifact(chunked)
            result=self.query(path,'mem-state',args)
            self.assertEqual(result['meta']['checkpoint_pairs'],3)
            self.assertEqual((result['meta']['total'],result['meta']['shown']),(8,3))
            groups=result['data']
            self.assertEqual([[(r['ev'],r['phase']) for r in group['data']] for group in groups],
                             [[(1,'post')],[(0,'post'),(1,'pre')]])
            self.assertEqual([r['data'][0]['value'] for group in groups for r in group['data']],['0x63','0x0','0x0'])
            command=shlex.split(result['meta']['next'])
            command[0]=str(ROOT/'cli/traceq')
            page=json.loads(subprocess.check_output(command,text=True,timeout=10))
            self.assertEqual(page['meta']['shown'],3)
            self.assertTrue(all(not row['data'][0]['known'] for row in page['data'][1]['data']))
            for invalid in [
                ['--range-checkpoint','0:post','--range','0x2000,1'],
                [*first,'--range','0x2003,2'],
                [*first,'--checkpoint','0:post'],
                [*first,'--at-ev','0'],
                [*first,'--phase','pre'],
                ['--range','0x2000,4096','--range-checkpoint','0:post',*second,'--limit','4096'],
            ]:
                self.assertEqual(self.query(path,'mem-state',invalid,ok=False)['error']['code'],'ARGUMENT')
            raw=path.read_bytes()
            for damage in (raw[:-1],raw+b'x'):
                path.write_bytes(damage)
                self.assertEqual(self.query(path,'mem-state',[*args,'--offset','99'],ok=False)['error']['code'],'TRACE_ERROR')

    def test_mem_state_compact_global_gap_and_damaged_empty_pages_remain_conservative(self):
        for chunked in [False,True]:
            events=self.compact_events();events.insert(-1,(3,6,0,0,0,0,0,4));events[-1]=(4,6,0,3,3,0,3,2)
            path=self.artifact(events,chunked)
            packed,named=self.assert_compact_memory_roundtrip(path,['--range','0x2000,16','--checkpoint','0:post','--checkpoint','4:post'])
            self.assertEqual(packed['meta']['pc_table'],[])
            self.assertTrue(all(s is None for row in packed['data']for s in row['data']['sources']))
            original=path.read_bytes()
            for damaged in [original[:-1],original+b'x']:
                path.write_bytes(damaged)
                for selector in [['--at-ev','0'],['--checkpoint','4:post','--checkpoint','0:pre']]:
                    result=self.query(path,'mem-state',['--range','0x2000,16',*selector,'--limit','1','--offset','999','--compact'],ok=False)
                    self.assertEqual(set(result),{'error'});self.assertEqual(result['error']['code'],'TRACE_ERROR')

    def test_mem_state_compact_capacity_and_json_contract(self):
        for chunked in [False,True]:
            path=self.artifact(self.base(),chunked);data=bytearray(path.read_bytes());data[32:40]=struct.pack('<Q',4096);path.write_bytes(data)
            packed,named=self.assert_compact_memory_roundtrip(path,['--range','0x2000,4096','--at-ev','0','--phase','post','--limit','4096'])
            self.assertEqual(packed['meta']['shown'],4096);self.assertEqual(packed['data'][0]['size'],4096)
            for args in [['--range','0x2000,4097','--at-ev','0'],
                         ['--range','0x2000,4096','--checkpoint','0:pre','--checkpoint','0:post','--limit','4096']]:
                self.assertEqual(self.query(path,'mem-state',[*args,'--compact'],ok=False)['error']['code'],'ARGUMENT')
            r=subprocess.run([str(ROOT/'cli/traceq'),'mem-state',str(path),'--range','0x2000,1','--at-ev','0','--compact'],capture_output=True,text=True,timeout=10)
            self.assertEqual(r.returncode,2);self.assertEqual(r.stdout,'');self.assertIn('--json',r.stderr)

    def test_mem_state_checkpoint_pages_and_global_gap(self):
        for chunked in [False,True]:
            events=self.compact_events();path=self.artifact(events,chunked)
            args=['--range','0x2000,16','--checkpoint','0:post','--checkpoint','2:post',
                  '--checkpoint','4:post','--checkpoint','5:pre','--limit','3']
            accumulated=[[]for _ in range(4)];page=self.query(path,'mem-state',args)
            while True:
                for i,row in enumerate(page['data']):accumulated[i].extend(row['data'])
                self.assertEqual(page['meta']['pagination_unit'],'bytes_per_checkpoint')
                if not page['meta']['truncated']:break
                argv=shlex.split(page['meta']['next']);argv[0]=str(ROOT/'cli/traceq')
                page=json.loads(subprocess.check_output(argv,text=True))
            self.assertEqual([len(r)for r in accumulated],[16]*4)
            self.assertEqual(accumulated[0][0]['value'],'0x0')
            self.assertTrue(accumulated[0][0]['known'])
            self.assertEqual(accumulated[1][0]['value'],'0x55')
            self.assertEqual([b['known']for b in accumulated[2]],[i in [2,3]for i in range(16)])
            self.assertEqual(accumulated[2][2]['observed_ev'],4)
            self.assertEqual(accumulated[3],accumulated[2])
            events.insert(-1,(3,6,0,0,0,0,0,4));events[-1]=(4,6,0,3,3,0,3,2)
            global_gap=self.query(self.artifact(events,chunked),'mem-state',args)
            self.assertTrue(global_gap['meta']['unpositioned_gap'])
            self.assertTrue(all(not b['known']for r in global_gap['data']for b in r['data']))

    def test_mem_state_checkpoints_reject_bad_arguments_and_unselected_damage(self):
        path=self.artifact(self.base());prefix=['--range','0x2000,16']
        for args in [['--checkpoint'],['--checkpoint','0'],['--checkpoint','0:both'],['--checkpoint',':pre'],
                     ['--checkpoint','0:pre','--at-ev','0'],['--checkpoint','0:pre','--phase','pre'],
                     ['--checkpoint','18446744073709551616:post'],['--checkpoint','99:post'],
                     [a for _ in range(65)for a in ['--checkpoint','0:pre']]]:
            self.assertEqual(self.query(path,'mem-state',prefix+args,ok=False)['error']['code'],'ARGUMENT')
        self.assertEqual(self.query(path,'mem-state',['--range','0x2000,4096','--checkpoint','0:pre',
            '--checkpoint','0:post','--limit','4096'],ok=False)['error']['code'],'ARGUMENT')
        self.assertEqual(self.query(path,'reg-state',['--at-ev','0','--checkpoint','0:pre'],ok=False)['error']['code'],'ARGUMENT')
        for chunked in [False,True]:
            invalid=self.base();invalid.insert(-1,(5,2,0x1008,65,8,1,0,1))
            for records in [invalid,self.base()[:-1]]:
                bad=self.artifact(records,chunked)
                for offset in [0,999]:
                    q=self.query(bad,'mem-state',prefix+['--checkpoint','0:pre','--checkpoint','0:post','--offset',str(offset)],ok=False)
                    self.assertEqual(set(q),{'error'});self.assertEqual(q['error']['code'],'TRACE_ERROR')
            bad=self.artifact(self.base(),chunked);bad.write_bytes(bad.read_bytes()+b'x')
            q=self.query(bad,'mem-state',prefix+['--checkpoint','0:pre','--offset','999'],ok=False)
            self.assertEqual(set(q),{'error'})

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

    def test_context_uses_final_site_metadata_and_rejects_corrupt_suffix(self):
        text=b'add x0, x0, #1';suffix=b' ; final metadata'
        words=struct.unpack('<3Q',suffix.ljust(24,b'\0'))
        for chunked in [False,True]:
            events=self.base();events.insert(-1,(8,len(text),0x1000,0x91000400,len(suffix),*words))
            path=self.artifact(events,chunked)
            args=['--at-ev','0','--before','0','--after','0','--reg','x0']
            row=self.query(path,'context',args)['data'][0]
            self.assertEqual(row['text'],(text+suffix).decode())
            self.assertEqual((row['pre']['x0'],row['post']['x0']),('0x1','0x2'))
            for command,options in [('instructions',['--from','0','--to','0','--limit','1']),
                                    ('find-pc',['--off','0','--limit','1'])]:
                selected=self.query(path,command,options)['data'][0]
                self.assertEqual(selected['text'],(text+suffix).decode())
                self.assertEqual((selected['opcode'],selected['completion'],selected['post_observed'],selected['gap']),
                                 ('0x91000400','confirmed',True,False))
            path.write_bytes(path.read_bytes()+b'x')
            self.assertEqual(set(self.query(path,'context',args,ok=False)),{'error'})
            self.assertEqual(set(self.query(path,'instructions',['--from','0','--to','0','--limit','1'],ok=False)),{'error'})

    def test_instruction_empty_pages_still_validate_unselected_records(self):
        for chunked in [False,True]:
            late=self.base();late.insert(-2,(5,2,0x1008,65,8,7,0,1))
            missing=[e for e in self.base() if not(e[0]==9 and e[1]==2)];missing[-1]=(4,3,0,0,0,0,1,2)
            bad_end=self.base();bad_end[-1]=(4,3,0,0,0,0,999,2)
            for events in [late,missing,bad_end]:
                for offset in [0,999]:
                    q=self.query(self.artifact(events,chunked),'instructions',
                        ['--from','0','--to','0','--limit','1','--offset',str(offset)],ok=False)
                    self.assertEqual(set(q),{'error'});self.assertEqual(q['error']['code'],'TRACE_ERROR')

    def test_context_empty_page_still_validates_unselected_records(self):
        for chunked in [False,True]:
            late=self.base();late.insert(-2,(5,2,0x1008,65,8,7,0,1))
            missing=[e for e in self.base() if not(e[0]==9 and e[1]==2)]
            missing[-1]=(4,3,0,0,0,0,1,2)
            bad_end=self.base();bad_end[-1]=(4,3,0,0,0,0,999,2)
            for events in [late,missing,bad_end]:
                for offset in [0,999]:
                    result=self.query(self.artifact(events,chunked),'context',
                        ['--at-ev','0','--before','0','--after','0','--limit','1','--offset',str(offset)],ok=False)
                    self.assertEqual(set(result),{'error'})
                    self.assertEqual(result['error']['code'],'TRACE_ERROR')

    def expand_context_columns(self,compact,named):
        expanded=copy.deepcopy(compact);meta=expanded['meta']
        self.assertEqual(meta.pop('context_format'),'columns-v1')
        columns=meta.pop('columns');sets=meta.pop('register_sets')
        self.assertEqual(set(columns),set(named['data'][0])|{'register_set'} if named['data'] else {
            'ev','pc','off','opcode','text','focus','completion','gap','gap_reasons',
            'register_set','pre','post','memory','scope_exit','scope_reentry'})
        rows=[]
        for cells in expanded['data']:
            self.assertEqual(len(cells),len(columns));row=dict(zip(columns,cells));ref=row.pop('register_set')
            self.assertIs(type(ref),int);self.assertTrue(0<=ref<len(sets));names=sets[ref]
            self.assertEqual(len(names),len(set(names)))
            for phase in ['pre','post']:
                if row[phase] is not None:
                    self.assertEqual(len(row[phase]),len(names));row[phase]=dict(zip(names,row[phase]))
            rows.append(row)
        expanded['data']=rows
        if meta['next']:
            args=shlex.split(meta['next']);self.assertIn('--compact',args)
            self.assertEqual([a for a in args if a!='--compact'],shlex.split(named['meta']['next']))
            meta['next']=named['meta']['next']
        self.assertEqual(expanded,named)
        return expanded

    def test_context_compact_keeps_full_facts_and_self_contained_pages(self):
        all65=[a for name in [*[f'x{i}' for i in range(31)],'sp','nzcv',*[f'v{i}' for i in range(32)]] for a in ['--reg',name]]
        for chunked in [False,True]:
            for selection in [[],all65,['--reg','w0','--reg','q31','--reg','d31','--reg','xzr','--reg','w0']]:
                events=self.compact_events();path=self.artifact(events,chunked)
                args=['--at-ev','0','--at-ev','5','--before','5','--after','5',*selection]
                for offset in [0,1,5,999]:
                    page_args=[*args,'--offset',str(offset),'--limit','2']
                    named=self.query(path,'context',page_args)
                    packed=self.query(path,'context',[*page_args,'--compact'])
                    self.expand_context_columns(packed,named)
                    if not named['data']:self.assertEqual(packed['meta']['register_sets'],[])
            events=self.base();events.insert(2,(5,0,0x1000,64,16,1,2,1));events.insert(4,(6,0,0x1000,64,16,3,4,1))
            events.insert(3,(7,0,0x1000,0x2000,8,0,0,0));events[-1]=(4,3,0,0,0,1,2,2)
            path=self.artifact(events,chunked);args=['--at-ev','0','--before','0','--after','0',*all65]
            q=self.expand_context_columns(self.query(path,'context',[*args,'--compact']),self.query(path,'context',args))
            self.assertEqual(len(q['data'][0]['pre']),65)
            self.assertEqual(q['data'][0]['pre']['v31'],'0x20000000000000001')
            self.assertEqual(q['data'][0]['post']['v31'],'0x40000000000000003')
            self.assertIsNone(q['data'][0]['pre']['x1']);self.assertIsNone(q['data'][0]['memory'][0]['val'])
            events.insert(-1,(3,3,0,0,0,0,0,4));events[-1]=(4,3,0,0,1,1,2,2)
            path=self.artifact(events,chunked);args=['--at-ev','0','--reg','x0','--reg','xzr']
            q=self.expand_context_columns(self.query(path,'context',[*args,'--compact']),self.query(path,'context',args))
            self.assertEqual(q['data'][0]['pre'],{'x0':None,'xzr':'0x0'})

    def test_context_compact_rejects_unselected_damage_and_requires_json(self):
        for chunked in [False,True]:
            late=self.base();late.insert(-2,(5,2,0x1008,65,8,7,0,1))
            missing=[e for e in self.base() if not(e[0]==9 and e[1]==2)];missing[-1]=(4,3,0,0,0,0,1,2)
            for events in [late,missing,self.base()]:
                path=self.artifact(events,chunked)
                if events==self.base():path.write_bytes(path.read_bytes()+b'x')
                for offset in [0,999]:
                    q=self.query(path,'context',['--at-ev','0','--before','0','--after','0','--limit','1','--offset',str(offset),'--compact'],ok=False)
                    self.assertEqual(set(q),{'error'});self.assertEqual(q['error']['code'],'TRACE_ERROR')
        r=subprocess.run([str(ROOT/'cli/traceq'),'context',str(self.artifact(self.base())),'--at-ev','0','--compact'],capture_output=True,text=True)
        self.assertEqual(r.returncode,2);self.assertIn('--compact requires --json',r.stderr)

    def paging_events(self):
        base=self.base()
        return [*base[:3],(2,0,0x1000,0x2000,2,0xbbaa,0,1),(7,0,0x1000,0x2002,1,0,0,0),
                *base[3:5],(3,1,0x1004,0,0,0,0,6),base[5],
                (2,2,0x1008,0x2001,1,0xcc,0,1),base[6],(4,3,0,2,1,1,2,2)]

    def test_query_pages_keep_totals_filters_and_later_state(self):
        path=self.artifact(self.paging_events())
        cases=[('instructions',[],'ev',[0,1,2]),
               ('instructions',['--gaps'],'ev',[1]),
               ('find-pc',['--off','0','--off','8'],'ev',[0,2]),
               ('mem-access',['--range','0x2000,4'],'ev',[0,0,2]),
               ('mem-access',['--range','0x2000,4','--read'],'val',[None]),
               ('mem-access',['--range','0x2000,4','--write','--from','1'],'val',['0xcc']),
               ('reg-state',['--at-ev','2','--reg','x0','--reg','xzr','--reg','v0'],'val',[None,'0x0',None]),
               ('mem-state',['--range','0x2000,4','--at-ev','2'],'value',[None,'0xcc',None,None]),
               ('last-writers',['--range','0x2000,4'],'value',[None,'0xcc',None,None]),
               ('stat',[],'profile',[2])]
        for cmd,args,key,expected in cases:
            for offset in sorted({0,1,len(expected)-1,len(expected),len(expected)+7}):
                with self.subTest(command=cmd,args=args,offset=offset):
                    q=self.query(path,cmd,[*args,'--limit','1','--offset',str(offset)])
                    self.assertEqual([row[key] for row in q['data']],expected[offset:offset+1])
                    self.assertEqual(q['meta']['total'],len(expected))
                    self.assertEqual(q['meta']['shown'],len(expected[offset:offset+1]))
                    self.assertEqual(q['meta']['truncated'],offset+1<len(expected))
                    self.assertEqual((q['meta']['reads'],q['meta']['stores'],q['meta']['capture_gaps']),(1,2,1))
                    if q['meta']['truncated']:
                        self.assertTrue(q['meta']['next'].endswith('--offset '+str(offset+1)))
                    else:self.assertEqual(q['meta']['next'],'')
        historical=self.query(path,'last-writers',['--range','0x2000,4','--limit','1'])['data'][0]
        self.assertFalse(historical['known'])
        self.assertEqual(historical['last_observed_write']['value'],'0xaa')
        self.assertEqual(historical['last_observed_write']['latest_gap_ev'],1)

    def test_page_limits_do_not_hide_invalid_suffix(self):
        events=self.paging_events()
        invalid=[events[:-1],events[:-1]+[(4,3,0,99,1,1,2,2)],
                 events[:-1]+[(999,2,0x1008,0,0,0,0,0),events[-1]]]
        cases=[('instructions',[]),('find-pc',['--off','0']),
               ('mem-access',['--range','0x2000,4']),('reg-state',['--at-ev','0']),
               ('mem-state',['--range','0x2000,4','--at-ev','0']),
               ('last-writers',['--range','0x2000,4']),('stat',[])]
        for variant in invalid:
            path=self.artifact(variant)
            for cmd,args in cases:
                for offset in [0,99]:
                    with self.subTest(command=cmd,offset=offset):
                        q=self.query(path,cmd,[*args,'--limit','1','--offset',str(offset)],ok=False)
                        self.assertEqual(set(q),{'error'})
                        self.assertEqual(q['error']['code'],'TRACE_ERROR')

    def test_all_register_slots_survive_updates_inheritance_and_gap(self):
        names=[*[f'x{i}' for i in range(31)],'sp','nzcv',*[f'v{i}' for i in range(32)]]
        values=[(0x8000000000000100+i) | ((0x8877000000000000+i)<<64 if i>=33 else 0) for i in range(65)]
        def observation(kind,seq,slot,value):
            return (kind,seq,0x1000+4*seq,slot,8 if slot<33 else 16,value&((1<<64)-1),value>>64,1)
        events=[(1,0,0x1000,0x91000400,0,0,0,1)]
        events += [observation(5,0,i,v) for i,v in enumerate(values)]
        changes={0:5,32:0xf0000000,64:(1<<128)-1}
        events += [observation(6,0,i,v) for i,v in changes.items()]
        events += [(9,0,0x1000,0,0,0,0,1),(1,1,0x1004,0x91000400,0,0,0,1),
                   (9,1,0x1004,0,0,0,0,1),(1,2,0x1008,0x91000400,0,0,0,0),
                   (3,2,0x1008,0,0,0,0,1),(1,3,0x100c,0x91000400,0,0,0,1),
                   observation(5,3,64,1<<127),observation(6,3,1,0x1234),
                   (9,3,0x100c,0,0,0,0,1),(4,4,0,0,1,0,3,2)]
        path=self.artifact(events);regs=[part for name in names for part in ('--reg',name)]
        for ev,phase in [(0,'pre'),(0,'post'),(1,'pre'),(1,'post'),(3,'pre'),(3,'post')]:
            expected={name:hex(values[i]) for i,name in enumerate(names)}
            if ev==1 or (ev==0 and phase=='post'):
                expected.update({names[i]:hex(v) for i,v in changes.items()})
            if ev==3:
                expected={name:None for name in names};expected['v31']=hex(1<<127)
                if phase=='post':expected['x1']='0x1234'
            q=self.query(path,'reg-state',['--at-ev',str(ev),'--phase',phase,*regs,'--limit','65'])
            self.assertEqual({r['reg']:r['val'] for r in q['data']},expected)
            self.assertEqual([r['known'] for r in q['data']],[expected[name] is not None for name in names])

    def test_adjacent_instruction_states_do_not_leak(self):
        events=[]
        def event(kind,seq,address=0,size=0,low=0,high=0,detail=1):
            events.append((kind,seq,0x1000+4*seq,address,size,low,high,detail))
        def instruction(seq,completion):
            event(1,seq,0x91000400,detail=completion)
        instruction(0,1)
        event(5,0,0,8,10);event(5,0,64,16,1,0x8000000000000000)
        event(6,0,0,8,11);event(6,0,64,16,2,0x9000000000000000)
        event(7,0,0x2000,8,0x1234);event(2,0,0x2008,8,0x5678);event(9,0)
        instruction(1,0);event(5,1,0,8,20)
        instruction(2,1);event(9,2)
        instruction(3,0);event(3,3,detail=1)
        instruction(4,1);event(5,4,64,16,3,0xa000000000000000)
        event(6,4,1,8,30);event(7,4,0x2000,4,detail=0);event(9,4)
        instruction(5,0)
        instruction(6,1);event(6,6,0,8,40);event(9,6)
        events.append((4,7,0,1,1,2,4,2))
        path=self.artifact(events)
        q=self.query(path,'context',['--at-ev','3','--before','3','--after','3',
                                    '--reg','x0','--reg','x1','--reg','v31'])
        vectors=[hex((h<<64)|lo) for h,lo in [(0x8000000000000000,1),(0x9000000000000000,2),(0xa000000000000000,3)]]
        expected=[((10,None,vectors[0]),(11,None,vectors[1])),
                  ((20,None,vectors[1]),None),((20,None,vectors[1]),(20,None,vectors[1])),
                  ((20,None,vectors[1]),None),((None,None,vectors[2]),(None,30,vectors[2])),
                  ((None,30,vectors[2]),None),((None,30,vectors[2]),(40,30,vectors[2]))]
        def state(values):
            return {k:hex(v) if isinstance(v,int) else v for k,v in zip(('x0','x1','v31'),values)}
        self.assertEqual(len(q['data']),7)
        for row,(pre,post) in zip(q['data'],expected):
            self.assertEqual(row['pre'],state(pre))
            self.assertEqual(row['post'],state(post) if post else None)
            self.assertEqual(row['gap'],row['ev']==3)
            self.assertIsNone(row['scope_exit']);self.assertIsNone(row['scope_reentry'])
        self.assertEqual([len(r['memory']) for r in q['data']],[2,0,0,0,1,0,0])
        self.assertFalse(q['data'][4]['memory'][0]['known'])
        self.assertIsNone(q['data'][4]['memory'][0]['val'])

    def test_first_located_gap_is_stable_and_reset_by_new_write(self):
        events=self.paging_events()
        # Insert the second gap before this instruction's memory/commit records.
        events.insert(9,(3,2,0x1008,0,0,0,0,1));events[-1]=(4,3,0,2,2,1,2,2)
        path=self.artifact(events)
        historical=self.query(path,'last-writers',['--range','0x2000,2','--at-seq','0'])
        self.assertTrue(all(r['known'] for r in historical['data']))
        self.assertTrue(all(r['last_observed_write']['first_located_gap'] is None for r in historical['data']))
        q=self.query(path,'last-writers',['--range','0x2000,2'])
        first=q['data'][0]['last_observed_write']
        self.assertFalse(q['data'][0]['known'])
        self.assertEqual((first['first_located_gap']['ev'],first['latest_gap_ev']),(1,2))
        self.assertEqual(first['first_located_gap']['reasons'],['outside_code_range'])
        self.assertIsNone(first['first_located_gap']['scope_exit'])
        self.assertTrue(q['data'][1]['known'])
        self.assertIsNone(q['data'][1]['last_observed_write']['first_located_gap'])

    def test_first_gap_links_boundary_without_future_reentry(self):
        shifted=[]
        for item in self.boundary_events():
            e=list(item)
            if e[0] in (1,3,5,11,12):e[1]+=1;e[2]+=4
            if e[0]==11 and e[4]==1:e[5]+=4
            if e[0]==12:e[3]+=1
            if e[0]==4:e=[4,3,0,1,1,0,1,2]
            shifted.append(tuple(e))
        prefix=[(1,0,0x1000,0x91000400,0,0,0,1),(2,0,0x1000,0x2000,1,0xab,0,1),
                (9,0,0x1000,0,0,0,0,1)]
        events=shifted[:2]+prefix+shifted[2:];path=self.artifact(events)
        def evidence(at):
            q=self.query(path,'last-writers',['--range','0x2000,1','--at-seq',str(at)])
            self.assertFalse(q['data'][0]['known'])
            return q['data'][0]['last_observed_write']['first_located_gap']
        first=evidence(1)
        self.assertEqual(first['ev'],1);self.assertEqual(first['pc_offset'],'0x4')
        self.assertEqual(first['scope_exit']['target']['module'],'external.so')
        self.assertEqual(first['scope_exit']['target']['offset'],'0x10')
        self.assertIsNone(first['scope_exit']['reentry_ev'])
        self.assertEqual(first['scope_exit']['memory_effects'],'unobserved')
        self.assertEqual(evidence(2)['scope_exit']['reentry_ev'],2)
        events.insert(-1,(3,3,0,0,0,0,0,4));events[-1]=(4,3,0,1,2,0,1,2)
        global_gap=self.query(self.artifact(events),'last-writers',['--range','0x2000,1','--at-seq','0'])
        self.assertTrue(global_gap['meta']['unpositioned_gap'])
        self.assertFalse(global_gap['data'][0]['known'])
        self.assertIsNone(global_gap['data'][0]['last_observed_write']['first_located_gap'])

    def test_queries_validate_unused_register_records_after_selection(self):
        def reg(kind,slot=0,size=8,low=1,high=0,detail=1,seq=2):
            return (kind,seq,0x1000+4*seq,slot,size,low,high,detail)
        variants=[([reg(6,65,16)],'invalid register observation'),
                  ([reg(6,64,8)],'invalid register observation'),
                  ([reg(6,high=1)],'invalid register observation'),
                  ([reg(6,detail=0)],'invalid register observation'),
                  ([reg(6),reg(5)],'late pre-state observation')]
        cases=[('instructions',['--from','0','--to','0']),
               ('find-pc',['--off','0','--to','0']),
               ('stat',[]),
               ('reg-state',['--at-ev','0','--phase','pre','--reg','v31']),
               ('reg-state',['--at-ev','0','--phase','post','--reg','x0']),
               ('mem-access',['--range','0x2000,4','--from','0','--to','0']),
               ('mem-state',['--range','0x2000,4','--at-ev','0']),
               ('last-writers',['--range','0x2000,4','--at-seq','0']),
               ('find-value',['--value','0xaa','--write','--from','0','--to','0']),
               ('find-value',['--value','0','--read','--from','0','--to','0'])]
        for suffix,message in variants:
            events=self.paging_events();events[-2:-2]=suffix
            path=self.artifact(events)
            for cmd,args in cases:
                with self.subTest(command=cmd,message=message,record=suffix):
                    q=self.query(path,cmd,[*args,'--limit','1'],ok=False)
                    self.assertEqual(set(q),{'error'})
                    self.assertEqual(q['error'],{'code':'TRACE_ERROR','message':message})

    def test_queries_validate_inherited_and_resynchronized_boundary_states(self):
        def reg(kind,ev,slot):
            return (kind,ev,0x1000+4*ev,slot,8 if slot<33 else 16,slot+1,1 if slot==64 else 0,1)
        events=self.boundary_events()[:2]+[(1,0,0x1000,0x91000400,0,0,0,1)]
        events += [reg(5,0,i) for i in range(65)]
        events += [reg(6,0,0),(2,0,0x1000,0x2000,1,0xab,0,1),(9,0,0x1000,0,0,0,0,1),
                   (1,1,0x1004,0x91000400,0,0,0,0),
                   (11,1,0x1004,0x3010,1,0x1008,0,1),(3,1,0x1004,0,0,0,0,6),
                   (1,2,0x1008,0x91000400,0,0,0,1)]
        events += [reg(5,2,i) for i in range(65)]
        events += [(12,2,0x1008,1,0,0,0,1),(7,2,0x1008,0x2002,1,0x99,0,0),
                   (2,2,0x1008,0x2001,1,0,0,1),(9,2,0x1008,0,0,0,0,1),
                   (1,3,0x100c,0x91000400,0,0,0,0),(11,3,0x100c,0x5000,3,0,0,1),
                   (4,4,0,2,1,1,2,2)]
        # A slot first observed after completion must also be inherited by
        # the next instruction, without counting a duplicate as a new slot.
        post_filled=[e for e in events if e[:4]!=(5,0,0x1000,64)]
        at=next(i for i,e in enumerate(post_filled) if e[0]==6)
        post_filled.insert(at,reg(6,0,64))
        for valid in [events,post_filled]:
            path=self.artifact(valid)
            rows=self.query(path,'last-writers',['--range','0x2000,3'])['data']
            self.assertEqual([r['known'] for r in rows],[False,True,False])
            self.assertEqual(rows[0]['last_observed_write']['value'],'0xab')
            self.assertEqual(rows[0]['last_observed_write']['first_located_gap']['scope_exit']['reentry_ev'],2)
            self.assertEqual(rows[1]['value'],'0x0')
            state=self.query(path,'mem-state',['--range','0x2000,3','--at-ev','2'])
            self.assertEqual([r['value'] for r in state['data']],[None,'0x0',None])
            self.assertEqual(self.query(path,'find-value',['--value','0','--read'])['data'],[])
            self.assertEqual([r['ev'] for r in self.query(path,'find-value',['--value','0','--write'])['data']],[2])
            for cmd,args in [('instructions',['--from','0','--to','0']),('find-pc',['--off','0']),('stat',[])]:
                summary=self.query(path,cmd,args)['meta']
                self.assertEqual((summary['instructions'],summary['confirmed_instructions'],summary['capture_gaps'],summary['scope_exits'],summary['scope_reentries']),(4,2,1,2,1))
                self.assertFalse(summary['unpositioned_gap'])
        cases=[('instructions',['--from','0','--to','0']),
               ('find-pc',['--off','0','--to','0']),
               ('stat',[]),
               ('mem-access',['--range','0x2000,3','--to','0']),
               ('mem-state',['--range','0x2000,3','--at-ev','0']),
               ('last-writers',['--range','0x2000,3','--at-seq','0']),
               ('find-value',['--value','0xab','--write','--to','0'])]
        for ev,message in [(0,'incomplete scope exit state'),(2,'incomplete scope reentry state')]:
            for duplicate in [False,True]:
                invalid=[]
                for e in events:
                    if e[:4]==(5,ev,0x1000+4*ev,64):
                        if duplicate:invalid.append(reg(5,ev,0))
                    else:invalid.append(e)
                path=self.artifact(invalid)
                for cmd,args in cases:
                    with self.subTest(command=cmd,event=ev,duplicate=duplicate):
                        q=self.query(path,cmd,[*args,'--limit','1'],ok=False)
                        self.assertEqual(q['error'],{'code':'TRACE_ERROR','message':message})

if __name__=='__main__':unittest.main()
