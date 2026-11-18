#!/usr/bin/env python3
"""Small behavioral check: real CLI outputs, rejected requests and cost accounting."""
import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'evaluation'))

import bench
import query


def validate_evaluation_logs(out):
    """Keep native Codex stderr distinct from its harness, including on failure."""
    out.mkdir(parents=True, exist_ok=False)
    run = out / 'native-control'
    bench.pack(run, 'independent', {}, 'Native log regression; no model call.')
    binary_dir = out / 'bin'
    binary_dir.mkdir()
    executable = binary_dir / 'codex'
    executable.write_text('#!' + sys.executable + '\nimport json, os, sys\n'
        'print(json.dumps({"type":"native_log_fixture", "env":{name:os.environ.get(name) '
        'for name in ("TMPDIR","TMPPREFIX","PYTHONPYCACHEPREFIX")}}))\n'
        'sys.stderr.write("codex-native-fixture-stderr\\n")\n'
        'raise SystemExit(17)\n')
    executable.chmod(0o755)
    command = [sys.executable, str(Path(bench.__file__)), 'agent', '--run', str(run),
               '--task', 'independent', '--model', 'gpt-6.1-terra', '--effort', 'max', '--seconds', '720']
    result = subprocess.run(command, capture_output=True, text=True, timeout=20,
                            env=dict(os.environ, PATH=str(binary_dir) + os.pathsep + os.environ['PATH']))
    destination = run / 'independent'
    assert result.returncode == 17 and result.stderr == ''
    assert (destination / 'agent.stderr').read_text() == 'codex-native-fixture-stderr\n'
    observed = json.loads((destination / 'agent.jsonl').read_text())
    environment = json.loads((destination / 'agent-environment.json').read_text())['overrides']
    assert observed['type'] == 'native_log_fixture' and observed['env'] == environment
    assert set(environment) == set(bench.EVALUATION_TEMP_ENV_KEYS)
    assert all(Path(value).is_relative_to(destination / 'work/scratch') for value in environment.values())
    runner_path = ROOT / 'evaluation/run_product_evaluation.py'
    spec = importlib.util.spec_from_file_location('product_evaluation_log_check', runner_path)
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    logs = runner.write_harness_logs(destination, 'agent', result)
    assert Path(logs['agent_stderr']).read_text() == 'codex-native-fixture-stderr\n'
    assert Path(logs['harness_stderr']).read_text() == ''
    assert json.loads(Path(logs['harness_stdout']).read_text())['returncode'] == 17
    before = {p.name: bench.sha(p) for p in destination.iterdir() if p.is_file()}
    try:
        runner.write_harness_logs(destination, 'agent', result)
    except FileExistsError:
        pass
    else:
        raise AssertionError('Existing harness evidence was overwritten')
    assert before == {p.name: bench.sha(p) for p in destination.iterdir() if p.is_file()}
    argv = json.loads((destination / 'agent-command.json').read_text())
    assert argv[argv.index('-m') + 1] == 'gpt-6.1-terra' and 'model_reasoning_effort="max"' in argv
    bench.write(out / 'result.json', {'pass': True, 'control_command': command, 'returncode': 17,
        'logs': logs, 'child_stderr_retained': True, 'raw_jsonl_retained': True,
        'actual_child_temporary_environment': observed['env'],
        'harness_streams_separate': True, 'duplicate_write_rejected_without_mutation': True,
        'model': 'gpt-6.1-terra', 'effort': 'max', 'budget_seconds': 720,
        'scope': 'Native executable fixture with actual bench.agent; no model service or full Agent evaluation.',
        'runner_sha256': bench.sha(runner_path), 'bench_sha256': bench.sha(Path(bench.__file__))})
    print('Native child failure logs retained; harness logs separate; duplicate write rejected', flush=True)


def validate_evaluation_scope(out, original, entry='python', query_kind='context'):
    """Exercise the actual local Codex filesystem policy without a model call."""
    out.mkdir(parents=True, exist_ok=False)
    packed = out / 'fresh'
    work = bench.pack(packed, 'independent', {'sample': {'path': str(original)}}, 'Read the captured evidence.')
    prompt = packed / 'independent/prompt.txt'
    assert prompt.read_text().count(bench.TEMP_GUIDANCE) == 1
    # A frozen old prompt must acquire the policy without changing the old run.
    prompt.write_text(prompt.read_text().replace(bench.TEMP_GUIDANCE + '\n', ''))
    (packed / 'grader').mkdir()
    bench.write(packed / 'manifest.json', {'purpose': 'temporary-write scope regression'})
    repeated = out / 'repeated'
    bench.repeat(repeated, packed)
    assert bench.TEMP_GUIDANCE not in prompt.read_text()
    for run in [repeated, out / 'repeated-again']:
        if run != repeated:
            bench.repeat(run, repeated)
        assert (run / 'independent/prompt.txt').read_text().count(bench.TEMP_GUIDANCE) == 1
    dest = repeated / 'independent'
    work = dest / 'work'
    if entry == 'rust':
        config = json.loads((work / 'tools.json').read_text())
        config['query_backend'] = 'rust'
        bench.write(work / 'tools.json', config)
    launch, env = bench.agent_launch(dest, bench.DEFAULT_MODEL, bench.DEFAULT_EFFORT)
    assert launch[launch.index('-m') + 1] == 'gpt-6.1-terra'
    assert 'model_reasoning_effort="max"' in launch and bench.DEFAULT_SECONDS == 720
    assert 'default_permissions="traceq-eval"' in launch and '--ignore-user-config' in launch
    token = 'traceq-scope-' + uuid.uuid4().hex
    scratch = work / 'scratch'
    targets = {'workspace': work / token, 'scratch': scratch / token,
               'slash_tmp': Path('/tmp') / token,
               'host_tmp': Path(os.environ.get('TMPDIR', '/tmp')).resolve() / token,
               'parent': work.parent / token}
    query_prefix = ([str(work / 'traceq'), 'agent-query', '--manifest', str(work / 'tools.json')]
                    if entry == 'rust' else [sys.executable, '-B', 'query.py'])
    scope_options = {
        'context': ['--at-ev', '0', '--before', '0', '--after', '0', '--reg', 'x0', '--json'],
        'instructions': ['--from', '0', '--limit', '1', '--json'],
        'mem-state': ['--range', '0x7fedf2f370,1', '--checkpoint', '65:post', '--limit', '1', '--json'],
    }
    script = '''import json, os, pathlib, subprocess, sys, tempfile
targets = json.loads(sys.argv[1]); writes = {}
for name, path in targets.items():
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.write(fd, b'traceq scope regression'); os.close(fd)
        writes[name] = {'written': True}
    except OSError as exc:
        writes[name] = {'written': False, 'errno': exc.errno, 'error': str(exc)}
with tempfile.NamedTemporaryFile(delete=False) as f:
    temporary = f.name
shell_text = "cat <<'END' > scratch/heredoc.txt" + chr(10) + 'local shell temporary' + chr(10) + 'END' + chr(10)
shell = subprocess.run(['/bin/zsh', '-lc', shell_text],
    capture_output=True, text=True)
source = pathlib.Path('scratch/compile_control.py')
source.write_text('value = 42' + chr(10))
compiled = subprocess.run([sys.executable, '-m', 'py_compile', str(source)], capture_output=True, text=True)
import importlib.util
bytecode = importlib.util.cache_from_source(str(source.resolve()))
with open('scratch/query-response.json', 'xb') as f:
    r = subprocess.run([*json.loads(sys.argv[2]), *json.loads(sys.argv[3])],
        stdout=f, stderr=subprocess.PIPE)
doc = json.loads(pathlib.Path('scratch/query-response.json').read_text())
print(json.dumps({'writes': writes, 'temporary': temporary,
    'heredoc_returncode': shell.returncode, 'heredoc_stderr': shell.stderr,
    'heredoc_contents': pathlib.Path('scratch/heredoc.txt').read_text(),
    'py_compile_returncode': compiled.returncode, 'py_compile_stderr': compiled.stderr,
    'bytecode': bytecode, 'bytecode_exists': pathlib.Path(bytecode).is_file(),
    'query_returncode': r.returncode,
    'query_stderr': r.stderr.decode(), 'query_rows': len(doc.get('data', [])),
    'query_data': doc.get('data', [])}))
'''
    configs = bench.evaluation_permissions(work)
    assert all(c in launch for c in configs)
    command = ['codex', 'sandbox', '-P', bench.EVALUATION_PROFILE, '-C', str(work),
               *[arg for c in configs for arg in ['-c', c]],
               sys.executable, '-B', '-c', script, json.dumps({k: str(v) for k, v in targets.items()}),
               json.dumps(query_prefix), json.dumps(['sample', query_kind, *scope_options[query_kind]])]
    r = subprocess.run(command, capture_output=True, text=True, env=env, timeout=30)
    record = {'command': command, 'agent_launch_command': launch,
              'environment_overrides': {name: env[name] for name in bench.EVALUATION_TEMP_ENV_KEYS},
              'version': subprocess.check_output(['codex', '--version'], text=True).strip(),
              'returncode': r.returncode, 'stdout': r.stdout, 'stderr': r.stderr,
              'CLI_sha256': bench.sha(work / 'traceq'),
              'bench_sha256': bench.sha(Path(bench.__file__)),
              'scope': 'Actual native Codex sandbox; no model call. O_EXCL never overwrites existing files. No read isolation claim.'}
    bench.write(out / 'native-scope.json', record)
    assert r.returncode == 0, r.stderr
    observed = json.loads(r.stdout)
    assert {k: v['written'] for k, v in observed['writes'].items()} == {
        'workspace': True, 'scratch': True, 'slash_tmp': False, 'host_tmp': False, 'parent': False}
    assert all(observed['writes'][k]['errno'] in (1, 13) for k in ['slash_tmp', 'host_tmp', 'parent'])
    assert Path(observed['temporary']).resolve().parent == scratch.resolve()
    assert observed['heredoc_returncode'] == 0 and observed['heredoc_contents'] == 'local shell temporary\n'
    assert observed['py_compile_returncode'] == 0 and observed['bytecode_exists']
    assert Path(observed['bytecode']).resolve().is_relative_to((scratch / 'pycache').resolve())
    assert observed['query_returncode'] == 0 and observed['query_rows'] == 1
    if query_kind == 'instructions':
        assert observed['query_data'][0]['ev'] == 0
    elif query_kind == 'mem-state':
        cell = observed['query_data'][0]['data'][0]
        assert cell['known'] and cell['value'] == '0xf1'
    calls = [json.loads(line) for line in (work / 'queries/calls.jsonl').read_text().splitlines()]
    assert len(calls) == 1 and calls[0]['returncode'] == 0 and calls[0]['command'] == query_kind
    if entry == 'rust':
        assert calls[0]['execution_path'] == 'in_process' and calls[0]['query_execution']
        assert not calls[0]['launched_cli'] and calls[0]['delegated_argv'] is None
    else:
        assert calls[0]['launched_cli']
    response = (scratch / 'query-response.json').read_bytes()
    assert (work / 'queries' / (calls[0]['id'] + '.stdout')).read_bytes() == response
    bench.write(out / 'result.json', {'pass': True, 'observed': observed, 'entry': entry, 'query_kind': query_kind,
        'fresh_and_repeated_guidance': True, 'actual_query_and_ledger': True,
        'model': bench.DEFAULT_MODEL, 'effort': bench.DEFAULT_EFFORT, 'budget_seconds': bench.DEFAULT_SECONDS,
        'new_Agent_started': False, 'read_isolation': False, 'native_record': str(out / 'native-scope.json')})
    print('Evaluation temporary-write scope and actual query passed', flush=True)


def validate(out, original, entry='python'):
    out.mkdir(parents=True, exist_ok=False)
    work = out / 'work'
    work.mkdir()
    shutil.copy2(Path(query.__file__), work / 'query.py')
    actual = bench.EVAL_CLI if entry == 'rust' else bench.GT
    marker = work / 'launches.jsonl'
    launcher = work / 'launch.py'
    launcher.write_text('#!' + sys.executable + '\nimport os,sys,json\n'
                        + 'with open(' + repr(str(marker)) + ',"a") as f: f.write(json.dumps(os.environ.get("TRACEQ_QUERY_BACKEND"))+"\\n")\n'
                        + 'os.execv(' + repr(str(bench.GT)) + ',[' + repr(str(bench.GT)) + ',*sys.argv[1:]])\n')
    launcher.chmod(0o755)
    config = bench.tool_manifest(launcher, {'sample1': {'path': str(original)}})
    config['query_backend'] = 'rust'
    bench.write(work / 'tools.json', config)
    assert config['query_policy']['row_limits']['maximum'] == 256
    assert config['query_policy']['row_limits']['default'] == 40
    assert config['query_policy']['memory_state_limits'] == {
        'commands': ['mem-state'], 'unit': 'bytes', 'default': 40, 'minimum': 1, 'maximum': 4096}
    assert config['query_policy']['metadata_reuse'] == query.METADATA_GUIDANCE
    assert config['query_policy']['batch_context'] == query.CONTEXT_GUIDANCE
    assert config['query_policy']['memory_checkpoints'] == query.MEMORY_CHECKPOINT_GUIDANCE
    checks = []

    def invoke(args):
        before = len((work / 'queries/calls.jsonl').read_text().splitlines()) if (work / 'queries/calls.jsonl').exists() else 0
        env = {**os.environ, 'TRACEQ_QUERY_BACKEND': 'cpp'}
        prefix = ([str(actual), 'agent-query', '--manifest', str(work / 'tools.json')]
                  if entry == 'rust' else [sys.executable, str(work / 'query.py')])
        r = subprocess.run([*prefix, *args], capture_output=True, env=env, timeout=15)
        rows = [json.loads(line) for line in (work / 'queries/calls.jsonl').read_text().splitlines()]
        assert len(rows) == before + 1
        c = rows[-1]
        assert c['returncode'] == r.returncode and c['log_schema'] == 2
        assert c['started_ns'] <= c['finished_ns'] and c['seconds'] >= 0
        assert (work / 'queries' / (c['id'] + '.stdout')).read_bytes() == r.stdout
        assert (work / 'queries' / (c['id'] + '.stderr')).read_bytes() == r.stderr
        return r, c

    for args in [
        ['sample1', 'instructions', '--from', '0', '--limit', '300', '--json'],
        ['sample1', 'context', '--at-ev', '0', '--limit', '257'],
        ['sample1', 'context', '--at-ev', '0', '--limit', '1', '--limit', '300'],
        ['sample1', 'instructions', '--limit', 'not-an-integer'],
        ['sample1', 'instructions', '--limit'],
        ['sample1', 'instructions', '--limit', '0'],
        ['sample1', 'mem-state', '--range', '0x7fedf2f370,32', '--at-ev', '65', '--limit', '4097'],
        ['sample1', 'mem-state', '--limit', '0'],
        ['sample1', 'mem-state', '--limit'],
        ['sample1', 'mem-state', '--limit', 'not-an-integer'],
        ['sample1', 'mem-state', '--limit', '32', '--limit', '4096'],
        ['sample1', 'instructions', '--all'],
        ['sample1', 'instructions', '-o', 'out'],
        ['sample1', 'unknown-command'], ['unknown-trace', 'stat'], ['sample1'], [],
    ]:
        r, c = invoke(args)
        assert r.returncode == 2 and c['failure_origin'] == 'adapter' and not c['launched_cli']
        result = json.loads(r.stdout)
        assert set(result) == {'error'} and result['error']['origin'] == 'adapter'
        assert result['error']['query_policy'] == config['query_policy']
        assert not marker.exists(), 'rejected request launched the spy/CLI'
        checks.append({'args': args, 'recorded_rejection_no_launch': True})

    options = ['--at-ev', '0', '--at-ev', '64', '--before', '0', '--after', '0', '--reg', 'x0', '--json']
    r, c = invoke(['sample1', 'context', *options])
    expected = subprocess.run([str(bench.GT), 'context', str(original), *options, '--limit', '40'], capture_output=True,
                              env={**os.environ, 'TRACEQ_QUERY_BACKEND': 'rust'}, check=True)
    assert r.returncode == 0 and (r.stdout, r.stderr) == (expected.stdout, expected.stderr)
    assert c['options'][-2:] == ['--limit', '40'] and c['launched_cli'] and c['failure_origin'] is None
    assert json.loads(marker.read_text().splitlines()[-1]) == 'rust'
    checks.append({'valid_context_stdout_unchanged': True, 'explicit_backend_overrides_environment': True})

    named = json.loads(expected.stdout)
    header = subprocess.run([str(actual), 'stat', str(original), '--json'], capture_output=True, check=True)
    header = json.loads(header.stdout)
    assert named['meta']['code_base'] == header['meta']['code_base'] == '0x7c38d4d000'
    assert named['meta']['thread_id'] == header['meta']['thread_id']
    for field, value in {'code_size': 12288, 'data_base': '0x0', 'data_size': '0xffffffffffffffff',
                         'reads': 8, 'unknown_reads': 0, 'stores': 9, 'confirmed_instructions': 58,
                         'scope_exits': 1, 'scope_reentries': 0}.items():
        assert named['meta'][field] == header['meta'][field] == value
    assert named['meta']['scope'] == header['meta']['scope']
    # Format/profile and detailed diagnostics still require stat.
    assert 'profile' not in named['meta'] and 'profile' in header['data'][0]

    r, _ = invoke(['sample1', 'context', '--at-ev', '0', '--before', '0', '--after', '39', '--json'])
    window = json.loads(r.stdout)
    r, _ = invoke(['sample1', 'instructions', '--from', '0', '--limit', '80', '--json'])
    navigation = json.loads(r.stdout)
    assert window['meta']['instructions'] == navigation['meta']['instructions'] == 67
    assert window['meta']['total'] == len(window['data']) == 40 and not window['meta']['truncated']
    projected = [{**{k: row[k] for k in ['ev', 'pc', 'off', 'opcode', 'text', 'completion', 'gap']},
                  'post_observed': row['completion'] == 'confirmed'} for row in window['data']]
    assert projected == navigation['data'][:40]
    assert len(navigation['data']) == 67 and navigation['data'][-1]['ev'] == 66
    checks.append({'context_contains_returned_instruction_facts': True,
                   'bounded_window_does_not_cover_27_other_events': True})

    memory_options = ['--range', '0x7fedf2f370,32', '--at-ev', '65', '--phase', 'post', '--json']
    r, c = invoke(['sample1', 'mem-state', *memory_options])
    expected_memory = subprocess.run([str(actual), 'mem-state', str(original), *memory_options, '--limit', '40'],
                                     capture_output=True, env={**os.environ, 'TRACEQ_QUERY_BACKEND': 'rust'}, check=True)
    assert r.returncode == 0 and (r.stdout, r.stderr) == (expected_memory.stdout, expected_memory.stderr)
    memory = json.loads(r.stdout)
    assert len(memory['data']) == 32 and not memory['meta']['truncated'] and memory['meta']['next'] == ''
    assert c['options'][-2:] == ['--limit', '40'] and '--limit' not in c['requested_options']
    # Independent full-buffer facts, including the input tail omitted by old20row default.
    assert [int(b['value'], 0) for b in memory['data'][:12]] == list(bytes.fromhex('f130366f79b8a6f8c0b77391'))
    assert memory['data'][23]['value'] == '0xff' and memory['data'][23]['observed_ev'] == 58
    assert all(not memory['data'][i]['known'] and memory['data'][i]['value'] is None for i in [12,13,14,15,24,25,26,27,28,29,30,31])
    for limit in [32, 4096, '0x1000', '010000']:
        r, c = invoke(['sample1', 'mem-state', *memory_options, '--limit', str(limit)])
        assert r.returncode == 0 and json.loads(r.stdout) == memory
        assert c['options'][-2:] == ['--limit', str(limit)]
    # Larger ranges stay bounded and visibly paginated; explicit old limits remain valid.
    large_options = ['--range', '0x7fedf2f370,64', '--at-ev', '65', '--phase', 'post', '--json']
    r, c = invoke(['sample1', 'mem-state', *large_options])
    page = json.loads(r.stdout)
    assert r.returncode == 0 and len(page['data']) == 40 and page['meta']['total'] == 64 and page['meta']['truncated']
    assert '--limit 40' in page['meta']['next'] and '--offset 40' in page['meta']['next']
    r, c = invoke(['sample1', 'mem-state', '--range', '0x7fedf2f370,512', '--at-ev', '65', '--limit', '4096', '--json'])
    assert r.returncode == 0 and len(json.loads(r.stdout)['data']) == 512 and not json.loads(r.stdout)['meta']['truncated']
    checks.append({'memory_default40_full32_known_unknown_sources': True,
                   'explicit_memory_4096_limit_preserved': True, 'larger_range_pagination_preserved': True})
    checkpoint_options=['--range','0x7fedf2f370,32','--checkpoint','0:pre','--checkpoint','65:post','--json']
    r,c=invoke(['sample1','mem-state',*checkpoint_options])
    batch=json.loads(r.stdout)
    assert r.returncode==0 and batch['meta']['memory_format']=='checkpoints-v1'
    assert batch['meta']['shown']==64 and not batch['meta']['truncated']
    assert c['options'][-2:]==['--limit','40']
    assert all(not b['known'] for b in batch['data'][0]['data'])
    assert batch['data'][1]['data']==memory['data']
    assert batch['data'][1]['instruction_completion']=='confirmed'
    r,c=invoke(['sample1','mem-state',*memory_options,'--compact'])
    assert r.returncode==0 and query.expand_mem_state(json.loads(r.stdout))==memory
    r,c=invoke(['sample1','mem-state',*checkpoint_options,'--compact'])
    assert r.returncode==0 and query.expand_mem_state(json.loads(r.stdout))==batch
    checks.append({'compact_memory_single_and_batch_preserve_every_byte_source':True,
                   'compact_frames_keep_byte_limits_and_unknowns':True})
    r,c=invoke(['sample1','mem-state',*checkpoint_options,'--limit','8','--offset','24'])
    assert r.returncode==0 and json.loads(r.stdout)['data'][1]['data']==memory['data'][24:]
    r,c=invoke(['sample1','mem-state',*checkpoint_options,'--phase','pre'])
    assert r.returncode==2 and c['failure_origin']=='cli' and set(json.loads(r.stdout))=={'error'}
    checks.append({'checkpoint_default40_and_per_point_paging':True,'snapshot_values_unknown_and_sources_preserved':True,
                   'mixed_selector_error_stays_recorded_CLI_error':True})
    config['context_format'] = 'columns-v1'
    bench.write(work / 'tools.json', config)
    r, c = invoke(['sample1', 'context', *options])
    compact = json.loads(r.stdout)
    assert query.expand_context(compact) == named
    assert c['context_format'] == 'columns-v1' and '--compact' in c['argv']
    assert '--compact' not in c['requested_options']
    assert compact['meta']['context_format'] == 'columns-v1'
    cols = compact['meta']['columns']
    # Independent literal expectations from the frozen native input, not the formatter.
    row = dict(zip(cols, compact['data'][0]))
    assert row['ev'] == 0 and row['pre'] == ['0xffffffff'] and row['post'] == ['0xffffffff']
    for kind in ['format', 'reference', 'bool_reference', 'width', 'columns', 'names', 'pre']:
        bad = copy.deepcopy(compact)
        if kind == 'format':bad['meta']['context_format'] = 'columns-v2'
        elif kind == 'reference':bad['data'][0][cols.index('register_set')] = -1
        elif kind == 'bool_reference':bad['data'][0][cols.index('register_set')] = True
        elif kind == 'width':bad['data'][0][cols.index('pre')] = []
        elif kind == 'columns':bad['meta']['columns'][0] = 'pc'
        elif kind == 'names':bad['meta']['register_sets'][0] = ['x0','x0']
        elif kind == 'pre':bad['data'][0][cols.index('pre')] = None
        try:query.expand_context(bad)
        except ValueError:pass
        else:raise AssertionError('accepted malformed compact context: ' + kind)
    assert query.expand_context(named) is named
    checks.append({'compact_config_actual_argv_and_facts': True, 'malformed_columns_rejected': 7})
    del config['context_format']

    broken = work / 'broken.gtsw'
    broken.write_bytes(original.read_bytes() + b'x')
    config['traces']['bad'] = {'path': str(broken)}
    bench.write(work / 'tools.json', config)
    r, c = invoke(['bad', 'context', '--at-ev', '0', '--before', '0', '--after', '0', '--json'])
    assert r.returncode and c['launched_cli'] and c['failure_origin'] == 'cli'
    assert json.loads(r.stdout)['error']['code'] == 'TRACE_ERROR'
    checks.append({'bad_trace_still_CLI_error_no_data': True})
    r, c = invoke(['bad', 'context', '--at-ev', '0', '--before', '0', '--after', '39',
                   '--offset', '999', '--json'])
    assert r.returncode and c['failure_origin'] == 'cli' and set(json.loads(r.stdout)) == {'error'}
    checks.append({'context_navigation_empty_page_bad_suffix_rejected': True})
    for offset in [0, 999]:
        r, c = invoke(['bad', 'mem-state', *memory_options, '--offset', str(offset)])
        assert r.returncode and c['launched_cli'] and c['failure_origin'] == 'cli'
        assert set(json.loads(r.stdout)) == {'error'} and json.loads(r.stdout)['error']['code'] == 'TRACE_ERROR'
        r,c=invoke(['bad','mem-state',*checkpoint_options,'--offset',str(offset)])
        assert r.returncode and c['failure_origin']=='cli' and set(json.loads(r.stdout))=={'error'}
    checks.append({'memory_bad_suffix_including_empty_page_still_CLI_error': True})

    packed = out / 'fresh-pack'
    bench.pack(packed, 'independent', config['traces'], "Use stat for each trace's code_base/data_base. Do not transfer addresses. "
               "Recover the actual32byte buffer pointer from x1 with reg-state.\n"
               "Available GTSW profile 2 commands: stat, instructions, reg-state, mem-state.\n"
               "Examples: python3 query.py sample0 instructions --from 0 --limit 80 --json\n"
               "Discover relevant events with instructions, then group known points for the same trace instead of repeating point queries.", entry='python')
    tools = json.loads((packed / 'independent/work/tools.json').read_text())
    assert tools['query_policy'] == query.capabilities()
    (packed / 'grader').mkdir()
    bench.write(packed / 'manifest.json', {'purpose': 'tool metadata fixture only'})
    repeated = out / 'repeated-pack'
    bench.repeat(repeated, packed)
    for task in ['independent']:
        assert json.loads((repeated / task / 'work/tools.json').read_text())['query_policy'] == query.capabilities()
        for run in [packed, repeated]:
            text = (run / task / 'work/TASK.md').read_text()
            assert text.count(query.METADATA_GUIDANCE) == 1
            assert "Use stat for each trace" not in text and 'Use stat for code_base;' not in text
            if task == 'independent':
                assert text.count('Batch known register points with context --reg') == 1
                assert 'buffer pointer from x1 with reg-state' not in text
                assert 'commands: stat, context, instructions, reg-state,' in text
                assert text.count('Examples: python3 query.py sample0 context --at-ev 0 --before 0 --after 39 --limit 40 --json') == 1
                assert 'Discover relevant events with instructions, then' not in text
    rows = [{'log_schema': 2, 'started_ns': a*10**9, 'finished_ns': b*10**9, 'seconds': b-a,
             'returncode': rc, 'launched_cli': launched, 'failure_origin': origin, 'stdout_bytes': 10}
            for a, b, rc, launched, origin in [(0, 2, 0, True, None), (1, 3, 2, False, 'adapter'), (5, 6, 0, True, None)]]
    cost = bench.query_cost(rows)
    assert (cost['count'], cost['errors'], cost['CLI_processes'], cost['adapter_rejections']) == (3, 1, 2, 1)
    assert cost['seconds'] == 5 and cost['active_wall_seconds'] == 4
    legacy = bench.query_cost([{'seconds': 1, 'returncode': 0, 'stdout_bytes': 10}])
    assert legacy['active_wall_seconds'] is None and legacy['adapter_rejections'] is None
    if entry == 'rust':
        direct = out / 'direct-context'
        direct.mkdir()
        direct_config = bench.tool_manifest(actual, {'sample1': {'path': str(original)},
                                                     'bad': {'path': str(broken)}}, 'rust')
        for backend, environment, executable, selected_path in [
                ('rust', 'cpp', actual, 'in_process'), (None, 'rust', actual, 'in_process'),
                ('cpp', 'rust', actual, 'in_process'), (None, 'cpp', actual, 'in_process'),
                ('rust', 'cpp', launcher, 'subprocess')]:
            direct_config['traceq'] = str(executable)
            if backend is None:
                direct_config.pop('query_backend', None)
            else:
                direct_config['query_backend'] = backend
            bench.write(direct / 'tools.json', direct_config)
            r = subprocess.run([str(actual), 'agent-query', '--manifest', str(direct / 'tools.json'),
                                'sample1', 'context', *options], capture_output=True,
                               env={**os.environ, 'TRACEQ_QUERY_BACKEND': environment}, timeout=15)
            assert r.returncode == 0 and (r.stdout, r.stderr) == (expected.stdout, expected.stderr)
            c = json.loads((direct / 'queries/calls.jsonl').read_text().splitlines()[-1])
            assert c['execution_path'] == selected_path and c['query_execution']
            assert c['launched_cli'] == (selected_path == 'subprocess')
            assert (c['delegated_argv'] is not None) == c['launched_cli']
        direct_config.update(traceq=str(actual), query_backend='rust')
        bench.write(direct / 'tools.json', direct_config)
        for trace, extras in [('bad', []), ('bad', ['--offset', '999']),
                              ('sample1', ['--reg', 'q0', '--reg', 'w0', '--compact']),
                              ('sample1', ['--reg', 'invalid']), ('sample1', ['--offset', '999'])]:
            arguments = [trace, 'context', *options, *extras]
            r = subprocess.run([str(actual), 'agent-query', '--manifest', str(direct / 'tools.json'),
                                *arguments], capture_output=True, timeout=15)
            source = direct_config['traces'][trace]['path']
            reference = subprocess.run([str(bench.GT), 'context', source, *options, *extras, '--limit', '40'],
                                       capture_output=True, env={**os.environ, 'TRACEQ_QUERY_BACKEND': 'rust'}, timeout=15)
            assert (r.returncode, r.stdout, r.stderr) == (reference.returncode, reference.stdout, reference.stderr)
            c = json.loads((direct / 'queries/calls.jsonl').read_text().splitlines()[-1])
            assert c['execution_path'] == 'in_process' and not c['launched_cli']
            if trace == 'bad':
                assert r.returncode != 0 and set(json.loads(r.stdout)) == {'error'}
        direct_calls = [json.loads(line) for line in (direct / 'queries/calls.jsonl').read_text().splitlines()]
        direct_cost = bench.query_cost(direct_calls)
        assert direct_cost['query_executions'] == 10 and direct_cost['CLI_processes'] == 1
        assert direct_cost['in_process_queries'] == 9
        direct_config['traces']['nul'] = {'path': 'invalid\0trace'}
        bench.write(direct / 'tools.json', direct_config)
        r = subprocess.run([str(actual), 'agent-query', '--manifest', str(direct / 'tools.json'),
                            'nul', 'context', '--at-ev', '0', '--json'], capture_output=True, timeout=15)
        assert r.returncode == 127 and r.stderr == b''
        assert json.loads(r.stdout)['error'] == {
            'code': 'QUERY_LAUNCH', 'origin': 'launch', 'message': 'nul byte found in provided data'}
        c = json.loads((direct / 'queries/calls.jsonl').read_text().splitlines()[-1])
        assert c['failure_origin'] == 'launch' and not c['query_execution'] and not c['launched_cli']
        assert (direct / 'queries' / (c['id'] + '.stdout')).read_bytes() == r.stdout
        assert (direct / 'queries' / (c['id'] + '.stderr')).read_bytes() == r.stderr
        checks.append({'in_process_same_context_facts_and_backend_selection': True,
                       'manifest_nul_path_preserves_launch_failure_before_worker': True,
                       'configured_other_executable_is_respected': True,
                       'in_process_bad_tail_and_empty_page_reject_success': True,
                       'process_counts_distinguish_queries_from_children': True})
        stream = out / 'direct-stream'
        stream.mkdir()
        stream_config = bench.tool_manifest(actual, {'sample1': {'path': str(original)},
                                                     'bad': {'path': str(broken)}}, 'rust')
        stream_config['query_backend'] = 'rust'
        bench.write(stream / 'tools.json', stream_config)
        stream_cases = [
            ('sample1', 'instructions', ['--from', '0', '--limit', '3', '--offset', '1', '--json']),
            ('sample1', 'instructions', ['--gaps', '--offset', '999', '--json']),
            ('bad', 'instructions', ['--gaps', '--offset', '999', '--json']),
            ('sample1', 'mem-state', memory_options),
            ('sample1', 'mem-state', [*checkpoint_options, '--limit', '8', '--offset', '24']),
            ('sample1', 'mem-state', [*checkpoint_options, '--offset', '999']),
            ('bad', 'mem-state', [*checkpoint_options, '--offset', '999']),
            ('sample1', 'stat', ['--json']),
            ('sample1', 'reg-state', ['--at-ev', '0', '--reg', 'q31', '--json']),
            ('sample1', 'mem-access', ['--range', '0x7fedf2f370,32', '--json']),
            ('sample1', 'last-writers', ['--range', '0x7fedf2f370,32', '--compact', '--json']),
            ('sample1', 'boundaries', ['--json']),
            ('sample1', 'find-pc', ['--off', '0', '--json']),
            ('sample1', 'find-value', ['--value', '0', '--json']),
            ('sample1', 'find-value', ['--bytes', '00', '--json']),
            ('sample1', 'find-value', ['--bytes', '00', '--across-events', '--write', '--context', '1', '--json']),
            ('bad', 'find-value', ['--bytes', '00', '--across-events', '--offset', '999', '--json']),
            ('bad', 'last-writers', ['--range', '0x7fedf2f370,32', '--offset', '999', '--json']),
            ('bad', 'find-value', ['--bytes', '00', '--offset', '999', '--json']),
        ]
        for trace, command, opts in stream_cases:
            limit = [] if '--limit' in opts or command in ('stat', 'last-writers', 'reg-state') else ['--limit', '40']
            r = subprocess.run([str(actual), 'agent-query', '--manifest', str(stream / 'tools.json'),
                                trace, command, *opts], capture_output=True, timeout=15)
            reference = subprocess.run([str(bench.GT), command, stream_config['traces'][trace]['path'], *opts, *limit],
                                       capture_output=True, env={**os.environ, 'TRACEQ_QUERY_BACKEND': 'rust'}, timeout=15)
            assert (r.returncode, r.stdout, r.stderr) == (reference.returncode, reference.stdout, reference.stderr)
            c = json.loads((stream / 'queries/calls.jsonl').read_text().splitlines()[-1])
            assert c['query_execution'] and c['execution_path'] == 'in_process' and not c['launched_cli']
            assert c['delegated_argv'] is None
            assert (stream / 'queries' / (c['id'] + '.stdout')).read_bytes() == r.stdout
            assert (stream / 'queries' / (c['id'] + '.stderr')).read_bytes() == r.stderr
            if trace == 'bad':
                assert r.returncode != 0 and set(json.loads(r.stdout)) == {'error'}
        checks.append({'in_process_instructions_and_memory_single_checkpoints_pages': True,
                       'whole_stream_validation_on_empty_and_gap_only_pages': True,
                       'all_direct_output_captured_in_ledger': True})
        r, c = invoke(['--help'])
        assert r.returncode == 0 and b'traceq agent-query' in r.stdout
        assert c['request_kind'] == 'help' and c['entry_kind'] == 'rust' and not c['launched_cli']
        r, c = invoke(['--capabilities'])
        assert r.returncode == 0 and json.loads(r.stdout) == query.capabilities()
        assert c['request_kind'] == 'capabilities' and not c['launched_cli']
        checks.append({'native_help_and_capabilities_recorded_without_trace_launch': True})
        native_pack = out / 'native-pack'
        assert bench.DEFAULT_ENTRY == 'rust'
        native_work = bench.pack(native_pack, 'independent', {'sample1': {'path': str(original)}},
                                 'Examples: python3 query.py sample1 context --at-ev 0 --json')
        (native_pack / 'grader').mkdir()
        bench.write(native_pack / 'manifest.json', {'purpose': 'entry selection regression'})
        native_repeat = out / 'native-repeat'
        bench.repeat(native_repeat, native_pack)
        python_repeat = out / 'python-repeat'
        bench.repeat(python_repeat, native_repeat, entry='python')
        python_inherited = out / 'python-inherited'
        bench.repeat(python_inherited, python_repeat)
        # Legacy packs predate query_entry; only the fresh repeat gets the new default.
        legacy_config = json.loads((native_work / 'tools.json').read_text())
        del legacy_config['query_entry']
        bench.write(native_work / 'tools.json', legacy_config)
        legacy_repeat = out / 'legacy-repeat'
        bench.repeat(legacy_repeat, native_pack)
        legacy_config['query_entry'] = 'rust'
        bench.write(native_work / 'tools.json', legacy_config)
        for run, selected in [(native_pack, 'rust'), (native_repeat, 'rust'), (python_repeat, 'python'),
                              (python_inherited, 'python'), (legacy_repeat, 'rust')]:
            folder = run / 'independent/work'
            metadata = json.loads((folder / 'tools.json').read_text())
            assert metadata['query_entry'] == selected
            assert metadata['query_policy'] == query.capabilities()
            assert bench.ENTRY_COMMANDS[selected] in (folder / 'TASK.md').read_text()
            assert bench.ENTRY_COMMANDS[selected] in (run / 'independent/prompt.txt').read_text()
            assert not (folder / 'queries').exists(), 'capability discovery created phantom query records'
        checks.append({'native_pack_repeat_and_explicit_python_compatibility': True,
                       'default_native_entry_and_legacy_repeat': True,
                       'compiled_capabilities_no_phantom_queries': True})
    report = {'pass': True, 'checks': checks, 'new_pack_advertises_actual_policy': True,
              'entry': entry,
              'overlap_accounting': cost, 'legacy_unknown_not_reported_as_zero': True,
              'CLI_sha256': hashlib.sha256(actual.read_bytes()).hexdigest(),
              'query_sha256': bench.sha(Path(query.__file__)), 'bench_sha256': bench.sha(Path(bench.__file__)),
              'scope': 'Real CLI over frozen Android SDK capture; spy records process launch only. No Agent, capture or phone operation.'}
    bench.write(out / 'result.json', report)
    print(json.dumps({k: v for k, v in report.items() if k != 'checks'}), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path, default=ROOT / 'artifacts' / ('adapter-check-' + str(time.time_ns())))
    parser.add_argument('--entry', choices=['python', 'rust'], default='python')
    parser.add_argument('--trace', type=Path,
                        help='Frozen iteration-083 sample1.gtsw fixture required by the adapter assertions')
    parser.add_argument('--scope-query', choices=['context', 'instructions', 'mem-state'])
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--evaluation-scope-only', action='store_true')
    modes.add_argument('--evaluation-logs-only', action='store_true')
    args = parser.parse_args()
    if args.scope_query is not None and not args.evaluation_scope_only:
        parser.error('--scope-query requires --evaluation-scope-only')
    if not args.evaluation_logs_only and args.trace is None:
        parser.error('--trace is required except with --evaluation-logs-only')
    if args.trace is not None and not args.trace.is_file():
        parser.error('--trace must point to the frozen sample1.gtsw file')
    if args.evaluation_logs_only:
        validate_evaluation_logs(args.out.resolve())
    else:
        if args.evaluation_scope_only:
            validate_evaluation_scope(args.out.resolve(), args.trace.resolve(), args.entry,
                                      args.scope_query or 'context')
        else:
            validate(args.out.resolve(), args.trace.resolve(), args.entry)
