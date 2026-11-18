"""Existing bounded Agent task, sequential fresh contexts and independent scorer."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
import bench


def write_harness_logs(destination, action, result):
    # bench.agent owns agent.jsonl and agent.stderr. Preserve those raw streams.
    logs = {}
    for stream in ('stdout', 'stderr'):
        path = destination / ('harness-' + action + '.' + stream)
        with path.open('x') as output:
            output.write(getattr(result, stream))
        logs['harness_' + stream] = str(path)
    if action == 'agent':
        logs.update(agent_jsonl=str(destination / 'agent.jsonl'),
                    agent_stderr=str(destination / 'agent.stderr'))
    return logs


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--artifact-dir', type=Path,
                        help='Read evaluation packs and save steps here; defaults to the active run')
    args = parser.parse_args()
    out = args.artifact_dir or Path(json.loads((ROOT / 'experiments/self_iteration/state.json').read_text())['active_run']['artifact_dir'])
    harness = ROOT / 'evaluation/bench.py'
    packs = json.loads((out / 'Agent-evaluation-packs.json').read_text())
    steps = []
    for pack in packs:
        assert (pack['model'], pack['effort'], pack['budget_seconds']) == (bench.DEFAULT_MODEL, bench.DEFAULT_EFFORT, bench.DEFAULT_SECONDS)
        run, backend, task = Path(pack['run']), pack['backend'], pack['task']
        assert bench.sha(run / task / 'work/traceq') == pack['sha256']
        config = json.loads((run / task / 'work/tools.json').read_text())
        assert config['query_backend'] == backend
        if 'entry' in pack:
            assert config.get('query_entry', 'python') == pack['entry']
        if 'context_format' in pack:
            assert config['context_format'] == pack['context_format']
        if 'adapter_sha256' in pack:
            assert bench.sha(run / task / 'work/query.py') == pack['adapter_sha256']
        for action in ['agent', 'score']:
            cmd = [sys.executable, str(harness), action, '--run', str(run), '--task', task]
            if action == 'agent':
                # Explicit values are retained in this invocation and actual codex argv.
                cmd += ['--model', 'gpt-6.1-terra', '--effort', 'max', '--seconds', '720']
            started = time.monotonic()
            env = os.environ.copy()
            env['TRACEQ_QUERY_BACKEND'] = backend
            r = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=750 if action == 'agent' else 180)
            logs = write_harness_logs(run / task, action, r)
            step = {'backend': backend, 'task': task, 'action': action, 'command': cmd,
                    'comparison_arm': pack.get('arm', backend), 'context_format': pack.get('context_format'),
                    'model': pack['model'], 'reasoning_effort': pack['effort'], 'budget_seconds': pack['budget_seconds'],
                    'query_backend': backend,
                    'returncode': r.returncode, 'seconds': time.monotonic() - started,
                    'logs': logs}
            steps.append(step)
            bench.write(out / 'Agent-evaluation-steps.json', steps)
            print(json.dumps(step), flush=True)
            if r.returncode:
                # Keep the requested configuration and raw error. Never switch models.
                raise SystemExit(r.returncode)
            if action == 'score':
                assert json.loads((run / task / 'score.json').read_text())['all_functional_checks_passed']
    print('Paired Terra/max product evaluations finished', flush=True)


if __name__ == '__main__':
    main()
