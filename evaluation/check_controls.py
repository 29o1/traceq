#!/usr/bin/env python3
"""Run a deliberately incorrect submission through the same actual scorer."""
import argparse
import json
from pathlib import Path

from bench import native_reference, repeat, score, write


OMITTED_WRITES = '''import json, sys
for line in sys.stdin:
    q = json.loads(line)
    s = q["seed"] & 0xffffffff
    data = q["initial"].to_bytes(8, "little")
    for b in data[:min(q["count"], 8)]:
        s = ((s ^ b) * 33 + 17) & 0xffffffff
    print(json.dumps({"result": s, "buffer_hex": "00" * 32}))
'''


def check(baseline, run):
    repeat(run, baseline)
    result = {}
    manifest = json.loads((run / 'manifest.json').read_text())
    native_reference(run, manifest)
    try:
        native_reference(run, dict(manifest, fixture_sha256='0' * 64))
    except ValueError:
        result['changed_native_reference_rejected'] = True
    else:
        raise AssertionError('Changed native reference escaped the identity gate')
    for task, code in [('independent', OMITTED_WRITES)]:
        dest = run / task
        if not dest.is_dir():
            continue
        (dest / 'work/solution.py').write_text(code)
        (dest / 'agent.jsonl').write_text('')
        write(dest / 'agent-run.json', {'model': None, 'role': 'deliberately wrong control; no agent invoked'})
        score(run, task)
        report = json.loads((dest / 'score.json').read_text())
        assert report['solution_protocol_ok'], 'Control failed to run, so it did not test semantic grading'
        assert not report['all_functional_checks_passed'], 'Incorrect implementation escaped grading'
        result[task] = report['scores']
        if task == 'independent':
            rows = json.loads((dest / 'score-details.json').read_text())['rows']
            result[task]['return_only'] = {'passed': sum(r['actual']['result'] == r['expected']['result'] for r in rows), 'total': len(rows)}
    write(run / 'control-results.json', result)
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--baseline', type=Path, required=True)
    parser.add_argument('--run', type=Path, required=True)
    args = parser.parse_args()
    check(args.baseline.resolve(), args.run.resolve())
