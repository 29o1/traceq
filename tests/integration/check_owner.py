#!/usr/bin/env python3
"""Check per-thread session ownership and sequential thread handoff."""
import json
from pathlib import Path
import subprocess
import time

ROOT=Path(__file__).resolve().parents[2]

def main():
    out=ROOT/'artifacts'/('owner-check-'+str(time.time_ns()));out.mkdir(parents=True)
    result=subprocess.run([str(ROOT/'build/traceq-host/traceq-thread-owner-test'),str(out/'session')],
                          capture_output=True,text=True,check=True,timeout=30)
    checks=json.loads(result.stdout)
    assert checks and all(checks.values())
    assert not (out/'session-nested.gtsw').exists()
    for name in ['main-first','worker','main-next']:
        q=json.loads(subprocess.check_output([str(ROOT/'cli/traceq'),'stat',str(out/('session-'+name+'.gtsw')),'--json']))
        assert q['meta']['instructions']==0 and q['meta']['capture_gaps']==0
    (out/'summary.json').write_text(json.dumps(checks,indent=2)+'\n')
    print('PASS: foreign stop, nested begin, sequential thread handoff and owner reuse')

if __name__=='__main__':main()
