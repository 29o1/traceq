#!/usr/bin/env python3
"""gumtrace-ng benchmark — driven entirely by real trace files.

No simulator, no synthetic corpus: every number below is the shipping `gt`
binary running on real GumTrace text logs (bench/traces/). What is measured:

  * import time (log -> .gtb), median of --repeat runs
  * .gtb size ratio vs the source log
  * two correctness gates per trace:
      - determinism: importing twice yields byte-identical .gtb
      - roundtrip:  `gt export --format upstream` reproduces the source
        log byte-for-byte (cmp)
  * a query battery against the imported .gtb (stat / export compact /
    export jsonl / find-value / mem-access / func-args / calltree / fold /
    taint forward+back), each timed --repeat times -> min/median/max

Anchors for the value/address/function queries are scraped from the first
500 lines of each trace (first non-zero `-> xN=0x..` write, first
`mem_w=0x..` address, first `call func: NAME(`). A trace that lacks an
anchor simply skips the dependent queries (recorded as skipped).

usage:
  run.py run [TRACE.log ...] [--repeat N] [--out DIR]
  run.py compare OLD/report.json NEW/report.json

run writes DIR/report.json + DIR/report.md (default:
bench/reports/<UTCts>-<gitsha>/) and exits non-zero if any gate fails.
compare prints a single JSON object to stdout and a human table to stderr.
"""
import hashlib
import json
import os
import re
import statistics
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
GT = os.path.join(HERE, "..", "cli", "gt")
DEFAULT_TRACES_DIR = os.path.join(HERE, "traces")
DEFAULT_REPORTS_DIR = os.path.join(HERE, "reports")
ANCHOR_SCAN_LINES = 500

RE_MEM_W = re.compile(r"mem_w=0x([0-9a-fA-F]+)")
RE_CALL = re.compile(r"call func: (\w+)\(")
RE_WRVAL = re.compile(r"-> x\d+=0x([0-9a-fA-F]+)")


def die(msg):
    sys.stderr.write("run.py: %s\n" % msg)
    sys.exit(1)


def sha256_path(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def git_short_sha():
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=HERE, capture_output=True, text=True, timeout=10)
        return out.stdout.strip() if out.returncode == 0 else "nogit"
    except Exception:
        return "nogit"


def fingerprint():
    return {
        "git": git_short_sha(),
        "gt_sha256": sha256_path(GT),
        "uname": subprocess.run(["uname", "-a"], capture_output=True,
                                text=True).stdout.strip(),
        "python": sys.version.split()[0],
    }


def scrape_anchors(log_path):
    """First non-zero reg-write value, first mem_w address, first call name."""
    val = addr = func = None
    with open(log_path, "r", errors="replace") as f:
        for i, line in enumerate(f):
            if i >= ANCHOR_SCAN_LINES:
                break
            if val is None:
                m = RE_WRVAL.search(line)
                if m and int(m.group(1), 16) != 0:
                    val = m.group(1)
            if addr is None:
                m = RE_MEM_W.search(line)
                if m:
                    addr = m.group(1)
            if func is None:
                m = RE_CALL.search(line)
                if m:
                    func = m.group(1)
            if val and addr and func:
                break
    return {"value": val, "addr": addr, "func": func}


def timed(argv, repeats):
    """Run argv `repeats` times; return sorted sample list (seconds)."""
    samples = []
    for _ in range(repeats):
        t0 = time.perf_counter()
        r = subprocess.run(argv, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
        samples.append(time.perf_counter() - t0)
        if r.returncode != 0:
            die("command failed: %s" % " ".join(argv))
    return sorted(samples)


def stats(samples):
    return {
        "samples": samples,
        "min": samples[0],
        "median": statistics.median(samples),
        "max": samples[-1],
    }


def run_trace(log_path, repeats, workdir):
    name = os.path.splitext(os.path.basename(log_path))[0]
    gtb = os.path.join(workdir, name + ".gtb")
    log_bytes = os.path.getsize(log_path)
    with open(log_path, "rb") as f:
        n_lines = f.read().count(b"\n")

    # gate 1: determinism — import twice, compare bytes
    gtb_b = os.path.join(workdir, name + ".b.gtb")
    subprocess.run([GT, "import", log_path, "-o", gtb], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run([GT, "import", log_path, "-o", gtb_b], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    determinism = sha256_path(gtb) == sha256_path(gtb_b)
    os.unlink(gtb_b)

    # gate 2: roundtrip — upstream export must equal the source log
    rt = os.path.join(workdir, name + ".roundtrip.log")
    with open(rt, "wb") as out:
        subprocess.run([GT, "export", "--format", "upstream", gtb],
                       check=True, stdout=out, stderr=subprocess.DEVNULL)
    roundtrip = sha256_path(rt) == sha256_path(log_path)
    os.unlink(rt)

    import_t = stats(timed([GT, "import", log_path, "-o", gtb], repeats))
    gtb_bytes = os.path.getsize(gtb)
    anchors = scrape_anchors(log_path)

    queries = {}
    skipped = []

    def battery(key, argv, need=None):
        if need and not anchors[need]:
            skipped.append(key)
            return
        queries[key] = stats(timed(argv, repeats))

    battery("stat", [GT, "stat", gtb])
    battery("export_compact",
            [GT, "export", "--format", "compact", "--limit", "5000", gtb])
    battery("export_jsonl",
            [GT, "export", "--format", "jsonl", "--limit", "5000", gtb])
    battery("find_value", [GT, "find-value", "0x" + anchors["value"], gtb]
            if anchors["value"] else [], need="value")
    battery("mem_access_w",
            [GT, "mem-access", gtb, "--addr", "0x" + anchors["addr"], "--write"]
            if anchors["addr"] else [], need="addr")
    battery("func_args", [GT, "func-args", "--func", anchors["func"], gtb]
            if anchors["func"] else [], need="func")
    battery("calltree", [GT, "calltree", "--func", anchors["func"], gtb]
            if anchors["func"] else [], need="func")
    battery("fold", [GT, "fold", "--top", "5", gtb])
    battery("taint_fwd",
            [GT, "taint", "--seed-addr", "0x" + anchors["addr"], gtb]
            if anchors["addr"] else [], need="addr")
    battery("taint_back",
            [GT, "taint", "--seed-addr", "0x" + anchors["addr"], "--back", gtb]
            if anchors["addr"] else [], need="addr")

    return {
        "path": os.path.relpath(log_path, HERE),
        "sha256": sha256_path(log_path),
        "bytes": log_bytes,
        "lines": n_lines,
        "gtb_bytes": gtb_bytes,
        "size_ratio": gtb_bytes / log_bytes if log_bytes else None,
        "anchors": anchors,
        "gates": {"determinism": determinism, "roundtrip": roundtrip},
        "import": import_t,
        "queries": queries,
        "skipped": skipped,
    }, gtb


def write_markdown(rep, path):
    fp = rep["fingerprint"]
    lines = [
        "# gumtrace-ng benchmark — %s" % rep["timestamp_utc"],
        "",
        "- git: `%s`  gt sha256: `%s`" % (fp["git"], fp["gt_sha256"][:16]),
        "- host: `%s`" % fp["uname"],
        "- repeat: %d (median reported)" % rep["repeat"],
        "- gates: %s" % ("ALL PASS" if rep["ok"] else "FAILURES PRESENT"),
        "",
    ]
    for name, t in rep["traces"].items():
        g = t["gates"]
        lines += [
            "## %s" % name,
            "",
            "- source: `%s` (%d bytes, %d lines, sha256 `%s`)"
            % (t["path"], t["bytes"], t["lines"], t["sha256"][:16]),
            "- import: %.3fs median (min %.3f / max %.3f)"
            % (t["import"]["median"], t["import"]["min"], t["import"]["max"]),
            "- .gtb: %d bytes (%.2fx the log)" % (t["gtb_bytes"], t["size_ratio"]),
            "- gates: determinism=%s roundtrip=%s"
            % ("PASS" if g["determinism"] else "FAIL",
               "PASS" if g["roundtrip"] else "FAIL"),
            "- anchors: value=%s addr=%s func=%s"
            % (t["anchors"]["value"], t["anchors"]["addr"], t["anchors"]["func"]),
            "",
            "| query | median s | min | max |",
            "| --- | ---: | ---: | ---: |",
        ]
        for q, s in t["queries"].items():
            lines.append("| %s | %.4f | %.4f | %.4f |"
                         % (q, s["median"], s["min"], s["max"]))
        if t["skipped"]:
            lines.append("\nskipped (no anchor in trace): %s"
                         % ", ".join(t["skipped"]))
        lines.append("")
    with open(path, "w") as f:
        f.write("\n".join(lines))


def cmd_run(traces, repeats, out_dir):
    if not os.path.isfile(GT):
        die("gt binary not found at %s — build it first (make -C cli)" % GT)
    if not traces:
        if not os.path.isdir(DEFAULT_TRACES_DIR):
            die("no traces given and %s missing" % DEFAULT_TRACES_DIR)
        traces = sorted(
            os.path.join(DEFAULT_TRACES_DIR, f)
            for f in os.listdir(DEFAULT_TRACES_DIR) if f.endswith(".log"))
        if not traces:
            die("no *.log traces in %s" % DEFAULT_TRACES_DIR)
    for t in traces:
        if not os.path.isfile(t):
            die("trace not found: %s" % t)

    if not out_dir:
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        out_dir = os.path.join(DEFAULT_REPORTS_DIR,
                               "%s-%s" % (ts, git_short_sha()))
    os.makedirs(out_dir, exist_ok=True)

    rep = {
        "schema": 1,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "fingerprint": fingerprint(),
        "repeat": repeats,
        "traces": {},
        "ok": True,
    }
    with tempfile.TemporaryDirectory(prefix="gt-bench-") as workdir:
        gtbs = {}
        for log in traces:
            name = os.path.splitext(os.path.basename(log))[0]
            sys.stderr.write("[run] %s ...\n" % name)
            entry, gtb = run_trace(log, repeats, workdir)
            rep["traces"][name] = entry
            gtbs[name] = gtb
            g = entry["gates"]
            if not (g["determinism"] and g["roundtrip"]):
                rep["ok"] = False
                sys.stderr.write("[run] %s GATE FAIL: %s\n" % (name, g))
        if len(gtbs) >= 2:
            a, b = (gtbs[n] for n in list(rep["traces"])[:2])
            rep["diff"] = stats(timed([GT, "diff", a, b], repeats))

    with open(os.path.join(out_dir, "report.json"), "w") as f:
        json.dump(rep, f, indent=2)
    write_markdown(rep, os.path.join(out_dir, "report.md"))
    sys.stderr.write("[run] wrote %s\n" % out_dir)
    return 0 if rep["ok"] else 1


def cmd_compare(old_path, new_path):
    with open(old_path) as f:
        old = json.load(f)
    with open(new_path) as f:
        new = json.load(f)
    new_ok = bool(new.get("ok"))

    def series(rep):
        out = {}
        for tname, t in rep.get("traces", {}).items():
            out.setdefault(tname, {})["import"] = t["import"]
            for q, s in t.get("queries", {}).items():
                out[tname][q] = s
        return out

    so, sn = series(old), series(new)
    results = []
    for tname in sorted(so):
        if tname not in sn:
            continue
        for q in sorted(so[tname]):
            if q not in sn[tname]:
                continue
            a, b = so[tname][q], sn[tname][q]
            ma, mb = a["median"], b["median"]
            if ma <= 0 or mb <= 0:
                continue
            spread_a = (a["max"] - a["min"]) / ma
            spread_b = (b["max"] - b["min"]) / mb
            noise = max(spread_a, spread_b, 0.05)
            delta = (mb - ma) / ma
            verdict = ("flat" if abs(delta) <= noise
                       else "regressed" if delta > 0 else "improved")
            results.append({
                "trace": tname, "query": q,
                "old_median": ma, "new_median": mb,
                "delta_pct": round(delta * 100, 2),
                "noise_pct": round(noise * 100, 2),
                "verdict": verdict,
            })
    counts = {"improved": 0, "regressed": 0, "flat": 0}
    for r in results:
        counts[r["verdict"]] += 1
    out = {
        "old": os.path.abspath(old_path),
        "new": os.path.abspath(new_path),
        "new_ok": new_ok,
        "verdict": "INVALID" if not new_ok else (
            "regressed" if counts["regressed"] else
            "improved" if counts["improved"] else "flat"),
        "summary": counts,
        "results": results,
    }
    sys.stderr.write("%-24s %-16s %10s %10s %8s %8s  %s\n"
                     % ("trace", "query", "old s", "new s", "delta%", "noise%",
                        "verdict"))
    for r in results:
        sys.stderr.write("%-24s %-16s %10.4f %10.4f %8.2f %8.2f  %s\n"
                         % (r["trace"], r["query"], r["old_median"],
                            r["new_median"], r["delta_pct"], r["noise_pct"],
                            r["verdict"]))
    sys.stderr.write("verdict: %s (+%d improved / -%d regressed / %d flat)\n"
                     % (out["verdict"], counts["improved"],
                        counts["regressed"], counts["flat"]))
    json.dump(out, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


def main(argv):
    if len(argv) < 2 or argv[1] in ("-h", "--help"):
        sys.stderr.write(__doc__)
        return 2
    cmd = argv[1]
    if cmd == "compare":
        if len(argv) != 4:
            die("usage: run.py compare OLD/report.json NEW/report.json")
        return cmd_compare(argv[2], argv[3])
    if cmd == "run":
        traces, repeats, out_dir = [], 3, None
        i = 2
        while i < len(argv):
            a = argv[i]
            if a == "--repeat":
                i += 1
                repeats = int(argv[i])
            elif a == "--out":
                i += 1
                out_dir = argv[i]
            elif a.startswith("--"):
                die("unknown flag: %s" % a)
            else:
                traces.append(a)
            i += 1
        return cmd_run(traces, repeats, out_dir)
    die("unknown command: %s" % cmd)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
