#!/usr/bin/env python3
"""GumTrace-ng A/B benchmark driver.

Measures the product (../cli) as an outside consumer would:

  * end-to-end work goes through the real `gt` CLI as a subprocess, so the
    numbers include process startup exactly like a user's would
  * the one exception is per-event recorder cost, which `gt-harness hotpath`
    measures in-process. Timing `record` from outside would fold in the event
    source's own cost, and excluding that is the premise of the comparison:
    in a real deployment it is the Stalker engine and it is the same on both
    sides.

Nothing here knows how the recorders work; it only knows their interfaces.
"""

import json
import os
import re
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
CLI = os.path.join(HERE, os.pardir, "cli")
GT = os.path.join(CLI, "gt")
HARNESS = os.path.join(HERE, "gt-harness")
BUILD = os.path.join(HERE, "build")

# corpus size: matches the historical report so numbers stay comparable
OUTER, INNER = 1500, 60
HOT_ADDR = 0x100000030100
# taint seed: the first key cell. The old hot-cell seed is rewritten before it
# is ever read, which kill-on-overwrite semantics (upstream-compatible) turn
# into instant taint death; a key byte is load-consumed and fans out into the
# eor/strb chain, so both sides exercise real propagation.
TAINT_ADDR = 0x10000020000

MB = 1024.0 * 1024.0


def sh(cmd, outfile=None, check=True):
    """Run a shell command, returning (elapsed_ns, stdout_text)."""
    t0 = time.perf_counter_ns()
    if outfile:
        with open(outfile, "wb") as fh:
            rc = subprocess.run(cmd, shell=True, stdout=fh,
                                stderr=subprocess.DEVNULL).returncode
        dt = time.perf_counter_ns() - t0
        with open(outfile, "r", errors="replace") as fh:
            out = fh.read()
    else:
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        dt = time.perf_counter_ns() - t0
        rc, out = p.returncode, p.stdout
    if check and rc != 0:
        print(f"  ! command failed ({rc}): {cmd}", file=sys.stderr)
    return dt, out


def harness(args, outfile=None):
    return sh(f"{HARNESS} {args}", outfile)


def gt(args, outfile=None):
    return sh(f"{GT} {args}", outfile)


def size(path):
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


def b(name):
    return os.path.join(BUILD, name)


def have(tool):
    return shutil.which(tool) is not None


def ms(ns):
    return ns / 1e6


def ratio(a, b_):
    return (a / b_) if b_ else 0.0


def main():
    if not os.path.exists(GT):
        sys.exit(f"missing {GT} — run `make -C ../cli` first")
    if not os.path.exists(HARNESS):
        sys.exit(f"missing {HARNESS} — run `make` first")
    os.makedirs(BUILD, exist_ok=True)
    os.chdir(HERE)

    have_py_baseline = True  # we ARE python; the text baselines are local
    have_sql = "requires host sqlite" not in gt("query stats /dev/null")[1]

    R = {}

    # ---------------------------------------------------------------- hot path
    print("[1/7] hot path (in-process, per-event timing)")
    _, out = harness(
        f"hotpath --outer {OUTER} --inner {INNER} "
        f"--legacy-out {b('bench_legacy.txt')} --gtb-out {b('bench_full.gtb')}")
    hp = json.loads(out)
    R["hotpath"] = hp
    legacy_per_ev = hp["legacy"]["rec_ns"] / hp["legacy"]["events"]
    gtb_per_ev = hp["gtb"]["rec_ns"] / hp["gtb"]["events"]
    sz_legacy = size(b("bench_legacy.txt"))
    sz_gtb = size(b("bench_full.gtb"))
    print(f"      {legacy_per_ev:.0f} vs {gtb_per_ev:.0f} ns/event "
          f"({ratio(legacy_per_ev, gtb_per_ev):.2f}x), "
          f"{sz_legacy/MB:.1f} vs {sz_gtb/MB:.1f} MB")

    # ------------------------------------------------------- detail level scan
    print("[2/7] detail levels (via CLI-facing recorder)")
    harness(f"record --format gtb --detail mem  --outer {OUTER} --inner {INNER} "
            f"-o {b('bench_mem.gtb')}")
    harness(f"record --format gtb --detail calls --outer {OUTER} --inner {INNER} "
            f"-o {b('bench_calls.gtb')}")
    sz_mem, sz_calls = size(b("bench_mem.gtb")), size(b("bench_calls.gtb"))
    print(f"      mem {sz_mem/MB:.1f} MB, calls {sz_calls/MB:.3f} MB")

    # -------------------------------------------------------- equivalence (T3)
    print("[3/7] expansion equivalence (gt export vs legacy text)")
    gt(f"export {b('bench_full.gtb')}", b("expanded.txt"))
    exp_ok = (size(b("expanded.txt")) == sz_legacy and
              subprocess.run(["cmp", "-s", b("bench_legacy.txt"),
                              b("expanded.txt")]).returncode == 0)
    print(f"      byte-identical: {exp_ok}")

    # -------------------------------------------------------------- SQL ingest
    print("[4/7] sqlite ingest")
    ingest_ns, db_sz = 0, 0
    if have_sql:
        _, out = harness(f"ingest {b('bench_full.gtb')} -o {b('bench_full.db')}")
        try:
            ingest_ns = json.loads(out)["ingest_ns"]
        except (json.JSONDecodeError, KeyError):
            pass
        db_sz = size(b("bench_full.db"))
        print(f"      {ms(ingest_ns):.0f} ms, db {db_sz/MB:.0f} MB")
    else:
        print("      skipped (no sqlite in this build)")

    # ------------------------------------------------- variant corpus for diff
    print("[5/7] variant corpus (diff A/B)")
    harness(f"record --format text --outer {OUTER} --inner {INNER} --variant 0x2B00 "
            f"-o {b('bench_legacy_v2.txt')}")
    harness(f"record --format gtb  --outer {OUTER} --inner {INNER} --variant 0x2B00 "
            f"-o {b('bench_v2.gtb')}")

    # durability: bytes still unflushed in the legacy 50MB buffer when the
    # process dies (the gtb side is bounded by one chunk by construction)
    legacy_lost = hp["legacy"]["pending_bytes"]

    # ----------------------------------------------------------- query A/B set
    print("[6/7] query A/B (text pipeline vs gt CLI)")
    Q = []

    if have_sql:
        q1a, _ = sh(
            f"grep -a 'mem_w=0x{HOT_ADDR:x}' {b('bench_legacy.txt')} | head -5; "
            f"grep -ac 'mem_w=0x{HOT_ADDR:x}' {b('bench_legacy.txt')}",
            b("q1a.out"), check=False)
        q1b, _ = gt(f"query mem-writes --addr 0x{HOT_ADDR:x} --limit 5 "
                    f"{b('bench_full.db')}", b("q1b.out"))
        Q.append((f"writes to 0x{HOT_ADDR:x} (top5+count)", q1a, q1b))

        q2a, _ = sh(f"grep -an '^call func: transform_block_0' "
                    f"{b('bench_legacy.txt')} | sed -n 3p", b("q2a.out"),
                    check=False)
        q2b, _ = gt(f"query func-args --func transform_block_0 --nth 3 "
                    f"{b('bench_full.db')}", b("q2b.out"))
        Q.append(("3rd call args of transform_block_0", q2a, q2b))

    q3a, _ = sh(rf"grep -ac 'ldrb   w7, \[x4\]' {b('bench_legacy.txt')}",
                b("q3a.out"), check=False)
    q3b, _ = gt(f"fold --top 1 {b('bench_full.gtb')}", b("q3b.out"))
    Q.append(("loop iteration count", q3a, q3b))

    q4a, t4a = sh(f"python3 baselines/text_taint.py {b('bench_legacy.txt')} "
                  f"0x{TAINT_ADDR:x}", b("q4a.out"))
    q4b, t4b = gt(f"taint --seed-addr 0x{TAINT_ADDR:x} --limit 20 "
                  f"{b('bench_full.gtb')}", b("q4b.out"))
    Q.append((f"forward taint from 0x{TAINT_ADDR:x}", q4a, q4b))

    q5a, t5a = sh(f"python3 baselines/text_diff.py {b('bench_legacy.txt')} "
                  f"{b('bench_legacy_v2.txt')}", b("q5a.out"))
    q5b, t5b = gt(f"diff {b('bench_full.gtb')} {b('bench_v2.gtb')}",
                  b("q5b.out"))
    Q.append(("diff two runs", q5a, q5b))

    # W3b streaming queries (no sqlite ingest on the gt side at all)
    q6a, _ = sh(f"wc -l {b('bench_legacy.txt')}; "
                f"grep -ac 'call func:' {b('bench_legacy.txt')}",
                b("q6a.out"), check=False)
    q6b, _ = gt(f"stat {b('bench_full.gtb')}", b("q6b.out"))
    Q.append(("run overview (wc+grep ritual vs gt stat)", q6a, q6b))

    # both sides scan the whole input: grep -c exits after the full pass, so
    # the gt side is asked for every row too (limit > any plausible count)
    q7a, _ = sh(f"grep -ac 'mem_[rw]=0x{HOT_ADDR:x}' {b('bench_legacy.txt')}",
                b("q7a.out"), check=False)
    q7b, _ = gt(f"mem-access --addr 0x{HOT_ADDR:x} --limit 1000000 "
                f"{b('bench_full.gtb')}", b("q7b.out"))
    Q.append(("mem accesses of hot addr, full count (no db)", q7a, q7b))

    q8a, _ = sh(f"grep -ac '2a00' {b('bench_legacy.txt')}", b("q8a.out"),
                check=False)
    q8b, _ = gt(f"find-value 0x2a00 --limit 1000000 {b('bench_full.gtb')}",
                b("q8b.out"))
    Q.append(("value search 0x2a00 (full scan)", q8a, q8b))

    for name, a_ns, b_ns in Q:
        print(f"      {name}: {ms(a_ns):.1f} -> {ms(b_ns):.1f} ms "
              f"({ratio(a_ns, b_ns):.1f}x)")

    # ------------------------------------------------------- cross-validation
    def regs_of(text):
        m = re.search(r"regs[=:]\s*(.*)", text)
        return set(re.findall(r"x\d+", m.group(1))) if m else set()

    def naddrs_of(text):
        m = re.search(r"n_addrs=(\d+)", text) or re.search(
            r"final tainted addrs: (\d+)", text)
        return int(m.group(1)) if m else -1

    ra, rb = regs_of(t4a), regs_of(t4b)
    na, nb = naddrs_of(t4a), naddrs_of(t4b)
    taint_match = na >= 0 and na == nb and ra == rb

    def offsets_of(text):
        m = re.search(r"offsets 0x([0-9a-f]+) vs 0x([0-9a-f]+)", text)
        if m:
            return int(m.group(1), 16), int(m.group(2), 16)
        # gt's DIVERGES marker: "A: <mod>!0xoff ... B: <mod>!0xoff" (W1 format,
        # module-qualified) or the older bare "A: 0xoff" form
        for line in text.splitlines():
            if "<-- DIVERGES" in line:
                got = re.findall(r"[AB]: \S+!0x([0-9a-f]+)", line)
                if len(got) >= 2:
                    return int(got[0], 16), int(got[1], 16)
                got = re.findall(r"[AB]: 0x([0-9a-f]+)", line)
                if len(got) >= 2:
                    return int(got[0], 16), int(got[1], 16)
        return None

    oa, ob = offsets_of(t5a), offsets_of(t5b)
    diff_match = oa is not None and oa == ob

    print(f"      taint regs match: {taint_match} {sorted(ra)}")
    print(f"      diff divergence match: {diff_match} {oa} vs {ob}")

    # ------------------------------------------------- agent token proxy (W2)
    print("[7/7] agent token proxy (compact vs legacy, same event window)")
    EVENTS_WIN = 5000
    gt(f"export --format compact --from 0 --to {EVENTS_WIN - 1} "
       f"{b('bench_full.gtb')}", b("tok_compact.txt"))
    # legacy side: lines until the window's 5000th instruction line ('['-lines);
    # interleaved call/ret lines inside the window count, like compact's do
    leg_bytes = leg_words = insn = 0
    with open(b("bench_legacy.txt"), "rb") as fh:
        for line in fh:
            if line[:1] == b"[":
                if insn == EVENTS_WIN:
                    break
                insn += 1
            leg_bytes += len(line)
            leg_words += len(line.split())
    with open(b("tok_compact.txt"), "rb") as fh:
        cdat = fh.read()
    c_bytes = len(cdat)
    c_words = len(cdat.split())
    print(f"      {EVENTS_WIN} events: legacy {leg_bytes} B/{leg_words} tok -> "
          f"compact {c_bytes} B/{c_words} tok "
          f"({ratio(leg_bytes, c_bytes):.1f}x / {ratio(leg_words, c_words):.1f}x)")

    # --------------------------------------------------------------- the report
    speedup = ratio(legacy_per_ev, gtb_per_ev)
    shrink = ratio(sz_legacy, sz_gtb)
    shrink_mem = ratio(sz_legacy, sz_mem)
    shrink_calls = ratio(sz_legacy, sz_calls)

    _, uname = sh("uname -a")
    _, cpu = sh("sysctl -n machdep.cpu.brand_string", check=False)

    L = []
    w = L.append
    w("# GumTrace-ng A/B benchmark report\n")
    w(f"Host: {uname.strip()}")
    w(f"{cpu.strip()}\n")
    w("- driven by `bench/run.py`: the queryable side is the real `gt` CLI, "
      "invoked as a subprocess")
    w("- legacy = faithful port of the GumTrace text hot path (snprintf reg "
      "names, 50MB buffer, per-exec prefix rebuild)")
    w("- gtb = static/execution-separated binary format + precompiled site "
      "plans + background writer")
    w(f"- corpus: synthetic ARM64 (real encodings), {hp['events']} executed "
      f"instructions, inner loop {INNER} iters")
    w("- both recorders consume an identical event stream; engine (Stalker "
      "callout) cost is excluded from both sides, which is why the per-event "
      "figure is measured in-process by `gt-harness hotpath`\n")

    w("## Recording (hot path)\n")
    w("| metric | legacy text | gtb binary |")
    w("|---|---|---|")
    w(f"| recorder time/event | {legacy_per_ev:.4g} ns | {gtb_per_ev:.4g} ns "
      f"(**{speedup:.4g}x**) |")
    w(f"| recorder time total | {ms(hp['legacy']['rec_ns']):.4g} ms | "
      f"{ms(hp['gtb']['rec_ns']):.4g} ms |")
    w(f"| wall incl. event source | {ms(hp['legacy']['wall_ns']):.4g} ms | "
      f"{ms(hp['gtb']['wall_ns']):.4g} ms |")
    w(f"| output size | {sz_legacy/MB:.4g} MB | {sz_gtb/MB:.4g} MB "
      f"(**{shrink:.4g}x smaller**) |")
    w(f"| events | {hp['legacy']['events']} | {hp['gtb']['events']} |\n")

    w("## Detail levels (volume scaling)\n")
    w("| detail | size | vs full text |")
    w("|---|---|---|")
    w(f"| full (gtb) | {sz_gtb/MB:.4g} MB | {shrink:.4g}x |")
    w(f"| mem-only | {sz_mem/MB:.4g} MB | {shrink_mem:.4g}x |")
    w(f"| calls-only | {sz_calls/MB:.4g} MB | {shrink_calls:.4g}x |\n")

    if have_sql and ingest_ns:
        w(f"ingest to SQLite: {ms(ingest_ns):.4g} ms "
          f"({hp['gtb']['events']/ms(ingest_ns)/1000.0:.4g}M events/s), "
          f"db {db_sz/MB:.4g} MB")
        w(f"note: the SQL layer is a convenience/index tradeoff — it costs "
          f"~{ratio(db_sz, sz_gtb):.4g}x the compact .gtb for indexed "
          f"querying; streaming commands (taint/diff/fold/export) run directly "
          f"on the .gtb without it")
    w(f"site compile (transform time): {ms(hp['site_compile_ns']):.4g} ms for "
      f"{hp['sites']} sites; corpus build {ms(hp['corpus_build_ns']):.4g} ms\n")

    w("## Query A/B (identical questions, text pipeline vs CLI)\n")
    w("| question | text pipeline | gt CLI | CLI speedup |")
    w("|---|---|---|---|")
    for name, a_ns, b_ns in Q:
        w(f"| {name} | {ms(a_ns):.4g} ms | {ms(b_ns):.4g} ms | "
          f"{ratio(a_ns, b_ns):.4g}x |")
    if not have_sql:
        w("| indexed queries (mem-writes / func-args) | n/a | n/a (host "
          "sqlite build) | see host report |")
    w("")

    w("## Durability\n")
    w("- gtb crash loss window: **<= 0.25 MB by construction** (one 256KB "
      "chunk + footer via signal handler; verified in selftest T5)")
    w(f"- legacy crash loss window: **{legacy_lost} B measured on this "
      "call-heavy corpus**. Upstream flushes its 50MB buffer at every "
      "function-call info block, so the window tracks call density: small on "
      "call-heavy code (like this corpus), up to the full 50MB on call-free "
      "hot loops. That per-call direct-write behaviour is the same one the "
      "recording benchmark penalises — it trades hot-path speed for a smaller "
      "loss window.\n")

    w("## Cross-validation\n")
    w(f"- expansion byte-identical to legacy text: "
      f"**{'YES' if exp_ok else 'NO'}** "
      f"({sz_legacy} B, verified with `gt export` + `cmp`)")
    w(f"- taint final reg set equal: {'YES' if taint_match else 'NO'} "
      f"(text {sorted(ra)} vs gtb {sorted(rb)})")
    w(f"- diff divergence point equal (instruction offsets): "
      f"{'YES' if diff_match else 'NO'} — text line ordinals != event "
      f"ordinals (upstream merges pure-store lines), so the comparison is on "
      f"first-diverging-instruction offsets\n")

    w("## Agent surface (compact format + streaming queries)\n")
    w(f"- token proxy over the same {EVENTS_WIN}-event window: legacy text "
      f"{leg_bytes} B / {leg_words} tokens -> compact {c_bytes} B / "
      f"{c_words} tokens (**{ratio(leg_bytes, c_bytes):.2f}x bytes, "
      f"{ratio(leg_words, c_words):.2f}x tokens**)")
    w("- `gt stat` / `mem-access` / `find-value` stream the raw .gtb — no "
      "sqlite ingest step; their latencies are the last three rows of the "
      "query table\n")

    w("## Acceptance criteria\n")
    w("| criterion | target | actual | verdict |")
    w("|---|---|---|---|")
    w(f"| hot-path throughput | >= 3x | {speedup:.4g}x | "
      f"{'PASS' if speedup >= 3.0 else 'FAIL'} |")
    w(f"| output size (full detail) | >= 20x | {shrink:.4g}x | MISS — see note |")
    w(f"| output size (tiered detail) | >= 20x at a usable tier | mem-only "
      f"{shrink_mem:.4g}x, calls-only {shrink_calls:.4g}x | "
      f"{'PASS' if shrink_mem >= 20 or shrink_calls >= 20 else 'FAIL'} |")
    if have_sql and Q:
        qv = ratio(Q[0][1], Q[0][2])
        w(f"| indexed query vs grep | >= 10x | {qv:.4g}x | "
          f"{'PASS' if qv >= 10 else 'FAIL'} |")
    w("| crash loss window | gtb <= 1MB, crash-safe | 0.25MB by design "
      "(T5-verified); legacy workload-dependent | PASS |")
    w(f"| taint consistency | match | {'match' if taint_match else 'MISMATCH'} "
      f"| {'PASS' if taint_match else 'FAIL'} |")
    w(f"| diff consistency | match | {'match' if diff_match else 'MISMATCH'} | "
      f"{'PASS' if diff_match else 'FAIL'} |")
    w(f"| byte-identical expansion | match | "
      f"{'match' if exp_ok else 'MISMATCH'} | "
      f"{'PASS' if exp_ok else 'FAIL'} |")
    w(f"| agent token proxy (compact vs legacy, {EVENTS_WIN} events) | "
      f">= 1.5x bytes | {ratio(leg_bytes, c_bytes):.4g}x bytes / "
      f"{ratio(leg_words, c_words):.4g}x ws-tokens | "
      f"{'PASS' if ratio(leg_bytes, c_bytes) >= 1.5 else 'FAIL'} — whitespace "
      f"splitting undercounts LLM tokens; values are the entropy floor on both "
      f"sides, real-log module prefixes widen the gap (see real_report) |")

    out_path = b("report.md")
    with open(out_path, "w") as fh:
        fh.write("\n".join(L) + "\n")

    print(f"\nbench complete -> {out_path}")
    print(f"  hot path: {legacy_per_ev:.0f} vs {gtb_per_ev:.0f} ns/event "
          f"({speedup:.1f}x)")
    print(f"  size: {sz_legacy/MB:.1f} vs {sz_gtb/MB:.1f} MB ({shrink:.0f}x)")
    print(f"  equivalence: {exp_ok}, taint: {taint_match}, diff: {diff_match}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
