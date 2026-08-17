#!/usr/bin/env python3
# Text-based forward taint over the legacy trace format — the "offline tooling"
# baseline an agent would have to run against GumTrace's text output today.
# Propagation rules are IDENTICAL to `gt taint` so the two outputs can be
# cross-validated (same rules, different data representation).
import re, sys

arg = lambda i, d: sys.argv[i] if len(sys.argv) > i else d
path = arg(1, "build/bench_legacy.txt")
seed_addr = int(arg(2, "0"), 0) if len(sys.argv) > 2 else 0

read_re = re.compile(r"(?:^|\s|;|\[)((?:x\d+|sp))=0x([0-9a-f]+)")
mem_re = re.compile(r"mem_([rw])=0x([0-9a-f]+)")
wr_re = re.compile(r"((?:x\d+|sp))=0x([0-9a-f]+)")

regs = set()
addrs = set()
if seed_addr:
    addrs.add(seed_addr)
edges = 0

with open(path, "r", errors="replace") as f:
    for line in f:
        if not line.startswith("["):
            continue  # call/svc/ret info blocks
        # split off the deferred-write tail (belongs to the same instruction)
        if " -> " in line:
            main, tail = line.split(" -> ", 1)
        else:
            main, tail = line, ""
        rd = {m.group(1) for m in read_re.finditer(main)}
        mem_r = {int(m.group(2), 16) for m in mem_re.finditer(main) if m.group(1) == "r"}
        mem_w = {int(m.group(2), 16) for m in mem_re.finditer(main) if m.group(1) == "w"}
        wr = {m.group(1) for m in wr_re.finditer(tail)} if tail else set()

        any_rd_t = any(r in regs for r in rd)
        src_mem = any(a in addrs for a in mem_r)
        if any_rd_t or src_mem:
            for w in wr:
                if w not in regs:
                    regs.add(w)
                    edges += 1
        if any_rd_t:
            for a in mem_w:
                if a not in addrs:
                    addrs.add(a)
                    edges += 1

print(f"text_taint: edges={edges} regs={sorted(regs)} n_addrs={len(addrs)}")
