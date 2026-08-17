#!/usr/bin/env python3
# Line-map diff over the legacy text format: extract the instruction offset
# from each insn line and find the first divergence between two runs.
# (This is the realistic "diff two text traces" workflow.)
import re, sys

off_re = re.compile(r"!0x([0-9a-f]+)")

def offsets(path):
    out = []
    with open(path, "r", errors="replace") as f:
        for line in f:
            if line.startswith("["):
                m = off_re.search(line)
                if m:
                    out.append(int(m.group(1), 16))
    return out

a = offsets(sys.argv[1])
b = offsets(sys.argv[2])
n = min(len(a), len(b))
div = n
for i in range(n):
    if a[i] != b[i]:
        div = i
        break
same = div == n and len(a) == len(b)
print(f"text_diff: A={len(a)} insn lines, B={len(b)} insn lines, "
      f"{'identical' if same else f'first divergence at insn line {div} (offsets 0x{a[div]:x} vs 0x{b[div]:x})'}")
