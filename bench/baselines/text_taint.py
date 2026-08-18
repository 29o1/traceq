#!/usr/bin/env python3
# Text-based forward taint over the legacy trace format — the "offline tooling"
# baseline an agent would have to run against GumTrace's text output today.
# Propagation rules mirror BOTH the upstream taint_tracker and `gt taint`
# (data-flow only, kill-on-overwrite, category dispatch, stp/ldp slot pairs,
# NZCV/SIMD dependence extensions), so the two outputs can be cross-validated.
import re, sys

arg = lambda i, d: sys.argv[i] if len(sys.argv) > i else d
path = arg(1, "build/bench_legacy.txt")
seed_addr = int(arg(2, "0"), 0) if len(sys.argv) > 2 else 0

IMM_LOAD = {"movz", "movn", "adr", "adrp"}
PARTIAL = {"movk"}
LOAD = {"ldr", "ldrb", "ldrh", "ldrsw", "ldrsb", "ldrsh", "ldur", "ldurb",
        "ldurh", "ldursw", "ldursb", "ldursh", "ldp", "ldpsw", "ldar", "ldarb",
        "ldarh", "ldxr", "ldaxr", "ldxrb", "ldaxrb", "ldxrh", "ldaxrh", "ldxp",
        "ldaxp", "ldnp", "ldtr", "ldtrb", "ldtrh", "ldtrsw", "ldtrsb", "ldtrsh"}
STORE = {"str", "strb", "strh", "stur", "sturb", "sturh", "stp", "stlr", "stlrb",
         "stlrh", "stxr", "stlxr", "stxrb", "stlxrb", "stxrh", "stlxrh", "stxp",
         "stlxp"}
COMPARE = {"cmp", "cmn", "tst", "ccmp", "ccmn", "fcmp", "fccmp", "fcmpe",
           "fccmpe"}
BRANCH = {"nop", "cbz", "cbnz", "svc", "dmb", "dsb", "dc", "isb", "ic", "b",
          "bl", "br", "blr", "bti", "ret", "retaa", "retab", "paciasp",
          "pacibsp", "pacia", "pacib", "pacda", "pacdb", "prfm", "prfum"}
PAIR = {"stp", "ldp", "ldpsw", "ldxp", "ldaxp", "ldnp"}
SETS_FLAGS = COMPARE | {"adds", "subs", "ands", "bics", "adcs", "sbcs", "negs",
                        "ngcs"}
READS_NZCV = {"csel", "csinc", "csinv", "csneg", "cset", "csetm", "cinc", "cinv",
              "cneg", "fcsel", "ccmp", "ccmn"}

tok_re = re.compile(r"[A-Za-z0-9]+")
reg_re = re.compile(r"^(?:[wx](\d{1,2})|fp|lr|sp|wsp|[vqdshb](\d{1,2}))$")


def slot(tok):
    m = reg_re.match(tok)
    if not m:
        return None
    if tok == "fp":
        return 29
    if tok == "lr":
        return 30
    if tok in ("sp", "wsp"):
        return 31
    if m.group(1) is not None:
        n = int(m.group(1))
        return n if n <= 30 else None
    n = int(m.group(2))
    return 32 + n if n <= 31 else None


def name(s):
    return "sp" if s == 31 else ("q%d" % (s - 32) if s >= 32 else "x%d" % s)


def lead_tok(op):
    m = tok_re.match(op)
    return slot(m.group(0)) if m else None


def bracket_regs(op):
    out = []
    for tok in tok_re.findall(op):
        s = slot(tok)
        if s is not None:
            out.append(s)
    return out


def split_ops(ops):
    """split at top-level commas; returns [(text, is_mem)]"""
    out, seg, depth = [], 0, 0
    for i, c in enumerate(ops + "\0"):
        if c == "[":
            depth += 1
        elif c == "]":
            depth -= 1
        if (c == "," and depth == 0) or c == "\0":
            t = ops[seg:i].strip()
            if t:
                out.append((t, "[" in t))
            seg = i + 1
    return out


line_re = re.compile(r"^\[[^\]]*\] 0x[0-9a-f]+!0x[0-9a-f]+ (\S+)([^;]*);(.*)$")
mem_re = re.compile(r"mem_([rw])=0x([0-9a-f]+)")

regs = set()
nzcv = False
addrs = set()
if seed_addr:
    addrs.add(seed_addr)
edges = 0
since_involved = 0

with open(path, "r", errors="replace") as f:
    for line in f:
        m = line_re.match(line)
        if not m:
            continue
        mnem, ops_s, info = m.group(1), m.group(2), m.group(3)
        if mnem.startswith("b.") or mnem.startswith("aut") or mnem in BRANCH:
            cat = "branch"
        elif mnem in IMM_LOAD:
            cat = "imm"
        elif mnem in PARTIAL:
            cat = "partial"
        elif mnem in LOAD:
            cat = "load"
        elif mnem in STORE:
            cat = "store"
        elif mnem in COMPARE:
            cat = "cmp"
        else:
            cat = "other"
        pair = mnem in PAIR
        ops = split_ops(ops_s)
        elem = 4 if ops and ops[0][0][:1] in ("w", "W") else 8

        dsts, srcs, st = [], set(), []
        for i, (op, is_mem) in enumerate(ops):
            if is_mem:
                srcs.update(bracket_regs(op))
                continue
            s = lead_tok(op)
            if s is None:
                continue
            if cat in ("branch", "cmp"):
                srcs.add(s)
            elif cat == "store":
                if len(st) < 2:
                    st.append(s)
                srcs.add(s)
            elif i == 0 or (cat == "load" and pair and i == 1):
                if len(dsts) < 2:
                    dsts.append(s)
            else:
                srcs.add(s)
        nzcv_r = mnem in READS_NZCV or mnem.startswith("b.")
        nzcv_w = mnem in SETS_FLAGS

        mr = mw = None
        for mm in mem_re.finditer(info):
            if mm.group(1) == "r" and mr is None:
                mr = int(mm.group(2), 16)
            elif mm.group(1) == "w" and mw is None:
                mw = int(mm.group(2), 16)
        mr_t = mr is not None and mr in addrs
        mr2_t = pair and mr is not None and (mr + elem) in addrs
        mw_t = mw is not None and mw in addrs
        mw2_t = pair and mw is not None and (mw + elem) in addrs
        src_t = any(s in regs for s in srcs) or (nzcv_r and nzcv) or mr_t or mr2_t
        involved = src_t or mw_t or mw2_t

        def setclr(s, on):
            if on:
                regs.add(s)
            else:
                regs.discard(s)

        if cat == "imm":
            for d in dsts:
                regs.discard(d)
        elif cat == "partial":
            pass
        elif cat == "load":
            if pair and len(dsts) >= 2:
                for d, t in ((dsts[0], mr_t), (dsts[1], mr2_t)):
                    if t and d not in regs:
                        edges += 1
                    setclr(d, t)
            else:
                for d in dsts:
                    if mr_t and d not in regs:
                        edges += 1
                    setclr(d, mr_t)
        elif cat == "store":
            if mw is not None:
                if pair and len(st) >= 2:
                    for a, s in ((mw, st[0]), (mw + elem, st[1])):
                        on = s in regs
                        if on and a not in addrs:
                            edges += 1
                        if on:
                            addrs.add(a)
                        else:
                            addrs.discard(a)
                else:
                    on = bool(st) and st[0] in regs
                    if on and mw not in addrs:
                        edges += 1
                    if on:
                        addrs.add(mw)
                    else:
                        addrs.discard(mw)
        elif cat == "cmp":
            if src_t and not nzcv:
                edges += 1
            nzcv = src_t
        elif cat == "branch":
            pass
        else:
            for d in dsts:
                if src_t and d not in regs:
                    edges += 1
                setclr(d, src_t)
            if nzcv_w:
                if src_t and not nzcv:
                    edges += 1
                nzcv = src_t
            if mw is not None:
                if src_t and mw not in addrs:
                    edges += 1
                if src_t:
                    addrs.add(mw)
                else:
                    addrs.discard(mw)

        if involved:
            since_involved = 0
        else:
            since_involved += 1
            if since_involved >= 1000000:
                break
        if not regs and not nzcv and not addrs:
            break

print(f"text_taint: edges={edges} regs={sorted(name(s) for s in regs)} "
      f"n_addrs={len(addrs)}")
