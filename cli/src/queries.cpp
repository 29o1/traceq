#include <gumtrace/queries.h>
#include <gumtrace/ingest.h>
#include <gumtrace/import.h>
#include <gumtrace/site.h>
#include "emit.h"
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <functional>
#include <iterator>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include <vector>

using namespace gt;

// ---------------------------------------------------------------------------
// taint (gtb-based stream walk)
//
// Semantics follow the upstream GumTrace taint_tracker (src/taint/
// TaintEngine.cpp) so result sets are directly comparable: data-flow only
// (a store taints memory through its DATA register, a load only through the
// memory cell — base/index registers never carry taint into the loaded
// value), overwriting with untainted data KILLS taint, movk preserves it,
// movz/movn/adr/adrp kill unconditionally, cmp/tst-class instructions set or
// clear NZCV, and stp/ldp pairs track the two memory slots independently
// (slot2 = addr + 4 or 8 by the first operand's w/x spelling, bug-compatible
// with upstream). The walk stops early when all taint is cleared or after 1M
// consecutive uninvolved events (upstream's scan limit), and reports why.
//
// Two documented extensions over upstream: NZCV is a first-class source for
// csel/ccmp-class instructions (upstream's operand parser never lists NZCV as
// a source, so cmp -> csel chains break there), and q/d/s/v SIMD registers
// propagate like integer registers. Both fire only on traces that contain
// those instructions, so plain integer data-flow yields the same taint sets
// as upstream.
//
// Register space: mask bits 0..31 = x0..x30/sp, bits 32..63 = q0..q31, plus a
// separate NZCV flag. Per-site source/destination roles are re-derived from
// the disassembly text — the same input upstream's TraceParser works from —
// memoized per site. SIMD/NZCV *values* are never recorded, only dependence.
//
// Memory: forward is a pure stream walk. Backward keeps a sliding ring of
// compact per-event records (whole-trace Group materialization cost ~200B per
// event; a 7M-event trace put the RSS floor above 1GB). Window limits are
// always reported loudly via a PARTIAL first line.
//
// Taint is not resumable (the walk is monotone over a seed), so the cursor
// contract degrades to an explicit "raise --limit" next command that reruns
// from the seed.
// ---------------------------------------------------------------------------
struct TaintEdge { uint64_t ev; std::string what; };

struct TaintRec {  // compact per-group record for backward walks
    uint32_t site_id;  // 0xFFFFFFFF for non-exec groups (call/svc/ret-only)
    uint8_t n_mem;
    struct { uint64_t addr; bool is_write; } mem[2];
};

struct CopyRec {  // verbatim-hexdump memcpy: dst <- src (n bytes), keyed by ev
    uint64_t dst, src, n;
};

static const char* taint_reg_name(int slot, char* buf) {
    if (slot < 31) { snprintf(buf, 16, "x%d", slot); return buf; }
    if (slot == 31) return "sp";
    if (slot < 64) { snprintf(buf, 16, "q%d", slot - 32); return buf; }
    return "nzcv";
}

// ---- upstream-compatible per-site taint roles, parsed from the disasm ----

enum TaintCat : uint8_t {
    TC_OTHER = 0, // data move / arith / logic / shift / bitfield / cond-select
    TC_IMM_LOAD,  // movz movn adr adrp: dst is killed unconditionally
    TC_PARTIAL,   // movk: dst taint preserved
    TC_LOAD,      // dst tainted iff the memory cell is, else killed
    TC_STORE,     // memory tainted iff the data register is, else cleared
    TC_COMPARE,   // sets or clears NZCV from its sources
    TC_BRANCH,    // no data-flow effect
};

struct TaintSite {
    uint8_t cat = TC_OTHER;
    uint64_t src_mask = 0;       // all true sources (store data + base/index)
    uint64_t dst_mask = 0;       // destination regs
    uint8_t dsts[2] = {0, 0};    // dst_mask in operand order (pair loads)
    uint8_t n_dsts = 0;
    uint8_t st[2] = {0, 0};      // STORE data regs in operand order
    uint8_t n_st = 0;
    uint8_t pair = 0;            // stp / ldp-class: second slot at addr+elem
    uint8_t elem = 8;            // pair slot size: 4 when w-spelled, else 8
    uint8_t nzcv_r = 0, nzcv_w = 0;
};

// mnemonic -> taint category; mirrors upstream classify_mnemonic, folded into
// the seven classes its propagation rules distinguish
static TaintCat taint_classify(const char* m, size_t n) {
    auto is = [&](const char* w) {
        size_t l = strlen(w);
        return n == l && memcmp(m, w, l) == 0;
    };
    if (is("movz") || is("movn") || is("adr") || is("adrp")) return TC_IMM_LOAD;
    if (is("movk")) return TC_PARTIAL;
    if (is("cmp") || is("cmn") || is("tst") || is("ccmp") || is("ccmn") ||
        is("fcmp") || is("fccmp") || is("fcmpe") || is("fccmpe"))
        return TC_COMPARE;
    if (is("ldr") || is("ldrb") || is("ldrh") || is("ldrsw") || is("ldrsb") ||
        is("ldrsh") || is("ldur") || is("ldurb") || is("ldurh") ||
        is("ldursw") || is("ldursb") || is("ldursh") || is("ldp") ||
        is("ldpsw") || is("ldar") || is("ldarb") || is("ldarh") || is("ldxr") ||
        is("ldaxr") || is("ldxrb") || is("ldaxrb") || is("ldxrh") ||
        is("ldaxrh") || is("ldxp") || is("ldaxp") || is("ldnp") || is("ldtr") ||
        is("ldtrb") || is("ldtrh") || is("ldtrsw") || is("ldtrsb") ||
        is("ldtrsh"))
        return TC_LOAD;
    if (is("str") || is("strb") || is("strh") || is("stur") || is("sturb") ||
        is("sturh") || is("stp") || is("stlr") || is("stlrb") || is("stlrh") ||
        is("stxr") || is("stlxr") || is("stxrb") || is("stlxrb") ||
        is("stxrh") || is("stlxrh") || is("stxp") || is("stlxp"))
        return TC_STORE;
    if (is("nop") || is("cbz") || is("cbnz") || is("svc") || is("dmb") ||
        is("dsb") || is("dc") || is("isb") || is("ic") || is("b") ||
        is("bl") || is("br") || is("blr") || is("bti") || is("ret") ||
        is("retaa") || is("retab") || is("paciasp") || is("pacibsp") ||
        is("pacia") || is("pacib") || is("pacda") || is("pacdb") ||
        is("prfm") || is("prfum"))
        return TC_BRANCH;
    if (n >= 5 && memcmp(m, "aut", 3) == 0) return TC_BRANCH;  // autiasp ...
    if (n >= 2 && m[0] == 'b' && m[1] == '.') return TC_BRANCH; // b.eq ...
    return TC_OTHER;
}

// register token -> taint slot (0..31 = x0..sp, 32..63 = q0..q31), -1 = not a
// register (immediates, shift/extend modifiers, condition codes, xzr)
static int taint_reg_slot(const char* p, size_t n) {
    int simd = -1;
    int ctx = text_name_ctx(p, n, &simd);
    if (ctx >= 0) return ctx & 31; // fp/lr/sp already canonical (29/30/31)
    if (simd >= 0) return 32 + simd;
    return -1;
}

// operand list ("x8, [x25, #0x28]") -> src/dst roles, following upstream
// parse_operands: split at top-level commas; branch/compare = all sources;
// store = pre-bracket operands are data sources, bracket regs are sources;
// everything else = first (pair: first two) non-mem operands are dsts
static void taint_parse_ops(const char* ops, size_t ops_len, TaintSite& ts) {
    struct Op { const char* p; size_t n; bool is_mem; };
    Op o[8];
    int no = 0;
    size_t seg = 0;
    int depth = 0;
    for (size_t i = 0; i <= ops_len && no < 8; i++) {
        char c = i < ops_len ? ops[i] : '\0';
        if (c == '[') depth++;
        else if (c == ']') depth--;
        if ((c == ',' && depth == 0) || c == '\0') {
            size_t s = seg, e = i;
            while (s < e && (ops[s] == ' ' || ops[s] == '\t')) s++;
            while (e > s && (ops[e - 1] == ' ' || ops[e - 1] == '\t')) e--;
            if (e > s) {
                o[no].p = ops + s;
                o[no].n = e - s;
                // a memory operand starts with '['; a SIMD lane reference
                // ("v2.b[0]") has the bracket mid-token and is NOT memory
                o[no].is_mem = ops[s] == '[';
                no++;
            }
            seg = i + 1;
        }
    }
    if (!no) return;
    ts.elem = (o[0].n && (o[0].p[0] == 'w' || o[0].p[0] == 'W')) ? 4 : 8;

    auto alnum = [&](char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
               (c >= '0' && c <= '9');
    };
    // leading alnum token of an operand ('#'-immediates yield nothing)
    auto lead_tok = [&](const Op& op) -> int {
        size_t i = 0;
        while (i < op.n && alnum(op.p[i])) i++;
        if (!i) return -1;
        return taint_reg_slot(op.p, i);
    };
    auto add_src = [&](int slot) {
        if (slot >= 0) ts.src_mask |= 1ULL << slot;
    };
    auto add_dst = [&](int slot) {
        if (slot < 0) return;
        ts.dst_mask |= 1ULL << slot;
        if (ts.n_dsts < 2) ts.dsts[ts.n_dsts++] = uint8_t(slot);
    };
    auto add_st = [&](int slot) {
        if (slot < 0) return;
        if (ts.n_st < 2) ts.st[ts.n_st++] = uint8_t(slot);
        add_src(slot);
    };
    // registers inside a [base, index, ...] operand
    auto bracket_srcs = [&](const Op& op) {
        for (size_t j = 0; j < op.n; j++) {
            char c = op.p[j];
            if (c != '[' && c != ',' && c != ' ') continue;
            size_t k = j + 1;
            while (k < op.n && op.p[k] == ' ') k++;
            if (k >= op.n || op.p[k] == '#' || op.p[k] == ']' || op.p[k] == '!')
                continue;
            size_t t = k;
            while (t < op.n && alnum(op.p[t])) t++;
            add_src(taint_reg_slot(op.p + k, t - k));
        }
    };

    switch (ts.cat) {
    case TC_BRANCH:
    case TC_COMPARE:
        for (int i = 0; i < no; i++) {
            if (o[i].is_mem) bracket_srcs(o[i]);
            else add_src(lead_tok(o[i]));
        }
        break;
    case TC_STORE:
        for (int i = 0; i < no; i++) {
            if (o[i].is_mem) bracket_srcs(o[i]);
            else add_st(lead_tok(o[i]));
        }
        break;
    default: { // OTHER / LOAD / IMM_LOAD / PARTIAL
        bool pair_load = ts.cat == TC_LOAD && ts.pair;
        for (int i = 0; i < no; i++) {
            if (o[i].is_mem) { bracket_srcs(o[i]); continue; }
            int slot = lead_tok(o[i]);
            if (slot < 0) continue;
            if (i == 0 || (pair_load && i == 1)) add_dst(slot);
            else add_src(slot);
        }
        break;
    }
    }
}

static TaintSite build_taint_site(const Site& s, const char* pool) {
    TaintSite ts;
    const char* dis = pool + s.disasm_off;
    size_t dn = s.disasm_len;
    size_t mn = 0;
    while (mn < dn && dis[mn] != ' ') mn++;
    ts.cat = taint_classify(dis, mn);
    // pair ops (upstream infers the second slot from the mnemonic + width)
    if (s.kind != SK_SVC && mn > 0) {
        auto is = [&](const char* w) {
            size_t l = strlen(w);
            return mn == l && memcmp(dis, w, l) == 0;
        };
        ts.pair = is("stp") || is("ldp") || is("ldpsw") || is("ldxp") ||
                  is("ldaxp") || is("ldnp");
    }
    if (mn < dn) taint_parse_ops(dis + mn + 1, dn - mn - 1, ts);
    for (uint8_t i = 0; i < s.n_ops; i++) {
        if (s.ops[i].op_flags & OPF_R_NZCV) ts.nzcv_r = 1;
        if (s.ops[i].op_flags & OPF_W_NZCV) ts.nzcv_w = 1;
    }
    return ts;
}

// verbatim-hexdump memcpy bridging and dump-payload search use the shared
// upstream-dialect parsers from gumtrace/import.h (parse_hexdump_header /
// parse_hexdump_row). The taint walkers bind dumps to the preceding call
// (args dst, src) and apply copy semantics, so copied buffers stop looking
// like orphan addresses.

static int run_taint(const std::string& gtb, uint64_t seed_addr, int seed_reg,
                     int seed_q, bool seed_nzcv, bool backward, int limit,
                     uint64_t window, uint64_t at_ev, uint64_t off,
                     const std::string& mod, bool json) {
    GtbFile f;
    if (!f.load(gtb)) { fprintf(stderr, "load failed\n"); return 1; }

    // --off resolves to the set of sites at that module-relative offset
    std::unordered_set<uint32_t> off_sites;
    if (off) {
        for (uint32_t i = 0; i < f.arena.sites().size(); i++) {
            const Site& s = f.arena.get(i);
            if (s.module_id >= f.arena.modules().size()) continue;
            if (!mod.empty() && f.arena.modules()[s.module_id] != mod) continue;
            if (s.addr - f.arena.module_base(s.module_id) == off) off_sites.insert(i);
        }
        if (off_sites.empty()) {
            fprintf(stderr, "taint: no site at %s!0x%llx\n",
                    mod.empty() ? "*" : mod.c_str(), (unsigned long long)off);
            return 1;
        }
    }

    uint64_t reg_t = 0;  // bits 0..31 int, 32..63 q
    bool nzcv_t = false;
    std::unordered_set<uint64_t> addr_t;
    std::vector<TaintEdge> edges;

    auto site_txt = [&](uint32_t site_id) -> std::string {
        if (site_id == 0xFFFFFFFFu) return "<event>";
        const Site& s = f.arena.get(site_id);
        return std::string(f.arena.pool_ptr() + s.disasm_off, s.disasm_len);
    };
    uint64_t edges_total = 0;
    auto add_edge = [&](uint64_t ev, std::string what) {
        edges_total++;
        if ((int)edges.size() < limit) edges.push_back({ev, std::move(what)});
    };
    // per-site taint roles, memoized (a handful of unique sites per hot loop)
    std::vector<TaintSite> ts_cache(f.arena.sites().size());
    std::vector<uint8_t> ts_done(f.arena.sites().size(), 0);
    auto taint_site = [&](uint32_t sid) -> const TaintSite& {
        static const TaintSite kEmpty;
        if (sid == 0xFFFFFFFFu || sid >= ts_cache.size()) return kEmpty;
        if (!ts_done[sid]) {
            ts_cache[sid] = build_taint_site(f.arena.get(sid), f.arena.pool_ptr());
            ts_done[sid] = 1;
        }
        return ts_cache[sid];
    };
    auto tainted = [&](int slot) -> bool { return reg_t & (1ULL << slot); };
    auto setclr_reg = [&](int slot, bool on) {
        if (on) reg_t |= 1ULL << slot;
        else reg_t &= ~(1ULL << slot);
    };
    auto setclr_addr = [&](uint64_t a, bool on) {
        if (on) addr_t.insert(a);
        else addr_t.erase(a);
    };
    // first mem read / write cell of a group (pairs infer the second slot)
    auto group_mem = [](const Group& g, uint64_t& mr, bool& has_mr,
                        uint64_t& mw, bool& has_mw) {
        has_mr = has_mw = false;
        for (int k = 0; k < g.n_mem; k++) {
            if (g.mem[k].is_write) { if (!has_mw) { has_mw = true; mw = g.mem[k].addr; } }
            else if (!has_mr) { has_mr = true; mr = g.mem[k].addr; }
        }
    };
    auto taint_reg_edge = [&](uint64_t ev, uint32_t site_id, int slot,
                              const char* via) {
        char rb[16], msg[288];
        snprintf(msg, sizeof msg, "%s : %s <- %s", site_txt(site_id).c_str(),
                 taint_reg_name(slot, rb), via);
        add_edge(ev, msg);
    };
    auto taint_mem_edge = [&](uint64_t ev, uint32_t site_id) {
        add_edge(ev, site_txt(site_id) + " : mem_w -> tainted");
    };
    auto apply_seed = [&]() {
        if (seed_reg >= 0) reg_t |= 1ULL << (seed_reg & 31);
        if (seed_q >= 0) reg_t |= 1ULL << (32 + (seed_q & 31));
        if (seed_nzcv) nzcv_t = true;
        if (seed_addr) addr_t.insert(seed_addr);
    };

    bool partial = false;
    uint64_t total = 0, walked = 0;
    uint64_t seed_ev = 0;
    uint64_t matched = 0;          // involved events (upstream "Total matched")
    const char* stop = "end of trace";

    if (!backward) {
        bool seeded = false;
        bool stopped = false;      // early-stop: keep streaming to count total
        uint64_t since_involved = 0;
        // verbatim-hexdump copy bridging: a memcpy-class call followed by a
        // source-buffer dump (upstream dialect) transfers src-cell taint to
        // the dst range — without it copied buffers look like orphan addresses
        bool pend_copy = false;
        uint64_t pend_dst = 0, pend_src = 0;
        Expander(f).for_each([&](uint64_t gi, const Group& g) -> bool {
            total = gi + 1;
            if (!seeded) {
                bool hit = off_sites.empty()
                               ? (gi >= at_ev)
                               : (g.has_exec && off_sites.count(g.site_id) && gi >= at_ev);
                if (!hit) return true;
                apply_seed();
                seed_ev = gi;
                seeded = true;
                matched = 1; // upstream records the seed line itself
                return true; // propagation starts after the seed event
            }
            if (stopped) return true; // total keeps counting
            if (window && walked >= window) {
                partial = true;
                stopped = true;
                stop = "window limit";
                return true;
            }
            walked++;
            if (g.has_verbatim) {
                if (pend_copy) {
                    pend_copy = false;
                    uint64_t ha = 0, hl = 0;
                    const std::string& vb = f.verbatim;
                    if (g.verbatim_off + g.verbatim_len <= vb.size() &&
                        parse_hexdump_header(vb.data() + g.verbatim_off,
                                             g.verbatim_len, ha, hl) &&
                        ha == pend_src && hl > 0 && hl <= (1u << 20)) {
                        std::vector<uint64_t> deltas;
                        for (uint64_t a : addr_t)
                            if (a >= pend_src && a - pend_src < hl)
                                deltas.push_back(a - pend_src);
                        for (auto it = addr_t.begin(); it != addr_t.end();) {
                            uint64_t a = *it;
                            it = (a >= pend_dst && a - pend_dst < hl)
                                     ? addr_t.erase(it)
                                     : std::next(it);
                        }
                        for (uint64_t d : deltas) addr_t.insert(pend_dst + d);
                        if (!deltas.empty()) {
                            add_edge(gi, "memcpy : dst <- tainted src cells");
                            matched++;
                            since_involved = 0;
                        }
                    }
                }
                return true;
            }
            if (!g.has_exec) {
                pend_copy = g.is_call && g.n_call_args >= 2;
                if (pend_copy) { pend_dst = g.args[0]; pend_src = g.args[1]; }
                return true;
            }
            const TaintSite& ts = taint_site(g.site_id);
            uint64_t mr, mw;
            bool has_mr, has_mw;
            group_mem(g, mr, has_mr, mw, has_mw);
            uint64_t mr2 = mr + ts.elem, mw2 = mw + ts.elem;
            bool mr_t = has_mr && addr_t.count(mr);
            bool mr2_t = ts.pair && has_mr && addr_t.count(mr2);
            bool mw_t = has_mw && addr_t.count(mw);
            bool mw2_t = ts.pair && has_mw && addr_t.count(mw2);
            bool src_t = (ts.src_mask & reg_t) != 0 || (ts.nzcv_r && nzcv_t) ||
                         mr_t || mr2_t;
            bool src_reg_t = (ts.src_mask & reg_t) != 0 || (ts.nzcv_r && nzcv_t);
            bool involved = src_t || mw_t || mw2_t;
            // upstream propagate_forward runs on EVERY line (kills included);
            // involvement only gates recording
            switch (ts.cat) {
            case TC_IMM_LOAD:
                for (int i = 0; i < ts.n_dsts; i++) setclr_reg(ts.dsts[i], false);
                break;
            case TC_PARTIAL:
                break;
            case TC_LOAD:
                if (ts.pair && ts.n_dsts >= 2) {
                    bool t0 = tainted(ts.dsts[0]), t1 = tainted(ts.dsts[1]);
                    setclr_reg(ts.dsts[0], mr_t);
                    setclr_reg(ts.dsts[1], mr2_t);
                    if (mr_t && !t0)
                        taint_reg_edge(gi, g.site_id, ts.dsts[0], "mem");
                    if (mr2_t && !t1)
                        taint_reg_edge(gi, g.site_id, ts.dsts[1], "mem");
                } else {
                    for (int i = 0; i < ts.n_dsts; i++) {
                        bool was = tainted(ts.dsts[i]);
                        setclr_reg(ts.dsts[i], mr_t);
                        if (mr_t && !was)
                            taint_reg_edge(gi, g.site_id, ts.dsts[i], "mem");
                    }
                }
                break;
            case TC_STORE:
                if (has_mw) {
                    if (ts.pair && ts.n_st >= 2) {
                        bool d0 = tainted(ts.st[0]), d1 = tainted(ts.st[1]);
                        if (d0 && !mw_t) taint_mem_edge(gi, g.site_id);
                        if (d1 && !mw2_t) taint_mem_edge(gi, g.site_id);
                        setclr_addr(mw, d0);
                        setclr_addr(mw2, d1);
                    } else {
                        bool d0 = ts.n_st > 0 && tainted(ts.st[0]);
                        if (d0 && !mw_t) taint_mem_edge(gi, g.site_id);
                        setclr_addr(mw, d0);
                    }
                }
                break;
            case TC_COMPARE:
                if (src_t && !nzcv_t)
                    add_edge(gi, site_txt(g.site_id) + " : nzcv <- reg");
                nzcv_t = src_t;
                break;
            case TC_BRANCH:
                break;
            default: { // TC_OTHER: data move / arith / logic / shift / cond-sel
                for (int i = 0; i < ts.n_dsts; i++) {
                    bool was = tainted(ts.dsts[i]);
                    setclr_reg(ts.dsts[i], src_t);
                    if (src_t && !was)
                        taint_reg_edge(gi, g.site_id, ts.dsts[i],
                                       src_reg_t ? "reg" : "mem");
                }
                if (ts.nzcv_w) {
                    if (src_t && !nzcv_t)
                        add_edge(gi, site_txt(g.site_id) + " : nzcv <- reg");
                    nzcv_t = src_t;
                }
                if (has_mw) { // OTHER-category mem write (casp-class)
                    if (src_t && !mw_t) taint_mem_edge(gi, g.site_id);
                    setclr_addr(mw, src_t);
                }
                break;
            }
            }
            if (involved) {
                matched++;
                since_involved = 0;
            } else if (++since_involved >= 1000000) {
                stopped = true;
                stop = "scan limit (1M uninvolved)";
            }
            if (reg_t == 0 && !nzcv_t && addr_t.empty()) {
                stopped = true;
                stop = "all taint cleared";
            }
            pend_copy = g.is_call && g.n_call_args >= 2;
            if (pend_copy) { pend_dst = g.args[0]; pend_src = g.args[1]; }
            return true;
        });
        if (!seeded) {
            fprintf(stderr, "taint: seed event not found (trace has %llu events)\n",
                    (unsigned long long)total);
            return 1;
        }
    } else {
        // stream into a ring of compact records, ending at --at-ev (default:
        // end of stream); window bounds history, default 2M events
        uint64_t back_window = window ? window : 2000000;
        std::vector<TaintRec> ring;
        ring.reserve(size_t(std::min<uint64_t>(back_window, 1u << 22)));
        size_t head = 0;  // ring read position (logical index ring_base = pushed - size)
        uint64_t pushed = 0;
        uint64_t last_match = UINT64_MAX;
        bool hit_end = false;
        // verbatim-hexdump memcpy sites (ev -> copy), gathered on the same pass
        std::unordered_map<uint64_t, CopyRec> copies;
        bool pend_copy = false;
        uint64_t pend_dst = 0, pend_src = 0;
        Expander(f).for_each([&](uint64_t gi, const Group& g) -> bool {
            if (at_ev && gi > at_ev) return false;
            if (g.has_verbatim) {
                if (pend_copy) {
                    pend_copy = false;
                    uint64_t ha = 0, hl = 0;
                    const std::string& vb = f.verbatim;
                    if (g.verbatim_off + g.verbatim_len <= vb.size() &&
                        parse_hexdump_header(vb.data() + g.verbatim_off,
                                             g.verbatim_len, ha, hl) &&
                        ha == pend_src && hl > 0 && hl <= (1u << 20))
                        copies[gi] = {pend_dst, pend_src, hl};
                }
            } else {
                pend_copy = g.is_call && g.n_call_args >= 2;
                if (pend_copy) { pend_dst = g.args[0]; pend_src = g.args[1]; }
            }
            if (g.has_exec && !off_sites.empty() && off_sites.count(g.site_id))
                last_match = gi;
            TaintRec r{};
            r.site_id = g.has_exec ? g.site_id : 0xFFFFFFFFu;
            r.n_mem = uint8_t(g.n_mem);
            for (int k = 0; k < g.n_mem && k < 2; k++)
                r.mem[k] = {g.mem[k].addr, g.mem[k].is_write};
            if (ring.size() < back_window) ring.push_back(r);
            else { ring[head] = r; head = (head + 1) % ring.size(); }
            pushed++;
            hit_end = true;
            return true;
        });
        if (!hit_end) { fprintf(stderr, "taint: empty trace\n"); return 1; }
        total = at_ev && at_ev < pushed ? at_ev + 1 : pushed;
        uint64_t ring_base = pushed - ring.size();
        seed_ev = off_sites.empty() ? pushed - 1 : last_match;
        if (seed_ev == UINT64_MAX || seed_ev < ring_base) {
            fprintf(stderr,
                    "taint: seed event %s; raise --window (have %llu) or lower --at-ev\n",
                    seed_ev == UINT64_MAX ? "not found in window"
                                          : "older than the retained window",
                    (unsigned long long)back_window);
            return 1;
        }
        partial = ring_base > 0;
        apply_seed();
        // upstream backward: the seed line itself propagates, then only
        // INVOLVED lines do; kills happen inside propagation (a propagated-
        // through destination is untainted, its sources tainted)
        uint64_t since_involved = 0;
        auto src_edge = [&](uint64_t ev, uint32_t sid, int slot) {
            char rb[16], msg[288];
            snprintf(msg, sizeof msg, "%s : source reg %s", site_txt(sid).c_str(),
                     taint_reg_name(slot, rb));
            add_edge(ev, msg);
        };
        auto mem_edge = [&](uint64_t ev, uint32_t sid, uint64_t a) {
            char msg[288];
            snprintf(msg, sizeof msg, "%s : source mem 0x%llx", site_txt(sid).c_str(),
                     (unsigned long long)a);
            add_edge(ev, msg);
        };
        auto taint_srcs = [&](uint64_t ev, uint32_t sid, uint64_t mask) {
            uint64_t newly = mask & ~reg_t;
            while (newly) {
                int slot = __builtin_ctzll(newly);
                newly &= newly - 1;
                reg_t |= 1ULL << slot;
                src_edge(ev, sid, slot);
            }
        };
        auto taint_cell = [&](uint64_t ev, uint32_t sid, uint64_t a) {
            if (!addr_t.count(a)) {
                addr_t.insert(a);
                mem_edge(ev, sid, a);
            }
        };
        for (uint64_t i = seed_ev + 1; i-- > ring_base;) {
            const TaintRec& r = ring[size_t((i - ring_base + head) % ring.size())];
            walked++;
            if (!copies.empty()) {
                auto cp = copies.find(i);
                if (cp != copies.end()) {
                    // backward copy: a demand on dst cells was produced by the
                    // corresponding src cells — move the demand across
                    const CopyRec& c = cp->second;
                    std::vector<uint64_t> deltas;
                    for (uint64_t a : addr_t)
                        if (a >= c.dst && a - c.dst < c.n)
                            deltas.push_back(a - c.dst);
                    for (uint64_t d : deltas) {
                        addr_t.erase(c.dst + d);
                        addr_t.insert(c.src + d);
                    }
                    if (!deltas.empty()) {
                        add_edge(i, "memcpy : demand -> src cells");
                        matched++;
                        since_involved = 0;
                    }
                }
            }
            const TaintSite& ts = taint_site(r.site_id);
            uint64_t mr = 0, mw = 0;
            bool has_mr = false, has_mw = false;
            for (int k = 0; k < r.n_mem; k++) {
                if (r.mem[k].is_write) { if (!has_mw) { has_mw = true; mw = r.mem[k].addr; } }
                else if (!has_mr) { has_mr = true; mr = r.mem[k].addr; }
            }
            uint64_t mr2 = mr + ts.elem, mw2 = mw + ts.elem;
            bool mw_t = has_mw && addr_t.count(mw);
            bool mw2_t = ts.pair && has_mw && addr_t.count(mw2);
            bool dst_t = (ts.dst_mask & reg_t) != 0;
            bool nz_t = ts.nzcv_w && nzcv_t;
            bool is_seed = (i == seed_ev);
            bool involved = dst_t || nz_t || mw_t || mw2_t;
            if (!is_seed && !involved) {
                if (++since_involved >= 1000000) {
                    stop = "scan limit (1M uninvolved)";
                    break;
                }
            } else {
                since_involved = 0;
                if (!is_seed) matched++;
                switch (ts.cat) {
                case TC_IMM_LOAD:
                    reg_t &= ~ts.dst_mask;
                    break;
                case TC_PARTIAL:
                    break;
                case TC_LOAD:
                    if (ts.pair && ts.n_dsts >= 2) {
                        if (tainted(ts.dsts[0])) {
                            reg_t &= ~(1ULL << ts.dsts[0]);
                            if (has_mr) taint_cell(i, r.site_id, mr);
                        }
                        if (tainted(ts.dsts[1])) {
                            reg_t &= ~(1ULL << ts.dsts[1]);
                            if (has_mr) taint_cell(i, r.site_id, mr2);
                        }
                    } else {
                        bool any = (ts.dst_mask & reg_t) != 0;
                        reg_t &= ~ts.dst_mask;
                        if (any && has_mr) taint_cell(i, r.site_id, mr);
                    }
                    break;
                case TC_STORE:
                    if (mw_t) {
                        addr_t.erase(mw);
                        if (ts.n_st > 0 && !tainted(ts.st[0])) {
                            reg_t |= 1ULL << ts.st[0];
                            src_edge(i, r.site_id, ts.st[0]);
                        }
                    }
                    if (ts.pair && ts.n_st >= 2 && mw2_t) {
                        addr_t.erase(mw2);
                        if (!tainted(ts.st[1])) {
                            reg_t |= 1ULL << ts.st[1];
                            src_edge(i, r.site_id, ts.st[1]);
                        }
                    }
                    break;
                case TC_COMPARE:
                    if (nzcv_t) {
                        nzcv_t = false;
                        taint_srcs(i, r.site_id, ts.src_mask);
                    }
                    break;
                case TC_BRANCH:
                    break;
                default: // TC_OTHER
                    if (dst_t || nz_t) {
                        reg_t &= ~ts.dst_mask;
                        if (nz_t) nzcv_t = false;
                        taint_srcs(i, r.site_id, ts.src_mask);
                        if (ts.nzcv_r && !nzcv_t) { // csel-class extension
                            nzcv_t = true;
                            add_edge(i, site_txt(r.site_id) + " : source reg nzcv");
                        }
                        if (dst_t && has_mr) taint_cell(i, r.site_id, mr);
                    }
                    break;
                }
                matched += is_seed ? 1 : 0;
            }
            if (reg_t == 0 && !nzcv_t && addr_t.empty()) {
                stop = "all taint cleared";
                break;
            }
        }
    }

    // seed renderers + rerun command for the not-resumable cursor
    auto hex_s = [](uint64_t v) {
        char hb[24];
        snprintf(hb, sizeof hb, "0x%llx", (unsigned long long)v);
        return std::string(hb);
    };
    auto seed_desc = [&]() -> std::string {
        std::string s;
        if (seed_addr) s += " addr=" + hex_s(seed_addr);
        if (seed_reg >= 0) {
            char rb[16];
            s += " reg=" + std::string(taint_reg_name(seed_reg & 31, rb));
        }
        if (seed_q >= 0) s += " reg=q" + std::to_string(seed_q);
        if (seed_nzcv) s += " nzcv";
        if (at_ev) s += " at ev=" + std::to_string(at_ev);
        if (off) s += " at " + (mod.empty() ? "*" : mod) + "!" + hex_s(off);
        return s.empty() ? " (none)" : s;
    };
    auto taint_cmd = [&](int new_limit) -> std::string {
        std::string s = "gt taint";
        if (seed_addr) s += " --seed-addr " + hex_s(seed_addr);
        if (seed_reg >= 0) s += " --seed-reg " + std::to_string(seed_reg);
        if (seed_q >= 0) s += " --seed-q " + std::to_string(seed_q);
        if (seed_nzcv) s += " --seed-nzcv";
        if (backward) s += " --back";
        s += " --limit " + std::to_string(new_limit);
        if (window) s += " --window " + std::to_string(window);
        if (at_ev) s += " --at-ev " + std::to_string(at_ev);
        if (off) {
            s += " --off " + hex_s(off);
            if (!mod.empty()) s += " --mod " + mod;
        }
        return s + " " + gtb;
    };
    // edges are capped by --limit; the walk itself is one pass
    bool edges_trunc = edges_total > edges.size();

    if (json) {
        if (partial) printf("{\"partial\":true}\n");
        std::string o;
        emit::kv_str(o, "seed_desc", seed_desc()); // human-readable seed summary
        o += ",\"seed\":{";
        if (seed_addr) { emit::kv_hex(o, "addr", seed_addr); o += ','; }
        if (seed_reg >= 0) { emit::kv_u64(o, "reg", uint64_t(seed_reg)); o += ','; }
        if (seed_q >= 0) { emit::kv_u64(o, "q", uint64_t(seed_q)); o += ','; }
        emit::kv_bool(o, "nzcv", seed_nzcv);
        o += ',';
        emit::kv_u64(o, "ev", seed_ev);
        o += "},\"direction\":\"";
        o += backward ? "backward" : "forward";
        o += "\",\"resume\":false,\"walked\":";
        char wb[48];
        snprintf(wb, sizeof wb, "%llu", (unsigned long long)walked);
        o += wb;
        o += ",\"total\":";
        snprintf(wb, sizeof wb, "%llu", (unsigned long long)total);
        o += wb;
        o += ",\"matched\":";
        snprintf(wb, sizeof wb, "%llu", (unsigned long long)matched);
        o += wb;
        o += ",\"stop\":\"";
        o += stop;
        o += "\",";
        o += "\"edges\":[";
        for (size_t i = 0; i < edges.size(); i++) {
            if (i) o += ',';
            const std::string& w = edges[i].what;
            size_t sp = w.find(" : ");
            o += '{';
            emit::kv_u64(o, "ev", edges[i].ev);
            o += ',';
            emit::kv_str(o, "txt", sp == std::string::npos ? "" : w.substr(0, sp));
            o += ',';
            emit::kv_str(o, "what", sp == std::string::npos ? w : w.substr(sp + 3));
            o += '}';
        }
        o += "],\"regs\":[";
        bool first = true;
        for (int slot = 0; slot < 64; slot++)
            if (reg_t & (1ULL << slot)) {
                char rb[16];
                if (!first) o += ',';
                first = false;
                o.push_back('"');
                o += taint_reg_name(slot, rb);
                o.push_back('"');
            }
        if (nzcv_t) {
            if (!first) o += ',';
            o += "\"nzcv\"";
        }
        o += "],\"addrs\":[";
        std::vector<uint64_t> addrs(addr_t.begin(), addr_t.end());
        std::sort(addrs.begin(), addrs.end());
        for (size_t i = 0; i < addrs.size(); i++) {
            if (i) o += ',';
            o += '"' + emit::hex64(addrs[i]) + '"';
        }
        o += ']';
        printf("{\"taint\":{%s}}\n", o.c_str());
    } else {
        if (partial)
            printf("PARTIAL: window limited — walked %llu of %llu events; widen with "
                   "--window 0 (forward) or a larger --window (backward)\n",
                   (unsigned long long)walked, (unsigned long long)total);
        printf("taint seed:%s (event %llu)\n", seed_desc().c_str(), (unsigned long long)seed_ev);
        printf("direction: %s | events walked: %llu of %llu | matched: %llu | stop: %s | edges (limit %d): %llu\n",
               backward ? "backward" : "forward", (unsigned long long)walked,
               (unsigned long long)total, (unsigned long long)matched, stop, limit,
               (unsigned long long)edges_total);
        for (auto& e : edges)
            printf("  ev=%-8llu %s\n", (unsigned long long)e.ev, e.what.c_str());
        printf("final tainted regs:");
        for (int slot = 0; slot < 64; slot++)
            if (reg_t & (1ULL << slot)) {
                char rb[16];
                printf(" %s", taint_reg_name(slot, rb));
            }
        if (nzcv_t) printf(" nzcv");
        printf("\nfinal tainted addrs: %zu\n", addr_t.size());
    }

    emit::Meta meta;
    meta.total = edges_total;
    meta.shown = edges.size();
    meta.truncated = edges_trunc;
    if (edges_trunc)
        meta.next = taint_cmd(limit > 0 ? limit * 5 : 100); // raise --limit; rerun from seed
    // suggestions: first tainted addrs -> mem queries; seed ev -> export window
    std::vector<uint64_t> addrs(addr_t.begin(), addr_t.end());
    std::sort(addrs.begin(), addrs.end());
    for (size_t i = 0; i < addrs.size() && i < 3; i++) {
        char b[256];
        snprintf(b, sizeof b, "gt mem-access --addr 0x%llx --limit 10 %s",
                 (unsigned long long)addrs[i], gtb.c_str());
        meta.suggest.push_back(b);
    }
    {
        uint64_t lo = seed_ev > 5 ? seed_ev - 5 : 0;
        char b[256];
        snprintf(b, sizeof b, "gt export --from %llu --to %llu --format compact %s",
                 (unsigned long long)lo, (unsigned long long)(seed_ev + 5), gtb.c_str());
        meta.suggest.push_back(b);
    }
    emit::finish(meta, json);
    if (edges_trunc && !json)
        printf("note: taint is not resumable — the next command reruns from the seed with a raised --limit\n");
    return 0;
}

int q_taint(const std::string& gtb, uint64_t seed_addr, int seed_reg, int seed_q,
            bool seed_nzcv, bool backward, int limit, uint64_t window,
            uint64_t at_ev, uint64_t off, const std::string& mod, bool json) {
    return run_taint(gtb, seed_addr, seed_reg, seed_q, seed_nzcv, backward, limit, window,
                     at_ev, off, mod, json);
}

// ---------------------------------------------------------------------------
// diff (gtb exec sequence)
//
// Comparison key is (module name, module-relative offset), not the arena site
// id: site ids are allocation-order artifacts of each run and only align when
// both runs interned sites in the same order, while (module, offset) is stable
// across ASLR and load-order differences. (v1 META payloads carry no module
// base; their offsets degrade to absolute addresses, which still compares
// correctly for same-base native recordings.)
// ---------------------------------------------------------------------------
int q_diff(const std::string& a_p, const std::string& b_p, int context, bool json) {
    GtbFile a, b;
    if (!a.load(a_p) || !b.load(b_p)) { fprintf(stderr, "load failed\n"); return 1; }
    std::vector<uint32_t> sa, sb;
    Expander(a).for_each([&](uint64_t, const Group& g) {
        if (g.has_exec) sa.push_back(g.site_id);
        return true;
    });
    Expander(b).for_each([&](uint64_t, const Group& g) {
        if (g.has_exec) sb.push_back(g.site_id);
        return true;
    });
    auto key = [](const GtbFile& f, uint32_t site, std::string& mod_out, uint64_t& off_out) {
        const Site& s = f.arena.get(site);
        mod_out = s.module_id < f.arena.modules().size()
                      ? f.arena.modules()[s.module_id] : std::string("?");
        off_out = s.addr - f.arena.module_base(s.module_id);
    };
    auto same = [&](uint32_t x, uint32_t y) {
        std::string ma, mb;
        uint64_t oa, ob;
        key(a, x, ma, oa);
        key(b, y, mb, ob);
        return ma == mb && oa == ob;
    };
    size_t n = std::min(sa.size(), sb.size());
    size_t div = n;
    for (size_t i = 0; i < n; i++)
        if (!same(sa[i], sb[i])) { div = i; break; }
    bool identical = div == n && sa.size() == sb.size();
    auto txt = [&](const GtbFile& f, uint32_t site) -> std::string {
        const Site& s = f.arena.get(site);
        return std::string(f.arena.pool_ptr() + s.disasm_off, s.disasm_len);
    };
    auto loc = [&](const GtbFile& f, uint32_t site) -> std::string {
        std::string m;
        uint64_t o;
        key(f, site, m, o);
        char b2[32];
        snprintf(b2, sizeof b2, "!0x%llx", (unsigned long long)o);
        return m + b2;
    };
    if (json) {
        std::string o;
        emit::kv_u64(o, "exec_a", sa.size());
        o += ',';
        emit::kv_u64(o, "exec_b", sb.size());
        o += ',';
        emit::kv_bool(o, "identical", identical);
        if (!identical) {
            o += ',';
            emit::kv_u64(o, "diverge_ev", div);
            size_t from = div >= size_t(context) ? div - size_t(context) : 0;
            size_t to = div + size_t(context) + 1;
            o += ",\"ctx\":[";
            for (size_t i = from; i < to; i++) {
                if (i >= sa.size() && i >= sb.size()) continue;
                if (i > from) o += ',';
                o += '{';
                emit::kv_u64(o, "ev", i);
                o += ',';
                emit::kv_str(o, "a", i < sa.size() ? loc(a, sa[i]) : "-");
                o += ',';
                emit::kv_str(o, "a_txt", i < sa.size() ? txt(a, sa[i]) : "<end>");
                o += ',';
                emit::kv_str(o, "b", i < sb.size() ? loc(b, sb[i]) : "-");
                o += ',';
                emit::kv_str(o, "b_txt", i < sb.size() ? txt(b, sb[i]) : "<end>");
                o += ',';
                emit::kv_bool(o, "diverges", i == div);
                o += '}';
            }
            o += ']';
        }
        printf("{\"diff\":{%s}}\n", o.c_str());
    } else {
        printf("exec counts: A=%zu B=%zu\n", sa.size(), sb.size());
        if (identical) {
            printf("identical execution sequences\n");
            emit::Meta meta;
            emit::finish(meta, json);
            return 0;
        }
        printf("first divergence at exec index %zu (0-based)\n", div);
        printf("context:\n");
        size_t from = div >= size_t(context) ? div - size_t(context) : 0;
        size_t to = div + size_t(context) + 1;
        for (size_t i = from; i < to; i++) {
            if (i < sa.size() || i < sb.size()) {
                printf("  [%5zu] A: %-22s %-34s B: %-22s %s%s\n", i,
                       i < sa.size() ? loc(a, sa[i]).c_str() : "-",
                       i < sa.size() ? txt(a, sa[i]).c_str() : "<end>",
                       i < sb.size() ? loc(b, sb[i]).c_str() : "-",
                       i < sb.size() ? txt(b, sb[i]).c_str() : "<end>",
                       i == div ? "   <-- DIVERGES" : "");
            }
        }
    }
    emit::Meta meta;
    if (!identical) {
        uint64_t lo = div > 5 ? div - 5 : 0;
        char b1[256], b2[256];
        snprintf(b1, sizeof b1, "gt export --from %llu --to %llu --format compact %s",
                 (unsigned long long)lo, (unsigned long long)(div + 5), a_p.c_str());
        snprintf(b2, sizeof b2, "gt export --from %llu --to %llu --format compact %s",
                 (unsigned long long)lo, (unsigned long long)(div + 5), b_p.c_str());
        meta.suggest.push_back(b1);
        meta.suggest.push_back(b2);
    }
    emit::finish(meta, json);
    return 0;
}

// ---------------------------------------------------------------------------
// fold (loop detection over the exec stream)
// ---------------------------------------------------------------------------
int q_fold(const std::string& gtb, int top, bool json) {
    GtbFile f;
    if (!f.load(gtb)) return 1;
    std::vector<uint32_t> s;
    Expander(f).for_each([&](uint64_t, const Group& g) {
        if (g.has_exec) s.push_back(g.site_id);
        return true;
    });
    struct Loop { size_t start; size_t period; size_t reps; };
    std::vector<Loop> loops;
    size_t i = 0;
    while (i + 2 < s.size()) {
        bool found = false;
        size_t maxp = s.size() - i >= 3 * 64 ? 64 : (s.size() - i) / 3;
        for (size_t p = 1; p <= maxp; p++) {
            bool ok = true;
            for (size_t k = 0; k < 2 * p && ok; k++)
                if (s[i + k] != s[i + p + k]) ok = false;
            if (!ok) continue;
            size_t reps = 2;
            while (i + (reps + 1) * p <= s.size()) {
                bool eq = true;
                for (size_t k = 0; k < p; k++)
                    if (s[i + k] != s[i + reps * p + k]) { eq = false; break; }
                if (!eq) break;
                reps++;
            }
            loops.push_back({i, p, reps});
            i += reps * p;
            found = true;
            break;
        }
        if (!found) i++;
    }
    std::sort(loops.begin(), loops.end(), [](const Loop& a, const Loop& b) {
        return a.reps * a.period > b.reps * b.period;
    });
    size_t shown = std::min<size_t>(loops.size(), top > 0 ? top : 0);
    if (json) {
        std::string o = "\"loops\":[";
        for (size_t k = 0; k < shown; k++) {
            const Loop& L = loops[k];
            if (k) o += ',';
            o += '{';
            emit::kv_u64(o, "start", L.start);
            o += ',';
            emit::kv_u64(o, "end", L.start + L.reps * L.period);
            o += ',';
            emit::kv_u64(o, "period", L.period);
            o += ',';
            emit::kv_u64(o, "reps", L.reps);
            o += ",\"body\":[";
            for (size_t j = 0; j < L.period && j < 8; j++) {
                if (j) o += ',';
                o.push_back('"');
                o.append(f.arena.pool_ptr() + f.arena.get(s[L.start + j]).disasm_off,
                         f.arena.get(s[L.start + j]).disasm_len);
                o.push_back('"');
            }
            o += "]}";
        }
        o += ']';
        printf("{\"fold\":{%s}}\n", o.c_str());
    } else {
        printf("detected %zu loop regions (top %d by executed instructions):\n", loops.size(), top);
        for (size_t k = 0; k < shown; k++) {
            const Loop& L = loops[k];
            printf("  exec [%zu, %zu): period=%zu reps=%zu (%zu insn execs)\n",
                   L.start, L.start + L.reps * L.period, L.period, L.reps,
                   L.reps * L.period);
            for (size_t j = 0; j < L.period && j < 8; j++) {
                const Site& st = f.arena.get(s[L.start + j]);
                printf("    %s\n", std::string(f.arena.pool_ptr() + st.disasm_off,
                                               st.disasm_len).c_str());
            }
            if (L.period > 8) printf("    ... (%zu more)\n", L.period - 8);
        }
    }
    emit::Meta meta;
    meta.total = loops.size();
    meta.shown = shown;
    meta.truncated = loops.size() > shown;
    if (!loops.empty()) {
        const Loop& L = loops[0];
        char b[256];
        snprintf(b, sizeof b, "gt export --from %llu --to %llu --format compact %s",
                 (unsigned long long)L.start,
                 (unsigned long long)(L.start + 2 * L.period), gtb.c_str());
        meta.suggest.push_back(b);
    }
    emit::finish(meta, json);
    return 0;
}

// ---------------------------------------------------------------------------
// W3b: streaming gtb queries. One Expander pass each, the dual-mode
// (text / JSON Lines) + meta-footer contract.
// ---------------------------------------------------------------------------

// "mod!0xoff" for a site (or "<no-site>" for call/svc/ret-only groups)
static std::string gtb_at(const GtbFile& f, uint32_t site_id) {
    if (site_id == 0xFFFFFFFFu) return "<event>";
    const Site& s = f.arena.get(site_id);
    char b[320];
    if (s.module_id < f.arena.modules().size())
        snprintf(b, sizeof b, "%s!0x%llx", f.arena.modules()[s.module_id].c_str(),
                 (unsigned long long)(s.addr - f.arena.module_base(s.module_id)));
    else
        snprintf(b, sizeof b, "0x%llx", (unsigned long long)s.addr);
    return b;
}

static const char* stop_reason_name(uint8_t r) {
    switch (r) {
        case STOP_NORMAL: return "normal";
        case STOP_MAX_BYTES: return "max_bytes";
        case STOP_MAX_EVENTS: return "max_events";
        case STOP_MAX_MS: return "max_ms";
        case STOP_CRASH: return "crash";
        case STOP_TRIGGER: return "trigger";
        default: return "none";
    }
}

int q_stat(const std::string& gtb, bool json) {
    GtbFile f;
    if (!f.load(gtb)) { fprintf(stderr, "load failed\n"); return 1; }
    std::vector<uint64_t> mod_exec(f.arena.modules().size(), 0);
    uint64_t first_addr = 0, first_off = 0;
    std::string first_mod;
    bool saw_exec = false;
    Expander(f).for_each([&](uint64_t, const Group& g) {
        if (!g.has_exec) return true;
        const Site& s = f.arena.get(g.site_id);
        if (s.module_id < mod_exec.size()) mod_exec[s.module_id]++;
        if (!saw_exec) {
            saw_exec = true;
            first_addr = s.addr;
            if (s.module_id < f.arena.modules().size()) {
                first_mod = f.arena.modules()[s.module_id];
                first_off = s.addr - f.arena.module_base(s.module_id);
            } else {
                first_off = s.addr;
            }
        }
        return true;
    });
    const char* dialect =
        f.dialect & 1 ? (f.dialect & 2 ? "upstream+crlf" : "upstream")
                      : (f.dialect & 2 ? "native+crlf" : "native");
    if (json) {
        std::string o;
        emit::kv_str(o, "file", gtb);
        o += ',';
        emit::kv_str(o, "dialect", dialect);
        o += ',';
        emit::kv_str(o, "stop", stop_reason_name(f.stop_reason));
        char b[256];
        snprintf(b, sizeof b,
                 ",\"exec\":%llu,\"regw\":%llu,\"mem\":%llu,\"call\":%llu,"
                 "\"svc\":%llu,\"ret\":%llu,\"rdval\":%llu,\"simdv\":%llu,"
                 "\"verbatim\":%llu,\"events_seen\":%llu,\"events_recorded\":%llu,"
                 "\"bytes_written\":%llu,",
                 (unsigned long long)f.n_exec, (unsigned long long)f.n_regw,
                 (unsigned long long)f.n_mem, (unsigned long long)f.n_call,
                 (unsigned long long)f.n_svc, (unsigned long long)f.n_ret,
                 (unsigned long long)f.n_rdval, (unsigned long long)f.n_simdv,
                 (unsigned long long)f.n_verbatim,
                 (unsigned long long)f.events_seen,
                 (unsigned long long)f.events_recorded,
                 (unsigned long long)f.bytes_written);
        o += b;
        emit::kv_hex(o, "initial_sp", f.initial_sp);
        if (saw_exec) {
            o += ',';
            emit::kv_hex(o, "first_addr", first_addr);
            o += ',';
            emit::kv_str(o, "first_at", first_mod + "!0x" + emit::hex64(first_off).substr(2));
        }
        o += ",\"modules\":[";
        for (size_t i = 0; i < f.arena.modules().size(); i++) {
            if (i) o += ',';
            o += '{';
            emit::kv_str(o, "name", f.arena.modules()[i]);
            o += ',';
            emit::kv_hex(o, "base", f.arena.module_base(uint32_t(i)));
            o += ',';
            emit::kv_u64(o, "exec", mod_exec[i]);
            o += '}';
        }
        o += ']';
        printf("{\"stat\":{%s}}\n", o.c_str());
    } else {
        printf("file: %s (dialect %s, stop %s)\n", gtb.c_str(), dialect,
               stop_reason_name(f.stop_reason));
        printf("events: exec=%llu regw=%llu mem=%llu call=%llu svc=%llu ret=%llu "
               "rdval=%llu simdv=%llu verbatim=%llu\n",
               (unsigned long long)f.n_exec, (unsigned long long)f.n_regw,
               (unsigned long long)f.n_mem, (unsigned long long)f.n_call,
               (unsigned long long)f.n_svc, (unsigned long long)f.n_ret,
               (unsigned long long)f.n_rdval, (unsigned long long)f.n_simdv,
               (unsigned long long)f.n_verbatim);
        printf("recorded: seen=%llu recorded=%llu bytes=%llu initial_sp=0x%llx\n",
               (unsigned long long)f.events_seen,
               (unsigned long long)f.events_recorded,
               (unsigned long long)f.bytes_written,
               (unsigned long long)f.initial_sp);
        if (saw_exec)
            printf("first: %s!0x%llx (addr 0x%llx)\n", first_mod.c_str(),
                   (unsigned long long)first_off, (unsigned long long)first_addr);
        printf("modules:\n");
        for (size_t i = 0; i < f.arena.modules().size(); i++)
            printf("  %s base=0x%llx exec=%llu\n", f.arena.modules()[i].c_str(),
                   (unsigned long long)f.arena.module_base(uint32_t(i)),
                   (unsigned long long)mod_exec[i]);
    }
    emit::Meta meta;
    meta.total = meta.shown = 1;
    meta.suggest.push_back("gt export --format compact --limit 200 " + gtb);
    meta.suggest.push_back("gt find-value 0xVALUE " + gtb);
    meta.suggest.push_back("gt mem-access --addr 0xADDR " + gtb);
    meta.suggest.push_back("gt taint --seed-reg 0 --at-ev 0 " + gtb);
    emit::finish(meta, json);
    return 0;
}

int q_mem_access(const std::string& gtb, uint64_t addr, bool use_range,
                 uint64_t range_base, uint64_t range_len, int limit,
                 uint64_t offset, bool json, bool writes_only) {
    GtbFile f;
    if (!f.load(gtb)) { fprintf(stderr, "load failed\n"); return 1; }
    uint64_t total = 0, shown = 0;
    uint64_t lim = limit > 0 ? uint64_t(limit) : UINT64_MAX;
    Expander(f).for_each([&](uint64_t gi, const Group& g) {
        for (int k = 0; k < g.n_mem; k++) {
            const MemOp& m = g.mem[k];
            if (writes_only && !m.is_write) continue;
            bool hit = use_range ? (m.addr >= range_base && m.addr < range_base + range_len)
                                 : (m.addr == addr);
            if (!hit) continue;
            if (total++ < offset) continue;
            if (shown >= lim) continue;
            shown++;
            if (json) {
                std::string o = "{";
                emit::kv_u64(o, "ev", gi);
                o += ',';
                emit::kv_str(o, "rw", m.is_write ? "w" : "r");
                o += ',';
                emit::kv_hex(o, "addr", m.addr);
                if (m.value_known) {
                    o += ',';
                    emit::kv_hex(o, "val", m.value);
                }
                o += ',';
                emit::kv_str(o, "at", gtb_at(f, g.has_exec ? g.site_id : 0xFFFFFFFFu));
                o += '}';
                printf("%s\n", o.c_str());
            } else {
                if (m.value_known)
                    printf("%llu %c 0x%llx =0x%llx %s\n", (unsigned long long)gi,
                           m.is_write ? 'w' : 'r', (unsigned long long)m.addr,
                           (unsigned long long)m.value,
                           gtb_at(f, g.has_exec ? g.site_id : 0xFFFFFFFFu).c_str());
                else
                    printf("%llu %c 0x%llx %s\n", (unsigned long long)gi,
                           m.is_write ? 'w' : 'r', (unsigned long long)m.addr,
                           gtb_at(f, g.has_exec ? g.site_id : 0xFFFFFFFFu).c_str());
            }
        }
        return true;
    });
    emit::Meta meta;
    meta.total = total;
    meta.shown = shown;
    meta.truncated = offset + shown < total;
    if (meta.truncated) {
        char b[320];
        if (use_range)
            snprintf(b, sizeof b, "gt mem-access --range 0x%llx,0x%llx --offset %llu %s%s",
                     (unsigned long long)range_base, (unsigned long long)range_len,
                     (unsigned long long)(offset + shown), gtb.c_str(),
                     json ? " --json" : "");
        else
            snprintf(b, sizeof b, "gt mem-access --addr 0x%llx%s --offset %llu %s%s",
                     (unsigned long long)addr, writes_only ? " --write" : "",
                     (unsigned long long)(offset + shown), gtb.c_str(),
                     json ? " --json" : "");
        meta.next = b;
    }
    meta.suggest.push_back("gt export --format compact --from EV --to EV+200 " + gtb);
    emit::finish(meta, json);
    return 0;
}

// function call sites directly on a gtb: streams the CALL events whose symbol
// matches --func and prints the arguments (x0..x3, delta-reconstructed) of the
// --nth (1-based) call onward. Named calls carry an exec context (module
// offset); target-only calls (crash-truncated or numeric) fall back to the
// raw branch target.
int q_func_args(const std::string& gtb, const std::string& func, int nth, int limit,
                bool json) {
    GtbFile f;
    if (!f.load(gtb)) { fprintf(stderr, "load failed\n"); return 1; }
    struct Row { uint64_t ev; std::string at; uint64_t target; uint64_t x[4]; int nargs; };
    std::vector<Row> rows;
    uint64_t total = 0;
    size_t base = nth > 1 ? size_t(nth - 1) : 0; // --nth 1-based; --nth 0/negative = from the top
    uint64_t lim = limit > 0 ? uint64_t(limit) : UINT64_MAX;
    Expander(f).for_each([&](uint64_t gi, const Group& g) {
        if (!g.is_call) return true;
        const char* name = g.call_name;
        if (!name || strcmp(name, func.c_str()) != 0) return true;
        total++;
        if (total - 1 < base) return true; // skip before the --nth window
        if (rows.size() >= lim) return true;
        Row r{};
        r.ev = gi;
        r.at = g.has_exec ? gtb_at(f, g.site_id) : "<event>";
        r.target = g.call_target;
        r.nargs = g.n_call_args >= 0 ? g.n_call_args : 4;
        if (r.nargs > 4) r.nargs = 4;
        for (int i = 0; i < 4; i++) r.x[i] = g.args[i];
        rows.push_back(r);
        return true;
    });
    uint64_t shown = 0;
    if (json) {
        for (size_t i = 0; i < rows.size(); i++, shown++) {
            const Row& r = rows[i];
            std::string o = "{";
            emit::kv_u64(o, "n", base + i + 1);
            o += ',';
            emit::kv_u64(o, "ev", r.ev);
            o += ',';
            emit::kv_str(o, "at", r.at);
            o += ",\"args\":[";
            for (int k = 0; k < r.nargs; k++) {
                if (k) o += ',';
                o += '"' + emit::hex64(r.x[k]) + '"';
            }
            o += ']';
            if (r.target) {
                o += ',';
                emit::kv_hex(o, "target", r.target);
            }
            o += '}';
            printf("%s\n", o.c_str());
        }
    } else {
        printf("calls to %s: %llu total\n", func.c_str(), (unsigned long long)total);
        for (size_t i = 0; i < rows.size(); i++, shown++) {
            const Row& r = rows[i];
            printf("  #%-8llu ev=%-8llu", (unsigned long long)(base + i + 1),
                   (unsigned long long)r.ev);
            for (int k = 0; k < r.nargs; k++)
                printf(" x%d=0x%-14llx", k, (unsigned long long)r.x[k]);
            printf("  %s\n", r.at.c_str());
        }
        if (total == 0) printf("  (no call to %s in %s)\n", func.c_str(), gtb.c_str());
    }
    emit::Meta meta;
    meta.total = total;
    meta.shown = shown;
    meta.truncated = base + shown < total;
    if (meta.truncated) {
        char b[320];
        snprintf(b, sizeof b, "gt func-args --func %s --nth %llu --limit %llu %s%s",
                 func.c_str(), (unsigned long long)(base + shown + 1),
                 (unsigned long long)lim, gtb.c_str(), json ? " --json" : "");
        meta.next = b;
    }
    if (!rows.empty()) {
        uint64_t ev0 = rows[std::min(base, rows.size() - 1)].ev;
        char b[320];
        uint64_t lo = ev0 > 5 ? ev0 - 5 : 0;
        snprintf(b, sizeof b, "gt export --from %llu --to %llu --format compact %s",
                 (unsigned long long)lo, (unsigned long long)(ev0 + 5), gtb.c_str());
        meta.suggest.push_back(b);
    }
    emit::finish(meta, json);
    return 0;
}

int q_find_value(const std::string& gtb, uint64_t val, int limit, uint64_t offset,
                 bool json) {
    GtbFile f;
    if (!f.load(gtb)) { fprintf(stderr, "load failed\n"); return 1; }
    uint64_t total = 0, shown = 0;
    uint64_t lim = limit > 0 ? uint64_t(limit) : UINT64_MAX;
    // dump-payload scan pattern: minimal-width LE bytes of val. Values that
    // only ever exist as memory bytes (protobuf payloads inside memcpy dumps)
    // have no register/obs lane; the verbatim hexdump rows are the only place
    // they appear. Width < 2 is too noisy for a byte-substring search.
    uint8_t pat[8];
    int pat_n = 0;
    {
        uint64_t v = val;
        do {
            pat[pat_n++] = uint8_t(v & 0xff);
            v >>= 8;
        } while (v && pat_n < 8);
    }
    auto row = [&](uint64_t gi, const char* lane, const Group& g) {
        if (total++ < offset) return;
        if (shown >= lim) return;
        shown++;
        if (json) {
            std::string o = "{";
            emit::kv_u64(o, "ev", gi);
            o += ',';
            emit::kv_str(o, "lane", lane);
            o += ',';
            emit::kv_hex(o, "val", val);
            o += ',';
            emit::kv_str(o, "at", gtb_at(f, g.has_exec ? g.site_id : 0xFFFFFFFFu));
            o += '}';
            printf("%s\n", o.c_str());
        } else {
            printf("%llu %s 0x%llx %s\n", (unsigned long long)gi, lane,
                   (unsigned long long)val,
                   gtb_at(f, g.has_exec ? g.site_id : 0xFFFFFFFFu).c_str());
        }
    };
    Expander(f).for_each([&](uint64_t gi, const Group& g) {
        char rb[16];
        if (g.has_verbatim) {
            // hexdump rows: byte-exact content search at any offset. Qword-
            // aligned full-width matches are already covered by the mem_r
            // lanes the importer synthesized from the same rows.
            if (pat_n >= 2) {
                const std::string& vb = f.verbatim;
                uint64_t raddr = 0;
                uint8_t bytes[16];
                int nb = 0;
                if (g.verbatim_off + g.verbatim_len <= vb.size() &&
                    parse_hexdump_row(vb.data() + g.verbatim_off,
                                      g.verbatim_len, raddr, bytes, nb))
                    for (int o = 0; o + pat_n <= nb; o++)
                        if (!memcmp(bytes + o, pat, size_t(pat_n)) &&
                            !(pat_n == 8 && (o & 7) == 0)) {
                            char lb[48];
                            snprintf(lb, sizeof lb, "dump:0x%llx",
                                     (unsigned long long)(raddr +
                                                          uint64_t(o)));
                            row(gi, lb, g);
                        }
            }
            // fall through: verbatim groups may carry synthesized mem lanes
        }
        // imported files dual-record writes (REGW + wobs token) — the wr:
        // lanes below already cover them, so skip the bare lane to avoid
        // counting one logical write twice
        for (int k = 0; k < g.n_wr; k++)
            if (g.n_wobs == 0 && g.wr_val[k] == val)
                row(gi, taint_reg_name(g.wr_id[k] & 31, rb), g);
        for (int k = 0; k < g.n_obs; k++) {
            unsigned __int128 v = g.obs[k].val;
            std::string ln = std::string("rd:") + f.arena.str(g.obs[k].name_id);
            if (v <= UINT64_MAX) {
                if (uint64_t(v) == val) row(gi, ln.c_str(), g);
            } else {
                // 128-bit SIMD observation: match either 64-bit lane exactly
                if (uint64_t(v) == val) row(gi, (ln + ".lo").c_str(), g);
                else if (uint64_t(v >> 64) == val) row(gi, (ln + ".hi").c_str(), g);
            }
        }
        for (int k = 0; k < g.n_wobs; k++) {
            unsigned __int128 v = g.wobs[k].val;
            std::string ln = std::string("wr:") + f.arena.str(g.wobs[k].name_id);
            if (v <= UINT64_MAX) {
                if (uint64_t(v) == val) row(gi, ln.c_str(), g);
            } else {
                if (uint64_t(v) == val) row(gi, (ln + ".lo").c_str(), g);
                else if (uint64_t(v >> 64) == val) row(gi, (ln + ".hi").c_str(), g);
            }
        }
        for (int k = 0; k < g.n_mem; k++)
            if (g.mem[k].value_known && g.mem[k].value == val)
                row(gi, g.mem[k].is_write ? "mem_w" : "mem_r", g);
        return true;
    });
    emit::Meta meta;
    meta.total = total;
    meta.shown = shown;
    meta.truncated = offset + shown < total;
    if (meta.truncated) {
        char b[320];
        snprintf(b, sizeof b, "gt find-value 0x%llx --offset %llu %s%s",
                 (unsigned long long)val, (unsigned long long)(offset + shown),
                 gtb.c_str(), json ? " --json" : "");
        meta.next = b;
    }
    meta.suggest.push_back("gt export --format compact --from EV --to EV+100 " + gtb);
    emit::finish(meta, json);
    return 0;
}

// calltree directly on a gtb: a stack over the call/ret stream (is_call
// pushes, is_ret pops — call first within a group: imported files carry both
// in one group). Every call named --func opens a capture window that prints
// descendant calls (2-space indent per level, --depth levels deep) until the
// matched frame returns.
int q_calltree_gtb(const std::string& gtb, const std::string& func, int depth,
                   int limit, bool json) {
    GtbFile f;
    if (!f.load(gtb)) { fprintf(stderr, "load failed\n"); return 1; }
    std::vector<std::string> stack;
    bool capturing = false;
    size_t base = 0;
    uint64_t lim = limit > 0 ? uint64_t(limit) : UINT64_MAX;
    uint64_t shown = 0, would_print = 0, matches = 0;
    auto emit_line = [&](uint64_t gi, int lvl, const Group& g, const char* name) {
        if (shown < lim) {
            shown++;
            int na = g.n_call_args >= 0 ? g.n_call_args : 4;
            if (json) {
                std::string o = "{";
                emit::kv_u64(o, "ev", gi);
                o += ',';
                emit::kv_u64(o, "depth", uint64_t(lvl));
                o += ',';
                emit::kv_str(o, "name", name);
                o += ",\"args\":[";
                for (int i = 0; i < na; i++) {
                    if (i) o += ',';
                    emit::esc_append(o, emit::hex64(g.args[i]).c_str());
                }
                o += "]}";
                printf("%s\n", o.c_str());
            } else {
                std::string line(size_t(lvl) * 2, ' ');
                line += name;
                line += '(';
                for (int i = 0; i < na; i++) {
                    if (i) line += ", ";
                    char b[32];
                    snprintf(b, sizeof b, "x%d=0x%llx", i, (unsigned long long)g.args[i]);
                    line += b;
                }
                line += ')';
                printf("%s\n", line.c_str());
            }
        }
        would_print++;
    };
    Expander(f).for_each([&](uint64_t gi, const Group& g) {
        if (g.is_call) {
            char tgt[24];
            const char* name = g.call_name;
            if (!name) {
                snprintf(tgt, sizeof tgt, "0x%llx", (unsigned long long)g.call_target);
                name = tgt;
            }
            size_t d = stack.size();
            if (capturing) {
                if (d - base <= size_t(depth < 0 ? 0 : depth))
                    emit_line(gi, int(d - base), g, name);
            } else if (func == name) {
                capturing = true;
                base = d;
                matches++;
                emit_line(gi, 0, g, name);
            }
            stack.push_back(name);
        }
        if (g.is_ret) {
            if (!stack.empty()) stack.pop_back();
            if (capturing && stack.size() <= base) capturing = false;
        }
        return true;
    });
    if (!capturing && matches == 0) {
        // func never called: say so plainly instead of printing nothing
        if (!json) printf("no call to %s in %s\n", func.c_str(), gtb.c_str());
    }
    emit::Meta meta;
    meta.total = would_print;
    meta.shown = shown;
    meta.truncated = would_print > shown;
    if (meta.truncated) {
        char b[256];
        snprintf(b, sizeof b, "gt calltree --func %s --depth %d --limit %d %s",
                 func.c_str(), depth, limit * 5, gtb.c_str());
        meta.next = b;
    }
    emit::finish(meta, json);
    return 0;
}
