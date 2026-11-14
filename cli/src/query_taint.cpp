#include <traceq/queries.h>
#include <traceq/ingest.h>
#include <traceq/import.h>
#include <traceq/site.h>
#include "emit.h"
#include "query_common.h"
#include <algorithm>
#include <cstdio>
#include <iterator>
#include <unordered_map>
#include <unordered_set>
#include <vector>

using namespace traceq;

// ---------------------------------------------------------------------------
// taint (gtb-based stream walk)
//
// Semantics follow the upstream GumTrace taint_tracker (src/taint/
// TaintEngine.cpp) so default result sets are directly comparable: data-flow
// only (a store taints memory through its DATA register, a load only through
// the memory cell). --index-deps optionally treats a load's index register as
// a source, which is useful for table lookups such as S-box/Base64 mappings.
// Overwriting with untainted data KILLS taint, movk preserves it,
// movz/movn/adr/adrp kill unconditionally, cmp/tst-class instructions set or
// clear NZCV, and stp/ldp pairs track the two memory slots independently
// (slot2 = addr + 4 or 8 by the first operand's w/x spelling, bug-compatible
// with upstream). The walk stops early when all taint is cleared or after 1M
// consecutive uninvolved events (upstream's scan limit), and reports why.
//
// Current upstream also propagates SIMD registers and NZCV writes. traceq's
// remaining documented extension is treating NZCV as a first-class source for
// csel/ccmp-class instructions (upstream's operand parser never lists NZCV as
// a source, so cmp -> csel chains break there). Plain integer data-flow yields
// the same taint sets as upstream.
//
// Register space: mask bits 0..31 = x0..x30/sp, bits 32..63 = q0..q31, plus a
// separate NZCV flag. Per-site source/destination roles are compiled from the
// disassembly during import. This walk uses those dependencies, not observed
// SIMD values.
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
struct TaintEdge { uint64_t ev, line; std::string what; };

struct TaintRec {  // compact per-group record for backward walks
    uint32_t site_id;  // 0xFFFFFFFF for non-exec groups (call/ret-only)
    uint64_t source_line;
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

// verbatim-hexdump memcpy bridging and dump-payload search use the shared
// upstream-dialect parsers from traceq/import.h (parse_hexdump_header /
// parse_hexdump_row). The taint walkers bind dumps to the preceding call
// (args dst, src) and apply copy semantics, so copied buffers stop looking
// like orphan addresses.

int q_taint(const std::string& gtb, const TaintOptions& options) {
    if (options.seed_reg < -1 || options.seed_reg > 31 ||
        options.seed_q < -1 || options.seed_q > 31 ||
        (!options.seed_addr && options.seed_reg < 0 && options.seed_q < 0 &&
         !options.seed_nzcv) || (!options.mod.empty() && !options.off)) {
        fprintf(stderr, "taint: invalid seed or module selector\n");
        return 2;
    }
    if (options.limit <= 0) {
        fprintf(stderr, "taint: --limit must be greater than zero\n");
        return 2;
    }
    GtbFile f;
    if (!load_query_file(f, gtb)) return 1;
    emit::QueryWriter writer(options.json, f);

    // --off resolves to the set of sites at that module-relative offset
    std::unordered_set<uint32_t> off_sites;
    if (options.off) {
        for (uint32_t i = 0; i < f.arena.sites().size(); i++) {
            const Site& s = f.arena.get(i);
            if (s.module_id >= f.arena.modules().size()) continue;
            if (!options.mod.empty() &&
                f.arena.modules()[s.module_id] != options.mod)
                continue;
            if (s.addr - f.arena.module_base(s.module_id) == *options.off)
                off_sites.insert(i);
        }
        if (off_sites.empty()) {
            fprintf(stderr, "taint: no site at %s!0x%llx\n",
                    options.mod.empty() ? "*" : options.mod.c_str(),
                    (unsigned long long)*options.off);
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
    auto add_edge = [&](uint64_t ev, uint64_t line, std::string what) {
        edges_total++;
        if ((int)edges.size() < options.limit)
            edges.push_back({ev, line, std::move(what)});
    };
    auto taint_site = [&](uint32_t sid) -> const TaintPlan& {
        static const TaintPlan kEmpty;
        if (sid == 0xFFFFFFFFu || sid >= f.arena.sites().size()) return kEmpty;
        return f.arena.get(sid).taint;
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
    auto taint_reg_edge = [&](uint64_t ev, uint64_t line, uint32_t site_id, int slot,
                              const char* via) {
        char rb[16], msg[288];
        snprintf(msg, sizeof msg, "%s : %s <- %s", site_txt(site_id).c_str(),
                 taint_reg_name(slot, rb), via);
        add_edge(ev, line, msg);
    };
    auto taint_mem_edge = [&](uint64_t ev, uint64_t line, uint32_t site_id) {
        add_edge(ev, line, site_txt(site_id) + " : mem_w -> tainted");
    };
    auto apply_seed = [&]() {
        if (options.seed_reg >= 0) reg_t |= 1ULL << (options.seed_reg & 31);
        if (options.seed_q >= 0) reg_t |= 1ULL << (32 + (options.seed_q & 31));
        if (options.seed_nzcv) nzcv_t = true;
        if (options.seed_addr) addr_t.insert(*options.seed_addr);
    };

    bool partial = false;
    uint64_t total = 0, walked = 0;
    uint64_t seed_ev = 0, seed_line = 0;
    uint64_t matched = 0;          // involved events (upstream "Total matched")
    const char* stop = "end of trace";

    if (!options.backward) {
        bool seeded = false;
        bool stopped = false;      // early-stop: keep streaming to count total
        uint64_t since_involved = 0;
        // verbatim-hexdump copy bridging: a memcpy-class call followed by a
        // source-buffer dump (upstream dialect) transfers src-cell taint to
        // the dst range — without it copied buffers look like orphan addresses
        bool pend_copy = false;
        uint64_t pend_dst = 0, pend_src = 0;
        if (!TraceScan(f).for_each([&](uint64_t gi, const Group& g) -> bool {
            total = gi + 1;
            if (!seeded) {
                bool hit = off_sites.empty()
                               ? (gi >= options.at_ev.value_or(0))
                               : (g.has_exec && off_sites.count(g.site_id) &&
                                  gi >= options.at_ev.value_or(0));
                if (!hit) return true;
                apply_seed();
                seed_ev = gi;
                seed_line = g.source_line;
                seeded = true;
                matched = 1; // upstream records the seed line itself
                return true; // propagation starts after the seed event
            }
            if (stopped) return true; // total keeps counting
            if (options.window && walked >= options.window) {
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
                    if (parse_hexdump_header(g.verbatim, g.verbatim_len,
                                             ha, hl) &&
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
                            add_edge(gi, g.source_line,
                                     "memcpy : dst <- tainted src cells");
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
            const TaintPlan& ts = taint_site(g.site_id);
            uint64_t mr = 0, mw = 0;
            bool has_mr, has_mw;
            group_mem(g, mr, has_mr, mw, has_mw);
            uint64_t mr2 = mr + ts.elem, mw2 = mw + ts.elem;
            bool mr_t = has_mr && addr_t.count(mr);
            bool mr2_t = ts.pair && has_mr && addr_t.count(mr2);
            bool index_t = options.index_deps && (ts.index_mask & reg_t) != 0;
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
                    setclr_reg(ts.dsts[0], mr_t || index_t);
                    setclr_reg(ts.dsts[1], mr2_t || index_t);
                    if ((mr_t || index_t) && !t0)
                        taint_reg_edge(gi, g.source_line, g.site_id, ts.dsts[0],
                                       mr_t ? "mem" : "index");
                    if ((mr2_t || index_t) && !t1)
                        taint_reg_edge(gi, g.source_line, g.site_id, ts.dsts[1],
                                       mr2_t ? "mem" : "index");
                } else {
                    for (int i = 0; i < ts.n_dsts; i++) {
                        bool was = tainted(ts.dsts[i]);
                        setclr_reg(ts.dsts[i], mr_t || index_t);
                        if ((mr_t || index_t) && !was)
                            taint_reg_edge(gi, g.source_line, g.site_id, ts.dsts[i],
                                           mr_t ? "mem" : "index");
                    }
                }
                break;
            case TC_STORE:
                if (has_mw) {
                    if (ts.pair && ts.n_st >= 2) {
                        bool d0 = tainted(ts.st[0]), d1 = tainted(ts.st[1]);
                        if (d0 && !mw_t) taint_mem_edge(gi, g.source_line, g.site_id);
                        if (d1 && !mw2_t) taint_mem_edge(gi, g.source_line, g.site_id);
                        setclr_addr(mw, d0);
                        setclr_addr(mw2, d1);
                    } else {
                        bool d0 = ts.n_st > 0 && tainted(ts.st[0]);
                        if (d0 && !mw_t) taint_mem_edge(gi, g.source_line, g.site_id);
                        setclr_addr(mw, d0);
                    }
                }
                break;
            case TC_COMPARE:
                if (src_t && !nzcv_t)
                    add_edge(gi, g.source_line, site_txt(g.site_id) + " : nzcv <- reg");
                nzcv_t = src_t;
                break;
            case TC_BRANCH:
                break;
            default: { // TC_OTHER: data move / arith / logic / shift / cond-sel
                for (int i = 0; i < ts.n_dsts; i++) {
                    bool was = tainted(ts.dsts[i]);
                    setclr_reg(ts.dsts[i], src_t);
                    if (src_t && !was)
                        taint_reg_edge(gi, g.source_line, g.site_id, ts.dsts[i],
                                       src_reg_t ? "reg" : "mem");
                }
                if (ts.nzcv_w) {
                    if (src_t && !nzcv_t)
                        add_edge(gi, g.source_line,
                                 site_txt(g.site_id) + " : nzcv <- reg");
                    nzcv_t = src_t;
                }
                if (has_mw) { // OTHER-category mem write (casp-class)
                    if (src_t && !mw_t) taint_mem_edge(gi, g.source_line, g.site_id);
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
        })) return scan_error(gtb);
        if (!seeded) {
            fprintf(stderr, "taint: seed event not found (trace has %llu events)\n",
                    (unsigned long long)total);
            return 1;
        }
    } else {
        // stream into a ring of compact records, ending at --at-ev (default:
        // end of stream); window bounds history, default 2M events
        uint64_t back_window = options.window ? options.window : 2000000;
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
        if (!TraceScan(f).for_each([&](uint64_t gi, const Group& g) -> bool {
            if (options.at_ev && gi > *options.at_ev) return false;
            if (g.has_verbatim) {
                if (pend_copy) {
                    pend_copy = false;
                    uint64_t ha = 0, hl = 0;
                    if (parse_hexdump_header(g.verbatim, g.verbatim_len,
                                             ha, hl) &&
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
            r.source_line = g.source_line;
            r.n_mem = uint8_t(g.n_mem);
            for (int k = 0; k < g.n_mem && k < 2; k++)
                r.mem[k] = {g.mem[k].addr, g.mem[k].is_write};
            if (ring.size() < back_window) ring.push_back(r);
            else { ring[head] = r; head = (head + 1) % ring.size(); }
            pushed++;
            hit_end = true;
            return true;
        })) return scan_error(gtb);
        if (!hit_end) { fprintf(stderr, "taint: empty trace\n"); return 1; }
        if (options.at_ev && *options.at_ev >= pushed) {
            fprintf(stderr, "taint: --at-ev is outside the trace\n");
            return 1;
        }
        total = pushed;
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
        seed_line = ring[size_t((seed_ev - ring_base + head) % ring.size())].source_line;
        apply_seed();
        // upstream backward: the seed line itself propagates, then only
        // INVOLVED lines do; kills happen inside propagation (a propagated-
        // through destination is untainted, its sources tainted)
        uint64_t since_involved = 0;
        auto src_edge = [&](uint64_t ev, uint64_t line, uint32_t sid, int slot,
                            const char* role = "source reg") {
            char rb[16], msg[288];
            snprintf(msg, sizeof msg, "%s : %s %s", site_txt(sid).c_str(), role,
                     taint_reg_name(slot, rb));
            add_edge(ev, line, msg);
        };
        auto mem_edge = [&](uint64_t ev, uint64_t line, uint32_t sid, uint64_t a) {
            char msg[288];
            snprintf(msg, sizeof msg, "%s : source mem 0x%llx", site_txt(sid).c_str(),
                     (unsigned long long)a);
            add_edge(ev, line, msg);
        };
        auto taint_srcs = [&](uint64_t ev, uint64_t line, uint32_t sid,
                              uint64_t mask, const char* role = "source reg") {
            uint64_t newly = mask & ~reg_t;
            while (newly) {
                int slot = __builtin_ctzll(newly);
                newly &= newly - 1;
                reg_t |= 1ULL << slot;
                src_edge(ev, line, sid, slot, role);
            }
        };
        auto taint_cell = [&](uint64_t ev, uint64_t line, uint32_t sid, uint64_t a) {
            if (!addr_t.count(a)) {
                addr_t.insert(a);
                mem_edge(ev, line, sid, a);
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
                        add_edge(i, r.source_line, "memcpy : demand -> src cells");
                        matched++;
                        since_involved = 0;
                    }
                }
            }
            const TaintPlan& ts = taint_site(r.site_id);
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
                            if (has_mr) taint_cell(i, r.source_line, r.site_id, mr);
                            if (options.index_deps)
                                taint_srcs(i, r.source_line, r.site_id, ts.index_mask,
                                           "source index");
                        }
                        if (tainted(ts.dsts[1])) {
                            reg_t &= ~(1ULL << ts.dsts[1]);
                            if (has_mr) taint_cell(i, r.source_line, r.site_id, mr2);
                            if (options.index_deps)
                                taint_srcs(i, r.source_line, r.site_id, ts.index_mask,
                                           "source index");
                        }
                    } else {
                        bool any = (ts.dst_mask & reg_t) != 0;
                        reg_t &= ~ts.dst_mask;
                        if (any && has_mr)
                            taint_cell(i, r.source_line, r.site_id, mr);
                        if (any && options.index_deps)
                            taint_srcs(i, r.source_line, r.site_id, ts.index_mask,
                                       "source index");
                    }
                    break;
                case TC_STORE:
                    if (mw_t) {
                        addr_t.erase(mw);
                        if (ts.n_st > 0 && !tainted(ts.st[0])) {
                            reg_t |= 1ULL << ts.st[0];
                            src_edge(i, r.source_line, r.site_id, ts.st[0]);
                        }
                    }
                    if (ts.pair && ts.n_st >= 2 && mw2_t) {
                        addr_t.erase(mw2);
                        if (!tainted(ts.st[1])) {
                            reg_t |= 1ULL << ts.st[1];
                            src_edge(i, r.source_line, r.site_id, ts.st[1]);
                        }
                    }
                    break;
                case TC_COMPARE:
                    if (nzcv_t) {
                        nzcv_t = false;
                        taint_srcs(i, r.source_line, r.site_id, ts.src_mask);
                    }
                    break;
                case TC_BRANCH:
                    break;
                default: // TC_OTHER
                    if (dst_t || nz_t) {
                        reg_t &= ~ts.dst_mask;
                        if (nz_t) nzcv_t = false;
                        taint_srcs(i, r.source_line, r.site_id, ts.src_mask);
                        if (ts.nzcv_r && !nzcv_t) { // csel-class extension
                            nzcv_t = true;
                            add_edge(i, r.source_line,
                                     site_txt(r.site_id) + " : source reg nzcv");
                        }
                        if (dst_t && has_mr)
                            taint_cell(i, r.source_line, r.site_id, mr);
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
    auto seed_desc = [&]() -> std::string {
        std::string s;
        if (options.seed_addr) s += " addr=" + emit::hex64(*options.seed_addr);
        if (options.seed_reg >= 0) {
            char rb[16];
            s += " reg=" +
                 std::string(taint_reg_name(options.seed_reg & 31, rb));
        }
        if (options.seed_q >= 0)
            s += " reg=q" + std::to_string(options.seed_q);
        if (options.seed_nzcv) s += " nzcv";
        if (options.at_ev) s += " at ev=" + std::to_string(*options.at_ev);
        if (options.off)
            s += " at " + (options.mod.empty() ? "*" : options.mod) + "!" +
                 emit::hex64(*options.off);
        return s.empty() ? " (none)" : s;
    };
    auto taint_cmd = [&](int new_limit) -> std::string {
        std::string s = "traceq taint";
        if (options.seed_addr)
            s += " --seed-addr " + emit::hex64(*options.seed_addr);
        if (options.seed_reg >= 0)
            s += " --seed-reg " + std::to_string(options.seed_reg);
        if (options.seed_q >= 0)
            s += " --seed-q " + std::to_string(options.seed_q);
        if (options.seed_nzcv) s += " --seed-nzcv";
        if (options.backward) s += " --back";
        if (options.index_deps) s += " --index-deps";
        s += " --limit " + std::to_string(new_limit);
        if (options.window)
            s += " --window " + std::to_string(options.window);
        if (options.at_ev)
            s += " --at-ev " + std::to_string(*options.at_ev);
        if (options.off) {
            s += " --off " + emit::hex64(*options.off);
            if (!options.mod.empty()) s += " --mod " + shell_arg(options.mod);
        }
        return s + " " + shell_arg(gtb) + (options.json ? " --json" : "");
    };
    // edges are capped by --limit; the walk itself is one pass
    bool edges_trunc = edges_total > edges.size();
    std::vector<uint64_t> addrs(addr_t.begin(), addr_t.end());
    std::sort(addrs.begin(), addrs.end());
    size_t frontier_shown = std::min(addrs.size(), size_t(options.limit));

    if (options.json) {
        std::string o;
        emit::kv_bool(o, "partial", partial);
        o += ",\"seed\":{";
        if (options.seed_addr) {
            emit::kv_hex(o, "addr", *options.seed_addr);
            o += ',';
        }
        if (options.seed_reg >= 0) {
            emit::kv_u64(o, "reg", uint64_t(options.seed_reg));
            o += ',';
        }
        if (options.seed_q >= 0) {
            emit::kv_u64(o, "q", uint64_t(options.seed_q));
            o += ',';
        }
        emit::kv_bool(o, "nzcv", options.seed_nzcv);
        o += ',';
        emit::kv_u64(o, "ev", seed_ev);
        if (seed_line) {
            o += ',';
            emit::kv_u64(o, "line", seed_line);
        }
        o += "},\"direction\":\"";
        o += options.backward ? "backward" : "forward";
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
            if (edges[i].line) {
                o += ',';
                emit::kv_u64(o, "line", edges[i].line);
            }
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
        o += "],\"addr_total\":" + std::to_string(addrs.size());
        o += ",\"addrs_truncated\":";
        o += frontier_shown < addrs.size() ? "true" : "false";
        o += ",\"addrs\":[";
        for (size_t i = 0; i < frontier_shown; i++) {
            if (i) o += ',';
            o += '"' + emit::hex64(addrs[i]) + '"';
        }
        o += ']';
        writer.row("{" + o + "}");
    } else {
        if (partial)
            printf("PARTIAL: window limited — walked %llu of %llu events; widen with "
                   "--window 0 (forward) or a larger --window (backward)\n",
                   (unsigned long long)walked, (unsigned long long)total);
        printf("taint seed:%s (event %llu", seed_desc().c_str(),
               (unsigned long long)seed_ev);
        if (seed_line) printf(", line %llu", (unsigned long long)seed_line);
        printf(")\n");
        printf("direction: %s | events walked: %llu of %llu | matched: %llu | stop: %s | edges (limit %d): %llu\n",
               options.backward ? "backward" : "forward",
               (unsigned long long)walked, (unsigned long long)total,
               (unsigned long long)matched, stop, options.limit,
               (unsigned long long)edges_total);
        for (auto& e : edges) {
            printf("  ev=%-8llu", (unsigned long long)e.ev);
            if (e.line) printf(" line=%-8llu", (unsigned long long)e.line);
            printf(" %s\n", e.what.c_str());
        }
        printf("final tainted regs:");
        for (int slot = 0; slot < 64; slot++)
            if (reg_t & (1ULL << slot)) {
                char rb[16];
                printf(" %s", taint_reg_name(slot, rb));
            }
        if (nzcv_t) printf(" nzcv");
        printf("\nfinal tainted addrs (%zu):", addrs.size());
        for (size_t i = 0; i < frontier_shown; i++)
            printf(" 0x%llx", (unsigned long long)addrs[i]);
        if (frontier_shown < addrs.size())
            printf(" ... [%zu more]", addrs.size() - frontier_shown);
        putchar('\n');
    }

    emit::Meta meta;
    meta.total = edges_total;
    meta.shown = edges.size();
    meta.truncated = edges_trunc;
    if (edges_trunc)
        meta.next = taint_cmd(options.limit * 5); // raise --limit; rerun from seed
    writer.finish(meta);
    if (edges_trunc && !options.json)
        printf("note: taint is not resumable — the next command reruns from the seed with a raised --limit\n");
    return 0;
}
