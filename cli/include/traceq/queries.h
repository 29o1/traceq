#pragma once
// Agent-facing query surface. Design rule: every output is bounded with an
// explicit truncation marker — the consumer is an agent with a limited
// context window, so queries must return small structured answers, never raw
// dumps. W2 contract: every command runs in text or --json mode (JSON Lines,
// integer values as hex strings) and ends with a meta footer carrying the cursor
// (truncated/total/shown/next).
//
// Every query sequentially scans the loaded .gtb event buffer (one Expander
// pass); there is no index/ingest step.
#include <cstdint>
#include <string>
#include <vector>

struct TaintOptions {
    uint64_t seed_addr = 0;
    int seed_reg = -1;
    int seed_q = -1;
    bool seed_nzcv = false;
    bool backward = false;
    int limit = 20;
    uint64_t window = 0;
    uint64_t at_ev = 0;
    uint64_t off = 0;
    std::string mod;
    bool json = false;
    bool index_deps = false;
};

struct MemAccessOptions {
    std::vector<uint64_t> addrs;
    bool use_range = false;
    uint64_t range_base = 0;
    uint64_t range_len = 0;
    int limit = 20;
    uint64_t offset = 0;
    uint64_t from_ev = 0;
    uint64_t to_ev = UINT64_MAX;
    int last = 0;
    bool json = false;
    bool writes_only = false;
    bool reads_only = false;
    // Explicit opt-in for selectorless write enumeration. The query accepts
    // it only for a finite event window and with writes_only=true.
    bool all_writes = false;
};

struct FindPcOptions {
    std::vector<uint64_t> addrs;
    std::vector<uint64_t> offs;
    std::string mod;
    int limit = 20;
    uint64_t offset = 0;
    uint64_t from_ev = 0;
    uint64_t to_ev = UINT64_MAX;
    bool json = false;
};

struct FindValueOptions {
    uint64_t value = 0;
    int limit = 20;
    uint64_t offset = 0;
    bool json = false;
    uint64_t from_ev = 0;
    uint64_t to_ev = UINT64_MAX;
    bool reads_only = false;
    bool writes_only = false;
};

struct MemStateRange {
    uint64_t base = 0;
    uint64_t len = 0;
};

struct MemStateOptions {
    std::vector<MemStateRange> ranges;
    std::vector<uint64_t> at_evs;
    bool json = false;
    bool qword = false;
};

struct FuncArgsOptions {
    std::vector<std::string> funcs;
    int nth = 1;
    int limit = 1;
    bool json = false;
};

// All implemented in queries.cpp. Option objects keep call sites explicit as
// the query surface grows; compatibility overloads remain below for existing
// libtraceq callers.
// taint coordinates: seeds are --seed-addr/--seed-reg/--seed-q/--seed-nzcv,
// placement is --at-ev N (event index) and/or --off O (module offset, --mod M
// to pick the module). window 0 = unlimited (forward) / 2M-event ring
// (backward); window-limited results are marked PARTIAL.
int q_taint(const std::string& gtb, const TaintOptions& options);
int q_diff(const std::string& a_gtb, const std::string& b_gtb, int context,
           bool json = false);
int q_fold(const std::string& gtb, int top, bool json = false);
int q_stat(const std::string& gtb, bool json = false);
int q_mem_accesses(const std::string& gtb, const MemAccessOptions& options);
int q_mem_states(const std::string& gtb, const MemStateOptions& options);
int q_mem_state(const std::string& gtb, uint64_t range_base,
                uint64_t range_len, uint64_t at_ev, bool json = false,
                bool qword = false);
int q_find_pcs(const std::string& gtb, const FindPcOptions& options);
// nth (1-based) selects the first call to show, limit the row count
int q_func_args(const std::string& gtb, const FuncArgsOptions& options);
int q_func_args(const std::string& gtb, const std::string& func, int nth, int limit,
                bool json = false);
int q_find_value(const std::string& gtb, const FindValueOptions& options);
int q_calltree_gtb(const std::string& gtb, const std::string& func, int depth,
                   int limit, bool json = false);

// Source-compatible wrappers for the original positional API.
inline int q_taint(const std::string& gtb, uint64_t seed_addr, int seed_reg,
                   int seed_q, bool seed_nzcv, bool backward, int limit,
                   uint64_t window, uint64_t at_ev, uint64_t off,
                   const std::string& mod, bool json = false,
                   bool index_deps = false) {
    TaintOptions o;
    o.seed_addr = seed_addr; o.seed_reg = seed_reg; o.seed_q = seed_q;
    o.seed_nzcv = seed_nzcv; o.backward = backward; o.limit = limit;
    o.window = window; o.at_ev = at_ev; o.off = off; o.mod = mod;
    o.json = json; o.index_deps = index_deps;
    return q_taint(gtb, o);
}

inline int q_mem_accesses(const std::string& gtb,
                          const std::vector<uint64_t>& addrs, bool use_range,
                          uint64_t range_base, uint64_t range_len, int limit,
                          uint64_t offset, uint64_t from_ev, uint64_t to_ev,
                          int last, bool json = false, bool writes_only = false,
                          bool reads_only = false) {
    MemAccessOptions o;
    o.addrs = addrs; o.use_range = use_range; o.range_base = range_base;
    o.range_len = range_len; o.limit = limit; o.offset = offset;
    o.from_ev = from_ev; o.to_ev = to_ev; o.last = last; o.json = json;
    o.writes_only = writes_only; o.reads_only = reads_only;
    return q_mem_accesses(gtb, o);
}

inline int q_find_pcs(const std::string& gtb,
                      const std::vector<uint64_t>& addrs,
                      const std::vector<uint64_t>& offs,
                      const std::string& mod, int limit, uint64_t offset,
                      uint64_t from_ev, uint64_t to_ev, bool json = false) {
    FindPcOptions o;
    o.addrs = addrs; o.offs = offs; o.mod = mod; o.limit = limit;
    o.offset = offset; o.from_ev = from_ev; o.to_ev = to_ev; o.json = json;
    return q_find_pcs(gtb, o);
}

inline int q_find_value(const std::string& gtb, uint64_t value, int limit,
                        uint64_t offset = 0, bool json = false,
                        uint64_t from_ev = 0, uint64_t to_ev = UINT64_MAX,
                        bool reads_only = false, bool writes_only = false) {
    FindValueOptions o;
    o.value = value; o.limit = limit; o.offset = offset; o.json = json;
    o.from_ev = from_ev; o.to_ev = to_ev;
    o.reads_only = reads_only; o.writes_only = writes_only;
    return q_find_value(gtb, o);
}
