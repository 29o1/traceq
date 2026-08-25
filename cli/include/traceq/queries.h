#pragma once
#include "common.h"

// Agent-facing query surface. List queries use bounded defaults and explicit
// truncation metadata; snapshot and aggregate commands are bounded by their
// selectors or command-specific controls. Every query runs in text or --json
// mode (one JSON document, integer values as hex strings) and returns data plus
// metadata (truncated/total/shown/next).
//
// Every query sequentially scans the loaded .gtb event buffer (one TraceScan
// pass); there is no index/ingest step.
#include <cstdint>
#include <string>
#include <vector>

struct QueryWindow {
    int limit = gt::DEFAULT_OUTPUT_ROWS;
    uint64_t offset = 0;
    uint64_t from_ev = 0;
    uint64_t to_ev = UINT64_MAX;
    int last = 0;

    bool valid() const {
        return limit > 0 && last >= 0 && from_ev <= to_ev &&
               (last == 0 || offset == 0);
    }
};

struct TaintOptions {
    uint64_t seed_addr = 0;
    int seed_reg = -1;
    int seed_q = -1;
    bool seed_nzcv = false;
    bool backward = false;
    int limit = gt::DEFAULT_OUTPUT_ROWS;
    uint64_t window = 0;
    uint64_t at_ev = 0;
    uint64_t off = 0;
    std::string mod;
    bool json = false;
    bool index_deps = false;
};

struct MemAccessOptions : QueryWindow {
    std::vector<uint64_t> addrs;
    bool use_range = false;
    uint64_t range_base = 0;
    uint64_t range_len = 0;
    bool json = false;
    bool writes_only = false;
    bool reads_only = false;
    // Explicit opt-in for selectorless write enumeration. The query accepts
    // it only for a finite event window and with writes_only=true.
    bool all_writes = false;
};

struct FindPcOptions : QueryWindow {
    std::vector<uint64_t> addrs;
    std::vector<uint64_t> offs;
    std::string mod;
    bool json = false;
};

struct FindValueOptions : QueryWindow {
    // `value` remains the single-selector compatibility field.
    uint64_t value = 0;
    bool json = false;
    bool reads_only = false;
    bool writes_only = false;
    // When non-empty, `values` replaces `value`; duplicates are removed.
    std::vector<uint64_t> values;
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

struct CallsOptions : QueryWindow {
    std::vector<std::string> names;
    std::vector<uint64_t> target_addrs;
    std::vector<uint64_t> target_offs;
    std::string mod;
    int top = 0;
    bool json = false;
};

// Implementations are grouped by capability in query_*.cpp. Option objects
// keep call sites explicit; compatibility overloads remain below for existing
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
int q_calls(const std::string& gtb, const CallsOptions& options);
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
