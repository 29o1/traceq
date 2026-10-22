#pragma once
#include "common.h"

// Agent-facing query surface. List queries use bounded defaults and explicit
// truncation metadata; snapshot and aggregate commands are bounded by their
// selectors or command-specific controls. Every query runs in text or --json
// mode (one JSON document, integer values as hex strings) and returns data plus
// metadata (truncated/total/shown/next).
//
// Queries scan the loaded .gtb event buffer; --context adds a bounded export
// scan around the first shown hit. There is no persistent index.
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

struct QueryWindow {
    int limit = gt::DEFAULT_OUTPUT_ROWS;
    uint64_t offset = 0;
    uint64_t from_ev = 0;
    uint64_t to_ev = UINT64_MAX;
    int last = 0;
    // --context N: render the compact instruction window [ev-N, ev+N] around
    // the first shown hit. 0 = off. Parsed by find-pc, mem-access, and
    // find-value only; the span stays bounded (1..200) to keep the one-round-
    // trip answer inside the output contract.
    int context = 0;

    bool valid() const {
        return limit > 0 && last >= 0 && from_ev <= to_ev &&
               (last == 0 || offset == 0);
    }
};

struct TaintOptions {
    // Presence is distinct from zero for the address and position selectors.
    std::optional<uint64_t> seed_addr;
    int seed_reg = -1;
    int seed_q = -1;
    bool seed_nzcv = false;
    bool backward = false;
    int limit = gt::DEFAULT_OUTPUT_ROWS;
    uint64_t window = 0;
    std::optional<uint64_t> at_ev;
    std::optional<uint64_t> off;
    std::string mod;
    bool json = false;
    bool index_deps = false;
};

struct MemStateRange {
    uint64_t base = 0;
    uint64_t len = 0;
};

struct MemAccessOptions : QueryWindow {
    std::vector<uint64_t> addrs;
    // Range selectors form a union; pagination applies to distinct access rows.
    std::vector<MemStateRange> ranges;
    // Single-range library callers remain supported.
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
    bool json = false;
    bool reads_only = false;
    bool writes_only = false;
    // Duplicates are removed before scanning.
    std::vector<uint64_t> values;
};

struct MemStateOptions {
    std::vector<MemStateRange> ranges;
    std::vector<uint64_t> at_evs;
    // Physical source lines must end a group, so no later facts leak backward.
    std::vector<uint64_t> at_lines;
    bool json = false;
    bool qword = false;
    bool provenance = false; // byte spans and annotated copy/fill evidence
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
// keep call sites explicit.
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
int q_find_pcs(const std::string& gtb, const FindPcOptions& options);
int q_calls(const std::string& gtb, const CallsOptions& options);
int q_find_value(const std::string& gtb, const FindValueOptions& options);
int q_calltree_gtb(const std::string& gtb, const std::string& func, int depth,
                   int limit, bool json = false);
