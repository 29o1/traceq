#pragma once
// Agent-facing query surface. Design rule: every output is bounded with an
// explicit truncation marker — the consumer is an agent with a limited
// context window, so queries must return small structured answers, never raw
// dumps. W2 contract: every command runs in text or --json mode (JSON Lines,
// integer values as hex strings) and ends with a meta footer carrying the cursor
// (truncated/total/shown/next) and suggested next commands.
//
// Every query streams the .gtb directly (one Expander pass); there is no
// index/ingest step.
#include <string>
#include <vector>

// all implemented in queries.cpp
// taint coordinates: seeds are --seed-addr/--seed-reg/--seed-q/--seed-nzcv,
// placement is --at-ev N (event index) and/or --off O (module offset, --mod M
// to pick the module). window 0 = unlimited (forward) / 2M-event ring
// (backward); window-limited results are marked PARTIAL.
int q_taint(const std::string& gtb, uint64_t seed_addr, int seed_reg, int seed_q,
            bool seed_nzcv, bool backward, int limit, uint64_t window,
            uint64_t at_ev, uint64_t off, const std::string& mod, bool json = false,
            bool index_deps = false);
int q_diff(const std::string& a_gtb, const std::string& b_gtb, int context,
           bool json = false);
int q_fold(const std::string& gtb, int top, bool json = false);
int q_stat(const std::string& gtb, bool json = false);
int q_mem_access(const std::string& gtb, uint64_t addr, bool use_range,
                 uint64_t range_base, uint64_t range_len, int limit,
                 uint64_t offset = 0, bool json = false, bool writes_only = false);
int q_mem_accesses(const std::string& gtb, const std::vector<uint64_t>& addrs,
                   bool use_range, uint64_t range_base, uint64_t range_len,
                   int limit, uint64_t offset, uint64_t from_ev,
                   uint64_t to_ev, int last, bool json = false,
                   bool writes_only = false);
int q_mem_state(const std::string& gtb, uint64_t range_base,
                uint64_t range_len, uint64_t at_ev, bool json = false);
int q_find_pc(const std::string& gtb, bool use_addr, uint64_t addr,
              bool use_off, uint64_t off, const std::string& mod, int limit,
              uint64_t offset = 0, bool json = false);
int q_find_pcs(const std::string& gtb, const std::vector<uint64_t>& addrs,
               const std::vector<uint64_t>& offs, const std::string& mod,
               int limit, uint64_t offset, uint64_t from_ev, uint64_t to_ev,
               bool json = false);
// nth (1-based) selects the first call to show, limit the row count
int q_func_args(const std::string& gtb, const std::string& func, int nth, int limit,
                bool json = false);
int q_find_value(const std::string& gtb, uint64_t val, int limit,
                 uint64_t offset = 0, bool json = false);
int q_calltree_gtb(const std::string& gtb, const std::string& func, int depth,
                   int limit, bool json = false);
