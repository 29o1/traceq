#pragma once
// Agent-facing query surface. Design rule: every output is bounded with an
// explicit truncation marker — the consumer is an agent with a limited
// context window, so queries must return small structured answers, never raw
// dumps.
#include <string>

// implemented in queries.cpp
int q_stats(const std::string& db);
int q_mem_writes(const std::string& db, uint64_t addr, int limit);
int q_func_args(const std::string& db, const std::string& func, int nth, int limit);

// taint/diff/fold/calltree implemented in queries.cpp too (gtb/db mixed)
int q_taint(const std::string& gtb, uint64_t seed_addr, int seed_reg, bool backward,
            int limit, uint64_t window);
int q_diff(const std::string& a_gtb, const std::string& b_gtb, int context);
int q_fold(const std::string& gtb, int top);
int q_calltree(const std::string& db, const std::string& func, int depth, int limit);
