#include <gumtrace/queries.h>
#include <gumtrace/ingest.h>
#ifndef GT_NO_SQLITE
#define GT_SQLITE_Q 1
#else
#define GT_SQLITE_Q 0
#endif
#include <gumtrace/site.h>
#include <cstdio>
#include <cstring>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include <vector>

using namespace gt;

static void print_truncated(uint64_t total, uint64_t shown) {
    if (total > shown)
        printf("... [%llu more rows truncated]\n",
               (unsigned long long)(total - shown));
}

// ---------------------------------------------------------------------------
// SQL-backed queries
// ---------------------------------------------------------------------------
#if GT_SQLITE_Q
int q_stats(const std::string& dbp) {
    sqlite3* db = db_open(dbp, true);
    if (!db) { fprintf(stderr, "cannot open %s\n", dbp.c_str()); return 1; }
    sqlite3_exec(db, "PRAGMA journal_mode=OFF; PRAGMA synchronous=OFF;", nullptr, nullptr, nullptr);
    char* err = nullptr;
    printf("== trace stats ==\n");
    sqlite3_exec(db, "SELECT 'module', v FROM meta;", [](void*, int c, char** v, char**) -> int {
        if (c >= 2) printf("module: %s\n", v[1]);
        return 0;
    }, nullptr, &err);
    auto one = [&](const char* sql) -> uint64_t {
        sqlite3_stmt* s;
        uint64_t r = 0;
        if (sqlite3_prepare_v2(db, sql, -1, &s, nullptr) == SQLITE_OK && sqlite3_step(s) == SQLITE_ROW)
            r = sqlite3_column_int64(s, 0);
        sqlite3_finalize(s);
        return r;
    };
    printf("exec:    %llu\n", (unsigned long long)one("SELECT COUNT(*) FROM exec"));
    printf("regw:    %llu\n", (unsigned long long)one("SELECT COUNT(*) FROM regw"));
    printf("mem:     %llu\n", (unsigned long long)one("SELECT COUNT(*) FROM mem"));
    printf("call:    %llu\n", (unsigned long long)one("SELECT COUNT(*) FROM call"));
    printf("svc:     %llu\n", (unsigned long long)one("SELECT COUNT(*) FROM svc"));
    printf("insns:   %llu\n", (unsigned long long)one("SELECT COUNT(*) FROM insn"));
    printf("\ntop functions by executions:\n");
    sqlite3_exec(db,
        "SELECT func, execs FROM v_func_stats ORDER BY execs DESC LIMIT 10;",
        [](void*, int c, char** v, char**) -> int {
            if (c >= 2) printf("  %-28s %s\n", v[0] ? v[0] : "?", v[1]);
            return 0;
        }, nullptr, &err);
    printf("\nmemory hotspots:\n");
    sqlite3_exec(db,
        "SELECT printf('0x%x',addr), CASE is_w WHEN 1 THEN 'W' ELSE 'R' END, hits "
        "FROM v_mem_hot LIMIT 10;",
        [](void*, int c, char** v, char**) -> int {
            if (c >= 3) printf("  %-14s %s  x%s\n", v[0], v[1], v[2]);
            return 0;
        }, nullptr, &err);
    if (err) { sqlite3_free(err); err = nullptr; }
    sqlite3_close(db);
    return 0;
}

#endif // stats
#if GT_SQLITE_Q
int q_mem_writes(const std::string& dbp, uint64_t addr, int limit) {
    sqlite3* db = db_open(dbp, true);
    if (!db) return 1;
    sqlite3_exec(db, "PRAGMA journal_mode=OFF; PRAGMA synchronous=OFF;", nullptr, nullptr, nullptr);
    uint64_t total = 0;
    {
        sqlite3_stmt* s;
        sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM mem WHERE addr=?1", -1, &s, nullptr);
        sqlite3_bind_int64(s, 1, sqlite3_int64(addr));
        if (sqlite3_step(s) == SQLITE_ROW) total = sqlite3_column_int64(s, 0);
        sqlite3_finalize(s);
    }
    sqlite3_stmt* s;
    sqlite3_prepare_v2(db,
        "SELECT m.ev, m.is_w, m.size, m.val, i.off, i.txt "
        "FROM mem m LEFT JOIN exec e ON e.ev=m.ev LEFT JOIN insn i ON i.id=e.site "
        "WHERE m.addr=?1 ORDER BY m.ev LIMIT ?2;", -1, &s, nullptr);
    sqlite3_bind_int64(s, 1, sqlite3_int64(addr));
    sqlite3_bind_int(s, 2, limit);
    printf("accesses to 0x%llx (total %llu):\n", (unsigned long long)addr,
           (unsigned long long)total);
    uint64_t shown = 0;
    while (sqlite3_step(s) == SQLITE_ROW) {
        uint64_t ev = sqlite3_column_int64(s, 0);
        int is_w = sqlite3_column_int(s, 1);
        int size = sqlite3_column_int(s, 2);
        int64_t val = sqlite3_column_int64(s, 3);
        int64_t off = sqlite3_column_int64(s, 4);
        const char* txt = (const char*)sqlite3_column_text(s, 5);
        printf("  ev=%-8llu %s size=%d val=0x%llx  [off 0x%llx] %s\n",
               (unsigned long long)ev, is_w ? "W" : "R", size,
               (unsigned long long)val, (unsigned long long)off,
               txt ? txt : "");
        shown++;
    }
    sqlite3_finalize(s);
    print_truncated(total, shown);
    sqlite3_close(db);
    return 0;
}

#endif // mem_writes
#if GT_SQLITE_Q
int q_func_args(const std::string& dbp, const std::string& func, int nth, int limit) {
    sqlite3* db = db_open(dbp, true);
    if (!db) return 1;
    sqlite3_exec(db, "PRAGMA journal_mode=OFF; PRAGMA synchronous=OFF;", nullptr, nullptr, nullptr);
    // pair calls with their true (stack-matched) returns
    struct Row { uint64_t ev; uint64_t x[4]; uint64_t ret; bool has_ret; };
    std::vector<Row> rows;
    {
        std::vector<std::pair<uint64_t, Row>> calls; // ev -> row
        sqlite3_stmt* s;
        sqlite3_prepare_v2(db, "SELECT ev, x0, x1, x2, x3 FROM call WHERE sym=?1 ORDER BY ev",
                           -1, &s, nullptr);
        sqlite3_bind_text(s, 1, func.c_str(), int(func.size()), SQLITE_TRANSIENT);
        while (sqlite3_step(s) == SQLITE_ROW) {
            Row r{};
            r.ev = sqlite3_column_int64(s, 0);
            for (int i = 0; i < 4; i++) r.x[i] = sqlite3_column_int64(s, 1 + i);
            calls.push_back({r.ev, r});
        }
        sqlite3_finalize(s);
        std::unordered_set<uint64_t> call_ev;
        for (auto& c : calls) call_ev.insert(c.first);
        // walk all calls + rets to pair (LIFO)
        sqlite3_stmt* sc, *sr;
        sqlite3_prepare_v2(db, "SELECT ev, sym FROM call ORDER BY ev", -1, &sc, nullptr);
        sqlite3_prepare_v2(db, "SELECT ev FROM ret ORDER BY ev", -1, &sr, nullptr);
        std::vector<std::pair<uint64_t, uint64_t>> stack; // (call_ev, ret_ev)
        bool have_c = sqlite3_step(sc) == SQLITE_ROW;
        bool have_r = sqlite3_step(sr) == SQLITE_ROW;
        std::unordered_map<uint64_t, uint64_t> ret_of;
        while (have_c || have_r) {
            uint64_t cev = have_c ? sqlite3_column_int64(sc, 0) : UINT64_MAX;
            uint64_t rev = have_r ? sqlite3_column_int64(sr, 0) : UINT64_MAX;
            if (cev < rev) {
                stack.push_back({cev, 0});
                have_c = sqlite3_step(sc) == SQLITE_ROW;
            } else {
                if (!stack.empty()) {
                    auto pr = stack.back();
                    stack.pop_back();
                    if (call_ev.count(pr.first)) ret_of[pr.first] = rev;
                }
                have_r = sqlite3_step(sr) == SQLITE_ROW;
            }
        }
        sqlite3_finalize(sc);
        sqlite3_finalize(sr);
        for (auto& c : calls) {
            auto it = ret_of.find(c.first);
            c.second.has_ret = it != ret_of.end();
            c.second.ret = it == ret_of.end() ? 0 : it->second;
            rows.push_back(c.second);
        }
    }
    printf("calls to %s: %llu total\n", func.c_str(), (unsigned long long)rows.size());
    size_t from = nth > 0 ? size_t(nth - 1) : 0;
    size_t to = nth > 0 ? size_t(nth) : rows.size();
    if (nth <= 0 && limit > 0 && rows.size() > size_t(limit)) to = size_t(limit);
    for (size_t i = from; i < to && i < rows.size(); i++) {
        printf("  #%-6llu ev=%-8llu x0=0x%-10llx x1=0x%-10llx x2=0x%-10llx x3=0x%-10llx",
               (unsigned long long)(i + 1), (unsigned long long)rows[i].ev,
               (unsigned long long)rows[i].x[0], (unsigned long long)rows[i].x[1],
               (unsigned long long)rows[i].x[2], (unsigned long long)rows[i].x[3]);
        if (rows[i].has_ret) printf(" -> ret ev=%llu", (unsigned long long)rows[i].ret);
        printf("\n");
    }
    print_truncated(rows.size(), nth > 0 ? (to > rows.size() ? rows.size() - from : to - from)
                                         : to);
    sqlite3_close(db);
    return 0;
}

#endif // func_args

// ---------------------------------------------------------------------------
// taint (gtb-based, in-memory stream walk)
// ---------------------------------------------------------------------------
struct TaintEdge { uint64_t ev; std::string what; };

static int run_taint(const std::string& gtb, uint64_t seed_addr, int seed_reg,
                     bool backward, int limit, uint64_t window) {
    GtbFile f;
    if (!f.load(gtb)) { fprintf(stderr, "load failed\n"); return 1; }

    // materialize groups once
    std::vector<Group> gs;
    f.n_exec = 0;
    Expander(f).for_each([&](uint64_t, const Group& g) { gs.push_back(g); return true; });

    std::vector<bool> reg_t(32, false);
    std::unordered_set<uint64_t> addr_t;
    std::vector<TaintEdge> edges;
    if (seed_reg >= 0) reg_t[seed_reg] = true;
    if (seed_addr) addr_t.insert(seed_addr);

    auto site_txt = [&](const Group& g) -> std::string {
        if (!g.has_exec) return "<event>";
        const Site& s = f.arena.get(g.site_id);
        return std::string(f.arena.pool_ptr() + s.disasm_off, s.disasm_len);
    };
    auto reads_of = [&](const Group& g, bool (&rd)[32]) {
        for (int i = 0; i < 32; i++) rd[i] = false;
        if (!g.has_exec) return;
        const Site& s = f.arena.get(g.site_id);
        for (uint8_t i = 0; i < s.n_ops; i++)
            if (s.ops[i].kind == OP_REG_R && s.ops[i].ctx_idx >= 0)
                rd[s.ops[i].ctx_idx & 31] = true;
    };
    auto add_edge = [&](uint64_t ev, std::string what) {
        if ((int)edges.size() < limit) edges.push_back({ev, std::move(what)});
    };

    if (!backward) {
        for (size_t i = 0; i < gs.size() && i < window; i++) {
            const Group& g = gs[i];
            bool rd[32];
            reads_of(g, rd);
            bool any_rd_t = false;
            for (int r = 0; r < 32; r++) if (rd[r] && reg_t[r]) any_rd_t = true;
            bool src_mem = false;
            for (int k = 0; k < g.n_mem; k++)
                if (!g.mem[k].is_write && addr_t.count(g.mem[k].addr)) src_mem = true;
            if (any_rd_t || src_mem) {
                for (int k = 0; k < g.n_wr; k++) {
                    if (!reg_t[g.wr_id[k] & 31]) {
                        reg_t[g.wr_id[k] & 31] = true;
                        std::string src = src_mem ? "mem" : "reg";
                        add_edge(i, site_txt(g) + " : <- " + src);
                    }
                }
            }
            for (int k = 0; k < g.n_mem; k++) {
                if (g.mem[k].is_write && any_rd_t) {
                    if (!addr_t.count(g.mem[k].addr)) {
                        addr_t.insert(g.mem[k].addr);
                        add_edge(i, site_txt(g) + " : mem_w -> tainted");
                    }
                }
            }
        }
    } else {
        for (size_t ii = 0; ii < gs.size() && ii < window; ii++) {
            size_t i = gs.size() - 1 - ii;
            const Group& g = gs[i];
            // does this event produce a currently-tainted value?
            bool produces_tainted_reg = false;
            for (int k = 0; k < g.n_wr; k++)
                if (reg_t[g.wr_id[k] & 31]) produces_tainted_reg = true;
            bool writes_tainted_addr = false;
            for (int k = 0; k < g.n_mem; k++)
                if (g.mem[k].is_write && addr_t.count(g.mem[k].addr)) writes_tainted_addr = true;
            if (produces_tainted_reg || writes_tainted_addr) {
                bool rd[32];
                reads_of(g, rd);
                for (int r = 0; r < 32; r++) {
                    if (rd[r] && !reg_t[r]) {
                        reg_t[r] = true;
                        add_edge(i, site_txt(g) + " : source reg x" + std::to_string(r));
                    }
                }
                for (int k = 0; k < g.n_mem; k++) {
                    if (!g.mem[k].is_write && !addr_t.count(g.mem[k].addr)) {
                        addr_t.insert(g.mem[k].addr);
                        add_edge(i, site_txt(g) + " : source mem 0x" +
                                        std::to_string(g.mem[k].addr));
                    }
                }
            }
        }
    }

    printf("taint seed: %s%s%s%s\n",
           seed_addr ? "addr=0x" : "", seed_addr ? std::to_string(seed_addr).c_str() : "",
           seed_reg >= 0 ? " reg=x" : "", seed_reg >= 0 ? std::to_string(seed_reg).c_str() : "");
    printf("direction: %s | events walked: %llu | edges (limit %d): %zu\n",
           backward ? "backward" : "forward",
           (unsigned long long)std::min<uint64_t>(window, gs.size()), limit, edges.size());
    for (auto& e : edges)
        printf("  ev=%-8llu %s\n", (unsigned long long)e.ev, e.what.c_str());
    printf("final tainted regs:");
    for (int r = 0; r < 32; r++) if (reg_t[r]) printf(" x%d", r);
    printf("\nfinal tainted addrs: %zu\n", addr_t.size());
    return 0;
}

int q_taint(const std::string& gtb, uint64_t seed_addr, int seed_reg, bool backward,
            int limit, uint64_t window) {
    return run_taint(gtb, seed_addr, seed_reg, backward, limit, window);
}

// ---------------------------------------------------------------------------
// diff (gtb exec sequence)
// ---------------------------------------------------------------------------
int q_diff(const std::string& a_p, const std::string& b_p, int context) {
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
    size_t n = std::min(sa.size(), sb.size());
    size_t div = n;
    for (size_t i = 0; i < n; i++)
        if (sa[i] != sb[i]) { div = i; break; }
    printf("exec counts: A=%zu B=%zu\n", sa.size(), sb.size());
    if (div == n && sa.size() == sb.size()) {
        printf("identical execution sequences\n");
        return 0;
    }
    printf("first divergence at exec index %zu (0-based)\n", div);
    printf("context:\n");
    size_t from = div >= size_t(context) ? div - size_t(context) : 0;
    size_t to = div + size_t(context) + 1;
    for (size_t i = from; i < to; i++) {
        auto txt = [&](const GtbFile& f, uint32_t site) -> std::string {
            const Site& s = f.arena.get(site);
            return std::string(f.arena.pool_ptr() + s.disasm_off, s.disasm_len);
        };
        auto off = [&](const GtbFile& f, uint32_t site) -> uint64_t {
            return f.arena.get(site).addr - 0x7000000000ULL;
        };
        if (i < sa.size() || i < sb.size()) {
            printf("  [%5zu] A: 0x%-6llx %-34s B: 0x%-6llx %s%s\n", i,
                   i < sa.size() ? off(a, sa[i]) : 0,
                   i < sa.size() ? txt(a, sa[i]).c_str() : "<end>",
                   i < sb.size() ? off(b, sb[i]) : 0,
                   i < sb.size() ? txt(b, sb[i]).c_str() : "<end>",
                   i == div ? "   <-- DIVERGES" : "");
        }
    }
    return 0;
}

// ---------------------------------------------------------------------------
// fold (loop detection over the exec stream)
// ---------------------------------------------------------------------------
int q_fold(const std::string& gtb, int top) {
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
    printf("detected %zu loop regions (top %d by executed instructions):\n", loops.size(), top);
    for (size_t k = 0; k < loops.size() && int(k) < top; k++) {
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
    return 0;
}

// ---------------------------------------------------------------------------
// calltree (db)
// ---------------------------------------------------------------------------
#if GT_SQLITE_Q
int q_calltree(const std::string& dbp, const std::string& func, int depth, int limit) {
    sqlite3* db = db_open(dbp, true);
    if (!db) return 1;
    sqlite3_exec(db, "PRAGMA journal_mode=OFF; PRAGMA synchronous=OFF;", nullptr, nullptr, nullptr);
    struct Node {
        uint64_t ev;
        std::string sym;
        uint64_t ret_ev = 0;
        std::vector<int> children;
        uint64_t subtree_execs = 0;
    };
    std::vector<Node> nodes;
    std::vector<int> stack;
    sqlite3_stmt *sc, *sr;
    sqlite3_prepare_v2(db, "SELECT ev, sym FROM call ORDER BY ev", -1, &sc, nullptr);
    sqlite3_prepare_v2(db, "SELECT ev FROM ret ORDER BY ev", -1, &sr, nullptr);
    bool have_c = sqlite3_step(sc) == SQLITE_ROW;
    bool have_r = sqlite3_step(sr) == SQLITE_ROW;
    int root = -1;
    while (have_c || have_r) {
        uint64_t cev = have_c ? sqlite3_column_int64(sc, 0) : UINT64_MAX;
        uint64_t rev = have_r ? sqlite3_column_int64(sr, 0) : UINT64_MAX;
        if (cev < rev) {
            const char* sym = (const char*)sqlite3_column_text(sc, 1);
            nodes.push_back({cev, sym ? sym : "?", 0, {}, 0});
            int id = int(nodes.size() - 1);
            if (!stack.empty()) nodes[stack.back()].children.push_back(id);
            else if (root == -1 && nodes[id].sym == func) root = id;
            stack.push_back(id);
            have_c = sqlite3_step(sc) == SQLITE_ROW;
        } else {
            if (!stack.empty()) {
                nodes[stack.back()].ret_ev = rev;
                stack.pop_back();
            }
            have_r = sqlite3_step(sr) == SQLITE_ROW;
        }
    }
    sqlite3_finalize(sc);
    sqlite3_finalize(sr);
    if (root == -1) { printf("function %s not found at top level\n", func.c_str()); sqlite3_close(db); return 1; }

    // aggregate repeated children
    std::function<void(int, int, uint64_t&)> print = [&](int id, int d, uint64_t& budget) {
        if (d > depth || budget == 0) return;
        budget--;
        // aggregate children by symbol
        std::unordered_map<std::string, std::pair<int, int>> agg; // sym -> (count, first_child)
        for (int c : nodes[id].children) {
            auto& e = agg[nodes[c].sym];
            e.first++;
            if (e.second == 0) e.second = c;
        }
        printf("%*s%s  [ev %llu..%llu]\n", d * 2, "", nodes[id].sym.c_str(),
               (unsigned long long)nodes[id].ev,
               (unsigned long long)(nodes[id].ret_ev ? nodes[id].ret_ev : nodes[id].ev));
        for (auto& [sym, e] : agg) {
            if (e.first > 1)
                printf("%*s├─%s x%llu\n", d * 2 + 2, "", sym.c_str(),
                       (unsigned long long)e.first);
            else
                print(e.second, d + 1, budget);
        }
        if (agg.empty() && !nodes[id].children.empty())
            printf("%*s(leaf calls collapsed)\n", d * 2 + 2, "");
    };
    uint64_t budget = limit;
    printf("call tree from %s (depth %d):\n", func.c_str(), depth);
    print(root, 0, budget);
    if (budget == 0) printf("... [output limit reached]\n");
    sqlite3_close(db);
    return 0;
}
#endif // calltree
