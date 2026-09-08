#include <traceq/queries.h>
#include <traceq/ingest.h>
#include <traceq/site.h>
#include "emit.h"
#include "query_common.h"
#include <algorithm>
#include <cstdio>
#include <deque>
#include <unordered_map>
#include <unordered_set>
#include <vector>

using namespace gt;

int q_calls(const std::string& gtb, const CallsOptions& options) {
    if (!options.valid() || options.top < 0 ||
        (options.top > 0 && (options.last > 0 || options.offset != 0)) ||
        (!options.mod.empty() && options.target_offs.empty())) {
        fprintf(stderr, "calls: invalid range, selector, or output mode\n");
        return 2;
    }
    std::unordered_set<std::string> names;
    for (const auto& name : options.names)
        if (!name.empty()) names.insert(name);
    std::unordered_set<uint64_t> target_addrs(options.target_addrs.begin(),
                                              options.target_addrs.end());
    std::unordered_set<uint64_t> target_offs(options.target_offs.begin(),
                                             options.target_offs.end());
    bool has_selector = !names.empty() || !target_addrs.empty() ||
                        !target_offs.empty();

    GtbFile f;
    if (!load_query_file(f, gtb)) return 1;
    emit::QueryWriter writer(options.json, f);

    struct Row {
        uint64_t n = 0, ev = 0, line = 0;
        uint64_t callsite_addr = 0, target = 0;
        std::string at, txt, name, target_at, target_mod, source;
        uint64_t target_off = 0;
        bool target_known = false, target_loc_known = false;
        uint64_t args[8] = {0};
        bool arg_known[8] = {false};
        bool has_ret = false;
        uint64_t ret_ev = 0, ret_line = 0, ret_val = 0;
    };
    struct Summary { Row row; uint64_t count = 0, first = 0, last = 0; };
    std::deque<Row> rows;
    std::vector<uint64_t> annotation_stack;
    std::unordered_map<std::string, Summary> grouped;
    uint64_t total_rows = 0;
    std::unordered_map<uint64_t, uint32_t> module_by_site_addr;
    for (const Site& site : f.arena.sites())
        module_by_site_addr.emplace(site.addr, site.module_id);

    auto locate_target = [&](uint64_t target, std::string& module,
                             uint64_t& off) -> bool {
        auto found = module_by_site_addr.find(target);
        if (found == module_by_site_addr.end() ||
            found->second >= f.arena.modules().size())
            return false;
        uint32_t module_id = found->second;
        uint64_t base = f.arena.module_base(module_id);
        if (target < base) return false;
        module = f.arena.modules()[module_id];
        off = target - base;
        return true;
    };
    auto matches_off = [&](uint64_t target) {
        for (size_t i = 0; i < f.arena.modules().size(); i++) {
            if (!options.mod.empty() && f.arena.modules()[i] != options.mod)
                continue;
            uint64_t base = f.arena.module_base(uint32_t(i));
            if (target < base) continue;
            if (target_offs.count(target - base)) return true;
        }
        return false;
    };

    TraceScan ex(f);
    if (!ex.for_each([&](uint64_t gi, const Group& g) {
        if (gi > options.to_ev) return false;
        if (gi < options.from_ev) return true;
        std::string disasm;
        const Site* call_site = nullptr;
        if (g.has_exec && g.site_id < f.arena.sites().size()) {
            const Site& site = f.arena.get(g.site_id);
            if (site.kind == SK_CALL_IMM || site.kind == SK_CALL_REG) {
                call_site = &site;
                disasm.assign(f.arena.pool_ptr() + site.disasm_off,
                              site.disasm_len);
            }
        }
        bool instruction = call_site != nullptr;
        uint64_t selected_annotation = 0;
        if (instruction || g.is_call) {
            Row row;
            row.ev = gi;
            row.line = g.is_call && g.call_source_line ? g.call_source_line
                                                       : g.source_line;
            row.txt = instruction ? disasm : "call annotation";
            row.source = instruction ? (g.is_call ? "instruction+annotation"
                                                   : "instruction")
                                     : "annotation";
            if (g.has_exec) {
                const Site& site = f.arena.get(g.site_id);
                row.callsite_addr = site.addr;
                row.at = query_at(f, g.site_id);
            } else {
                row.at = "<event>";
            }
            if (g.call_name) row.name = g.call_name;

            if (instruction) {
                if (call_site->kind == SK_CALL_IMM) {
                    row.target = call_site->branch_imm;
                    row.target_known = row.target != 0;
                } else {
                    int ctx = call_site->branch_reg;
                    if (ctx >= 0 && ctx < 32 && ex.reg_known()[ctx]) {
                        row.target = ex.regfile()[ctx];
                        row.target_known = true;
                    }
                }
            }
            if (row.target_known &&
                locate_target(row.target, row.target_mod, row.target_off)) {
                row.target_loc_known = true;
                row.target_at = row.target_mod + "!" + emit::hex64(row.target_off);
            }

            if (instruction)
                for (int i = 0; i < 8; i++) {
                    row.args[i] = ex.regfile()[i];
                    row.arg_known[i] = ex.reg_known()[i] != 0;
                }
            if (g.is_call) {
                int nargs = std::min<int>(g.n_call_args, 8);
                for (int i = 0; i < nargs; i++) {
                    row.args[i] = g.args[i];
                    row.arg_known[i] = true;
                }
            }

            bool selected = !has_selector;
            if (!row.name.empty() && names.count(row.name)) selected = true;
            if (row.target_known && target_addrs.count(row.target)) selected = true;
            if (row.target_known && !target_offs.empty() && matches_off(row.target))
                selected = true;
            if (selected) {
                row.n = ++total_rows;
                selected_annotation = row.n;
                if (options.top > 0) {
                    std::string key = row.target_known
                                          ? "target:" + std::to_string(row.target)
                                          : !row.name.empty()
                                                ? "name:" + row.name
                                                : "unknown";
                    Summary& summary = grouped[key];
                    if (summary.count++ == 0) {
                        summary.row = row;
                        summary.first = row.ev;
                    } else if (summary.row.name.empty() && !row.name.empty()) {
                        summary.row.name = row.name;
                    }
                    summary.last = row.ev;
                } else {
                    uint64_t row_index = row.n - 1;
                    bool retain = options.last > 0 ||
                                  (row_index >= options.offset &&
                                   row_index - options.offset <
                                       uint64_t(options.limit));
                    if (retain) {
                        rows.push_back(std::move(row));
                        if (options.last > 0 &&
                            rows.size() > size_t(options.last))
                            rows.pop_front();
                    }
                }
            }
        }
        if (g.is_call) annotation_stack.push_back(selected_annotation);
        if (g.is_ret && !annotation_stack.empty()) {
            uint64_t selected = annotation_stack.back();
            annotation_stack.pop_back();
            if (selected && !rows.empty() && selected >= rows.front().n &&
                selected <= rows.back().n) {
                Row& row = rows[size_t(selected - rows.front().n)];
                row.has_ret = true;
                row.ret_ev = gi;
                row.ret_line =
                    g.ret_source_line ? g.ret_source_line : g.source_line;
                row.ret_val = g.ret_val;
            }
        }
        return true;
    })) return scan_error(gtb);

    auto append_target = [](std::string& o, const Row& row) {
        o += ",\"target\":";
        if (row.target_known) emit::esc_append(o, emit::hex64(row.target).c_str());
        else o += "null";
        o += ",\"target_at\":";
        if (row.target_loc_known) emit::esc_append(o, row.target_at.c_str());
        else o += "null";
        o += ",\"name\":";
        if (!row.name.empty()) emit::esc_append(o, row.name.c_str());
        else o += "null";
    };
    auto emit_detail = [&](const Row& row) {
        if (options.json) {
            std::string o = "{";
            emit::kv_u64(o, "n", row.n);
            o += ',';
            emit::kv_u64(o, "ev", row.ev);
            if (row.line) {
                o += ',';
                emit::kv_u64(o, "line", row.line);
            }
            o += ',';
            emit::kv_str(o, "source", row.source);
            o += ',';
            emit::kv_str(o, "at", row.at);
            if (row.callsite_addr) {
                o += ',';
                emit::kv_hex(o, "addr", row.callsite_addr);
            }
            o += ',';
            emit::kv_str(o, "txt", row.txt);
            append_target(o, row);
            o += ",\"args\":[";
            for (int i = 0; i < 8; i++) {
                if (i) o += ',';
                if (row.arg_known[i])
                    emit::esc_append(o, emit::hex64(row.args[i]).c_str());
                else
                    o += "null";
            }
            o += ']';
            if (row.has_ret) {
                o += ',';
                emit::kv_u64(o, "ret_ev", row.ret_ev);
                if (row.ret_line) {
                    o += ',';
                    emit::kv_u64(o, "ret_line", row.ret_line);
                }
                o += ',';
                emit::kv_hex(o, "ret", row.ret_val);
            }
            o += '}';
            writer.row(std::move(o));
            return;
        }
        printf("#%-6llu ev=%-8llu", (unsigned long long)row.n,
               (unsigned long long)row.ev);
        if (row.line) printf(" line=%-8llu", (unsigned long long)row.line);
        printf(" %s %s -> ", row.at.c_str(), row.txt.c_str());
        if (!row.name.empty()) printf("%s ", row.name.c_str());
        if (row.target_loc_known) printf("%s", row.target_at.c_str());
        else if (row.target_known) printf("0x%llx", (unsigned long long)row.target);
        else printf("?");
        for (int i = 0; i < 8; i++) {
            if (row.arg_known[i])
                printf(" x%d=0x%llx", i, (unsigned long long)row.args[i]);
            else
                printf(" x%d=?", i);
        }
        if (row.has_ret)
            printf(" ret=0x%llx ret_ev=%llu", (unsigned long long)row.ret_val,
                   (unsigned long long)row.ret_ev);
        putchar('\n');
    };

    emit::Meta meta;
    if (options.top > 0) {
        std::vector<Summary> summaries;
        summaries.reserve(grouped.size());
        for (auto& item : grouped) summaries.push_back(std::move(item.second));
        std::sort(summaries.begin(), summaries.end(), [](const Summary& a,
                                                          const Summary& b) {
            if (a.count != b.count) return a.count > b.count;
            return a.first < b.first;
        });
        size_t shown = std::min(summaries.size(), size_t(options.top));
        if (!options.json)
            printf("call targets: %zu total (top %d)\n", summaries.size(),
                   options.top);
        for (size_t i = 0; i < shown; i++) {
            const Summary& summary = summaries[i];
            if (options.json) {
                std::string o = "{";
                emit::kv_u64(o, "count", summary.count);
                o += ',';
                emit::kv_u64(o, "first_ev", summary.first);
                o += ',';
                emit::kv_u64(o, "last_ev", summary.last);
                append_target(o, summary.row);
                o += '}';
                writer.row(std::move(o));
            } else {
                printf("%-8llu first=%-8llu last=%-8llu ",
                       (unsigned long long)summary.count,
                       (unsigned long long)summary.first,
                       (unsigned long long)summary.last);
                if (!summary.row.name.empty()) printf("%s ", summary.row.name.c_str());
                printf("%s\n", summary.row.target_loc_known
                                   ? summary.row.target_at.c_str()
                                   : summary.row.target_known
                                         ? emit::hex64(summary.row.target).c_str()
                                         : "?");
            }
        }
        meta.total = summaries.size();
        meta.shown = shown;
        meta.truncated = shown < summaries.size();
    } else {
        if (!options.json)
            printf("calls: %llu total\n", (unsigned long long)total_rows);
        for (const Row& row : rows) emit_detail(row);
        meta.total = total_rows;
        meta.shown = rows.size();
        meta.truncated = options.last > 0 ? meta.shown < meta.total
                                         : options.offset + meta.shown < meta.total;
        if (meta.truncated && options.last <= 0) {
            std::string next = "gt calls";
            for (const auto& name : names) next += " --name " + shell_arg(name);
            for (uint64_t target : target_addrs)
                next += " --target-addr " + emit::hex64(target);
            for (uint64_t off : target_offs)
                next += " --target-off " + emit::hex64(off);
            if (!options.mod.empty()) next += " --mod " + shell_arg(options.mod);
            if (options.from_ev) next += " --from " + std::to_string(options.from_ev);
            if (options.to_ev != UINT64_MAX)
                next += " --to " + std::to_string(options.to_ev);
            next += " --limit " + std::to_string(options.limit);
            next += " --offset " + std::to_string(options.offset + meta.shown);
            next += ' ' + shell_arg(gtb);
            if (options.json) next += " --json";
            meta.next = std::move(next);
        }
    }
    writer.finish(meta);
    return 0;
}

// calltree directly on a gtb: a stack over the call/ret stream (is_call
// pushes, is_ret pops — call first within a group: imported files carry both
// in one group). Every call named --func opens a capture window that prints
// descendant calls (2-space indent per level, --depth levels deep) until the
// matched frame returns. An empty selector emits the bounded global forest.
int q_calltree_gtb(const std::string& gtb, const std::string& func, int depth,
                   int limit, bool json) {
    if (limit <= 0) {
        fprintf(stderr, "calltree: --limit must be greater than zero\n");
        return 2;
    }
    GtbFile f;
    if (!load_query_file(f, gtb)) return 1;
    emit::QueryWriter writer(json, f);
    size_t stack_depth = 0;
    bool capturing = false;
    size_t base = 0;
    uint64_t lim = uint64_t(limit);
    uint64_t shown = 0, would_print = 0, matches = 0;
    bool global = func.empty();
    auto emit_line = [&](uint64_t gi, int lvl, const Group& g, const char* name) {
        if (shown < lim) {
            shown++;
            int na = std::min<int>(g.n_call_args, 8);
            if (json) {
                std::string o = "{";
                emit::kv_u64(o, "ev", gi);
                uint64_t line_no = g.call_source_line ? g.call_source_line
                                                       : g.source_line;
                if (line_no) {
                    o += ',';
                    emit::kv_u64(o, "line", line_no);
                }
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
                writer.row(std::move(o));
            } else {
                std::string line(size_t(lvl) * 2, ' ');
                uint64_t line_no = g.call_source_line ? g.call_source_line
                                                       : g.source_line;
                if (line_no)
                    line += "line=" + std::to_string(line_no) + " ";
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
    if (!TraceScan(f).for_each([&](uint64_t gi, const Group& g) {
        if (g.is_call) {
            const char* name = g.call_name ? g.call_name : "<unknown>";
            size_t d = stack_depth;
            if (global) {
                if (d <= size_t(depth < 0 ? 0 : depth))
                    emit_line(gi, int(d), g, name);
            } else if (capturing) {
                if (d - base <= size_t(depth < 0 ? 0 : depth))
                    emit_line(gi, int(d - base), g, name);
            } else if (func == name) {
                capturing = true;
                base = d;
                matches++;
                emit_line(gi, 0, g, name);
            }
            stack_depth++;
        }
        if (g.is_ret) {
            if (stack_depth > 0) stack_depth--;
            if (capturing && stack_depth <= base) capturing = false;
        }
        return true;
    })) return scan_error(gtb);
    if (!global && !capturing && matches == 0) {
        // func never called: say so plainly instead of printing nothing
        if (!json) printf("no call to %s in %s\n", func.c_str(), gtb.c_str());
    }
    emit::Meta meta;
    meta.total = would_print;
    meta.shown = shown;
    meta.truncated = would_print > shown;
    if (meta.truncated) {
        std::string next = "gt calltree";
        if (!global) next += " --func " + shell_arg(func);
        next += " --depth " + std::to_string(depth);
        next += " --limit " + std::to_string(limit * 5);
        next += ' ' + shell_arg(gtb);
        if (json) next += " --json";
        meta.next = std::move(next);
    }
    writer.finish(meta);
    return 0;
}
