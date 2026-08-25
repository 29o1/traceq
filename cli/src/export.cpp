#include "export.h"
#include "emit.h"

#include <algorithm>
#include <cstdio>
#include <string>
#include <vector>

namespace gt {

uint64_t export_upstream(const GtbFile& file, FILE* out, uint64_t from_idx,
                         uint64_t to_idx, uint64_t max_lines,
                         uint64_t* stop_event) {
    if (stop_event) *stop_event = UINT64_MAX;
    const SiteArena& arena = file.arena;
    const char* pool = arena.pool_ptr();
    const char* newline = file.crlf ? "\r\n" : "\n";
    std::string line;
    uint64_t lines = 0;

    auto append_observations = [&](const Group::Obs* values, int count) {
        char hex[40];
        for (int i = 0; i < count; i++) {
            line += arena.str(values[i].name_id);
            line += "=0x";
            size_t length = legacy_hex128(hex, values[i].val);
            line.append(hex, length);
            line += ' ';
        }
    };

    TraceScan(file).for_each([&](uint64_t event, const Group& group) {
        if (event < from_idx || event > to_idx) return event <= to_idx;
        if (max_lines && lines >= max_lines) {
            if (stop_event) *stop_event = event;
            return false;
        }
        line.clear();
        if (group.has_verbatim) {
            line.append(group.verbatim, group.verbatim_len);
            fwrite(line.data(), 1, line.size(), out);
            lines++;
            return true;
        }
        if (group.has_exec) {
            const Site& site = arena.get(group.site_id);
            line.append(pool + site.prefix_off, site.prefix_len);
        }
        append_observations(group.obs, group.n_obs);
        if (group.n_wobs > 0) {
            line += "-> ";
            append_observations(group.wobs, group.n_wobs);
        }
        if (group.has_exec) {
            line += newline;
            fwrite(line.data(), 1, line.size(), out);
            lines++;
        }
        if (group.is_call) {
            line.clear();
            line += group.is_jni_call ? "call jni func: " : "call func: ";
            line += group.call_name ? group.call_name : "<unknown>";
            line += '(';
            for (uint8_t i = 0; i < group.n_call_args; i++) {
                if (i) line += ", ";
                line += "0x";
                char hex[24];
                size_t length = legacy_hex64(hex, group.args[i]);
                line.append(hex, length);
            }
            line += ')';
            line += newline;
            fwrite(line.data(), 1, line.size(), out);
            lines++;
        }
        if (group.is_ret) {
            line.clear();
            line += "ret: 0x";
            char hex[24];
            size_t length = legacy_hex64(hex, group.ret_val);
            line.append(hex, length);
            line += newline;
            fwrite(line.data(), 1, line.size(), out);
            lines++;
        }
        return true;
    });
    return lines;
}

static void append_call(std::string& line, const Group& group) {
    char value[40];
    line += "+call ";
    line += group.call_name ? group.call_name : "<unknown>";
    line += '(';
    for (uint8_t i = 0; i < group.n_call_args; i++) {
        if (i) line += ", ";
        snprintf(value, sizeof value, "x%d=0x%llx", i,
                 (unsigned long long)group.args[i]);
        line += value;
    }
    line += ")\n";
}

static uint64_t export_agent(const GtbFile& file, FILE* out, bool json,
                             uint64_t from_idx, uint64_t to_idx,
                             uint64_t max_lines, uint64_t* stop_event,
                             uint64_t* total_selected) {
    if (stop_event) *stop_event = UINT64_MAX;
    if (total_selected) *total_selected = 0;
    const SiteArena& arena = file.arena;
    uint64_t lines = 0, selected = 0;
    uint32_t current_module = UINT32_MAX;
    std::string line;
    std::vector<AgentRegVal> reads, writes;
    std::vector<AgentMemVal> memory;
    reads.reserve(8);
    writes.reserve(8);
    memory.reserve(2);

    TraceScan scan(file);
    scan.for_each([&](uint64_t event, const Group& group) {
        if (event < from_idx) return true;
        if (event > to_idx) return false;
        selected++;
        if (max_lines && lines >= max_lines) {
            if (stop_event && *stop_event == UINT64_MAX) *stop_event = event;
            // JSON metadata needs the exact number of selected groups. Finish
            // the scan without formatting more rows.
            return json && total_selected;
        }

        line.clear();
        if (json && !group.has_exec) {
            char value[64];
            snprintf(value, sizeof value, "{\"ev\":%llu",
                     (unsigned long long)event);
            line += value;
            if (group.has_verbatim) line += ",\"verbatim\":true";
        }

        const uint64_t* registers = scan.regfile();
        if (group.has_exec) {
            const Site& site = arena.get(group.site_id);
            uint32_t module_id =
                site.module_id < arena.modules().size() ? site.module_id : 0;
            if (!json && module_id != current_module) {
                current_module = module_id;
                line += "== ";
                line += arena.modules().empty() ? "?" : arena.modules()[module_id];
                line += " ==\n";
            }
            uint64_t offset = site.addr - arena.module_base(module_id);
            std::string disasm(arena.pool_ptr() + site.disasm_off,
                               site.disasm_len);
            reads.clear();
            writes.clear();
            memory.clear();
            reconstruct_agent_values(arena, site, group, registers, reads,
                                     writes, memory);

            if (json) {
                char value[64];
                snprintf(value, sizeof value, "{\"ev\":%llu",
                         (unsigned long long)event);
                line += value;
                if (group.source_line) {
                    line += ',';
                    emit::kv_u64(line, "line", group.source_line);
                }
                line += ',';
                emit::kv_str(line, "mod",
                             arena.modules().empty() ? "?"
                                                     : arena.modules()[module_id]);
                line += ',';
                emit::kv_hex(line, "off", offset);
                line += ',';
                emit::kv_str(line, "txt", disasm);
                line += ",\"rd\":[";
                for (size_t i = 0; i < reads.size(); i++) {
                    if (i) line += ',';
                    char row[96];
                    snprintf(row, sizeof row, "[\"%s\",\"0x%llx\"]",
                             agent_reg_name(reads[i].ctx),
                             (unsigned long long)reads[i].val);
                    line += row;
                }
                line += "],\"wr\":[";
                for (size_t i = 0; i < writes.size(); i++) {
                    if (i) line += ',';
                    char row[96];
                    snprintf(row, sizeof row, "[\"%s\",\"0x%llx\"]",
                             agent_reg_name(writes[i].ctx),
                             (unsigned long long)writes[i].val);
                    line += row;
                }
                line += ']';
                if (!memory.empty()) {
                    line += ",\"mem\":[";
                    for (size_t i = 0; i < memory.size(); i++) {
                        if (i) line += ',';
                        line += "{\"w\":";
                        line += memory[i].is_w ? '1' : '0';
                        line += ",\"addr\":\"" + emit::hex64(memory[i].addr) + '"';
                        line += ",\"size\":" + std::to_string(memory[i].size);
                        if (memory[i].known)
                            line += ",\"val\":\"" + emit::hex128(memory[i].val) + '"';
                        line += '}';
                    }
                    line += ']';
                }
            } else {
                char value[64];
                if (group.source_line)
                    snprintf(value, sizeof value, "%llu line=%llu !0x%llx ",
                             (unsigned long long)event,
                             (unsigned long long)group.source_line,
                             (unsigned long long)offset);
                else
                    snprintf(value, sizeof value, "%llu !0x%llx ",
                             (unsigned long long)event,
                             (unsigned long long)offset);
                line += value;
                line += disasm;
                if (!reads.empty() || !writes.empty()) {
                    line += "; ";
                    for (size_t i = 0; i < reads.size(); i++) {
                        if (i) line += ' ';
                        snprintf(value, sizeof value, "%s=0x%llx",
                                 agent_reg_name(reads[i].ctx),
                                 (unsigned long long)reads[i].val);
                        line += value;
                    }
                    if (!reads.empty() && !writes.empty()) line += " -> ";
                    else if (!writes.empty()) line += "-> ";
                    for (size_t i = 0; i < writes.size(); i++) {
                        if (i) line += ' ';
                        snprintf(value, sizeof value, "%s=0x%llx",
                                 agent_reg_name(writes[i].ctx),
                                 (unsigned long long)writes[i].val);
                        line += value;
                    }
                }
                if (!memory.empty()) {
                    line += "; ";
                    for (size_t i = 0; i < memory.size(); i++) {
                        if (i) line += ' ';
                        snprintf(value, sizeof value, "%s=0x%llx",
                                 memory[i].is_w ? "mem_w" : "mem_r",
                                 (unsigned long long)memory[i].addr);
                        line += value;
                        if (memory[i].known) {
                            line += ':';
                            line += emit::hex128(memory[i].val);
                        }
                    }
                }
                line += '\n';
            }
        }

        if (group.is_call) {
            if (json) {
                line += ",\"call\":{";
                emit::kv_str(line, "sym",
                             group.call_name ? group.call_name : "<unknown>");
                std::vector<std::string> args;
                args.reserve(group.n_call_args);
                for (uint8_t i = 0; i < group.n_call_args; i++)
                    args.push_back(emit::hex64(group.args[i]));
                line += ",\"args\":" + emit::str_array(args) + '}';
            } else {
                append_call(line, group);
            }
        }
        if (group.is_ret) {
            if (json) {
                line += ',';
                emit::kv_hex(line, "ret", group.ret_val);
            } else {
                char value[32];
                snprintf(value, sizeof value, "+ret x0=0x%llx\n",
                         (unsigned long long)group.ret_val);
                line += value;
            }
        }
        if (json && !line.empty()) line += "}\n";
        if (!line.empty()) {
            fwrite(line.data(), 1, line.size(), out);
            lines += std::count(line.begin(), line.end(), '\n');
        }
        return true;
    });
    if (total_selected) *total_selected = selected;
    return lines;
}

uint64_t export_compact(const GtbFile& file, FILE* out, uint64_t from_idx,
                        uint64_t to_idx, uint64_t max_lines,
                        uint64_t* stop_event) {
    return export_agent(file, out, false, from_idx, to_idx, max_lines,
                        stop_event, nullptr);
}

uint64_t export_jsonl(const GtbFile& file, FILE* out, uint64_t from_idx,
                      uint64_t to_idx, uint64_t max_lines,
                      uint64_t* stop_event, uint64_t* total_selected) {
    return export_agent(file, out, true, from_idx, to_idx, max_lines,
                        stop_event, total_selected);
}

} // namespace gt
