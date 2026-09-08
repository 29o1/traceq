#include <traceq/queries.h>
#include <traceq/ingest.h>
#include <traceq/import.h>
#include <traceq/site.h>
#include "emit.h"
#include "event_decoder.h"
#include "export.h"
#include "gtb_format.h"
#include "query_common.h"
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <deque>
#include <unordered_map>
#include <unordered_set>
#include <vector>

using namespace gt;

int q_stat(const std::string& gtb, bool json) {
    GtbFile f;
    if (!load_query_file(f, gtb)) return 1;
    emit::QueryWriter writer(json, f);
    std::vector<uint64_t> mod_exec(f.arena.modules().size(), 0);
    uint64_t first_addr = 0, first_off = 0;
    uint64_t call_instructions = 0, return_instructions = 0;
    uint64_t n_exec = 0, n_regw = 0, n_mem = 0, n_call = 0, n_ret = 0;
    uint64_t n_rdval = 0, n_simdv = 0, n_verbatim = 0;
    std::string first_mod;
    bool saw_exec = false;
    EventCursor cursor(f.events, f.arena);
    RawEvent batch[64];
    size_t count;
    while ((count = cursor.next_batch(batch, 64)) != 0) {
        for (size_t i = 0; i < count; i++) {
            const RawEvent& event = batch[i];
            switch (event.tag) {
            case gt::format::EV_EXEC: {
                n_exec++;
                if (event.site_id >= f.arena.sites().size()) break;
                const Site& s = f.arena.get(event.site_id);
                if (s.module_id < mod_exec.size()) mod_exec[s.module_id]++;
                if (s.kind == SK_CALL_IMM || s.kind == SK_CALL_REG)
                    call_instructions++;
                else if (s.kind == SK_RET)
                    return_instructions++;
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
                break;
            }
            case gt::format::EV_REGW: n_regw++; break;
            case gt::format::EV_MEM:
            case gt::format::EV_MEMW_NV: n_mem++; break;
            case gt::format::EV_CALL: n_call++; break;
            case gt::format::EV_RET: n_ret++; break;
            case gt::format::EV_RDVAL: n_rdval++; break;
            case gt::format::EV_SIMDV: n_simdv++; break;
            case gt::format::EV_VERBATIM: n_verbatim++; break;
            default: break;
            }
        }
    }
    if (!cursor.ok()) return scan_error(gtb);
    const char* dialect = f.crlf ? "upstream+crlf" : "upstream";
    if (json) {
        std::string o;
        emit::kv_str(o, "file", gtb);
        o += ',';
        emit::kv_str(o, "dialect", dialect);
        o += ',';
        emit::kv_str(o, "stop",
                     stop_reason_name(static_cast<StopReason>(f.stop_reason)));
        char b[512];
        snprintf(b, sizeof b,
                 ",\"exec\":%llu,\"regw\":%llu,\"mem\":%llu,"
                 "\"call_instructions\":%llu,\"return_instructions\":%llu,"
                 "\"call_annotations\":%llu,\"return_annotations\":%llu,"
                 "\"rdval\":%llu,\"simdv\":%llu,"
                 "\"verbatim\":%llu,\"events_seen\":%llu,\"events_recorded\":%llu,"
                 "\"bytes_written\":%llu",
                 (unsigned long long)n_exec, (unsigned long long)n_regw,
                 (unsigned long long)n_mem,
                 (unsigned long long)call_instructions,
                 (unsigned long long)return_instructions,
                 (unsigned long long)n_call,
                 (unsigned long long)n_ret,
                 (unsigned long long)n_rdval, (unsigned long long)n_simdv,
                 (unsigned long long)n_verbatim,
                 (unsigned long long)f.events_seen,
                 (unsigned long long)f.events_recorded,
                 (unsigned long long)f.bytes_written);
        o += b;
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
        writer.row("{\"stat\":{" + o + "}}");
    } else {
        printf("file: %s (dialect %s, stop %s)\n", gtb.c_str(), dialect,
               stop_reason_name(static_cast<StopReason>(f.stop_reason)));
        printf("events: exec=%llu regw=%llu mem=%llu rdval=%llu simdv=%llu "
               "verbatim=%llu\n",
               (unsigned long long)n_exec, (unsigned long long)n_regw,
               (unsigned long long)n_mem,
               (unsigned long long)n_rdval, (unsigned long long)n_simdv,
               (unsigned long long)n_verbatim);
        printf("flow: call_instructions=%llu return_instructions=%llu "
               "call_annotations=%llu return_annotations=%llu\n",
               (unsigned long long)call_instructions,
               (unsigned long long)return_instructions,
               (unsigned long long)n_call,
               (unsigned long long)n_ret);
        printf("recorded: seen=%llu recorded=%llu bytes=%llu\n",
               (unsigned long long)f.events_seen,
               (unsigned long long)f.events_recorded,
               (unsigned long long)f.bytes_written);
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
    writer.finish(meta);
    return 0;
}

int q_mem_accesses(const std::string& gtb, const MemAccessOptions& options) {
    const auto& addrs = options.addrs;
    bool use_range = options.use_range;
    uint64_t range_base = options.range_base, range_len = options.range_len;
    int limit = options.limit, last = options.last;
    uint64_t offset = options.offset, from_ev = options.from_ev;
    uint64_t to_ev = options.to_ev;
    bool json = options.json, writes_only = options.writes_only;
    bool reads_only = options.reads_only;
    bool all_writes = options.all_writes;
    bool has_selector = use_range || !addrs.empty();
    if (!options.valid() || (!has_selector && !all_writes) ||
        (all_writes && (has_selector || !writes_only || to_ev == UINT64_MAX)) ||
        (use_range && range_len == 0) || (writes_only && reads_only)) {
        fprintf(stderr, "mem-access: invalid selector or event range\n");
        return 2;
    }
    GtbFile f;
    if (!load_query_file(f, gtb)) return 1;
    emit::QueryWriter writer(json, f);
    uint64_t ctx_first_ev = UINT64_MAX;
    const int ctx_span = options.context;
    struct Row {
        uint64_t ev, line, addr;
        unsigned __int128 value;
        uint32_t site_id;
        uint8_t size;
        bool is_write, value_known, has_exec, has_prior_write;
        uint64_t prior_write_ev;
    };
    std::unordered_set<uint64_t> addr_set(addrs.begin(), addrs.end());
    std::unordered_map<uint64_t, uint64_t> last_write;
    std::deque<Row> tail;
    uint64_t total = 0, shown = 0;
    uint64_t lim = uint64_t(limit);
    auto emit_row = [&](const Row& r) {
        if (ctx_span > 0 && ctx_first_ev == UINT64_MAX) ctx_first_ev = r.ev;
        if (json) {
            std::string o = "{";
            emit::kv_u64(o, "ev", r.ev);
            if (r.line) {
                o += ',';
                emit::kv_u64(o, "line", r.line);
            }
            o += ',';
            emit::kv_str(o, "rw", r.is_write ? "w" : "r");
            o += ',';
            emit::kv_hex(o, "addr", r.addr);
            if (use_range) {
                o += ',';
                emit::kv_hex(o, "off", std::max(r.addr, range_base) - range_base);
            }
            o += ',';
            emit::kv_u64(o, "size", r.size);
            if (!r.is_write) {
                o += ",\"prior_write_ev\":";
                if (r.has_prior_write)
                    o += std::to_string(r.prior_write_ev);
                else
                    o += "null";
            }
            if (r.value_known) {
                o += ',';
                emit::kv_hex128(o, "val", r.value);
            }
            o += ',';
            emit::kv_str(o, "at", query_at(f, r.has_exec ? r.site_id : 0xFFFFFFFFu));
            o += '}';
            writer.row(std::move(o));
        } else {
            printf("%llu", (unsigned long long)r.ev);
            if (r.line) printf(" line=%llu", (unsigned long long)r.line);
            printf(" %c 0x%llx", r.is_write ? 'w' : 'r',
                   (unsigned long long)r.addr);
            if (r.value_known) {
                std::string value = emit::hex128(r.value);
                printf(" =%s", value.c_str());
            }
            if (use_range)
                printf(" off=0x%llx",
                       (unsigned long long)(std::max(r.addr, range_base) -
                                            range_base));
            printf(" size=%u", unsigned(r.size));
            if (!r.is_write) {
                if (r.has_prior_write)
                    printf(" prior_write_ev=%llu",
                           (unsigned long long)r.prior_write_ev);
                else
                    printf(" prior_write_ev=none");
            }
            printf(" %s\n", query_at(f, r.has_exec ? r.site_id : 0xFFFFFFFFu).c_str());
        }
    };
    TraceScan ex(f);
    std::vector<AgentMemVal> mems;
    mems.reserve(2);
    auto selected_byte = [&](uint64_t addr) {
        return use_range ? addr >= range_base && addr - range_base < range_len
                         : addr_set.count(addr) != 0;
    };
    if (!ex.for_each([&](uint64_t gi, const Group& g) {
        if (gi > to_ev) return false;
        // In selectorless mode no pre-window write history is needed: only
        // writes inside the explicitly bounded event window are returned.
        if (all_writes && gi < from_ev) return true;
        if (g.n_mem == 0) return true;
        mems.clear();
        if (g.has_exec)
            reconstruct_agent_memory(f.arena.get(g.site_id), g, ex.regfile(),
                                     ex.reg_known(), mems);
        int lanes = mems.empty() ? g.n_mem : int(mems.size());
        for (int k = 0; k < lanes; k++) {
            bool is_write = mems.empty() ? g.mem[k].is_write : mems[size_t(k)].is_w;
            uint64_t mem_addr = mems.empty() ? g.mem[k].addr : mems[size_t(k)].addr;
            bool value_known = mems.empty() ? g.mem[k].value_known
                                            : mems[size_t(k)].known;
            unsigned __int128 value = mems.empty() ? g.mem[k].value
                                                    : mems[size_t(k)].val;
            uint8_t mem_size = mems.empty() ? g.mem[k].size
                                            : mems[size_t(k)].size;
            uint64_t width = mem_size ? mem_size : 1;
            bool hit = all_writes ||
                       (use_range
                            ? (mem_addr >= range_base
                                   ? mem_addr - range_base < range_len
                                   : range_base - mem_addr < width)
                            : std::any_of(addrs.begin(), addrs.end(),
                                          [&](uint64_t addr) {
                                              return addr >= mem_addr &&
                                                     addr - mem_addr < width;
                                          }));
            if (!hit) continue;
            if (is_write && !writes_only) {
                for (uint64_t lane = 0; lane < width; lane++) {
                    if (lane > UINT64_MAX - mem_addr) break;
                    uint64_t addr = mem_addr + lane;
                    if (selected_byte(addr)) last_write[addr] = gi;
                }
            }
            if (gi < from_ev || (writes_only && !is_write) ||
                (reads_only && is_write)) continue;
            bool has_prior = false;
            uint64_t prior_write_ev = 0;
            if (!is_write) {
                for (uint64_t lane = 0; lane < width; lane++) {
                    if (lane > UINT64_MAX - mem_addr) break;
                    uint64_t addr = mem_addr + lane;
                    if (!selected_byte(addr)) continue;
                    auto prior = last_write.find(addr);
                    if (prior != last_write.end() &&
                        (!has_prior || prior->second > prior_write_ev)) {
                        has_prior = true;
                        prior_write_ev = prior->second;
                    }
                }
            }
            Row row{gi, g.source_line, mem_addr, value, g.site_id, mem_size,
                    is_write, value_known, g.has_exec, has_prior,
                    prior_write_ev};
            uint64_t row_index = total++;
            if (last > 0) {
                if (tail.size() == size_t(last)) tail.pop_front();
                tail.push_back(row);
            } else if (row_index >= offset && shown < lim) {
                emit_row(row);
                shown++;
            }
        }
        return true;
    })) return scan_error(gtb);
    if (last > 0) {
        for (const Row& row : tail) {
            emit_row(row);
            shown++;
        }
    }
    emit::Meta meta;
    meta.total = total;
    meta.shown = shown;
    meta.truncated = last > 0 ? shown < total
                              : offset < total && shown < total - offset;
    if (meta.truncated && last <= 0) {
        std::string next = "gt mem-access";
        if (use_range)
            next += " --range " + emit::hex64(range_base) + ',' +
                    emit::hex64(range_len);
        else
            for (uint64_t addr : addrs) next += " --addr " + emit::hex64(addr);
        if (reads_only) next += " --read";
        if (writes_only) next += " --write";
        if (all_writes || from_ev)
            next += " --from " + std::to_string(from_ev);
        if (to_ev != UINT64_MAX) next += " --to " + std::to_string(to_ev);
        next += " --limit " + std::to_string(limit);
        next += " --offset " + std::to_string(offset + shown);
        next += ' ' + shell_arg(gtb);
        if (ctx_span > 0) next += " --context " + std::to_string(ctx_span);
        if (json) next += " --json";
        meta.next = std::move(next);
    }
    if (ctx_span > 0 && ctx_first_ev != UINT64_MAX) {
        std::string rows;
        if (!render_context(f, ctx_first_ev, uint64_t(ctx_span), json, rows))
            return scan_error(gtb, "cannot render context");
        if (!rows.empty()) writer.set_context(ctx_first_ev, std::move(rows));
    }
    writer.finish(meta);
    return 0;
}

int q_mem_states(const std::string& gtb, const MemStateOptions& options) {
    if (options.ranges.empty() || options.at_evs.empty()) {
        fprintf(stderr, "mem-state: at least one range and event are required\n");
        return 2;
    }

    std::vector<MemStateRange> ranges;
    for (const auto& range : options.ranges) {
        if (range.len == 0 || range.len > (1u << 20)) {
            fprintf(stderr, "mem-state: range length must be 1..0x100000 bytes\n");
            return 2;
        }
        if (range.base > UINT64_MAX - range.len) {
            fprintf(stderr, "mem-state: range overflows address space\n");
            return 2;
        }
        if (options.qword && (range.len & 7)) {
            fprintf(stderr,
                    "mem-state: --qword range length must be a multiple of 8\n");
            return 2;
        }
        auto duplicate = std::find_if(
            ranges.begin(), ranges.end(), [&](const MemStateRange& old) {
                return old.base == range.base && old.len == range.len;
            });
        if (duplicate == ranges.end()) ranges.push_back(range);
    }
    std::vector<uint64_t> at_evs = options.at_evs;
    std::sort(at_evs.begin(), at_evs.end());
    at_evs.erase(std::unique(at_evs.begin(), at_evs.end()), at_evs.end());

    GtbFile f;
    if (!load_query_file(f, gtb)) return 1;
    emit::QueryWriter writer(options.json, f);

    struct State {
        MemStateRange range;
        std::vector<uint8_t> bytes;
        std::vector<uint8_t> known;
    };
    std::vector<State> states;
    states.reserve(ranges.size());
    for (const auto& range : ranges)
        states.push_back({range, std::vector<uint8_t>(size_t(range.len), 0),
                          std::vector<uint8_t>(size_t(range.len), 0)});

    bool batched = states.size() > 1 || at_evs.size() > 1;
    uint64_t shown = 0;
    auto emit_state = [&](const State& state, uint64_t at_ev) {
        uint64_t range_base = state.range.base;
        uint64_t range_len = state.range.len;
        const auto& bytes = state.bytes;
        const auto& known = state.known;
        if (options.qword) {
            if (batched && !options.json)
                printf("mem-state base=0x%llx len=0x%llx at-ev=%llu\n",
                       (unsigned long long)range_base,
                       (unsigned long long)range_len,
                       (unsigned long long)at_ev);
            for (size_t i = 0; i < bytes.size(); i += 8) {
                bool word_known = true;
                uint64_t val = 0;
                for (size_t j = 0; j < 8; j++) {
                    if (!known[i + j]) word_known = false;
                    val |= uint64_t(bytes[i + j]) << (j * 8);
                }
                if (options.json) {
                    std::string o = "{";
                    if (batched) {
                        emit::kv_u64(o, "at_ev", at_ev);
                        o += ',';
                        emit::kv_hex(o, "base", range_base);
                        o += ',';
                    }
                    emit::kv_hex(o, "addr", range_base + i);
                    o += ",\"known\":";
                    o += word_known ? "true" : "false";
                    o += ",\"val\":";
                    if (word_known) emit::esc_append(o, emit::hex64(val).c_str());
                    else o += "null";
                    o += '}';
                    writer.row(std::move(o));
                } else if (word_known) {
                    printf("0x%llx =0x%llx\n",
                           (unsigned long long)(range_base + i),
                           (unsigned long long)val);
                } else {
                    printf("0x%llx =??\n",
                           (unsigned long long)(range_base + i));
                }
                shown++;
            }
            return;
        }

        static const char kHex[] = "0123456789abcdef";
        std::string data_hex;
        data_hex.reserve(size_t(range_len) * 2);
        uint64_t known_count = 0;
        for (size_t i = 0; i < bytes.size(); i++) {
            if (!known[i]) {
                data_hex += "00";
                continue;
            }
            known_count++;
            data_hex.push_back(kHex[bytes[i] >> 4]);
            data_hex.push_back(kHex[bytes[i] & 15]);
        }

        if (options.json) {
            std::string o = "{\"mem_state\":{";
            emit::kv_hex(o, "base", range_base);
            o += ',';
            emit::kv_u64(o, "len", range_len);
            o += ',';
            emit::kv_u64(o, "at_ev", at_ev);
            o += ',';
            emit::kv_u64(o, "known", known_count);
            o += ',';
            emit::kv_str(o, "data_hex", data_hex);
            o += ",\"unknown\":[";
            bool first = true;
            for (size_t i = 0; i < known.size();) {
                if (known[i]) {
                    i++;
                    continue;
                }
                size_t j = i + 1;
                while (j < known.size() && !known[j]) j++;
                if (!first) o += ',';
                first = false;
                o += '{';
                emit::kv_hex(o, "addr", range_base + i);
                o += ',';
                emit::kv_u64(o, "len", j - i);
                o += '}';
                i = j;
            }
            o += "]}}";
            writer.row(std::move(o));
        } else {
            printf("mem-state base=0x%llx len=0x%llx at-ev=%llu known=%llu/%llu\n",
                   (unsigned long long)range_base,
                   (unsigned long long)range_len,
                   (unsigned long long)at_ev,
                   (unsigned long long)known_count,
                   (unsigned long long)range_len);
            for (size_t i = 0; i < known.size(); i += 16) {
                printf("  0x%llx:", (unsigned long long)(range_base + i));
                size_t end = std::min(i + 16, known.size());
                for (size_t j = i; j < end; j++) {
                    if (known[j]) printf(" %02x", bytes[j]);
                    else printf(" ??");
                }
                putchar('\n');
            }
        }
        shown++;
    };

    bool saw_event = false;
    size_t next_at = 0;
    TraceScan ex(f);
    std::vector<AgentMemVal> mems;
    mems.reserve(2);
    if (!ex.for_each([&](uint64_t gi, const Group& g) {
        if (gi > at_evs.back()) return false;
        saw_event = true;
        if (g.n_mem != 0) {
            mems.clear();
            if (g.has_exec)
                reconstruct_agent_memory(f.arena.get(g.site_id), g,
                                         ex.regfile(), ex.reg_known(), mems);
            if (mems.empty())
                for (int i = 0; i < g.n_mem; i++) {
                    const MemOp& m = g.mem[i];
                    mems.push_back({m.is_write, m.addr, m.value,
                                    m.value_known, m.size});
                }
            for (const auto& m : mems) {
                uint64_t width = m.size ? m.size : 8;
                if (m.addr > UINT64_MAX - width) continue;
                uint64_t mem_end = m.addr + width;
                for (auto& state : states) {
                    uint64_t range_base = state.range.base;
                    uint64_t range_end = range_base + state.range.len;
                    if (m.addr >= range_end || mem_end <= range_base) continue;
                    uint64_t lo = std::max(m.addr, range_base);
                    uint64_t hi = std::min(mem_end, range_end);
                    for (uint64_t a = lo; a < hi; a++) {
                        size_t out_i = size_t(a - range_base);
                        uint64_t lane_i = a - m.addr;
                        if (m.known && lane_i < sizeof(m.val)) {
                            state.bytes[out_i] = uint8_t(m.val >> (lane_i * 8));
                            state.known[out_i] = 1;
                        } else if (m.is_w) {
                            // An unknown write invalidates an older observation.
                            state.known[out_i] = 0;
                        }
                    }
                }
            }
        }
        if (next_at < at_evs.size() && gi == at_evs[next_at]) {
            for (const auto& state : states) emit_state(state, gi);
            next_at++;
        }
        return true;
    })) return scan_error(gtb);
    if (!saw_event || next_at != at_evs.size()) {
        uint64_t missing = next_at < at_evs.size() ? at_evs[next_at] : 0;
        fprintf(stderr, "mem-state: --at-ev %llu is outside the trace\n",
                (unsigned long long)missing);
        return 2;
    }
    emit::Meta meta;
    meta.total = shown;
    meta.shown = shown;
    writer.finish(meta);
    return 0;
}

int q_find_pcs(const std::string& gtb, const FindPcOptions& options) {
    const auto& addrs = options.addrs;
    const auto& offs = options.offs;
    const auto& mod = options.mod;
    int limit = options.limit, last = options.last;
    uint64_t offset = options.offset, from_ev = options.from_ev;
    uint64_t to_ev = options.to_ev;
    bool json = options.json;
    if (!options.valid() || (addrs.empty() && offs.empty())) {
        fprintf(stderr, "find-pc: invalid selector, range, or --last combination\n");
        return 2;
    }
    GtbFile f;
    if (!load_query_file(f, gtb)) return 1;
    emit::QueryWriter writer(json, f);
    uint64_t ctx_first_ev = UINT64_MAX;
    const int ctx_span = options.context;
    std::unordered_set<uint64_t> addr_set(addrs.begin(), addrs.end());
    std::unordered_set<uint64_t> off_set(offs.begin(), offs.end());
    struct Row {
        uint64_t ev = 0, line = 0, off = 0, addr = 0;
        std::string mod, txt;
        std::vector<AgentRegVal> rd, wr;
        std::vector<AgentMemVal> mems;
    };
    std::deque<Row> tail;
    uint64_t total = 0, shown = 0;
    uint64_t lim = uint64_t(limit);
    TraceScan ex(f);
    std::vector<AgentRegVal> rd, wr;
    std::vector<AgentMemVal> mems;
    rd.reserve(8);
    wr.reserve(8);
    mems.reserve(2);
    auto emit_row = [&](const Row& r) {
        if (ctx_span > 0 && ctx_first_ev == UINT64_MAX) ctx_first_ev = r.ev;
        if (json) {
            std::string o = "{";
            emit::kv_u64(o, "ev", r.ev);
            if (r.line) {
                o += ',';
                emit::kv_u64(o, "line", r.line);
            }
            o += ',';
            emit::kv_str(o, "mod", r.mod);
            o += ',';
            emit::kv_hex(o, "off", r.off);
            o += ',';
            emit::kv_hex(o, "addr", r.addr);
            o += ',';
            emit::kv_str(o, "txt", r.txt);
            o += ",\"rd\":[";
            for (size_t i = 0; i < r.rd.size(); i++) {
                if (i) o += ',';
                o += "[\"" + std::string(agent_reg_name(r.rd[i].ctx)) +
                     "\",\"" + emit::hex64(r.rd[i].val) + "\"]";
            }
            o += "],\"wr\":[";
            for (size_t i = 0; i < r.wr.size(); i++) {
                if (i) o += ',';
                o += "[\"" + std::string(agent_reg_name(r.wr[i].ctx)) +
                     "\",\"" + emit::hex64(r.wr[i].val) + "\"]";
            }
            o += ']';
            if (!r.mems.empty()) {
                o += ",\"mem\":[";
                for (size_t i = 0; i < r.mems.size(); i++) {
                    if (i) o += ',';
                    o += "{\"w\":" + std::string(r.mems[i].is_w ? "1" : "0") +
                         ",\"addr\":\"" + emit::hex64(r.mems[i].addr) + "\"" +
                         ",\"size\":" + std::to_string(r.mems[i].size);
                    if (r.mems[i].known)
                        o += ",\"val\":\"" + emit::hex128(r.mems[i].val) + "\"";
                    o += '}';
                }
                o += ']';
            }
            o += '}';
            writer.row(std::move(o));
            return;
        }
        printf("%llu", (unsigned long long)r.ev);
        if (r.line) printf(" line=%llu", (unsigned long long)r.line);
        printf(" %s!0x%llx %s", r.mod.c_str(), (unsigned long long)r.off,
               r.txt.c_str());
        if (!r.rd.empty() || !r.wr.empty()) {
            printf(";");
            for (const auto& value : r.rd)
                printf(" %s=0x%llx", agent_reg_name(value.ctx),
                       (unsigned long long)value.val);
            if (!r.wr.empty()) {
                printf(" ->");
                for (const auto& value : r.wr)
                    printf(" %s=0x%llx", agent_reg_name(value.ctx),
                           (unsigned long long)value.val);
            }
        }
        for (const auto& mem : r.mems) {
            printf("; %s=0x%llx", mem.is_w ? "mem_w" : "mem_r",
                   (unsigned long long)mem.addr);
            if (mem.known) {
                std::string value = emit::hex128(mem.val);
                printf(":%s", value.c_str());
            }
        }
        putchar('\n');
    };
    if (!ex.for_each([&](uint64_t gi, const Group& g) {
        if (gi < from_ev) return true;
        if (gi > to_ev) return false;
        if (!g.has_exec) return true;
        const Site& s = f.arena.get(g.site_id);
        std::string module = s.module_id < f.arena.modules().size()
                                 ? f.arena.modules()[s.module_id]
                                 : "?";
        uint64_t site_off = s.module_id < f.arena.modules().size()
                                ? s.addr - f.arena.module_base(s.module_id)
                                : s.addr;
        bool hit = !addr_set.empty() ? addr_set.count(s.addr) != 0
                                     : off_set.count(site_off) != 0 &&
                                           (mod.empty() || module == mod);
        if (!hit) return true;
        uint64_t row_index = total++;
        if (last <= 0 && (row_index < offset || shown >= lim)) return true;

        rd.clear();
        wr.clear();
        mems.clear();
        reconstruct_agent_values(s, g, ex.regfile(), ex.reg_known(), rd, wr, mems);
        std::string txt(f.arena.pool_ptr() + s.disasm_off, s.disasm_len);
        Row row{gi, g.source_line, site_off, s.addr, std::move(module),
                std::move(txt), rd, wr, mems};
        if (last > 0) {
            if (tail.size() == size_t(last)) tail.pop_front();
            tail.push_back(std::move(row));
        } else {
            emit_row(row);
            shown++;
        }
        return true;
    })) return scan_error(gtb);
    if (last > 0)
        for (const Row& row : tail) {
            emit_row(row);
            shown++;
        }

    emit::Meta meta;
    meta.total = total;
    meta.shown = shown;
    meta.truncated = last > 0 ? shown < total : offset + shown < total;
    if (meta.truncated && last <= 0) {
        std::string next = "gt find-pc";
        for (uint64_t addr : addrs) next += " --addr " + emit::hex64(addr);
        for (uint64_t off : offs) next += " --off " + emit::hex64(off);
        if (!mod.empty()) next += " --mod " + shell_arg(mod);
        if (from_ev) next += " --from " + std::to_string(from_ev);
        if (to_ev != UINT64_MAX) next += " --to " + std::to_string(to_ev);
        next += " --limit " + std::to_string(lim);
        next += " --offset " + std::to_string(offset + shown);
        next += " " + shell_arg(gtb);
        if (ctx_span > 0) next += " --context " + std::to_string(ctx_span);
        if (json) next += " --json";
        meta.next = std::move(next);
    }
    if (ctx_span > 0 && ctx_first_ev != UINT64_MAX) {
        std::string rows;
        if (!render_context(f, ctx_first_ev, uint64_t(ctx_span), json, rows))
            return scan_error(gtb, "cannot render context");
        if (!rows.empty()) writer.set_context(ctx_first_ev, std::move(rows));
    }
    writer.finish(meta);
    return 0;
}

int q_find_value(const std::string& gtb, const FindValueOptions& options) {
    std::vector<uint64_t> values;
    std::unordered_set<uint64_t> seen_values;
    for (uint64_t value : options.values)
        if (seen_values.insert(value).second) values.push_back(value);

    uint64_t offset = options.offset;
    uint64_t from_ev = options.from_ev, to_ev = options.to_ev;
    int limit = options.limit, last = options.last;
    bool json = options.json, reads_only = options.reads_only;
    bool writes_only = options.writes_only;
    if (!options.valid() || values.empty() || (reads_only && writes_only)) {
        fprintf(stderr, "find-value: invalid range, filter, or --last combination\n");
        return 2;
    }
    GtbFile f;
    if (!load_query_file(f, gtb)) return 1;
    emit::QueryWriter writer(json, f);
    uint64_t ctx_first_ev = UINT64_MAX;
    const int ctx_span = options.context;
    std::unordered_map<uint64_t, size_t> value_index;
    for (size_t i = 0; i < values.size(); i++) value_index.emplace(values[i], i);
    std::vector<uint64_t> totals(values.size(), 0);
    std::vector<uint64_t> shown_per_value(values.size(), 0);
    uint64_t shown = 0;
    uint64_t lim = uint64_t(limit);
    struct ValueRow {
        size_t value_i = 0;
        uint64_t ev = 0, line = 0, addr = 0;
        std::string lane, kind, reg, at;
        char rw = 0;
        uint8_t size = 0;
    };
    std::vector<std::deque<ValueRow>> tails(values.size());
    // dump-payload scan pattern: minimal-width LE bytes of val. Values that
    // only ever exist as memory bytes (protobuf payloads inside memcpy dumps)
    // have no register/obs lane; the verbatim hexdump rows are the only place
    // they appear. Width < 2 is too noisy for a byte-substring search.
    struct Pattern { uint8_t bytes[8]; int n = 0; };
    std::vector<Pattern> patterns(values.size());
    for (size_t i = 0; i < values.size(); i++) {
        uint64_t v = values[i];
        do {
            patterns[i].bytes[patterns[i].n++] = uint8_t(v & 0xff);
            v >>= 8;
        } while (v && patterns[i].n < 8);
    }
    auto emit_value_row = [&](const ValueRow& row) {
        if (ctx_span > 0 && ctx_first_ev == UINT64_MAX) ctx_first_ev = row.ev;
        uint64_t val = values[row.value_i];
        if (json) {
            std::string o = "{";
            emit::kv_u64(o, "ev", row.ev);
            if (row.line) {
                o += ',';
                emit::kv_u64(o, "line", row.line);
            }
            o += ',';
            emit::kv_str(o, "lane", row.lane);
            o += ',';
            emit::kv_str(o, "kind", row.kind);
            if (row.rw) {
                o += ',';
                emit::kv_str(o, "rw", row.rw == 'w' ? "w" : "r");
            }
            if (!row.reg.empty()) {
                o += ',';
                emit::kv_str(o, "reg", row.reg);
            }
            if (row.kind == "mem" || row.kind == "dump") {
                o += ',';
                emit::kv_hex(o, "addr", row.addr);
                o += ',';
                emit::kv_u64(o, "size", row.size);
            }
            o += ',';
            emit::kv_hex(o, "val", val);
            o += ',';
            emit::kv_str(o, "at", row.at);
            o += '}';
            writer.row(std::move(o));
        } else {
            printf("%llu", (unsigned long long)row.ev);
            if (row.line) printf(" line=%llu", (unsigned long long)row.line);
            printf(" %s 0x%llx %s\n", row.lane.c_str(),
                   (unsigned long long)val, row.at.c_str());
        }
    };
    auto row = [&](size_t value_i, uint64_t gi, const std::string& lane,
                   const char* kind, char rw, const std::string& reg,
                   uint64_t addr, uint8_t size, const Group& g) {
        if ((reads_only && rw != 'r') || (writes_only && rw != 'w')) return;
        uint64_t row_index = totals[value_i]++;
        if (last <= 0 && (row_index < offset || shown_per_value[value_i] >= lim))
            return;
        ValueRow value_row{value_i, gi, g.source_line, addr, lane, kind, reg,
                           query_at(f, g.has_exec ? g.site_id : 0xFFFFFFFFu), rw,
                           size};
        if (last > 0) {
            auto& tail = tails[value_i];
            if (tail.size() == size_t(last)) tail.pop_front();
            tail.push_back(std::move(value_row));
            return;
        }
        emit_value_row(value_row);
        shown_per_value[value_i]++;
        shown++;
    };
    TraceScan ex(f);
    std::vector<AgentMemVal> mems;
    mems.reserve(2);
    if (!ex.for_each([&](uint64_t gi, const Group& g) {
        if (gi > to_ev) return false;
        if (gi < from_ev) return true;
        if (g.has_verbatim) {
            // hexdump rows: byte-exact content search at any offset. Qword-
            // aligned full-width matches are already covered by the mem_r
            // lanes the importer synthesized from the same rows.
            uint64_t raddr = 0;
            uint8_t bytes[16];
            int nb = 0;
            if (parse_hexdump_row(g.verbatim, g.verbatim_len, raddr, bytes, nb)) {
                for (size_t value_i = 0; value_i < patterns.size(); value_i++) {
                    const Pattern& pat = patterns[value_i];
                    if (pat.n < 2) continue;
                    for (int o = 0; o + pat.n <= nb; o++)
                        if (!memcmp(bytes + o, pat.bytes, size_t(pat.n)) &&
                            !(pat.n == 8 && (o & 7) == 0)) {
                            char lb[48];
                            snprintf(lb, sizeof lb, "dump:0x%llx",
                                     (unsigned long long)(raddr + uint64_t(o)));
                            row(value_i, gi, lb, "dump", 0, "",
                                raddr + uint64_t(o), uint8_t(pat.n), g);
                        }
                }
            }
            // fall through: verbatim groups may carry synthesized mem lanes
        }
        // imported files dual-record writes (REGW + wobs token) — the wr:
        // lanes below already cover them, so skip the bare lane to avoid
        // counting one logical write twice
        for (int k = 0; k < g.n_wr; k++) {
            auto match = value_index.find(g.wr_val[k]);
            if (g.n_wobs == 0 && match != value_index.end()) {
                std::string reg = agent_reg_name(g.wr_id[k] & 31);
                row(match->second, gi, reg, "reg", 'w', reg, 0, 0, g);
            }
        }
        for (int k = 0; k < g.n_obs; k++) {
            unsigned __int128 v = g.obs[k].val;
            std::string reg = f.arena.str(g.obs[k].name_id);
            // Imported mem_r/mem_w observations carry the accessed address,
            // not a register value. Memory matches are emitted from mems below.
            if (reg == "mem_r" || reg == "mem_w") continue;
            std::string ln = std::string("rd:") + reg;
            if (v <= UINT64_MAX) {
                auto match = value_index.find(uint64_t(v));
                if (match != value_index.end())
                    row(match->second, gi, ln, "reg", 'r', reg, 0, 0, g);
            } else {
                // 128-bit SIMD observation: match either 64-bit lane exactly
                auto low = value_index.find(uint64_t(v));
                if (low != value_index.end())
                    row(low->second, gi, ln + ".lo", "reg", 'r', reg + ".lo",
                        0, 0, g);
                auto high = value_index.find(uint64_t(v >> 64));
                if (high != value_index.end() &&
                    (low == value_index.end() || high->second != low->second))
                    row(high->second, gi, ln + ".hi", "reg", 'r', reg + ".hi",
                        0, 0, g);
            }
        }
        for (int k = 0; k < g.n_wobs; k++) {
            unsigned __int128 v = g.wobs[k].val;
            std::string reg = f.arena.str(g.wobs[k].name_id);
            std::string ln = std::string("wr:") + reg;
            if (v <= UINT64_MAX) {
                auto match = value_index.find(uint64_t(v));
                if (match != value_index.end())
                    row(match->second, gi, ln, "reg", 'w', reg, 0, 0, g);
            } else {
                auto low = value_index.find(uint64_t(v));
                if (low != value_index.end())
                    row(low->second, gi, ln + ".lo", "reg", 'w', reg + ".lo",
                        0, 0, g);
                auto high = value_index.find(uint64_t(v >> 64));
                if (high != value_index.end() &&
                    (low == value_index.end() || high->second != low->second))
                    row(high->second, gi, ln + ".hi", "reg", 'w', reg + ".hi",
                        0, 0, g);
            }
        }
        mems.clear();
        if (g.has_exec && g.n_mem)
            reconstruct_agent_memory(f.arena.get(g.site_id), g, ex.regfile(),
                                     ex.reg_known(), mems);
        int mem_count = mems.empty() ? g.n_mem : int(mems.size());
        for (int k = 0; k < mem_count; k++) {
            bool known = mems.empty() ? g.mem[k].value_known
                                      : mems[size_t(k)].known;
            unsigned __int128 mem_val = mems.empty() ? g.mem[k].value
                                                      : mems[size_t(k)].val;
            if (!known || mem_val > UINT64_MAX) continue;
            auto match = value_index.find(uint64_t(mem_val));
            if (match == value_index.end()) continue;
            bool is_write = mems.empty() ? g.mem[k].is_write
                                         : mems[size_t(k)].is_w;
            uint64_t addr = mems.empty() ? g.mem[k].addr
                                         : mems[size_t(k)].addr;
            uint8_t size = mems.empty() ? g.mem[k].size
                                        : mems[size_t(k)].size;
            row(match->second, gi, is_write ? "mem_w" : "mem_r", "mem",
                is_write ? 'w' : 'r', "", addr, size, g);
        }
        return true;
    })) return scan_error(gtb);
    if (last > 0)
        for (size_t value_i = 0; value_i < tails.size(); value_i++)
            for (const ValueRow& value_row : tails[value_i]) {
                emit_value_row(value_row);
                shown_per_value[value_i]++;
                shown++;
            }
    emit::Meta meta;
    for (uint64_t total : totals) meta.total += total;
    meta.shown = shown;
    for (size_t i = 0; i < values.size(); i++) {
        uint64_t available = last > 0
                                 ? totals[i]
                                 : totals[i] > offset ? totals[i] - offset : 0;
        if (shown_per_value[i] < available) meta.truncated = true;
    }
    if (meta.truncated && last <= 0) {
        bool batched = values.size() > 1;
        std::string next = batched ? "gt find-value " + shell_arg(gtb)
                                   : "gt find-value " + emit::hex64(values[0]);
        if (batched)
            for (uint64_t value : values)
                next += " --value " + emit::hex64(value);
        if (reads_only) next += " --read";
        if (writes_only) next += " --write";
        if (from_ev) next += " --from " + std::to_string(from_ev);
        if (to_ev != UINT64_MAX) next += " --to " + std::to_string(to_ev);
        next += " --limit " + std::to_string(limit);
        next += " --offset " + std::to_string(offset + uint64_t(limit));
        if (!batched) next += ' ' + shell_arg(gtb);
        if (ctx_span > 0) next += " --context " + std::to_string(ctx_span);
        if (json) next += " --json";
        meta.next = std::move(next);
    }
    if (ctx_span > 0 && ctx_first_ev != UINT64_MAX) {
        std::string rows;
        if (!render_context(f, ctx_first_ev, uint64_t(ctx_span), json, rows))
            return scan_error(gtb, "cannot render context");
        if (!rows.empty()) writer.set_context(ctx_first_ev, std::move(rows));
    }
    writer.finish(meta);
    return 0;
}
