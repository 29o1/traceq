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
    auto ranges = options.ranges;
    if (options.use_range) ranges.push_back({options.range_base, options.range_len});
    std::vector<MemStateRange> unique_ranges;
    for (auto r : ranges) {
        if (!r.len || r.len > UINT64_MAX - r.base) {
            fprintf(stderr, "mem-access: range must be nonempty and not overflow\n");
            return 2;
        }
        if (std::none_of(unique_ranges.begin(), unique_ranges.end(), [&](auto old) {
                return old.base == r.base && old.len == r.len;
            })) unique_ranges.push_back(r);
    }
    ranges = std::move(unique_ranges);
    bool use_range = !ranges.empty(), single_range = ranges.size() == 1;
    uint64_t range_base = single_range ? ranges[0].base : 0;
    int limit = options.limit, last = options.last;
    uint64_t offset = options.offset, from_ev = options.from_ev;
    uint64_t to_ev = options.to_ev;
    bool json = options.json, writes_only = options.writes_only;
    bool reads_only = options.reads_only;
    bool all_writes = options.all_writes;
    bool has_selector = use_range || !addrs.empty();
    if (!options.valid() || (!has_selector && !all_writes) ||
        (all_writes && (has_selector || !writes_only || to_ev == UINT64_MAX)) ||
        (use_range && !addrs.empty()) || (writes_only && reads_only)) {
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
            if (single_range) {
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
            if (single_range)
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
        return use_range ? std::any_of(ranges.begin(), ranges.end(), [&](auto r) {
                               return addr >= r.base && addr - r.base < r.len;
                           })
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
                            ? std::any_of(ranges.begin(), ranges.end(), [&](auto r) {
                                  return mem_addr >= r.base
                                      ? mem_addr - r.base < r.len
                                      : r.base - mem_addr < width;
                              })
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
            for (auto r : ranges)
                next += " --range " + emit::hex64(r.base) + ',' + emit::hex64(r.len);
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

namespace {

// Memory effects are inferred only for named C-library annotations with explicit
// bounds and a matching destination return. An arbitrary two-pointer call is
// not a copy. Keep this local to memory reconstruction; no persistent index or
// whole-address-space memory dictionary is needed.
bool memory_call_name(const char* name, bool& move, bool& fill) {
    if (!name) return false;
    move = fill = false;
    for (const char* stem : {"memcpy", "memmove", "memset"}) {
        std::string s(stem);
        if (!strcmp(name, stem) || !strcmp(name, ("__" + s + "_chk").c_str()) ||
            !strncmp(name, ("__" + s + "_aarch64_").c_str(), s.size() + 11)) {
            move = s == "memmove";
            fill = s == "memset";
            return true;
        }
    }
    return false;
}

struct MemoryOrigin {
    enum Kind { Unobserved, Observation, Hexdump, UnknownWrite, PendingCopy,
                ReturnedCopy, UnconfirmedCopy, PendingFill, ReturnedFill,
                UnconfirmedFill } kind = Unobserved;
    uint64_t ev = 0, line = 0;
    size_t effect = SIZE_MAX;
    bool operator==(const MemoryOrigin& b) const {
        return kind == b.kind && ev == b.ev && line == b.line && effect == b.effect;
    }
};

const char* origin_kind(MemoryOrigin::Kind kind) {
    switch (kind) {
    case MemoryOrigin::Observation: return "observation";
    case MemoryOrigin::Hexdump: return "hexdump";
    case MemoryOrigin::UnknownWrite: return "unknown_write";
    case MemoryOrigin::PendingCopy: return "copy_pending";
    case MemoryOrigin::ReturnedCopy: return "copy";
    case MemoryOrigin::UnconfirmedCopy: return "unconfirmed_copy";
    case MemoryOrigin::PendingFill: return "fill_pending";
    case MemoryOrigin::ReturnedFill: return "fill";
    case MemoryOrigin::UnconfirmedFill: return "unconfirmed_fill";
    default: return "unobserved";
    }
}

struct MemoryState {
    MemStateRange range;
    std::vector<uint8_t> bytes, known, written;
    std::vector<MemoryOrigin> origins;
    MemoryState(MemStateRange r, bool provenance) : range(r),
        bytes(size_t(r.len), 0), known(size_t(r.len), 0), written(size_t(r.len), 0) {
        if (provenance) origins.resize(size_t(r.len));
    }
};

struct MemorySourceSpan {
    uint64_t addr = 0, len = 0;
    bool known = false;
    MemoryOrigin origin;
};

struct MemoryEffect {
    std::string name, status = "pending", invalid;
    uint64_t dst = 0, src = 0, len = 0, span = 0;
    uint64_t call_ev = 0, call_line = 0;
    uint64_t ret_ev = UINT64_MAX, ret_line = 0, ret_val = 0;
    uint8_t nargs = 0;
    bool safe = false, fill = false;
    struct Piece {
        MemStateRange dst, src;
        std::vector<uint8_t> bytes, known;
        std::vector<MemoryOrigin> origins;
    };
    std::vector<Piece> pieces;
    std::vector<MemorySourceSpan> evidence;
};

// Plan only the source slices on which the requested destinations depend, then
// replay observations in order. This also handles effects without a hexdump,
// copy chains, and memmove overlap without retaining unrelated memory. Source
// bytes are snapshotted BEFORE destination invalidation, never read from a
// partially updated destination.
class MemoryReplay {
public:
    explicit MemoryReplay(bool provenance) : provenance_(provenance) {}
    std::vector<MemoryEffect> effects;
    std::string coordinate_error;

    static uint64_t last_line(const Group& g) {
        uint64_t line = std::max(g.source_line, std::max(g.call_source_line, g.ret_source_line));
        if (g.has_verbatim) {
            uint64_t lines = 0;
            for (uint32_t i = 0; i < g.verbatim_len; i++)
                if (g.verbatim[i] == '\n') lines++;
            if (g.verbatim_len && g.verbatim[g.verbatim_len - 1] != '\n') lines++;
            line = lines ? line + lines - 1 : line ? line - 1 : 0;
        }
        return line;
    }

    bool plan(const GtbFile& f, const std::vector<MemStateRange>& ranges,
              std::vector<uint64_t>& checkpoints, const std::vector<uint64_t>& lines,
              std::unordered_map<uint64_t, uint64_t>& resolved_lines) {
        uint64_t last_ev = checkpoints.empty() ? 0 : checkpoints.back();
        auto needed = ranges;
        merge(needed);
        bool may_copy = false, move = false, fill = false;
        for (const auto& s : f.arena.strings())
            if (memory_call_name(s.c_str(), move, fill)) { may_copy = true; break; }
        if (may_copy || !lines.empty()) {
            std::vector<size_t> stack;
            size_t next_line = 0;
            uint64_t source_end = 0;
            TraceScan scan(f, /*track_registers=*/false);
            if (!scan.for_each([&](uint64_t ev, const Group& g) {
                if (ev > last_ev && next_line == lines.size()) return false;
                source_end = last_line(g);
                while (next_line < lines.size() && lines[next_line] <= source_end) {
                    uint64_t requested = lines[next_line];
                    if (requested != source_end) {
                        coordinate_error = "source line " + std::to_string(requested) +
                            " is inside event " + std::to_string(ev) +
                            "; its completed state includes through line " + std::to_string(source_end) +
                            ". Use --at-line " + std::to_string(source_end) +
                            " or --at-ev " + std::to_string(ev) + " explicitly";
                        return false;
                    }
                    checkpoints.push_back(ev);
                    resolved_lines[ev] = requested;
                    last_ev = std::max(last_ev, ev);
                    next_line++;
                }
                if (g.is_call) {
                    size_t id = SIZE_MAX;
                    if (!g.is_jni_call && memory_call_name(g.call_name, move, fill)) {
                        MemoryEffect c;
                        c.fill = fill;
                        c.name = g.call_name;
                        c.call_ev = ev;
                        c.call_line = g.call_source_line;
                        c.nargs = g.n_call_args;
                        c.dst = g.n_call_args ? g.args[0] : 0;
                        c.src = g.n_call_args > 1 ? g.args[1] : 0;
                        c.len = g.n_call_args > 2 ? g.args[2] : 0;
                        // With no length, even an old value cannot establish
                        // that the possible destination suffix was untouched.
                        c.span = g.n_call_args > 2
                            ? std::min(c.len, UINT64_MAX - c.dst)
                            : UINT64_MAX - c.dst;
                        if (g.n_call_args < 3)
                            c.invalid = fill ? "missing_fill_bounds" : "missing_copy_bounds";
                        else if (c.len > UINT64_MAX - c.dst ||
                                 (!fill && c.len > UINT64_MAX - c.src))
                            c.invalid = fill ? "overflowing_fill_bounds" : "overflowing_copy_bounds";
                        else if (!fill && !move && c.len && c.dst < c.src + c.len &&
                                 c.src < c.dst + c.len)
                            c.invalid = "overlapping_memcpy";
                        c.safe = c.invalid.empty();
                        id = effects.size();
                        effects.push_back(std::move(c));
                    }
                    stack.push_back(id);
                }
                if (g.is_ret && !stack.empty()) {
                    size_t id = stack.back(); stack.pop_back();
                    if (id != SIZE_MAX) {
                        auto& c = effects[id];
                        c.ret_ev = ev; c.ret_line = g.ret_source_line;
                        c.ret_val = g.ret_val;
                    }
                }
                return true;
            })) return false;
            if (!coordinate_error.empty()) return false;
            if (next_line < lines.size()) {
                coordinate_error = source_end
                    ? "--at-line " + std::to_string(lines[next_line]) +
                      " is outside source lines 1.." + std::to_string(source_end)
                    : "trace has no source lines; cannot resolve --at-line " +
                      std::to_string(lines[next_line]);
                return false;
            }
        }
        std::sort(checkpoints.begin(), checkpoints.end());
        checkpoints.erase(std::unique(checkpoints.begin(), checkpoints.end()), checkpoints.end());
        // Backward slice discovery is metadata-only. It cannot lend a future
        // observation to an earlier checkpoint in the forward replay below.
        for (auto it = effects.rbegin(); it != effects.rend(); ++it) {
            auto& c = *it;
            if (!c.safe || c.ret_ev == UINT64_MAX || c.ret_val != c.dst) continue;
            std::vector<MemStateRange> sources;
            for (auto r : needed) {
                uint64_t lo = std::max(r.base, c.dst);
                uint64_t hi = std::min(r.base + r.len, c.dst + c.len);
                if (lo >= hi) continue;
                MemStateRange src = c.fill ? MemStateRange{} :
                    MemStateRange{c.src + (lo - c.dst), hi - lo};
                c.pieces.push_back({{lo, hi - lo}, src, {}, {}, {}});
                if (!c.fill) sources.push_back(src);
            }
            needed.insert(needed.end(), sources.begin(), sources.end());
            merge(needed);
        }
        for (auto r : needed) states_.emplace_back(r, provenance_);
        for (size_t i = 0; i < effects.size(); i++) {
            call_at_.emplace(effects[i].call_ev, i);
            if (effects[i].ret_ev != UINT64_MAX)
                ret_at_.emplace(effects[i].ret_ev, i);
        }
        return true;
    }

    MemoryState snapshot(MemStateRange r) const {
        MemoryState out(r, provenance_);
        for (const auto& s : states_) {
            uint64_t lo = std::max(r.base, s.range.base);
            uint64_t hi = std::min(r.base + r.len, s.range.base + s.range.len);
            for (uint64_t a = lo; a < hi; a++) {
                size_t i = size_t(a - r.base), j = size_t(a - s.range.base);
                out.bytes[i] = s.bytes[j]; out.known[i] = s.known[j];
                if (provenance_) out.origins[i] = s.origins[j];
            }
        }
        return out;
    }

    void apply(uint64_t ev, const Group& g, const GtbFile& f,
               const uint64_t* regs, const uint8_t* known) {
        uint64_t line = g.source_line;
        if (!g.has_verbatim && g.n_mem) {
            mems_.clear();
            if (g.has_exec)
                reconstruct_agent_memory(f.arena.get(g.site_id), g, regs, known, mems_);
            if (mems_.empty())
                for (int i = 0; i < g.n_mem; i++) {
                    const auto& m = g.mem[i];
                    mems_.push_back({m.is_write, m.addr, m.value, m.value_known, m.size});
                }
            for (const auto& m : mems_) {
                uint64_t width = m.size ? m.size : 8;
                if (m.addr > UINT64_MAX - width) continue;
                for (size_t id : active_) {
                    auto& c = effects[id];
                    for (auto& p : c.pieces) {
                        uint64_t lo = std::max(m.addr, p.src.base);
                        uint64_t hi = std::min(m.addr + width, p.src.base + p.src.len);
                        for (uint64_t a = lo; a < hi; a++) {
                            size_t i = size_t(a - p.src.base);
                            uint64_t lane = a - m.addr;
                            // memmove's own overlapping destination writes do
                            // not change its entry-source snapshot.
                            if (m.is_w && (a < c.dst || a - c.dst >= c.len)) {
                                p.bytes[i] = p.known[i] = 0;
                                if (provenance_)
                                    p.origins[i] = {MemoryOrigin::UnknownWrite, ev, line};
                            } else if (!m.is_w && !p.known[i] && m.known && lane < sizeof(m.val)) {
                                p.bytes[i] = uint8_t(m.val >> (lane * 8)); p.known[i] = 1;
                                if (provenance_)
                                    p.origins[i] = {MemoryOrigin::Observation, ev, line};
                            }
                        }
                    }
                }
                visit(m.addr, width, [&](MemoryState& s, uint64_t a, size_t i) {
                    uint64_t lane = a - m.addr;
                    if (m.known && lane < sizeof(m.val)) {
                        s.bytes[i] = uint8_t(m.val >> (lane * 8)); s.known[i] = 1;
                        origin(s, i, {MemoryOrigin::Observation, ev, line});
                    } else if (m.is_w) {
                        s.bytes[i] = s.known[i] = 0;
                        origin(s, i, {MemoryOrigin::UnknownWrite, ev, line});
                    }
                    if (m.is_w) s.written[i] = 1;
                });
            }
        }
        if (g.is_call) {
            auto found = call_at_.find(ev);
            if (found != call_at_.end()) {
                size_t id = found->second;
                auto& c = effects[id];
                for (size_t parent : active_)
                    for (auto& p : effects[parent].pieces) {
                        uint64_t lo = std::max(c.dst, p.src.base);
                        uint64_t hi = std::min(c.dst + c.span, p.src.base + p.src.len);
                        for (uint64_t a = lo; a < hi; a++) {
                            const auto& outer = effects[parent];
                            if (a >= outer.dst && a - outer.dst < outer.len) continue;
                            size_t i = size_t(a - p.src.base);
                            p.bytes[i] = p.known[i] = 0;
                            if (provenance_)
                                p.origins[i] = {c.fill ? MemoryOrigin::PendingFill : MemoryOrigin::PendingCopy,
                                                ev, c.call_line, id};
                        }
                    }
                for (auto& p : c.pieces) {
                    if (c.fill) continue;
                    auto s = snapshot(p.src);
                    p.bytes = std::move(s.bytes); p.known = std::move(s.known);
                    p.origins = std::move(s.origins);
                }
                invalidate(c, {c.fill ? MemoryOrigin::PendingFill : MemoryOrigin::PendingCopy,
                               ev, c.call_line, id});
                if (!c.fill && !c.pieces.empty()) active_.push_back(id);
            }
        }
        if (g.has_verbatim) {
            uint64_t addr = 0, len = 0;
            uint8_t bytes[16]; int nb = 0;
            if (parse_hexdump_header(g.verbatim, g.verbatim_len, addr, len) &&
                len <= UINT64_MAX - addr) {
                dump_ = true; dump_base_ = addr; dump_end_ = addr + len;
                dump_copy_ = SIZE_MAX;
                if (ev) {
                    auto found = call_at_.find(ev - 1);
                    if (found != call_at_.end() && !effects[found->second].fill &&
                        effects[found->second].src == addr)
                        dump_copy_ = found->second;
                }
            } else if (dump_ &&
                       parse_hexdump_row(g.verbatim, g.verbatim_len, addr, bytes, nb) &&
                       uint64_t(nb) <= UINT64_MAX - addr) {
                uint64_t lo = std::max(addr, dump_base_);
                uint64_t hi = std::min(addr + uint64_t(nb), dump_end_);
                MemoryOrigin source{MemoryOrigin::Hexdump, ev, line};
                if (lo < hi) {
                    visit(lo, hi - lo, [&](MemoryState& s, uint64_t a, size_t i) {
                        s.bytes[i] = bytes[a - addr]; s.known[i] = 1;
                        origin(s, i, source);
                    });
                    if (dump_copy_ != SIZE_MAX)
                        for (auto& p : effects[dump_copy_].pieces) {
                            uint64_t first = std::max(lo, p.src.base);
                            uint64_t last = std::min(hi, p.src.base + p.src.len);
                            for (uint64_t a = first; a < last; a++) {
                                size_t i = size_t(a - p.src.base);
                                p.bytes[i] = bytes[a - addr]; p.known[i] = 1;
                                if (provenance_) p.origins[i] = source;
                            }
                        }
                }
            } else dump_ = false;
        } else dump_ = false;
        if (g.is_ret) {
            auto found = ret_at_.find(ev);
            if (found != ret_at_.end()) {
                size_t id = found->second;
                auto& c = effects[id];
                if (!c.safe || c.ret_val != c.dst) {
                    c.status = c.safe ? "return_mismatch" : c.invalid;
                    // A source dump may overlap the destination and expose
                    // its OLD contents while the call is pending. Those reads
                    // do not establish the post-return destination. Only actual
                    // writes in the call can survive an unconfirmed copy.
                    invalidate(c, {c.fill ? MemoryOrigin::UnconfirmedFill : MemoryOrigin::UnconfirmedCopy,
                                   ev, c.ret_line, id}, true);
                } else {
                    c.status = "returned";
                    for (auto& p : c.pieces) {
                        if (provenance_ && !c.fill) save_evidence(c, p);
                        visit(p.dst.base, p.dst.len,
                              [&](MemoryState& s, uint64_t a, size_t i) {
                            size_t j = size_t(a - p.dst.base);
                            // An actual in-call write is stronger evidence
                            // than an inferred copy, including unknown writes.
                            // Never resurrect an entry value over such a write.
                            if (s.written[i]) return;
                            s.bytes[i] = c.fill ? uint8_t(c.src) : p.known[j] ? p.bytes[j] : 0;
                            s.known[i] = c.fill ? 1 : p.known[j];
                            origin(s, i, {c.fill ? MemoryOrigin::ReturnedFill : MemoryOrigin::ReturnedCopy,
                                           ev, c.ret_line, id});
                        });
                    }
                    c.pieces.clear();
                }
                active_.erase(std::remove(active_.begin(), active_.end(), id), active_.end());
            }
        }
    }

private:
    bool provenance_ = false, dump_ = false;
    uint64_t dump_base_ = 0, dump_end_ = 0;
    size_t dump_copy_ = SIZE_MAX;
    std::vector<MemoryState> states_;
    std::vector<size_t> active_;
    std::vector<AgentMemVal> mems_;
    std::unordered_map<uint64_t, size_t> call_at_, ret_at_;

    static void merge(std::vector<MemStateRange>& rs) {
        std::sort(rs.begin(), rs.end(), [](auto a, auto b) { return a.base < b.base; });
        size_t n = 0;
        for (auto r : rs) {
            if (n && r.base <= rs[n - 1].base + rs[n - 1].len) {
                auto& prev = rs[n - 1];
                prev.len = std::max(prev.base + prev.len, r.base + r.len) - prev.base;
            } else rs[n++] = r;
        }
        rs.resize(n);
    }
    template<class Fn> void visit(uint64_t base, uint64_t len, Fn fn) {
        for (auto& s : states_) {
            if (s.range.base >= base + len) break;
            uint64_t lo = std::max(base, s.range.base);
            uint64_t hi = std::min(base + len, s.range.base + s.range.len);
            for (uint64_t a = lo; a < hi; a++) fn(s, a, size_t(a - s.range.base));
        }
    }
    void origin(MemoryState& s, size_t i, MemoryOrigin value) {
        if (provenance_) s.origins[i] = value;
    }
    void invalidate(const MemoryEffect& c, MemoryOrigin value, bool keep_writes = false) {
        visit(c.dst, c.span, [&](MemoryState& s, uint64_t, size_t i) {
            if (keep_writes && s.written[i]) return;
            s.bytes[i] = s.known[i] = s.written[i] = 0; origin(s, i, value);
        });
    }
    static void save_evidence(MemoryEffect& c, const MemoryEffect::Piece& p) {
        for (size_t i = 0; i < p.known.size();) {
            size_t j = i + 1;
            while (j < p.known.size() && p.known[i] == p.known[j] &&
                   p.origins[i] == p.origins[j]) j++;
            c.evidence.push_back({p.src.base + i, j - i, p.known[i] != 0, p.origins[i]});
            i = j;
        }
    }
};

} // namespace

int q_mem_states(const std::string& gtb, const MemStateOptions& options) {
    if (options.ranges.empty() || (options.at_evs.empty() && options.at_lines.empty())) {
        fprintf(stderr, "mem-state: at least one range and event/source-line checkpoint are required\n");
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
    auto at_lines = options.at_lines;
    std::sort(at_lines.begin(), at_lines.end());
    at_lines.erase(std::unique(at_lines.begin(), at_lines.end()), at_lines.end());
    if (!at_lines.empty() && at_lines.front() == 0) {
        fprintf(stderr, "mem-state: source lines are 1-based; --at-line must be >=1\n");
        return 2;
    }

    GtbFile f;
    if (!load_query_file(f, gtb)) return 1;
    emit::QueryWriter writer(options.json, f);

    MemoryReplay replay(options.provenance);
    std::unordered_map<uint64_t, uint64_t> resolved_lines;
    if (!replay.plan(f, ranges, at_evs, at_lines, resolved_lines)) {
        if (replay.coordinate_error.empty()) return scan_error(gtb);
        fprintf(stderr, "mem-state: %s\n", replay.coordinate_error.c_str());
        return 2;
    }

    auto append_origin = [&](std::string& o, const MemoryOrigin& origin) {
        emit::kv_str(o, "kind", origin_kind(origin.kind));
        if (origin.kind != MemoryOrigin::Unobserved) {
            o += ','; emit::kv_u64(o, "ev", origin.ev);
            if (origin.line) { o += ','; emit::kv_u64(o, "line", origin.line); }
        }
        if (origin.effect != SIZE_MAX) {
            o += ',';
            emit::kv_u64(o, replay.effects[origin.effect].fill ? "fill" : "copy", origin.effect + 1);
        }
    };
    auto append_provenance = [&](std::string& o, const MemoryState& s,
                                 size_t first, size_t end, uint64_t at_ev,
                                 bool copy_table = true) {
        if (!options.provenance) return;
        std::vector<size_t> ids;
        std::unordered_set<size_t> seen;
        auto need_effect = [&](const MemoryOrigin& origin) {
            if (origin.effect != SIZE_MAX && seen.insert(origin.effect).second)
                ids.push_back(origin.effect);
        };
        o += ",\"provenance\":[";
        for (size_t i = first; i < end;) {
            size_t j = i + 1;
            while (j < end && s.known[i] == s.known[j] && s.origins[i] == s.origins[j]) j++;
            if (i != first) o += ',';
            o += '{'; emit::kv_hex(o, "addr", s.range.base + i);
            o += ','; emit::kv_u64(o, "len", j - i);
            o += ",\"known\":"; o += s.known[i] ? "true" : "false";
            o += ','; append_origin(o, s.origins[i]); o += '}';
            need_effect(s.origins[i]);
            i = j;
        }
        o += "]";
        if (!copy_table) return;
        // Qword output shares one copy-evidence table per range/checkpoint;
        // do not repeat a large source dump for every eight-byte cell.
        if (first != 0 || end != s.origins.size())
            for (const auto& origin : s.origins) need_effect(origin);
        if (ids.empty()) return;
        for (size_t i = 0; i < ids.size(); i++)
            for (const auto& e : replay.effects[ids[i]].evidence) need_effect(e.origin);
        std::sort(ids.begin(), ids.end());
        for (bool fill : {false, true}) {
            if (std::none_of(ids.begin(), ids.end(), [&](size_t id) { return replay.effects[id].fill == fill; }))
                continue;
            o += fill ? ",\"fills\":[" : ",\"copies\":[";
            bool first_effect = true;
            for (size_t i = 0; i < ids.size(); i++) {
                const auto& c = replay.effects[ids[i]];
                if (c.fill != fill) continue;
                if (!first_effect) o += ',';
                first_effect = false;
                o += '{'; emit::kv_u64(o, "id", ids[i] + 1);
                o += ','; emit::kv_str(o, "name", c.name);
                o += ",\"dst\":";
                if (c.nargs) emit::esc_append(o, emit::hex64(c.dst).c_str());
                else o += "null";
                o += fill ? ",\"fill_byte\":" : ",\"src\":";
                if (c.nargs > 1) emit::esc_append(o, emit::hex64(fill ? uint8_t(c.src) : c.src).c_str());
                else o += "null";
                o += ",\"len\":";
                if (c.nargs < 3) o += "null";
                else o += std::to_string(c.len);
                o += ','; emit::kv_u64(o, "call_ev", c.call_ev);
                o += ','; emit::kv_u64(o, "call_line", c.call_line);
                o += ','; emit::kv_str(o, "status", c.status);
                if (!c.invalid.empty()) { o += ','; emit::kv_str(o, "limitation", c.invalid); }
                // Planning has seen later metadata, but an earlier snapshot must
                // not expose its future return or source observations.
                o += ",\"ret_ev\":";
                if (c.ret_ev > at_ev) o += "null";
                else {
                    o += std::to_string(c.ret_ev);
                    o += ','; emit::kv_u64(o, "ret_line", c.ret_line);
                    o += ','; emit::kv_hex(o, "ret_val", c.ret_val);
                }
                o += ",\"source_evidence\":[";
                for (size_t j = 0; j < c.evidence.size(); j++) {
                    const auto& e = c.evidence[j];
                    if (j) o += ',';
                    o += '{'; emit::kv_hex(o, "addr", e.addr);
                    o += ','; emit::kv_u64(o, "len", e.len);
                    o += ",\"known\":"; o += e.known ? "true" : "false";
                    o += ','; append_origin(o, e.origin); o += '}';
                }
                o += "]}";
            }
            o += ']';
        }
    };

    bool batched = ranges.size() > 1 || at_evs.size() > 1 || !resolved_lines.empty();
    uint64_t shown = 0;
    auto emit_state = [&](const MemoryState& state, uint64_t at_ev) {
        uint64_t range_base = state.range.base;
        uint64_t range_len = state.range.len;
        const auto& bytes = state.bytes;
        const auto& known = state.known;
        auto source = resolved_lines.find(at_ev);
        if (!options.json && source != resolved_lines.end())
            printf("source-line checkpoint %llu -> event %llu\n",
                   (unsigned long long)source->second, (unsigned long long)at_ev);
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
                        if (source != resolved_lines.end()) {
                            o += ','; emit::kv_u64(o, "at_line", source->second);
                        }
                        o += ',';
                    }
                    emit::kv_hex(o, "addr", range_base + i);
                    o += ",\"known\":";
                    o += word_known ? "true" : "false";
                    o += ",\"val\":";
                    if (word_known) emit::esc_append(o, emit::hex64(val).c_str());
                    else o += "null";
                    append_provenance(o, state, i, i + 8, at_ev, i == 0);
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
            if (options.provenance && !options.json) {
                std::string o = "{";
                emit::kv_u64(o, "at_ev", at_ev);
                append_provenance(o, state, 0, bytes.size(), at_ev);
                o += '}'; printf("%s\n", o.c_str());
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
            if (source != resolved_lines.end()) {
                o += ','; emit::kv_u64(o, "at_line", source->second);
            }
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
            o += ']';
            append_provenance(o, state, 0, bytes.size(), at_ev);
            o += "}}";
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
            if (options.provenance) {
                std::string o = "{";
                emit::kv_u64(o, "at_ev", at_ev);
                append_provenance(o, state, 0, bytes.size(), at_ev);
                o += '}'; printf("%s\n", o.c_str());
            }
        }
        shown++;
    };

    bool saw_event = false;
    uint64_t last_event = 0, last_source_line = 0;
    size_t next_at = 0;
    TraceScan ex(f);
    if (!ex.for_each([&](uint64_t gi, const Group& g) {
        if (gi > at_evs.back()) return false;
        saw_event = true;
        last_event = gi;
        last_source_line = MemoryReplay::last_line(g);
        replay.apply(gi, g, f, ex.regfile(), ex.reg_known());
        if (next_at < at_evs.size() && gi == at_evs[next_at]) {
            for (const auto& range : ranges) emit_state(replay.snapshot(range), gi);
            next_at++;
        }
        return true;
    })) return scan_error(gtb);
    if (!saw_event || next_at != at_evs.size()) {
        uint64_t missing = next_at < at_evs.size() ? at_evs[next_at] : 0;
        fprintf(stderr, "mem-state: --at-ev %llu is outside the trace\n",
                (unsigned long long)missing);
        if (saw_event)
            fprintf(stderr, "valid event indices: 0..%llu; source lines: 1..%llu. "
                            "For a physical log line use --at-line L\n",
                    (unsigned long long)last_event, (unsigned long long)last_source_line);
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
