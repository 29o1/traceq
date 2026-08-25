#include <traceq/ingest.h>
#include <traceq/varint.h>
#include "event_decoder.h"
#include "emit.h"
#include "gtb_format.h"
#include <cstring>
#include <cstdio>
#include <algorithm>

namespace gt {

using namespace format;

// Import-only string-pool marker used to retain the upstream
// "call jni func:" spelling without a separate event tag.
static constexpr char JNI_CALL_SYM_PREFIX[] = "\x1fJNI:";
static constexpr size_t JNI_CALL_SYM_PREFIX_LEN = sizeof(JNI_CALL_SYM_PREFIX) - 1;

static const char* decoded_call_name(const std::string& sym, bool& is_jni) {
    if (sym.size() >= JNI_CALL_SYM_PREFIX_LEN &&
        memcmp(sym.data(), JNI_CALL_SYM_PREFIX, JNI_CALL_SYM_PREFIX_LEN) == 0) {
        is_jni = true;
        return sym.c_str() + JNI_CALL_SYM_PREFIX_LEN;
    }
    is_jni = false;
    return sym.c_str();
}

bool GtbFile::load(const std::string& path, bool scan_stats) {
    FILE* f = fopen(path.c_str(), "rb");
    if (!f) return false;
    uint32_t hdr[2];
    if (fread(hdr, 4, 2, f) != 2 || hdr[0] != GTB_MAGIC) { fclose(f); return false; }

    // CH_EVENTS payloads occupy no more bytes than the file itself. Reserve
    // that upper bound once so repeated chunk appends do not briefly retain
    // both the old and newly grown event buffers on large traces.
    long chunk_start = ftell(f);
    if (chunk_start >= 0 && fseek(f, 0, SEEK_END) == 0) {
        long file_size = ftell(f);
        if (file_size > 0) events.reserve(size_t(file_size));
        if (fseek(f, chunk_start, SEEK_SET) != 0) {
            fclose(f);
            return false;
        }
    }

    std::vector<uint8_t> meta_payload;
    bool footer_seen = false;
    while (!footer_seen) {
        uint32_t ch[3]; // magic, type, len
        if (fread(ch, 4, 3, f) != 3) break;
        if (ch[0] != CHUNK_MAGIC) break;
        std::vector<uint8_t> payload(ch[2]);
        if (!payload.empty() && fread(payload.data(), 1, payload.size(), f) != payload.size())
            break;
        if (ch[1] == CH_META) {
            meta_payload = std::move(payload);
        } else if (ch[1] == CH_EVENTS) {
            events.insert(events.end(), payload.begin(), payload.end());
        } else if (ch[1] == CH_FOOTER) {
            size_t o = 0;
            auto gv = [&](uint64_t& v) {
                size_t n = get_uvar(payload.data() + o, payload.size() - o, v);
                if (n) o += n;
                return n != 0;
            };
            if (payload.empty()) break;
            stop_reason = payload[o++];
            uint64_t v;
            if (!gv(v)) break;
            events_seen = v;
            if (!gv(v)) break;
            events_recorded = v;
            if (!gv(v)) break;
            bytes_written = v;
            if (o >= payload.size()) break;
            crlf = payload[o++] != 0;
            footer_seen = true;
        }
    }
    fclose(f);
    if (meta_payload.empty()) return false;
    if (!footer_seen ||
        !SiteArena::deserialize(meta_payload.data(), meta_payload.size(), arena))
        return false;

    if (!scan_stats) return true;

    EventCursor cursor(events);
    RawEvent batch[64];
    size_t count;
    while ((count = cursor.next_batch(batch, 64)) != 0) {
        for (size_t i = 0; i < count; i++) {
            switch (batch[i].tag) {
            case EV_EXEC: n_exec++; break;
            case EV_REGW: n_regw++; break;
            case EV_MEM:
            case EV_MEMW_NV: n_mem++; break;
            case EV_CALL: n_call++; break;
            case EV_RET: n_ret++; break;
            case EV_RDVAL: n_rdval++; break;
            case EV_SIMDV: n_simdv++; break;
            case EV_VERBATIM: n_verbatim++; break;
            default: break;
            }
        }
    }
    return true;
}

bool Expander::for_each(const std::function<bool(uint64_t, const Group&)>& cb) {
    memset(regs_, 0, sizeof(regs_));
    memset(known_, 0, sizeof(known_));
    Group g;
    uint64_t gi = 0;
    uint64_t next_source_line = 1;
    auto add_obs = [&](Group::Obs* arr, int& cnt, uint32_t name_id,
                       unsigned __int128 val) {
        if (cnt >= Group::MAX_OBS) return;
        arr[cnt].name_id = name_id;
        arr[cnt].val = val;
        cnt++;
    };
    auto apply_observed_regs = [&](const Group::Obs* arr, int cnt) {
        for (int i = 0; i < cnt; i++) {
            if (arr[i].name_id >= f_.arena.strings().size() ||
                arr[i].val > UINT64_MAX)
                continue;
            const std::string& name = f_.arena.str(arr[i].name_id);
            int simd = -1;
            int ctx = text_name_ctx(name.data(), name.size(), &simd);
            if (ctx < 0 || ctx >= 32) continue;
            uint64_t value = uint64_t(arr[i].val);
            if (!name.empty() && name[0] == 'w') value &= 0xffffffffu;
            regs_[ctx] = value;
            known_[ctx] = 1;
        }
    };
    auto flush_group = [&]() -> bool {
        if (!g.has_exec && !g.is_call && !g.is_ret && !g.has_verbatim)
            return true;
        {
            if (g.has_verbatim) {
                g.source_line = next_source_line;
                uint64_t lines = 0;
                const char* vp = g.verbatim;
                for (uint32_t i = 0; i < g.verbatim_len; i++)
                    if (vp[i] == '\n') lines++;
                if (g.verbatim_len && vp[g.verbatim_len - 1] != '\n') lines++;
                next_source_line += lines;
            } else {
                if (g.has_exec) g.source_line = next_source_line++;
                if (g.is_call) g.call_source_line = next_source_line++;
                if (g.is_ret) g.ret_source_line = next_source_line++;
            }
        }
        // Imported read observations are authoritative PRE-execution values.
        // Fold them into the reconstructed state before exposing the group.
        apply_observed_regs(g.obs, g.n_obs);
        // callback sees PRE-execution register state (reads print before the
        // writes of this event are applied)
        bool go = cb(gi++, g);
        if (g.has_exec && g.site_id < f_.arena.sites().size()) {
            const Site& site = f_.arena.get(g.site_id);
            for (uint8_t i = 0; i < site.n_ops; i++)
                if (site.ops[i].kind == OP_REG_W && site.ops[i].ctx_idx >= 0)
                    known_[site.ops[i].ctx_idx & 31] = 0;
        }
        for (int i = 0; i < g.n_wr; i++) {
            if (g.wr_id[i] < 0 || g.wr_id[i] >= 32) continue;
            regs_[g.wr_id[i]] = g.wr_val[i];
            known_[g.wr_id[i]] = 1;
        }
        apply_observed_regs(g.wobs, g.n_wobs);
        g = Group();
        return go;
    };

    auto consume_event = [&](const RawEvent& event) -> bool {
        if (event.tag == EV_EXEC) {
            // EXEC terminates the previous group
            if (!flush_group()) return false;
            g.has_exec = true;
            g.site_id = event.site_id;
        } else if (event.tag == EV_REGW) {
            if (g.n_wr < 8) {
                g.wr_id[g.n_wr] = event.reg;
                g.wr_val[g.n_wr] = event.value;
                g.n_wr++;
            }
        } else if (event.tag == EV_MEM || event.tag == EV_MEMW_NV) {
            if (g.n_mem < 2) {
                MemOp m{event.is_write, event.addr, event.size,
                        event.value_known ? event.value : 0,
                        event.value_known};
                g.mem[g.n_mem++] = m;
            }
        } else if (event.tag == EV_CALL) {
            // a second call in one group would silently overwrite the first
            // (importer files can emit consecutive call lines with no EXEC
            // between them) — close the group instead
            if (g.is_call && !flush_group()) return false;
            g.is_call = true;
            g.n_call_args = event.nargs;
            if (event.symbol_id < f_.arena.strings().size()) {
                const std::string& name = f_.arena.str(event.symbol_id);
                g.call_name = decoded_call_name(name, g.is_jni_call);
            } else {
                return false;
            }
            for (uint8_t i = 0; i < event.nargs; i++) g.args[i] = event.args[i];
        } else if (event.tag == EV_RET) {
            g.is_ret = true;
            g.ret_val = event.value;
        } else if (event.tag == EV_RDVAL || event.tag == EV_SIMDV) {
            // observed value token (importer files): RDVAL extends the read
            // list, SIMDV extends the "-> " write list
            if (event.tag == EV_RDVAL)
                add_obs(g.obs, g.n_obs, event.name_id, event.observed);
            else
                add_obs(g.wobs, g.n_wobs, event.name_id, event.observed);
        } else if (event.tag == EV_VERBATIM) {
            // verbatim is ALWAYS its own group: the upstream renderer replays
            // only the raw body for such groups, so letting it ride an open
            // exec group would drop that group's line
            if (!flush_group()) return false;
            g.has_verbatim = true;
            g.verbatim = reinterpret_cast<const char*>(event.verbatim);
            g.verbatim_len = event.verbatim_len;
            if (!flush_group()) return false;
        }
        return true;
    };

    EventCursor cursor(f_.events);
    RawEvent batch[64];
    size_t count;
    while ((count = cursor.next_batch(batch, 64)) != 0) {
        for (size_t i = 0; i < count; i++)
            if (!consume_event(batch[i])) return true;
    }
    flush_group();
    return true;
}

// ---------------------------------------------------------------------------
// register name table for the expansion engines
// ---------------------------------------------------------------------------
const char* agent_reg_name(int ctx_idx) {
    static const char* names[32] = {
        "x0","x1","x2","x3","x4","x5","x6","x7","x8","x9","x10","x11","x12","x13","x14","x15",
        "x16","x17","x18","x19","x20","x21","x22","x23","x24","x25","x26","x27","x28","x29","x30","sp"};
    return names[ctx_idx & 31];
}

static int call_arg_count(const Group& g) {
    return g.n_call_args;
}

// plan reads (pre-event values) and writes (matched against the group's
// write records), in plan order. SIMD reads have no value lane and are
// skipped.
//
// Imported groups carry the upstream-observed token values: obs = read tokens
// (incl. mem tokens) in plan order, wobs = "-> " write tokens. When the counts
// pair up exactly, those are the true values — register reconstruction cannot
// know a register nobody wrote yet (imported logs have no initial context).
// Native groups have no observations and always reconstruct.
struct ObsMap {
    bool use_obs, use_wobs;
    int obs_at[8], wobs_at[8]; // plan op index -> obs/wobs slot, -1 = none
};
static ObsMap obs_map(const Site& s, const Group& g) {
    ObsMap m{};
    int n_rd = 0, n_wr = 0, k = 0, kw = 0;
    for (uint8_t i = 0; i < s.n_ops; i++) {
        uint8_t kd = s.ops[i].kind;
        bool rd_kind = kd == OP_REG_R || kd == OP_MEM_R || kd == OP_MEM_W;
        if (rd_kind) n_rd++;
        else if (kd == OP_REG_W) n_wr++;
        m.obs_at[i] = rd_kind ? k++ : -1;
        m.wobs_at[i] = kd == OP_REG_W ? kw++ : -1;
    }
    m.use_obs = n_rd > 0 && g.n_obs == n_rd;
    m.use_wobs = n_wr > 0 && g.n_wobs == n_wr;
    return m;
}

// ---------------------------------------------------------------------------
// Upstream-dialect text expansion (gt import round-trip). Every value here is
// an observed token, not a reconstruction: names print in their original
// spelling from the arena string pool and hex values re-render through
// legacy_hex64/128 exactly as upstream trimmed them.
//
// Newline model (matches the observed upstream printer): each instruction
// line ends with its own line ending; the "-> " write tail prints on the same
// line before it. The merged-line quirk (a writeless pure store swallowing
// the newline, seen in other upstream logs) is not representable — the
// importer sends such physical lines to VERBATIM instead, so bytes still
// round-trip and the quirk never reaches this renderer.
// ---------------------------------------------------------------------------
uint64_t Expander::expand_upstream(FILE* out, uint64_t from_idx, uint64_t to_idx,
                                   uint64_t max_lines, uint64_t* stop_gi) {
    if (stop_gi) *stop_gi = UINT64_MAX;
    const SiteArena& A = f_.arena;
    const char* pool = A.pool_ptr();
    const char* nl = f_.crlf ? "\r\n" : "\n";
    std::string line;
    uint64_t lines = 0;

    auto emit_obs = [&](const Group::Obs* arr, int cnt) {
        char tmp[40];
        for (int i = 0; i < cnt; i++) {
            line += A.str(arr[i].name_id);
            line += "=0x";
            size_t n = legacy_hex128(tmp, arr[i].val);
            line.append(tmp, n);
            line += ' ';
        }
    };

    for_each([&](uint64_t gi, const Group& g) -> bool {
        if (gi < from_idx || gi > to_idx) return true;
        if (max_lines && lines >= max_lines) {
            if (stop_gi) *stop_gi = gi;
            return false;
        }
        line.clear();
        if (g.has_verbatim) {
            line.append(g.verbatim, g.verbatim_len);
            fwrite(line.data(), 1, line.size(), out);
            lines++;
            return true; // verbatim is always its own group
        }
        if (g.has_exec) {
            const Site& s = A.get(g.site_id);
            line.append(pool + s.prefix_off, s.prefix_len);
        }
        emit_obs(g.obs, g.n_obs);
        if (g.n_wobs > 0) {
            line += "-> ";
            emit_obs(g.wobs, g.n_wobs);
        }
        if (g.has_exec) {
            line += nl;
            fwrite(line.data(), 1, line.size(), out);
            lines++;
        }
        if (g.is_call) {
            line.clear();
            line += g.is_jni_call ? "call jni func: " : "call func: ";
            line += g.call_name ? g.call_name : "<unknown>";
            line += '(';
            int na = call_arg_count(g);
            for (int i = 0; i < na; i++) {
                if (i) line += ", ";
                line += "0x";
                char tmp[24];
                size_t n = legacy_hex64(tmp, g.args[i]);
                line.append(tmp, n);
            }
            line += ')';
            line += nl;
            fwrite(line.data(), 1, line.size(), out);
            lines++;
        }
        if (g.is_ret) {
            line.clear();
            line += "ret: 0x";
            char tmp[24];
            size_t n = legacy_hex64(tmp, g.ret_val);
            line.append(tmp, n);
            line += nl;
            fwrite(line.data(), 1, line.size(), out);
            lines++;
        }
        return true;
    });
    return lines;
}

// ---------------------------------------------------------------------------
// Agent-facing expansions (compact text / JSON Lines)
//
// Same group reconstruction as expand_upstream, but token-lean: modules ride
// "== name ==" header lines instead of per-event prefixes, addresses are
// module-relative (!0xoffset), there is no column padding, and JSON Lines
// carry u64 values as hex strings.
// ---------------------------------------------------------------------------
static void agent_regs(const Site& s, const Group& g, const uint64_t* regs,
                       std::vector<AgentRegVal>& rd, std::vector<AgentRegVal>& wr) {
    auto push_unique = [](std::vector<AgentRegVal>& values, int ctx, uint64_t val) {
        for (const auto& item : values)
            if (item.ctx == ctx) return;
        values.push_back({ctx, val});
    };
    ObsMap m = obs_map(s, g);
    for (uint8_t i = 0; i < s.n_ops; i++) {
        const OpPlan& op = s.ops[i];
        if (op.kind == OP_REG_R && op.ctx_idx >= 0)
            push_unique(rd, op.ctx_idx,
                        m.use_obs ? uint64_t(g.obs[m.obs_at[i]].val)
                                  : op.ctx_idx == 31 ? regs[31]
                                                     : regs[op.ctx_idx & 31]);
        else if (op.kind == OP_REG_W && op.ctx_idx >= 0) {
            if (m.use_wobs) {
                push_unique(wr, op.ctx_idx,
                            uint64_t(g.wobs[m.wobs_at[i]].val));
                continue;
            }
            for (int k = 0; k < g.n_wr; k++)
                if (g.wr_id[k] == op.ctx_idx) {
                    push_unique(wr, op.ctx_idx, g.wr_val[k]);
                    break;
                }
        }
    }
}

static unsigned __int128 mask_mem_value(unsigned __int128 value, uint8_t size) {
    if (size == 0 || size >= 16) return value;
    unsigned bits = unsigned(size) * 8;
    return value & ((static_cast<unsigned __int128>(1) << bits) - 1);
}

static void agent_mems(const SiteArena& arena, const Site& s, const Group& g,
                       const uint64_t* regs,
                       std::vector<AgentMemVal>& out) {
    ObsMap om = obs_map(s, g);
    uint8_t inferred_size = s.mem_width;
    unsigned __int128 pair_values[8];
    int n_pair_values = 0;
    int mem_idx = 0;
    for (uint8_t i = 0; i < s.n_ops && mem_idx < g.n_mem; i++) {
        const OpPlan& op = s.ops[i];
        if (op.kind != OP_MEM_R && op.kind != OP_MEM_W) continue;
        const MemOp& m = g.mem[mem_idx++];
        uint8_t size = m.size ? m.size : (inferred_size ? inferred_size : 8);
        AgentMemVal mv{op.kind == OP_MEM_W, m.addr, 0, false, size};
        if (m.value_known) {
            mv.val = m.value;
            mv.known = true;
        }

        unsigned __int128 data_values[8];
        int n_data_values = 0;
        auto add_data_value = [&](unsigned __int128 value) {
            if (n_data_values < 8) data_values[n_data_values++] = value;
        };
        if (op.kind == OP_MEM_W) {
            for (uint8_t j = 0; j < s.n_ops; j++) {
                const OpPlan& r = s.ops[j];
                if (r.kind != OP_REG_R) continue;
                if (om.use_obs && om.obs_at[j] >= 0)
                    add_data_value(g.obs[om.obs_at[j]].val);
                else if (r.ctx_idx >= 0)
                    add_data_value(r.ctx_idx == 31 ? regs[31]
                                                    : regs[r.ctx_idx & 31]);
            }
        } else {
            for (uint8_t j = 0; j < s.n_ops; j++) {
                const OpPlan& w = s.ops[j];
                if (w.kind != OP_REG_W) continue;
                if (om.use_wobs && om.wobs_at[j] >= 0) {
                    add_data_value(g.wobs[om.wobs_at[j]].val);
                    continue;
                }
                for (int k = 0; k < g.n_wr; k++)
                    if (w.ctx_idx >= 0 && g.wr_id[k] == w.ctx_idx) {
                        add_data_value(g.wr_val[k]);
                        break;
                    }
            }
        }
        if (!mv.known && n_data_values > 0) {
            mv.val = data_values[0];
            mv.known = true;
        }
        if (mv.known) mv.val = mask_mem_value(mv.val, mv.size);
        if (n_pair_values == 0) {
            n_pair_values = n_data_values;
            for (int j = 0; j < n_data_values; j++)
                pair_values[j] = data_values[j];
        }
        out.push_back(mv);
    }

    // Upstream GumTrace prints one mem token for ldp/stp. The two register
    // values still carry both lanes, so expose the second adjacent cell too.
    uint64_t stride = s.pair_stride;
    if (stride && out.size() == 1) {
        AgentMemVal second = out[0];
        second.addr += stride;
        second.size = uint8_t(stride);
        second.known = false;
        if (n_pair_values >= 2) {
            second.val = mask_mem_value(pair_values[1], second.size);
            second.known = true;
        }
        out.push_back(second);
    }
}

void reconstruct_agent_registers(const Site& site, const Group& group,
                                 const uint64_t* regs,
                                 std::vector<AgentRegVal>& reads,
                                 std::vector<AgentRegVal>& writes) {
    agent_regs(site, group, regs, reads, writes);
}

void reconstruct_agent_memory(const SiteArena& arena, const Site& site,
                              const Group& group, const uint64_t* regs,
                              std::vector<AgentMemVal>& mems) {
    agent_mems(arena, site, group, regs, mems);
}

void reconstruct_agent_values(const SiteArena& arena, const Site& site,
                              const Group& group, const uint64_t* regs,
                              std::vector<AgentRegVal>& reads,
                              std::vector<AgentRegVal>& writes,
                              std::vector<AgentMemVal>& mems) {
    reconstruct_agent_registers(site, group, regs, reads, writes);
    reconstruct_agent_memory(arena, site, group, regs, mems);
}

static void agent_call_text(std::string& line, const Group& g) {
    char b[40];
    line += "+call ";
    if (g.call_name) line += g.call_name;
    else line += "<unknown>";
    line += '(';
    int na = call_arg_count(g);
    for (int i = 0; i < na; i++) {
        if (i) line += ", ";
        snprintf(b, sizeof b, "x%d=0x%llx", i,
                 (unsigned long long)g.args[i]);
        line += b;
    }
    line += ")\n";
}

static uint64_t expand_agent(const GtbFile& f, Expander& ex, FILE* out, bool json,
                             uint64_t from_idx, uint64_t to_idx, uint64_t max_lines,
                             uint64_t* stop_gi, uint64_t* total_selected) {
    if (stop_gi) *stop_gi = UINT64_MAX;
    if (total_selected) *total_selected = 0;
    const SiteArena& A = f.arena;
    uint64_t lines = 0, selected = 0;
    uint32_t cur_mod = 0xFFFFFFFFu;
    std::string line;
    std::vector<AgentRegVal> rd, wr;
    std::vector<AgentMemVal> mems;
    rd.reserve(8);
    wr.reserve(8);
    mems.reserve(2);
    auto count_line = [&]() {
        size_t nl = std::count(line.begin(), line.end(), '\n');
        lines += nl;
    };
    ex.for_each([&](uint64_t gi, const Group& g) -> bool {
        if (gi < from_idx) return true;
        if (gi > to_idx) return false;
        selected++;
        if (max_lines && lines >= max_lines) {
            if (stop_gi && *stop_gi == UINT64_MAX) *stop_gi = gi;
            // JSON needs an exact meta.total. Keep decoding the same pass but
            // stop formatting rows once the output limit is reached.
            return json && total_selected;
        }
        line.clear();
        if (json && !g.has_exec) {
            char b[64];
            snprintf(b, sizeof b, "{\"ev\":%llu", (unsigned long long)gi);
            line += b;
            if (g.has_verbatim) line += ",\"verbatim\":true";
        }
        const uint64_t* regs = ex.regfile();
        if (g.has_exec) {
            const Site& s = A.get(g.site_id);
            uint32_t mod_id = s.module_id < A.modules().size() ? s.module_id : 0;
            if (!json && mod_id != cur_mod) {
                cur_mod = mod_id;
                line += "== " + (A.modules().empty() ? std::string("?") : A.modules()[mod_id]) +
                        " ==\n";
            }
            uint64_t off = s.addr - A.module_base(mod_id);
            std::string txt(A.pool_ptr() + s.disasm_off, s.disasm_len);
            rd.clear();
            wr.clear();
            mems.clear();
            reconstruct_agent_values(A, s, g, regs, rd, wr, mems);
            if (json) {
                char b[64];
                snprintf(b, sizeof b, "{\"ev\":%llu", (unsigned long long)gi);
                line += b;
                if (g.source_line) {
                    line += ',';
                    emit::kv_u64(line, "line", g.source_line);
                }
                line += ',';
                emit::kv_str(line, "mod",
                             A.modules().empty() ? "?" : A.modules()[mod_id]);
                line += ',';
                emit::kv_hex(line, "off", off);
                line += ',';
                emit::kv_str(line, "txt", txt);
                // rd/wr: [["x1","0x5000"], ...]
                line += ",\"rd\":[";
                for (size_t i = 0; i < rd.size(); i++) {
                    if (i) line += ',';
                    char rb[96];
                    snprintf(rb, sizeof rb, "[\"%s\",\"0x%llx\"]",
                             agent_reg_name(rd[i].ctx), (unsigned long long)rd[i].val);
                    line += rb;
                }
                line += "],\"wr\":[";
                for (size_t i = 0; i < wr.size(); i++) {
                    if (i) line += ',';
                    char rb[96];
                    snprintf(rb, sizeof rb, "[\"%s\",\"0x%llx\"]",
                             agent_reg_name(wr[i].ctx), (unsigned long long)wr[i].val);
                    line += rb;
                }
                line += "]";
                if (!mems.empty()) {
                    line += ",\"mem\":[";
                    for (size_t i = 0; i < mems.size(); i++) {
                        if (i) line += ',';
                        line += "{\"w\":";
                        line += mems[i].is_w ? '1' : '0';
                        line += ",\"addr\":\"" + emit::hex64(mems[i].addr) + '"';
                        line += ",\"size\":" + std::to_string(mems[i].size);
                        if (mems[i].known)
                            line += ",\"val\":\"" + emit::hex128(mems[i].val) + '"';
                        line += '}';
                    }
                    line += ']';
                }
            } else {
                char b[64];
                if (g.source_line)
                    snprintf(b, sizeof b, "%llu line=%llu !0x%llx ",
                             (unsigned long long)gi,
                             (unsigned long long)g.source_line,
                             (unsigned long long)off);
                else
                    snprintf(b, sizeof b, "%llu !0x%llx ",
                             (unsigned long long)gi, (unsigned long long)off);
                line += b;
                line += txt;
                if (!rd.empty() || !wr.empty()) {
                    line += "; ";
                    for (size_t i = 0; i < rd.size(); i++) {
                        if (i) line += ' ';
                        snprintf(b, sizeof b, "%s=0x%llx", agent_reg_name(rd[i].ctx),
                                 (unsigned long long)rd[i].val);
                        line += b;
                    }
                    if (!rd.empty() && !wr.empty()) line += " -> ";
                    else if (!wr.empty()) line += "-> ";
                    for (size_t i = 0; i < wr.size(); i++) {
                        if (i) line += ' ';
                        snprintf(b, sizeof b, "%s=0x%llx", agent_reg_name(wr[i].ctx),
                                 (unsigned long long)wr[i].val);
                        line += b;
                    }
                }
                if (!mems.empty()) {
                    line += "; ";
                    for (size_t i = 0; i < mems.size(); i++) {
                        if (i) line += ' ';
                        snprintf(b, sizeof b, "%s=0x%llx", mems[i].is_w ? "mem_w" : "mem_r",
                                 (unsigned long long)mems[i].addr);
                        line += b;
                        if (mems[i].known) {
                            line += ':';
                            line += emit::hex128(mems[i].val);
                        }
                    }
                }
                line += "\n";
            }
        }
        // call/svc/ret ride their own compact lines / JSON fields
        if (g.is_call) {
            if (json) {
                line += ",\"call\":{";
                if (g.call_name) emit::kv_str(line, "sym", g.call_name);
                std::vector<std::string> args;
                int na = call_arg_count(g);
                args.reserve(size_t(na));
                for (int i = 0; i < na; i++) args.push_back(emit::hex64(g.args[i]));
                line += ",\"args\":" + emit::str_array(args) + "}";
            } else {
                agent_call_text(line, g);
            }
        }
        if (g.is_ret) {
            if (json) {
                line += ',';
                emit::kv_hex(line, "ret", g.ret_val);
            } else {
                char b[32];
                snprintf(b, sizeof b, "+ret x0=0x%llx\n", (unsigned long long)g.ret_val);
                line += b;
            }
        }
        if (json && !line.empty()) line += "}\n";
        if (!line.empty()) {
            fwrite(line.data(), 1, line.size(), out);
            count_line();
        }
        return true;
    });
    if (total_selected) *total_selected = selected;
    return lines;
}

uint64_t Expander::expand_compact(FILE* out, uint64_t from_idx, uint64_t to_idx,
                                  uint64_t max_lines, uint64_t* stop_gi) {
    return expand_agent(f_, *this, out, false, from_idx, to_idx, max_lines,
                        stop_gi, nullptr);
}

uint64_t Expander::expand_jsonl(FILE* out, uint64_t from_idx, uint64_t to_idx,
                                uint64_t max_lines, uint64_t* stop_gi,
                                uint64_t* total_selected) {
    return expand_agent(f_, *this, out, true, from_idx, to_idx, max_lines,
                        stop_gi, total_selected);
}

} // namespace gt
