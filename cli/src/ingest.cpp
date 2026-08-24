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
// "call jni func:" spelling while keeping the existing CALL2 event layout.
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
            if (!payload.empty()) stop_reason = payload[o++];
            uint64_t v;
            gv(v); events_seen = v;
            gv(v); events_recorded = v;
            gv(v); bytes_written = v;
            // initial_sp is a later addition: absent in older files, which is
            // why it is read defensively rather than assumed present
            if (gv(v)) initial_sp = v;
            if (o < payload.size()) dialect = payload[o++]; // absent = native
            footer_seen = true;
        }
    }
    fclose(f);
    if (meta_payload.empty()) return false;
    if (!SiteArena::deserialize(meta_payload.data(), meta_payload.size(), arena, modules))
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
            case EV_CALL2: n_call++; n_call2++; break;
            case EV_RET: n_ret++; break;
            case EV_SVC: n_svc++; break;
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
    // sp comes from the trace itself (recorded in the footer by the event
    // source), not from any assumption about who produced the file
    memset(regs_, 0, sizeof(regs_));
    regs_[31] = f_.initial_sp;
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
    auto flush_group = [&]() -> bool {
        if (!g.has_exec && !g.is_call && !g.is_svc && !g.is_ret && !g.has_verbatim)
            return true;
        if (f_.dialect & 1) {
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
        // callback sees PRE-execution register state (reads print before the
        // writes of this event are applied)
        bool go = cb(gi++, g);
        for (int i = 0; i < g.n_wr; i++)
            if (g.wr_id[i] >= 0 && g.wr_id[i] < 32) regs_[g.wr_id[i]] = g.wr_val[i];
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
        } else if (event.tag == EV_CALL || event.tag == EV_CALL2) {
            // a second call in one group would silently overwrite the first
            // (importer files can emit consecutive call lines with no EXEC
            // between them) — close the group instead
            if (g.is_call && !flush_group()) return false;
            g.is_call = true;
            g.n_call_args = event.tag == EV_CALL2 ? int(event.nargs) : -1;
            if (event.symbol_plus_one == 0) {
                g.call_target = event.target;
                g.call_name = nullptr;
            } else if (event.symbol_plus_one - 1 < f_.arena.strings().size()) {
                const std::string& name =
                    f_.arena.str(uint32_t(event.symbol_plus_one - 1));
                g.call_name = decoded_call_name(name, g.is_jni_call);
                g.call_target = 0;
            } else {
                // crash-truncated file: symbol interned after the surviving
                // META was written — degrade to a numeric target
                g.call_name = nullptr;
                g.call_target = 0;
            }
            for (uint8_t i = 0; i < event.nargs; i++) g.args[i] = event.args[i];
        } else if (event.tag == EV_RET) {
            g.is_ret = true;
            g.ret_val = event.value;
        } else if (event.tag == EV_SVC) {
            g.is_svc = true;
            g.svc_num = event.svc_num;
            for (int i = 0; i < 3; i++) g.svc_args[i] = event.args[i];
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
    const char* nl = (f_.dialect & 2) ? "\r\n" : "\n";
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
            int na = g.n_call_args >= 0 ? g.n_call_args : 4;
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

// value a memory access moved: a recorded value when the trace has one,
// otherwise the loaded register's write (loads) / the stored register's
// pre-event value (stores, first plan read that is not the base/index).
static uint64_t pair_mem_stride(const SiteArena& arena, const Site& s) {
    const char* dis = arena.pool_ptr() + s.disasm_off;
    size_t n = s.disasm_len;
    size_t mnemonic = 0;
    while (mnemonic < n && dis[mnemonic] != ' ') mnemonic++;
    bool ldp = mnemonic == 3 && !memcmp(dis, "ldp", 3);
    bool stp = mnemonic == 3 && !memcmp(dis, "stp", 3);
    bool ldpsw = mnemonic == 5 && !memcmp(dis, "ldpsw", 5);
    if (!ldp && !stp && !ldpsw) return 0;
    if (ldpsw) return 4;
    size_t operand = mnemonic;
    while (operand < n && dis[operand] == ' ') operand++;
    if (operand >= n) return 0;
    if (dis[operand] == 'w' || dis[operand] == 's') return 4;
    if (dis[operand] == 'q') return 16;
    return 8;
}

// Imported GumTrace text carries addresses but not access widths. Recover the
// width from the instruction spelling so mem-state does not turn `strb w7`
// into an eight-byte observation. Native events keep their recorded m.size.
static uint8_t disasm_mem_width(const SiteArena& arena, const Site& s) {
    const char* dis = arena.pool_ptr() + s.disasm_off;
    size_t n = s.disasm_len, mn = 0;
    while (mn < n && dis[mn] != ' ') mn++;
    auto starts = [&](const char* pfx) {
        size_t l = strlen(pfx);
        return mn >= l && memcmp(dis, pfx, l) == 0;
    };
    if (starts("ldrb") || starts("ldrsb") || starts("ldurb") ||
        starts("ldursb") || starts("ldtrb") || starts("ldtrsb") ||
        starts("ldarb") || starts("ldxrb") || starts("ldaxrb") ||
        starts("strb") || starts("sturb") || starts("sttrb") ||
        starts("stlrb") || starts("stxrb") || starts("stlxrb")) return 1;
    if (starts("ldrh") || starts("ldrsh") || starts("ldurh") ||
        starts("ldursh") || starts("ldtrh") || starts("ldtrsh") ||
        starts("ldarh") || starts("ldxrh") || starts("ldaxrh") ||
        starts("strh") || starts("sturh") || starts("sttrh") ||
        starts("stlrh") || starts("stxrh") || starts("stlxrh")) return 2;
    if (starts("ldrsw") || starts("ldursw") || starts("ldtrsw")) return 4;
    uint64_t pair = pair_mem_stride(arena, s);
    if (pair) return uint8_t(pair);
    size_t op = mn;
    while (op < n && dis[op] == ' ') op++;
    if (op >= n) return 0;
    switch (dis[op]) {
    case 'b': case 'B': return 1;
    case 'h': case 'H': return 2;
    case 'w': case 'W': case 's': case 'S': return 4;
    case 'x': case 'X': case 'd': case 'D': return 8;
    case 'q': case 'Q': return 16;
    default: return 0;
    }
}

static void agent_mems(const SiteArena& arena, const Site& s, const Group& g,
                       const uint64_t* regs,
                       std::vector<AgentMemVal>& out) {
    ObsMap om = obs_map(s, g);
    uint8_t inferred_size = disasm_mem_width(arena, s);
    unsigned __int128 pair_values[8];
    int n_pair_values = 0;
    int mem_idx = 0;
    for (uint8_t i = 0; i < s.n_ops && mem_idx < g.n_mem; i++) {
        const OpPlan& op = s.ops[i];
        if (op.kind != OP_MEM_R && op.kind != OP_MEM_W) continue;
        const MemOp& m = g.mem[mem_idx++];
        AgentMemVal mv{op.kind == OP_MEM_W, m.addr, 0, false,
                       m.size ? m.size : (inferred_size ? inferred_size : op.size)};
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
                if (r.ctx_idx >= 0 &&
                    (r.ctx_idx == op.base_ctx_idx || r.ctx_idx == op.index_ctx_idx))
                    continue;
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
        if (n_pair_values == 0) {
            n_pair_values = n_data_values;
            for (int j = 0; j < n_data_values; j++)
                pair_values[j] = data_values[j];
        }
        out.push_back(mv);
    }

    // Upstream GumTrace prints one mem token for ldp/stp. The two register
    // values still carry both lanes, so expose the second adjacent cell too.
    uint64_t stride = pair_mem_stride(arena, s);
    if (stride && out.size() == 1) {
        AgentMemVal second = out[0];
        second.addr += stride;
        second.size = uint8_t(stride);
        second.known = false;
        if (n_pair_values >= 2) {
            second.val = pair_values[1];
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
    else if (g.call_target) {
        snprintf(b, sizeof b, "0x%llx", (unsigned long long)g.call_target);
        line += b;
    } else line += "<unknown>";
    line += "(x0=0x";
    for (int i = 0; i < 4; i++) {
        snprintf(b, sizeof b, "%llx", (unsigned long long)g.args[i]);
        line += b;
        if (i < 3) {
            snprintf(b, sizeof b, ", x%d=0x", i + 1);
            line += b;
        }
    }
    line += ")\n";
}

static void agent_svc_text(std::string& line, const Group& g) {
    char b[40];
    const char* nm = svc_name(g.svc_num);
    if (nm) {
        line += std::string("+svc ") + nm + "(x0=0x";
        snprintf(b, sizeof b, "%llx", (unsigned long long)g.svc_args[0]);
        line += b;
        line += ", x1=0x";
        snprintf(b, sizeof b, "%llx", (unsigned long long)g.svc_args[1]);
        line += b;
        line += ", x2=0x";
        snprintf(b, sizeof b, "%llx", (unsigned long long)g.svc_args[2]);
        line += b;
        line += ")\n";
    } else {
        snprintf(b, sizeof b, "%llu", (unsigned long long)g.svc_num);
        line += std::string("+svc #") + b + "(x0=0x";
        snprintf(b, sizeof b, "%llx", (unsigned long long)g.svc_args[0]);
        line += b;
        line += ")\n";
    }
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
                else if (g.call_target) emit::kv_hex(line, "target", g.call_target);
                std::vector<std::string> args;
                for (int i = 0; i < 4; i++) args.push_back(emit::hex64(g.args[i]));
                line += ",\"args\":" + emit::str_array(args) + "}";
            } else {
                agent_call_text(line, g);
            }
        }
        if (g.is_svc) {
            if (json) {
                char b[48];
                snprintf(b, sizeof b, ",\"svc\":{\"num\":%llu", (unsigned long long)g.svc_num);
                line += b;
                const char* nm = svc_name(g.svc_num);
                if (nm) {
                    line += ',';
                    emit::kv_str(line, "nm", nm);
                }
                std::vector<std::string> args;
                for (int i = 0; i < 3; i++) args.push_back(emit::hex64(g.svc_args[i]));
                line += ",\"args\":" + emit::str_array(args) + "}";
            } else {
                agent_svc_text(line, g);
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
