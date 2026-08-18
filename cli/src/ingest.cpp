#include <traceq/ingest.h>
#include <traceq/varint.h>
#include "emit.h"
#include <cstring>
#include <cstdio>
#include <algorithm>
#include <unordered_map>

namespace gt {

static constexpr uint32_t CHUNK_MAGIC = 0x47544348u;
static constexpr uint32_t GTB_MAGIC   = 0x47544231u;

// event tags (mirror recorder.cpp; importer tags 8..11 replay in for_each)
enum : uint8_t {
    T_EXEC = 1, T_REGW = 2, T_MEM = 3, T_CALL = 4, T_RET = 5, T_SVC = 6,
    T_MEMW_NV = 7, T_RDVAL = 8, T_SIMDV = 9, T_VERBATIM = 10, T_CALL2 = 11,
};

bool GtbFile::load(const std::string& path) {
    FILE* f = fopen(path.c_str(), "rb");
    if (!f) return false;
    uint32_t hdr[2];
    if (fread(hdr, 4, 2, f) != 2 || hdr[0] != GTB_MAGIC) { fclose(f); return false; }

    std::vector<uint8_t> meta_payload;
    bool footer_seen = false;
    while (!footer_seen) {
        uint32_t ch[3]; // magic, type, len
        if (fread(ch, 4, 3, f) != 3) break;
        if (ch[0] != CHUNK_MAGIC) break;
        std::vector<uint8_t> payload(ch[2]);
        if (!payload.empty() && fread(payload.data(), 1, payload.size(), f) != payload.size())
            break;
        if (ch[1] == 1) { // META
            meta_payload = std::move(payload);
        } else if (ch[1] == 2) { // EVENTS
            events.insert(events.end(), payload.begin(), payload.end());
        } else if (ch[1] == 3) { // FOOTER
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

    // decode event stream once for stats + group streaming support
    const uint8_t* p = events.data();
    size_t len = events.size(), o = 0;
    uint64_t last_reg[32] = {0}, last_addr = 0, last_mv[2] = {0};
    uint64_t last_arg[8] = {0}, last_ret = 0;
    std::unordered_map<uint32_t, uint64_t> last_obs;
    while (o < len) {
        uint8_t tag = p[o++];
        if (tag == 1) { // EXEC (site id delta carries no stats of its own)
            int64_t d;
            size_t n = get_var(p + o, len - o, d);
            if (!n) break;
            o += n;
            (void)d;
            n_exec++;
        } else if (tag == 2 || (tag & 0x80)) { // REGW (extended or inline)
            if (tag & 0x80) {
                uint8_t reg = (tag >> 3) & 15;
                uint8_t code = tag & 7;
                int64_t d = code == 7 ? 0 : zigzag_dec(code); // 7 never emitted
                last_reg[reg & 31] = uint64_t(int64_t(last_reg[reg & 31]) + d);
                n_regw++;
            } else {
                if (o >= len) break;
                uint8_t reg = p[o++];
                int64_t d;
                size_t n = get_var(p + o, len - o, d);
                if (!n) break;
                o += n;
                last_reg[reg & 31] = uint64_t(int64_t(last_reg[reg & 31]) + d);
                n_regw++;
            }
        } else if (tag == 3 || tag == 7) { // MEM (with value / store-no-value)
            if (o >= len) break;
            uint8_t fl = p[o++];
            // both encoders set flags bit0 = is_write (the hot path's MEMW_NV
            // is write-only and always has it set; the importer's tag-7 mem
            // events carry real reads with bit0 clear)
            bool is_w = (fl & 1);
            int64_t ad, vd = 0;
            size_t n = get_var(p + o, len - o, ad);
            if (!n) break;
            o += n;
            if (tag == 3) {
                n = get_var(p + o, len - o, vd);
                if (!n) break;
                o += n;
                last_mv[is_w ? 1 : 0] = uint64_t(int64_t(last_mv[is_w ? 1 : 0]) + vd);
            }
            last_addr = uint64_t(int64_t(last_addr) + ad);
            n_mem++;
        } else if (tag == 4) { // CALL
            uint64_t sym;
            size_t n = get_uvar(p + o, len - o, sym);
            if (!n) break;
            o += n;
            if (sym == 0) {
                int64_t a;
                n = get_var(p + o, len - o, a);
                if (!n) break;
                o += n;
            }
            for (int i = 0; i < 4; i++) {
                int64_t d;
                n = get_var(p + o, len - o, d);
                if (!n) break;
                o += n;
                last_arg[i] = uint64_t(int64_t(last_arg[i]) + d);
            }
            n_call++;
        } else if (tag == 5) { // RET
            int64_t d;
            size_t n = get_var(p + o, len - o, d);
            if (!n) break;
            o += n;
            last_ret = uint64_t(int64_t(last_ret) + d);
            n_ret++;
        } else if (tag == 6) { // SVC
            uint64_t num;
            size_t n = get_uvar(p + o, len - o, num);
            if (!n) break;
            o += n;
            for (int i = 0; i < 3; i++) {
                int64_t d;
                n = get_var(p + o, len - o, d);
                if (!n) break;
                o += n;
                last_arg[4 + i] = uint64_t(int64_t(last_arg[4 + i]) + d);
            }
            n_svc++;
        } else if (tag == 8 || tag == 9) { // RDVAL / SIMDV (importer only)
            uint64_t name;
            size_t n = get_uvar(p + o, len - o, name);
            if (!n) break;
            o += n;
            if (o >= len) break;
            uint8_t kind = p[o++];
            if (kind == 0) {
                int64_t d;
                n = get_var(p + o, len - o, d);
                if (!n) break;
                o += n;
                last_obs[uint32_t(name)] =
                    uint64_t(int64_t(last_obs[uint32_t(name)]) + d);
            } else if (kind == 1) {
                if (o + 16 > len) break;
                o += 16;
            } else break; // corrupt
            if (tag == 8) n_rdval++; else n_simdv++;
        } else if (tag == 10) { // VERBATIM
            uint64_t vl;
            size_t n = get_uvar(p + o, len - o, vl);
            if (!n || o + n + vl > len) break;
            o += n + vl;
            n_verbatim++;
        } else if (tag == 11) { // CALL2 (importer only)
            uint64_t sym;
            size_t n = get_uvar(p + o, len - o, sym);
            if (!n) break;
            o += n;
            if (o >= len) break;
            uint8_t na = p[o++];
            if (na > 8) break;
            for (int i = 0; i < na; i++) {
                int64_t d;
                n = get_var(p + o, len - o, d);
                if (!n) break;
                o += n;
                last_arg[i] = uint64_t(int64_t(last_arg[i]) + d);
            }
            n_call++; n_call2++;
        } else {
            break; // corrupt
        }
    }
    return true;
}

bool Expander::for_each(const std::function<bool(uint64_t, const Group&)>& cb) {
    // sp comes from the trace itself (recorded in the footer by the event
    // source), not from any assumption about who produced the file
    regs_[31] = f_.initial_sp;
    const uint8_t* p = f_.events.data();
    size_t len = f_.events.size(), o = 0;
    std::string& verbatim = f_.verbatim;
    Group g;
    uint64_t gi = 0;
    std::unordered_map<uint32_t, uint64_t> last_obs;
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
        // callback sees PRE-execution register state (reads print before the
        // writes of this event are applied)
        bool go = cb(gi++, g);
        for (int i = 0; i < g.n_wr; i++)
            if (g.wr_id[i] >= 0 && g.wr_id[i] < 32) regs_[g.wr_id[i]] = g.wr_val[i];
        g = Group();
        return go;
    };
    int64_t last_site = 0;
    uint64_t last_reg[32] = {0}, last_addr = 0, last_mv[2] = {0};
    uint64_t last_arg[8] = {0}, last_ret = 0;
    while (o < len) {
        uint8_t tag = p[o++];
        if (tag == 1) {
            // EXEC terminates the previous group
            if (!flush_group()) return true;
            int64_t d;
            size_t n = get_var(p + o, len - o, d);
            if (!n) break;
            o += n;
            last_site += d;
            g.has_exec = true;
            g.site_id = uint32_t(last_site);
        } else if (tag == 2 || (tag & 0x80)) {
            if (tag & 0x80) {
                uint8_t reg = (tag >> 3) & 15;
                uint8_t code = tag & 7;
                int64_t d = code == 7 ? 0 : zigzag_dec(code);
                last_reg[reg & 31] = uint64_t(int64_t(last_reg[reg & 31]) + d);
                if (g.n_wr < 8) {
                    g.wr_id[g.n_wr] = reg;
                    g.wr_val[g.n_wr] = last_reg[reg & 31];
                    g.n_wr++;
                }
            } else {
                uint8_t reg = p[o++];
                int64_t d;
                size_t n = get_var(p + o, len - o, d);
                if (!n) break;
                o += n;
                last_reg[reg & 31] = uint64_t(int64_t(last_reg[reg & 31]) + d);
                if (g.n_wr < 8) {
                    g.wr_id[g.n_wr] = reg;
                    g.wr_val[g.n_wr] = last_reg[reg & 31];
                    g.n_wr++;
                }
            }
        } else if (tag == 3 || tag == 7) {
            uint8_t fl = p[o++];
            bool is_w = (fl & 1); // flags bit0 = is_write in both encoders
            uint8_t size = uint8_t(fl >> 1);
            int64_t ad, vd = 0;
            size_t n = get_var(p + o, len - o, ad);
            if (!n) break;
            o += n;
            if (tag == 3) {
                n = get_var(p + o, len - o, vd);
                if (!n) break;
                o += n;
                last_mv[is_w ? 1 : 0] = uint64_t(int64_t(last_mv[is_w ? 1 : 0]) + vd);
            }
            last_addr = uint64_t(int64_t(last_addr) + ad);
            if (g.n_mem < 2) {
                MemOp m{is_w, last_addr, size,
                        tag == 3 ? last_mv[is_w ? 1 : 0] : 0,
                        tag == 3};
                g.mem[g.n_mem++] = m;
            }
        } else if (tag == 4) {
            // a second call in one group would silently overwrite the first
            // (importer files can emit consecutive call lines with no EXEC
            // between them) — close the group instead
            if (g.is_call && !flush_group()) return true;
            uint64_t sym;
            size_t n = get_uvar(p + o, len - o, sym);
            if (!n) break;
            o += n;
            g.is_call = true;
            if (sym == 0) {
                int64_t a;
                n = get_var(p + o, len - o, a);
                if (!n) break;
                o += n;
                g.call_target = uint64_t(a);
                g.call_name = nullptr;
            } else if (sym - 1 < f_.arena.strings().size()) {
                g.call_name = f_.arena.str(uint32_t(sym - 1)).c_str();
                g.call_target = 0;
            } else {
                // crash-truncated file: symbol interned after the surviving
                // META was written — degrade to a numeric target
                g.call_name = nullptr;
                g.call_target = 0;
            }
            for (int i = 0; i < 4; i++) {
                int64_t d;
                n = get_var(p + o, len - o, d);
                if (!n) break;
                o += n;
                last_arg[i] = uint64_t(int64_t(last_arg[i]) + d);
                g.args[i] = last_arg[i];
            }
        } else if (tag == 5) {
            int64_t d;
            size_t n = get_var(p + o, len - o, d);
            if (!n) break;
            o += n;
            last_ret = uint64_t(int64_t(last_ret) + d);
            g.is_ret = true;
            g.ret_val = last_ret;
        } else if (tag == T_SVC) {
            uint64_t num;
            size_t n = get_uvar(p + o, len - o, num);
            if (!n) break;
            o += n;
            g.is_svc = true;
            g.svc_num = num;
            for (int i = 0; i < 3; i++) {
                int64_t d;
                n = get_var(p + o, len - o, d);
                if (!n) break;
                o += n;
                last_arg[4 + i] = uint64_t(int64_t(last_arg[4 + i]) + d);
                g.svc_args[i] = last_arg[4 + i];
            }
        } else if (tag == T_RDVAL || tag == T_SIMDV) {
            // observed value token (importer files): RDVAL extends the read
            // list, SIMDV extends the "-> " write list
            uint64_t name;
            size_t n = get_uvar(p + o, len - o, name);
            if (!n) break;
            o += n;
            if (o >= len) break;
            uint8_t kind = p[o++];
            if (kind == 0) {
                int64_t d;
                n = get_var(p + o, len - o, d);
                if (!n) break;
                o += n;
                uint64_t v = uint64_t(int64_t(last_obs[uint32_t(name)]) + d);
                last_obs[uint32_t(name)] = v;
                if (tag == T_RDVAL) add_obs(g.obs, g.n_obs, uint32_t(name), v);
                else add_obs(g.wobs, g.n_wobs, uint32_t(name), v);
            } else if (kind == 1) {
                if (o + 16 > len) break;
                unsigned __int128 w;
                memcpy(&w, p + o, 16);
                o += 16;
                if (tag == T_RDVAL)
                    add_obs(g.obs, g.n_obs, uint32_t(name), w);
                else
                    add_obs(g.wobs, g.n_wobs, uint32_t(name), w);
            } else break; // corrupt
        } else if (tag == T_VERBATIM) {
            uint64_t vl;
            size_t n = get_uvar(p + o, len - o, vl);
            if (!n || o + n + vl > len) break;
            // verbatim is ALWAYS its own group: the upstream renderer replays
            // only the raw body for such groups, so letting it ride an open
            // exec group would drop that group's line
            if (!flush_group()) return true;
            g.has_verbatim = true;
            g.verbatim_off = uint32_t(verbatim.size());
            g.verbatim_len = uint32_t(vl);
            verbatim.append((const char*)p + o + n, size_t(vl));
            if (!flush_group()) return true;
            o += n + vl;
        } else if (tag == T_CALL2) {
            if (g.is_call && !flush_group()) return true; // see T_CALL
            uint64_t sym;
            size_t n = get_uvar(p + o, len - o, sym);
            if (!n) break;
            o += n;
            if (o >= len) break;
            uint8_t na = p[o++];
            if (na > 8) break;
            g.is_call = true;
            g.n_call_args = na;
            if (sym == 0) {
                int64_t a;
                n = get_var(p + o, len - o, a);
                if (!n) break;
                o += n;
                g.call_target = uint64_t(a);
                g.call_name = nullptr;
            } else if (sym - 1 < f_.arena.strings().size()) {
                g.call_name = f_.arena.str(uint32_t(sym - 1)).c_str();
                g.call_target = 0;
            } else {
                g.call_name = nullptr; // see T_CALL
                g.call_target = 0;
            }
            for (int i = 0; i < na; i++) {
                int64_t d;
                n = get_var(p + o, len - o, d);
                if (!n) break;
                o += n;
                last_arg[i] = uint64_t(int64_t(last_arg[i]) + d);
                g.args[i] = last_arg[i];
            }
        } else {
            break;
        }
    }
    flush_group();
    (void)last_mv;
    return true;
}

// ---------------------------------------------------------------------------
// register name table for the expansion engines
// ---------------------------------------------------------------------------
static const char* idx_name(int ctx_idx) {
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
    const std::string& vb = f_.verbatim;
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
            line.append(vb.data() + g.verbatim_off, g.verbatim_len);
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
            line += "call func: ";
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
struct AgentRegVal { int ctx; uint64_t val; };
struct AgentMemVal { bool is_w; uint64_t addr; uint64_t val; bool known; };

static void agent_regs(const Site& s, const Group& g, const uint64_t* regs,
                       std::vector<AgentRegVal>& rd, std::vector<AgentRegVal>& wr) {
    ObsMap m = obs_map(s, g);
    for (uint8_t i = 0; i < s.n_ops; i++) {
        const OpPlan& op = s.ops[i];
        if (op.kind == OP_REG_R && op.ctx_idx >= 0)
            rd.push_back({op.ctx_idx,
                          m.use_obs ? uint64_t(g.obs[m.obs_at[i]].val)
                                    : op.ctx_idx == 31 ? regs[31]
                                                       : regs[op.ctx_idx & 31]});
        else if (op.kind == OP_REG_W && op.ctx_idx >= 0) {
            if (m.use_wobs) {
                wr.push_back({op.ctx_idx, uint64_t(g.wobs[m.wobs_at[i]].val)});
                continue;
            }
            for (int k = 0; k < g.n_wr; k++)
                if (g.wr_id[k] == op.ctx_idx) {
                    wr.push_back({op.ctx_idx, g.wr_val[k]});
                    break;
                }
        }
    }
}

// value a memory access moved: a recorded value when the trace has one,
// otherwise the loaded register's write (loads) / the stored register's
// pre-event value (stores, first plan read that is not the base/index).
static void agent_mems(const Site& s, const Group& g, const uint64_t* regs,
                       std::vector<AgentMemVal>& out) {
    ObsMap om = obs_map(s, g);
    int mem_idx = 0;
    for (uint8_t i = 0; i < s.n_ops && mem_idx < g.n_mem; i++) {
        const OpPlan& op = s.ops[i];
        if (op.kind != OP_MEM_R && op.kind != OP_MEM_W) continue;
        const MemOp& m = g.mem[mem_idx++];
        AgentMemVal mv{op.kind == OP_MEM_W, m.addr, 0, false};
        if (m.value_known) {
            mv.val = m.value;
            mv.known = true;
        } else if (op.kind == OP_MEM_W) {
            for (uint8_t j = 0; j < s.n_ops && !mv.known; j++) {
                const OpPlan& r = s.ops[j];
                if (r.kind != OP_REG_R || r.ctx_idx < 0) continue;
                if (r.ctx_idx == op.base_ctx_idx || r.ctx_idx == op.index_ctx_idx) continue;
                mv.val = om.use_obs ? uint64_t(g.obs[om.obs_at[j]].val)
                                    : r.ctx_idx == 31 ? regs[31] : regs[r.ctx_idx & 31];
                mv.known = true;
            }
        } else {
            for (uint8_t j = 0; j < s.n_ops && !mv.known; j++) {
                const OpPlan& w = s.ops[j];
                if (w.kind != OP_REG_W || w.ctx_idx < 0) continue;
                if (om.use_wobs) {
                    mv.val = uint64_t(g.wobs[om.wobs_at[j]].val);
                    mv.known = true;
                    break;
                }
                for (int k = 0; k < g.n_wr; k++)
                    if (g.wr_id[k] == w.ctx_idx) {
                        mv.val = g.wr_val[k];
                        mv.known = true;
                        break;
                    }
            }
        }
        out.push_back(mv);
    }
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
                             uint64_t* stop_gi) {
    if (stop_gi) *stop_gi = UINT64_MAX;
    const SiteArena& A = f.arena;
    uint64_t lines = 0;
    uint32_t cur_mod = 0xFFFFFFFFu;
    std::string line;
    auto count_line = [&]() {
        size_t nl = std::count(line.begin(), line.end(), '\n');
        lines += nl;
    };
    ex.for_each([&](uint64_t gi, const Group& g) -> bool {
        if (gi < from_idx || gi > to_idx) return true;
        if (max_lines && lines >= max_lines) {
            if (stop_gi) *stop_gi = gi;
            return false;
        }
        line.clear();
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
            std::vector<AgentRegVal> rd, wr;
            std::vector<AgentMemVal> mems;
            agent_regs(s, g, regs, rd, wr);
            agent_mems(s, g, regs, mems);
            if (json) {
                char b[64];
                snprintf(b, sizeof b, "{\"ev\":%llu", (unsigned long long)gi);
                line += b;
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
                             idx_name(rd[i].ctx), (unsigned long long)rd[i].val);
                    line += rb;
                }
                line += "],\"wr\":[";
                for (size_t i = 0; i < wr.size(); i++) {
                    if (i) line += ',';
                    char rb[96];
                    snprintf(rb, sizeof rb, "[\"%s\",\"0x%llx\"]",
                             idx_name(wr[i].ctx), (unsigned long long)wr[i].val);
                    line += rb;
                }
                line += "]";
                if (!mems.empty()) {
                    line += ",\"mem\":[";
                    for (size_t i = 0; i < mems.size(); i++) {
                        if (i) line += ',';
                        char rb[112];
                        if (mems[i].known)
                            snprintf(rb, sizeof rb, "{\"w\":%d,\"addr\":\"0x%llx\",\"val\":\"0x%llx\"}",
                                     mems[i].is_w ? 1 : 0, (unsigned long long)mems[i].addr,
                                     (unsigned long long)mems[i].val);
                        else
                            snprintf(rb, sizeof rb, "{\"w\":%d,\"addr\":\"0x%llx\"}",
                                     mems[i].is_w ? 1 : 0, (unsigned long long)mems[i].addr);
                        line += rb;
                    }
                    line += ']';
                }
            } else {
                char b[64];
                snprintf(b, sizeof b, "%llu !0x%llx ", (unsigned long long)gi,
                         (unsigned long long)off);
                line += b;
                line += txt;
                if (!rd.empty() || !wr.empty()) {
                    line += "; ";
                    for (size_t i = 0; i < rd.size(); i++) {
                        if (i) line += ' ';
                        snprintf(b, sizeof b, "%s=0x%llx", idx_name(rd[i].ctx),
                                 (unsigned long long)rd[i].val);
                        line += b;
                    }
                    if (!rd.empty() && !wr.empty()) line += " -> ";
                    else if (!wr.empty()) line += "-> ";
                    for (size_t i = 0; i < wr.size(); i++) {
                        if (i) line += ' ';
                        snprintf(b, sizeof b, "%s=0x%llx", idx_name(wr[i].ctx),
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
                            snprintf(b, sizeof b, ":0x%llx", (unsigned long long)mems[i].val);
                            line += b;
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
        if (json) line += "}\n"; // closes the {"ev":... object opened above
        if (!line.empty()) {
            fwrite(line.data(), 1, line.size(), out);
            count_line();
        }
        return true;
    });
    return lines;
}

uint64_t Expander::expand_compact(FILE* out, uint64_t from_idx, uint64_t to_idx,
                                  uint64_t max_lines, uint64_t* stop_gi) {
    return expand_agent(f_, *this, out, false, from_idx, to_idx, max_lines, stop_gi);
}

uint64_t Expander::expand_jsonl(FILE* out, uint64_t from_idx, uint64_t to_idx,
                                uint64_t max_lines, uint64_t* stop_gi) {
    return expand_agent(f_, *this, out, true, from_idx, to_idx, max_lines, stop_gi);
}

} // namespace gt
