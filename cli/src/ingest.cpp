#include <gumtrace/ingest.h>
#include <gumtrace/varint.h>
#include <cstring>
#include <cstdio>
#include <algorithm>

namespace gt {

static constexpr uint32_t CHUNK_MAGIC = 0x47544348u;
static constexpr uint32_t GTB_MAGIC   = 0x47544231u;

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
    int64_t last_site = 0;
    uint64_t last_reg[32] = {0}, last_addr = 0, last_mv[2] = {0};
    uint64_t last_arg[7] = {0}, last_ret = 0;
    while (o < len) {
        uint8_t tag = p[o++];
        if (tag == 1) { // EXEC
            int64_t d;
            size_t n = get_var(p + o, len - o, d);
            if (!n) break;
            o += n; last_site += d;
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
            bool is_w = (tag == 7) || (fl & 1);
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
        } else {
            break; // corrupt
        }
    }
    return true;
}

bool Expander::for_each(const std::function<bool(uint64_t, const Group&)>& cb) {
    // sp comes from the trace itself, not from any assumption about the event
    // source (it used to be hardcoded to the benchmark corpus' stack top)
    regs_[31] = f_.initial_sp;
    const uint8_t* p = f_.events.data();
    size_t len = f_.events.size(), o = 0;
    Group g;
    uint64_t gi = 0;
    auto flush_group = [&]() -> bool {
        if (!g.has_exec && !g.is_call && !g.is_svc && !g.is_ret) return true;
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
    uint64_t last_arg[7] = {0}, last_ret = 0;
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
            bool is_w = (tag == 7) || (fl & 1);
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
            } else {
                g.call_name = f_.arena.str(uint32_t(sym - 1)).c_str();
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
        } else if (tag == 6) {
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
        } else {
            break;
        }
    }
    flush_group();
    (void)last_mv;
    return true;
}

// ---------------------------------------------------------------------------
// Legacy-identical text expansion
// ---------------------------------------------------------------------------
static void emit_hex64(std::string& s, uint64_t v) {
    char tmp[16];
    size_t n = legacy_hex64(tmp, v);
    s.append(tmp, n);
}
static const char* idx_name(int ctx_idx) {
    static const char* names[32] = {
        "x0","x1","x2","x3","x4","x5","x6","x7","x8","x9","x10","x11","x12","x13","x14","x15",
        "x16","x17","x18","x19","x20","x21","x22","x23","x24","x25","x26","x27","x28","x29","x30","sp"};
    return names[ctx_idx & 31];
}

uint64_t Expander::expand_text(FILE* out, uint64_t from_idx, uint64_t to_idx,
                               bool print_idx, uint64_t max_lines) {
    const SiteArena& A = f_.arena;
    const char* pool = A.pool_ptr();
    const std::string& mod = f_.modules.empty() ? std::string("?") : f_.modules[0];

    std::string line;
    uint64_t lines = 0;

    // pending state across groups (mirrors LegacyRecorder)
    int pwr = 0;
    int pwr_id[8];
    uint64_t pwr_val[8];
    bool pend_call = false, pend_svc = false, pend_ret = false;
    std::string pend_name;
    uint64_t pargs[4] = {0}, psvc_num = 0, psvc_args[3] = {0}, pret_val = 0;

    auto emit_group_text = [&](uint64_t gi, const Group& g) -> bool {
        if (gi < from_idx || gi > to_idx) {
            // still must maintain pending state correctly
            if (g.has_exec || (!g.has_exec)) {
                pwr = 0;
                pend_call = pend_svc = pend_ret = false;
                return true;
            }
            return true;
        }
        if (max_lines && lines >= max_lines) return false;

        // 2. deferred writes of the previous group
        if (pwr > 0) {
            line.append("-> ");
            for (int i = 0; i < pwr; i++) {
                line.append(idx_name(pwr_id[i]));
                line.append("=0x");
                emit_hex64(line, pwr_val[i]);
                line.append(" ");
            }
            line.append("\n");
        }
        // 3. pending blocks
        if (pend_call) {
            line += "call func: " + pend_name + "(x0=0x";
            emit_hex64(line, pargs[0]); line += ", x1=0x";
            emit_hex64(line, pargs[1]); line += ", x2=0x";
            emit_hex64(line, pargs[2]); line += ", x3=0x";
            emit_hex64(line, pargs[3]); line += ")\n";
        }
        if (pend_svc) {
            const char* nm = svc_name(psvc_num);
            if (nm) {
                line += std::string("svc ") + nm + "(x0=0x";
                emit_hex64(line, psvc_args[0]); line += ", x1=0x";
                emit_hex64(line, psvc_args[1]); line += ", x2=0x";
                emit_hex64(line, psvc_args[2]); line += ")\n";
            } else {
                line += "svc #";
                char b[32];
                snprintf(b, sizeof(b), "%llu", (unsigned long long)psvc_num);
                line += b;
                line += "(x0=0x";
                emit_hex64(line, psvc_args[0]);
                line += ")\n";
            }
        }
        if (pend_ret) {
            line += "ret: x0=0x";
            emit_hex64(line, pret_val);
            line += "\n";
        }
        pwr = 0;
        pend_call = pend_svc = pend_ret = false;

        if (!g.has_exec) return true; // call-only detail: blocks already above

        const Site& s = A.get(g.site_id);
        if (print_idx) {
            char b[32];
            snprintf(b, sizeof(b), "%llu ", (unsigned long long)gi);
            line += b;
        }
        line.append(pool + s.prefix_off, s.prefix_len);

        bool is_write = false;
        int mem_idx = 0;
        for (uint8_t i = 0; i < s.n_ops; i++) {
            const OpPlan& op = s.ops[i];
            if (op.kind == OP_REG_R) {
                line.append(idx_name(op.ctx_idx));
                line.append("=0x");
                emit_hex64(line, op.ctx_idx == 31 ? regs_[31] : regs_[op.ctx_idx & 31]);
                line.append(" ");
            } else if (op.kind == OP_REG_W) {
                is_write = true;
            } else if (op.kind == OP_MEM_R || op.kind == OP_MEM_W) {
                if (mem_idx < g.n_mem) {
                    const MemOp& m = g.mem[mem_idx++];
                    if (op.base_ctx_idx >= 0) {
                        line.append(idx_name(op.base_ctx_idx));
                        line.append("=0x");
                        emit_hex64(line, op.base_ctx_idx == 31 ? regs_[31]
                                                               : regs_[op.base_ctx_idx & 31]);
                        line.append(" ");
                    }
                    line.append(op.kind == OP_MEM_W ? "mem_w=0x" : "mem_r=0x");
                    emit_hex64(line, m.addr);
                    line.append(" ");
                    if (op.kind == OP_MEM_W) is_write = true;
                }
            }
        }

        // deferred write tail: plan-driven (implicit x30 writes from calls are
        // recorded for reconstruction but not printed, matching upstream)
        for (uint8_t i = 0; i < s.n_ops && pwr < 8; i++) {
            if (s.ops[i].kind != OP_REG_W) continue;
            for (int k = 0; k < g.n_wr; k++) {
                if (g.wr_id[k] == s.ops[i].ctx_idx) {
                    pwr_id[pwr] = g.wr_id[k];
                    pwr_val[pwr] = g.wr_val[k];
                    pwr++;
                    break;
                }
            }
        }
        if (!is_write) line.append("\n");

        if (g.is_call) {
            pend_call = true;
            pend_name = g.call_name ? g.call_name : "<unknown>";
            for (int i = 0; i < 4; i++) pargs[i] = g.args[i];
        }
        if (g.is_svc) {
            pend_svc = true;
            psvc_num = g.svc_num;
            for (int i = 0; i < 3; i++) psvc_args[i] = g.svc_args[i];
        }
        if (g.is_ret) {
            pend_ret = true;
            pret_val = g.ret_val;
        }

        fwrite(line.data(), 1, line.size(), out);
        lines++;
        line.clear();
        return true;
    };

    for_each(emit_group_text);

    // tail (mirrors LegacyRecorder::finish)
    if (pwr > 0) {
        line.append("-> ");
        for (int i = 0; i < pwr; i++) {
            line.append(idx_name(pwr_id[i]));
            line.append("=0x");
            emit_hex64(line, pwr_val[i]);
            line.append(" ");
        }
        line.append("\n");
    }
    if (pend_call) {
        line += "call func: " + pend_name + "(x0=0x";
        emit_hex64(line, pargs[0]); line += ", x1=0x";
        emit_hex64(line, pargs[1]); line += ", x2=0x";
        emit_hex64(line, pargs[2]); line += ", x3=0x";
        emit_hex64(line, pargs[3]); line += ")\n";
    }
    if (pend_svc) {
        const char* nm = svc_name(psvc_num);
        if (nm) {
            line += std::string("svc ") + nm + "(x0=0x";
            emit_hex64(line, psvc_args[0]); line += ")\n";
        } else {
            line += "svc #";
            char b[32];
            snprintf(b, sizeof(b), "%llu", (unsigned long long)psvc_num);
            line += b;
            line += "(x0=0x";
            emit_hex64(line, psvc_args[0]);
            line += ")\n";
        }
    }
    if (pend_ret) {
        line += "ret: x0=0x";
        emit_hex64(line, pret_val);
        line += "\n";
    }
    if (!line.empty()) {
        fwrite(line.data(), 1, line.size(), out);
        lines++;
    }
    return lines;
}

// ---------------------------------------------------------------------------
// SQLite ingest
// ---------------------------------------------------------------------------
#ifndef GT_NO_SQLITE

sqlite3* db_open(const std::string& path, bool read_only) {
    sqlite3* db = nullptr;
    int flags = read_only ? SQLITE_OPEN_READONLY : SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE;
    if (sqlite3_open_v2(path.c_str(), &db, flags, nullptr) != SQLITE_OK) return nullptr;
    sqlite3_exec(db, "PRAGMA journal_mode=OFF; PRAGMA synchronous=OFF; PRAGMA cache_size=-65536;",
                 nullptr, nullptr, nullptr);
    return db;
}

static int op_base_of(const Site& s, const MemOp& m) {
    (void)m;
    for (uint8_t i = 0; i < s.n_ops; i++)
        if (s.ops[i].kind == OP_MEM_R || s.ops[i].kind == OP_MEM_W)
            return s.ops[i].base_ctx_idx;
    return -1;
}

IngestResult ingest_sqlite(const GtbFile& f, const std::string& db_path) {
    sqlite3* db = db_open(db_path, false);
    IngestResult r;
    if (!db) return r;
    // SQLite has no multi-table DROP; each object needs its own statement.
    // Views must be dropped explicitly (DROP TABLE removes a table's indexes
    // but not views built on it), otherwise re-ingesting into an existing db
    // fails at CREATE VIEW and leaves stale rows behind.
    static const char* kResetSchema =
        "DROP VIEW  IF EXISTS v_func_stats;"
        "DROP VIEW  IF EXISTS v_mem_hot;"
        "DROP TABLE IF EXISTS meta;"
        "DROP TABLE IF EXISTS insn;"
        "DROP TABLE IF EXISTS exec;"
        "DROP TABLE IF EXISTS regw;"
        "DROP TABLE IF EXISTS mem;"
        "DROP TABLE IF EXISTS call;"
        "DROP TABLE IF EXISTS svc;"
        "DROP TABLE IF EXISTS ret;";
    char* err = nullptr;
    if (sqlite3_exec(db, kResetSchema, nullptr, nullptr, &err) != SQLITE_OK) {
        fprintf(stderr, "ingest: schema reset failed: %s\n", err ? err : "?");
        sqlite3_free(err);
        sqlite3_close(db);
        return r;
    }
    sqlite3_exec(db, "BEGIN;", nullptr, nullptr, nullptr);
    if (sqlite3_exec(db,
        "CREATE TABLE meta(k TEXT PRIMARY KEY, v TEXT);"
        "CREATE TABLE insn(id INTEGER PRIMARY KEY, off INTEGER, txt TEXT, kind INTEGER, func TEXT);"
        "CREATE TABLE exec(ev INTEGER PRIMARY KEY, site INTEGER);"
        "CREATE TABLE regw(ev INTEGER, reg INTEGER, val INTEGER);"
        "CREATE TABLE mem(ev INTEGER, is_w INTEGER, addr INTEGER, size INTEGER, val INTEGER);"
        "CREATE TABLE call(ev INTEGER PRIMARY KEY, site INTEGER, sym TEXT, x0 INTEGER, x1 INTEGER, x2 INTEGER, x3 INTEGER);"
        "CREATE TABLE svc(ev INTEGER PRIMARY KEY, num INTEGER, nm TEXT, x0 INTEGER, x1 INTEGER, x2 INTEGER);"
        "CREATE TABLE ret(ev INTEGER PRIMARY KEY, x0 INTEGER);",
        nullptr, nullptr, &err) != SQLITE_OK) {
        fprintf(stderr, "ingest: schema create failed: %s\n", err ? err : "?");
        sqlite3_free(err);
        sqlite3_exec(db, "ROLLBACK;", nullptr, nullptr, nullptr);
        sqlite3_close(db);
        return r;
    }

    sqlite3_stmt *st_meta, *st_insn, *st_exec, *st_regw, *st_mem, *st_call, *st_svc, *st_ret;
    sqlite3_prepare_v2(db, "INSERT OR REPLACE INTO meta VALUES(?,?)", -1, &st_meta, nullptr);
    sqlite3_prepare_v2(db, "INSERT INTO insn VALUES(?,?,?,?,?)", -1, &st_insn, nullptr);
    sqlite3_prepare_v2(db, "INSERT INTO exec VALUES(?,?)", -1, &st_exec, nullptr);
    sqlite3_prepare_v2(db, "INSERT INTO regw VALUES(?,?,?)", -1, &st_regw, nullptr);
    sqlite3_prepare_v2(db, "INSERT INTO mem VALUES(?,?,?,?,?)", -1, &st_mem, nullptr);
    sqlite3_prepare_v2(db, "INSERT INTO call VALUES(?,?,?,?,?,?,?)", -1, &st_call, nullptr);
    sqlite3_prepare_v2(db, "INSERT INTO svc VALUES(?,?,?,?,?,?)", -1, &st_svc, nullptr);
    sqlite3_prepare_v2(db, "INSERT INTO ret VALUES(?,?)", -1, &st_ret, nullptr);

    auto bind_txt = [](sqlite3_stmt* s, int i, const std::string& v) {
        sqlite3_bind_text(s, i, v.c_str(), int(v.size()), SQLITE_TRANSIENT);
    };

    // static tables
    for (uint32_t i = 0; i < f.arena.size(); i++) {
        const Site& s = f.arena.get(i);
        sqlite3_reset(st_insn);
        sqlite3_bind_int(st_insn, 1, int(i));
        sqlite3_bind_int64(st_insn, 2, sqlite3_int64(s.addr));
        std::string txt(f.arena.pool_ptr() + s.disasm_off, s.disasm_len);
        bind_txt(st_insn, 3, txt);
        sqlite3_bind_int(st_insn, 4, int(s.kind));
        if (s.func_sym >= 0) bind_txt(st_insn, 5, f.arena.str(uint32_t(s.func_sym)));
        else sqlite3_bind_null(st_insn, 5);
        sqlite3_step(st_insn);
    }
    sqlite3_reset(st_meta);
    bind_txt(st_meta, 1, "module");
    bind_txt(st_meta, 2, f.modules.empty() ? "?" : f.modules[0]);
    sqlite3_step(st_meta);

    // event stream
    Expander ex(f);
    const uint64_t* rf = ex.regfile();
    auto store_value_of = [&](const Group& g, const MemOp& m) -> uint64_t {
        // first plan REG_R that is not the mem base/index is the stored
        // register; its pre-event value equals the stored value
        if (!g.has_exec) return 0;
        const Site& s = f.arena.get(g.site_id);
        for (uint8_t i = 0; i < s.n_ops; i++) {
            const OpPlan& op = s.ops[i];
            if (op.kind != OP_REG_R || op.ctx_idx < 0) continue;
            if (op.ctx_idx == op_base_of(s, m)) continue;
            return op.ctx_idx == 31 ? rf[31] : rf[op.ctx_idx & 31];
        }
        return 0;
    };
    ex.for_each([&](uint64_t gi, const Group& g) {
        uint64_t ev = gi + 1;
        if (g.has_exec) {
            sqlite3_reset(st_exec);
            sqlite3_bind_int64(st_exec, 1, sqlite3_int64(ev));
            sqlite3_bind_int(st_exec, 2, int(g.site_id));
            sqlite3_step(st_exec);
            r.n_exec++;
        }
        for (int i = 0; i < g.n_wr; i++) {
            sqlite3_reset(st_regw);
            sqlite3_bind_int64(st_regw, 1, sqlite3_int64(ev));
            sqlite3_bind_int(st_regw, 2, g.wr_id[i]);
            sqlite3_bind_int64(st_regw, 3, sqlite3_int64(g.wr_val[i]));
            sqlite3_step(st_regw);
            r.n_regw++;
        }
        for (int i = 0; i < g.n_mem; i++) {
            MemOp m = g.mem[i];
            if (!m.value_known) m.value = store_value_of(g, m);
            sqlite3_reset(st_mem);
            sqlite3_bind_int64(st_mem, 1, sqlite3_int64(ev));
            sqlite3_bind_int(st_mem, 2, m.is_write ? 1 : 0);
            sqlite3_bind_int64(st_mem, 3, sqlite3_int64(m.addr));
            sqlite3_bind_int(st_mem, 4, m.size);
            sqlite3_bind_int64(st_mem, 5, sqlite3_int64(m.value));
            sqlite3_step(st_mem);
            r.n_mem++;
        }
        if (g.is_call) {
            sqlite3_reset(st_call);
            sqlite3_bind_int64(st_call, 1, sqlite3_int64(ev));
            sqlite3_bind_int(st_call, 2, int(g.site_id));
            if (g.call_name) bind_txt(st_call, 3, g.call_name);
            else sqlite3_bind_null(st_call, 3);
            for (int i = 0; i < 4; i++)
                sqlite3_bind_int64(st_call, 4 + i, sqlite3_int64(g.args[i]));
            sqlite3_step(st_call);
            r.n_call++;
        }
        if (g.is_svc) {
            sqlite3_reset(st_svc);
            sqlite3_bind_int64(st_svc, 1, sqlite3_int64(ev));
            sqlite3_bind_int64(st_svc, 2, sqlite3_int64(g.svc_num));
            const char* nm = svc_name(g.svc_num);
            if (nm) bind_txt(st_svc, 3, nm); else sqlite3_bind_null(st_svc, 3);
            for (int i = 0; i < 3; i++)
                sqlite3_bind_int64(st_svc, 4 + i, sqlite3_int64(g.svc_args[i]));
            sqlite3_step(st_svc);
            r.n_svc++;
        }
        if (g.is_ret) {
            sqlite3_reset(st_ret);
            sqlite3_bind_int64(st_ret, 1, sqlite3_int64(ev));
            sqlite3_bind_int64(st_ret, 2, sqlite3_int64(g.ret_val));
            sqlite3_step(st_ret);
            r.n_ret++;
        }
        return true;
    });
    sqlite3_exec(db, "COMMIT;", nullptr, nullptr, nullptr);

    // indexes built after the bulk load (2-3x faster ingest)
    sqlite3_exec(db,
        "CREATE INDEX i_regw_ev ON regw(ev);"
        "CREATE INDEX i_mem_addr ON mem(addr);"
        "CREATE INDEX i_mem_ev ON mem(ev);"
        "CREATE INDEX i_call_sym ON call(sym);",
        nullptr, nullptr, nullptr);

    // precomputed aggregates for agents
    sqlite3_exec(db,
        "CREATE VIEW v_func_stats AS "
        "SELECT i.func AS func, COUNT(*) AS execs FROM exec e JOIN insn i ON i.id=e.site GROUP BY i.func;"
        "CREATE VIEW v_mem_hot AS "
        "SELECT addr, is_w, COUNT(*) AS hits FROM mem GROUP BY addr, is_w ORDER BY hits DESC;",
        nullptr, nullptr, nullptr);

    sqlite3_finalize(st_meta); sqlite3_finalize(st_insn); sqlite3_finalize(st_exec);
    sqlite3_finalize(st_regw); sqlite3_finalize(st_mem); sqlite3_finalize(st_call);
    sqlite3_finalize(st_svc); sqlite3_finalize(st_ret);
    sqlite3_close(db);
    return r;
}


#endif // GT_NO_SQLITE

} // namespace gt
