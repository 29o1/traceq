#include <gumtrace/site.h>
#include <gumtrace/varint.h>
#include <capstone/capstone.h>
#include <cassert>
#include <cstring>
#include <algorithm>

namespace gt {

static csh g_cs = 0;

bool site_compiler_init() {
    if (g_cs) return true;
    return cs_open(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, &g_cs) == CS_ERR_OK &&
           cs_option(g_cs, CS_OPT_DETAIL, CS_OPT_ON) == CS_ERR_OK;
}
void site_compiler_shutdown() {
    if (g_cs) { cs_close(&g_cs); g_cs = 0; }
}

size_t legacy_hex64(char* p, uint64_t v) {
    // matches Utils::append_uint64_hex: 0 -> "0", otherwise trimmed hex
    if (v == 0) { p[0] = '0'; return 1; }
    static const char* hx = "0123456789abcdef";
    char tmp[16];
    int i = 0;
    while (v) { tmp[i++] = hx[v & 0xF]; v >>= 4; }
    for (int k = 0; k < i; k++) p[k] = tmp[i - 1 - k];
    return size_t(i);
}

size_t legacy_hex128(char* p, unsigned __int128 v) {
    uint64_t hi = uint64_t(v >> 64), lo = uint64_t(v);
    if (hi > 0) {
        size_t n = legacy_hex64(p, hi);
        // low 64 bits fixed-width 16
        static const char* hx = "0123456789abcdef";
        for (int i = 15; i >= 0; i--) { p[n + i] = hx[lo & 0xF]; lo >>= 4; }
        return n + 16;
    }
    return legacy_hex64(p, lo);
}

// ctx_idx: 0..30 for x/w views, -1 unsupported (SIMD/nzcv)
static int ctx_idx_of(arm64_reg r) {
    if (r >= ARM64_REG_X0 && r <= ARM64_REG_X28) return r - ARM64_REG_X0;
    if (r >= ARM64_REG_W0 && r <= ARM64_REG_W30) return r - ARM64_REG_W0;
    if (r == ARM64_REG_FP) return 29;
    if (r == ARM64_REG_LR) return 30;
    if (r == ARM64_REG_SP) return 31;
    return -1;
}
// simd_idx: 0..31 for q/d/s/h/b/v views of the same SIMD/FP register file,
// -1 for non-SIMD. The value width is irrelevant for dependence tracking.
static int simd_idx_of(arm64_reg r) {
    if (r >= ARM64_REG_Q0 && r <= ARM64_REG_Q31) return r - ARM64_REG_Q0;
    if (r >= ARM64_REG_V0 && r <= ARM64_REG_V31) return r - ARM64_REG_V0;
    if (r >= ARM64_REG_D0 && r <= ARM64_REG_D31) return r - ARM64_REG_D0;
    if (r >= ARM64_REG_S0 && r <= ARM64_REG_S31) return r - ARM64_REG_S0;
    if (r >= ARM64_REG_H0 && r <= ARM64_REG_H31) return r - ARM64_REG_H0;
    if (r >= ARM64_REG_B0 && r <= ARM64_REG_B31) return r - ARM64_REG_B0;
    return -1;
}
static int name_id_of(arm64_reg r) {
    if (r >= ARM64_REG_X0 && r <= ARM64_REG_X28) return r - ARM64_REG_X0;
    if (r >= ARM64_REG_W0 && r <= ARM64_REG_W30) return 32 + (r - ARM64_REG_W0);
    if (r == ARM64_REG_FP) return 29;  // "x29" matches how values are keyed
    if (r == ARM64_REG_LR) return 30;
    if (r == ARM64_REG_SP) return 31;
    if (r == ARM64_REG_WSP) return 63;
    return -1;
}

int32_t SiteArena::intern_string(const std::string& s) {
    auto it = str_ids_.find(s);
    if (it != str_ids_.end()) return int32_t(it->second);
    str_ids_[s] = strings_.size();
    strings_.push_back(s);
    return int32_t(strings_.size() - 1);
}

uint32_t SiteArena::intern(uint64_t addr, uint32_t word, const char* module_name,
                           uint64_t module_base, int32_t func_sym) {
    auto it = by_addr_.find(addr);
    if (it != by_addr_.end()) return it->second;

    cs_insn* arr = nullptr;
    size_t n = site_compiler_init()
                   ? cs_disasm(g_cs, (const uint8_t*)&word, 4, addr, 1, &arr)
                   : 0;
    if (n != 1) return 0xFFFFFFFFu; // should not happen with a valid encoder
    uint32_t id = intern_disasm(addr, arr, module_name, module_base, func_sym);
    cs_free(arr, 1);
    return id;
}

uint32_t SiteArena::intern_disasm(uint64_t addr, const cs_insn* insn,
                                  const char* module_name, uint64_t module_base,
                                  int32_t func_sym) {
    auto it = by_addr_.find(addr);
    if (it != by_addr_.end()) return it->second;

    auto mid = module_ids_.find(module_name);
    uint32_t module_id;
    if (mid == module_ids_.end()) {
        module_id = modules_.size();
        modules_.push_back(module_name);
        module_ids_[module_name] = module_id;
        module_str_ids_.push_back(uint32_t(intern_string(module_name)));
        module_bases_.push_back(module_base);
    } else {
        module_id = mid->second;
    }

    Site s;
    s.addr = addr;
    s.module_id = module_id;
    s.func_sym = func_sym;

    const cs_arm64* a = &insn->detail->arm64;

    switch (insn->id) {
        case ARM64_INS_BL:  s.kind = SK_CALL_IMM; break;
        case ARM64_INS_BLR: s.kind = SK_CALL_REG; break;
        case ARM64_INS_BR:  s.kind = SK_BR; break;
        case ARM64_INS_RET: s.kind = SK_RET; break;
        case ARM64_INS_SVC: s.kind = SK_SVC; break;
        case ARM64_INS_B:
            // capstone 5: conditional branches are ARM64_INS_B with a valid cc
            s.kind = (a->cc != ARM64_CC_INVALID && a->cc != ARM64_CC_AL)
                         ? SK_BCOND : SK_B_IMM;
            break;
        default:            s.kind = SK_NORMAL; break;
    }
    if ((s.kind == SK_CALL_IMM || s.kind == SK_B_IMM) && a->op_count >= 1 &&
        a->operands[0].type == ARM64_OP_IMM)
        s.branch_imm = uint64_t(a->operands[0].imm);

    // ---- prefix (legacy-identical) ----
    char tmp[160];
    size_t n = 0;
    tmp[n++] = '[';
    memcpy(tmp + n, module_name, strlen(module_name)); n += strlen(module_name);
    memcpy(tmp + n, "] 0x", 4); n += 4;
    n += legacy_hex64(tmp + n, addr);
    memcpy(tmp + n, "!0x", 3); n += 3;
    n += legacy_hex64(tmp + n, addr - module_base);
    tmp[n++] = ' ';
    size_t dis_off = n;
    size_t mn = strlen(insn->mnemonic);
    memcpy(tmp + n, insn->mnemonic, mn); n += mn;
    tmp[n++] = ' ';
    size_t op_off = n;
    size_t on = strlen(insn->op_str);
    memcpy(tmp + n, insn->op_str, on); n += on;
    memcpy(tmp + n, "; ", 2); n += 2;
    assert(n < sizeof(tmp));
    s.disasm_off = 0; s.disasm_len = 0; // patched after pool append
    size_t dis_len = (op_off + on) - dis_off;

    s.prefix_off = prefix_pool_.size();
    prefix_pool_.append(tmp, n);
    // also store disasm separately for query display
    s.disasm_off = prefix_pool_.size();
    prefix_pool_.append(tmp + dis_off, dis_len);
    s.prefix_len = uint32_t(n);
    s.disasm_len = uint32_t(dis_len);

    // ---- operand plan ----
    // NZCV dependence of the whole instruction, from capstone detail:
    // cc covers conditional consumers (b.cond/csel/cset/ccmp/fcsel/...),
    // update_flags covers producers (adds/subs/cmp/fcmp/ccmp/...).
    uint8_t nzcv_flags = 0;
    if (a->cc != ARM64_CC_INVALID && a->cc != ARM64_CC_AL) nzcv_flags |= OPF_R_NZCV;
    if (a->update_flags) nzcv_flags |= OPF_W_NZCV;
    auto push_reg_op = [&](uint8_t kind, int idx, int sidx, int name) {
        if (s.n_ops >= 8) return;
        OpPlan& p = s.ops[s.n_ops];
        p.kind = kind;
        p.ctx_idx = int8_t(idx);
        p.simd_idx = int8_t(sidx);
        p.name_id = uint8_t(name < 0 ? 0 : name);
        p.op_flags = nzcv_flags;
        s.n_ops++;
    };
    bool writeback = strstr(insn->op_str, "],") != nullptr ||
                     strstr(insn->op_str, "]!") != nullptr;
    // capstone 5 quirk: cmp (subs xzr) marks its source operand as WRITE;
    // force READ so the plan prints the compared register inline
    bool is_cmp = insn->id == ARM64_INS_CMP;
    for (uint8_t i = 0; i < a->op_count && s.n_ops < 8; i++) {
        const cs_arm64_op& op = a->operands[i];
        if (op.type == ARM64_OP_REG) {
            int idx = ctx_idx_of(op.reg);
            int name = name_id_of(op.reg);
            if (idx < 0) {
                // SIMD/FP register: no runtime value (never recorded), but the
                // plan carries the register identity for dependence tracking
                int sidx = simd_idx_of(op.reg);
                if (sidx < 0) continue; // psr etc still unsupported
                bool r = op.access & CS_AC_READ;
                bool w = op.access & CS_AC_WRITE;
                if (r && s.n_ops < 8) push_reg_op(OP_REG_R, -1, sidx, -1);
                if (w && s.n_ops < 8) push_reg_op(OP_REG_W, -1, sidx, -1);
                continue;
            }
            if (name < 0) continue;
            bool r = is_cmp || (op.access & CS_AC_READ);
            bool w = !is_cmp && (op.access & CS_AC_WRITE);
            if (r && w) {
                push_reg_op(OP_REG_R, idx, -1, name);
                if (s.n_ops < 8) push_reg_op(OP_REG_W, idx, -1, name);
            } else if (r) {
                push_reg_op(OP_REG_R, idx, -1, name);
            } else if (w) {
                push_reg_op(OP_REG_W, idx, -1, name);
            }
        } else if (op.type == ARM64_OP_MEM) {
            OpPlan& p = s.ops[s.n_ops];
            p.kind = (op.access & CS_AC_WRITE) ? OP_MEM_W : OP_MEM_R;
            p.op_flags = nzcv_flags;
            p.base_ctx_idx = int8_t(ctx_idx_of(op.mem.base));
            p.index_ctx_idx = int8_t(ctx_idx_of(op.mem.index));
            p.shift_type = uint8_t(op.shift.type);
            p.shift_amt = uint8_t(op.shift.value);
            p.disp = op.mem.disp;
            p.size = 8;
            // width heuristics (subset of Utils::get_data_width)
            if (op.reg != ARM64_REG_INVALID) p.size = 8;
            s.n_ops++;
            if (writeback && op.mem.base != ARM64_REG_INVALID && s.n_ops < 8) {
                // writeback: base register is written after the access
                push_reg_op(OP_REG_W, ctx_idx_of(op.mem.base), -1,
                            name_id_of(op.mem.base));
            }
        }
    }

    by_addr_[addr] = sites_.size();
    sites_.push_back(std::move(s));
    return uint32_t(sites_.size() - 1);
}

// ---------------------------------------------------------------------------
// text-built sites (gt import)
// ---------------------------------------------------------------------------
int text_name_ctx(const char* s, size_t n, int* simd_idx) {
    *simd_idx = -1;
    if (n == 0 || n > 4) return -1;
    // aliases
    if (n == 2 && s[0] == 'f' && s[1] == 'p') return 29;
    if (n == 2 && s[0] == 'l' && s[1] == 'r') return 30;
    if (n == 2 && s[0] == 's' && s[1] == 'p') return 31;
    if (n == 3 && s[0] == 'w' && s[1] == 's' && s[2] == 'p') return 31;
    // <prefix><digits>: x/w = integer view, v/q/d/s/h/b = SIMD view
    char p = s[0];
    if (p != 'x' && p != 'w' && p != 'v' && p != 'q' && p != 'd' && p != 's' &&
        p != 'h' && p != 'b')
        return -1;
    if (n < 2) return -1;
    int v = 0;
    for (size_t i = 1; i < n; i++) {
        if (s[i] < '0' || s[i] > '9') return -1;
        v = v * 10 + (s[i] - '0');
    }
    if (v > 31) return -1;
    if (p == 'x' || p == 'w') return v;
    *simd_idx = v;
    return -1;
}

// mnemonic -> NZCV flags / site kind, for plans built from text (no capstone)
static uint8_t mnem_nzcv(const char* m, size_t n) {    auto is = [&](const char* w) {
        size_t l = strlen(w);
        return n == l && memcmp(m, w, l) == 0;
    };
    auto pre = [&](const char* w) {
        size_t l = strlen(w);
        return n >= l && memcmp(m, w, l) == 0;
    };
    uint8_t f = 0;
    // keep in step with upstream taint_tracker's sets_flags list
    if (is("cmp") || is("cmn") || is("tst") || pre("subs") || pre("adds") ||
        is("ands") || is("bics") || is("adcs") || is("sbcs") || is("negs") ||
        is("ngcs") || is("fcmp") || is("fcmpe") || is("fccmp") ||
        is("fccmpe") || is("sbc") || is("adc"))
        f |= OPF_W_NZCV;
    if (is("ccmp") || is("ccmn")) f |= OPF_R_NZCV | OPF_W_NZCV;
    if (pre("b.") || is("csel") || is("csinc") || is("csinv") || is("cset") ||
        is("csetm") || is("cneg") || is("fcsel"))
        f |= OPF_R_NZCV;
    return f;
}

// mnemonic -> NZCV flags / site kind, for plans built from text (no capstone)
static uint8_t mnem_kind(const char* m, size_t n) {
    auto is = [&](const char* w) {
        size_t l = strlen(w);
        return n == l && memcmp(m, w, l) == 0;
    };
    auto pre = [&](const char* w) {
        size_t l = strlen(w);
        return n >= l && memcmp(m, w, l) == 0;
    };
    if (is("bl")) return SK_CALL_IMM;
    if (is("blr") || pre("braa") || pre("brab") || pre("blraa") || pre("blrab"))
        return SK_CALL_REG;
    if (is("br") || pre("bra")) return SK_BR;
    if (is("ret") || pre("retaa") || pre("retab")) return SK_RET;
    if (is("svc")) return SK_SVC;
    if (pre("b.")) return SK_BCOND;
    if (is("b")) return SK_B_IMM;
    return SK_NORMAL;
}

uint32_t SiteArena::intern_text(uint64_t addr, const char* prefix, size_t prefix_len,
                               const char* module_name, uint64_t module_base,
                               const TextOp* tops, int n_tops) {
    auto it = by_addr_.find(addr);
    if (it != by_addr_.end()) return it->second;
    if (n_tops < 0 || n_tops > 8) return 0xFFFFFFFFu;

    // disasm = text between "0xABS!0xOFF " and the trailing "; "
    // ([mod] 0xABS!0xOFF mnem ops; )
    const char* bang = nullptr;
    for (size_t i = 0; i + 1 < prefix_len; i++)
        if (prefix[i] == '!' && prefix[i + 1] == '0' && prefix[i + 2] == 'x') {
            bang = prefix + i;
            break;
        }
    if (!bang || prefix_len < 4) return 0xFFFFFFFFu;
    size_t hex_end = (size_t)(bang - prefix) + 3;
    while (hex_end < prefix_len && ((prefix[hex_end] >= '0' && prefix[hex_end] <= '9') ||
                                    (prefix[hex_end] >= 'a' && prefix[hex_end] <= 'f')))
        hex_end++;
    if (hex_end >= prefix_len || prefix[hex_end] != ' ') return 0xFFFFFFFFu;
    size_t dis_off = hex_end + 1;
    if (prefix_len < dis_off + 2 ||
        prefix[prefix_len - 2] != ';' || prefix[prefix_len - 1] != ' ')
        return 0xFFFFFFFFu;
    size_t dis_len = prefix_len - 2 - dis_off;
    // mnemonic = first word of the disasm
    size_t mn_len = 0;
    while (mn_len < dis_len && prefix[dis_off + mn_len] != ' ') mn_len++;

    auto mid = module_ids_.find(module_name);
    uint32_t module_id;
    if (mid == module_ids_.end()) {
        module_id = modules_.size();
        modules_.push_back(module_name);
        module_ids_[module_name] = module_id;
        module_str_ids_.push_back(uint32_t(intern_string(module_name)));
        module_bases_.push_back(module_base);
    } else {
        module_id = mid->second;
    }

    Site s;
    s.addr = addr;
    s.module_id = module_id;
    s.func_sym = -1;
    s.kind = mnem_kind(prefix + dis_off, mn_len);
    uint8_t nzcv = mnem_nzcv(prefix + dis_off, mn_len);

    // classify every operand first: a failure must not touch arena state
    // (the pool is append-only and the same line will be retried on every
    // occurrence in the log)
    OpPlan plans[8];
    for (int i = 0; i < n_tops; i++) {
        OpPlan& p = plans[i];
        p.kind = tops[i].kind;
        p.op_flags = nzcv;
        if (tops[i].kind == OP_MEM_R || tops[i].kind == OP_MEM_W) {
            p.base_ctx_idx = -1; // address is carried by the observed event
            p.index_ctx_idx = -1;
            p.size = tops[i].size ? tops[i].size : 8;
        } else {
            int simd = -1;
            int ctx = text_name_ctx(tops[i].name, tops[i].name_len, &simd);
            if (ctx < 0 && simd < 0) return 0xFFFFFFFFu;
            p.ctx_idx = int8_t(ctx);
            p.simd_idx = int8_t(simd);
            p.name_id = uint8_t(ctx >= 0 ? (ctx & 63) : 0);
        }
    }

    s.prefix_off = prefix_pool_.size();
    prefix_pool_.append(prefix, prefix_len);
    s.prefix_len = uint32_t(prefix_len);
    s.disasm_off = prefix_pool_.size();
    prefix_pool_.append(prefix + dis_off, dis_len);
    s.disasm_len = uint32_t(dis_len);
    for (int i = 0; i < n_tops; i++) s.ops[i] = plans[i];
    s.n_ops = uint8_t(n_tops);

    by_addr_[addr] = sites_.size();
    sites_.push_back(std::move(s));
    return uint32_t(sites_.size() - 1);
}

// ---------------------------------------------------------------------------
// Serialization
// ---------------------------------------------------------------------------
// v2 marker: a v1 payload starts with the string count (u32), which can never
// plausibly reach this value — its presence means the payload is v2.
static constexpr uint32_t META_V2_MAGIC = 0x47544D32u; // "GTM2"

void SiteArena::serialize(std::vector<uint8_t>& out) const {
    auto put32 = [&](uint32_t v) {
        for (int i = 0; i < 4; i++) out.push_back(uint8_t(v >> (i * 8)));
    };
    put32(META_V2_MAGIC);
    // strings
    put32(uint32_t(strings_.size()));
    for (const auto& s : strings_) {
        put32(uint32_t(s.size()));
        out.insert(out.end(), s.begin(), s.end());
    }
    // modules (string id + base the module was loaded at)
    put32(uint32_t(modules_.size()));
    for (size_t i = 0; i < modules_.size(); i++) {
        put32(module_str_ids_[i]);
        uint64_t b = i < module_bases_.size() ? module_bases_[i] : 0;
        for (int k = 0; k < 8; k++) out.push_back(uint8_t(b >> (k * 8)));
    }
    // prefix pool
    put32(uint32_t(prefix_pool_.size()));
    out.insert(out.end(), prefix_pool_.begin(), prefix_pool_.end());
    // sites
    put32(uint32_t(sites_.size()));
    uint8_t v[16];
    for (const auto& s : sites_) {
        size_t n = put_uvar(v, s.addr);      out.insert(out.end(), v, v + n);
        out.push_back(s.kind);
        n = put_uvar(v, s.branch_imm);       out.insert(out.end(), v, v + n);
        n = put_uvar(v, s.prefix_off);       out.insert(out.end(), v, v + n);
        n = put_uvar(v, s.prefix_len);       out.insert(out.end(), v, v + n);
        n = put_uvar(v, s.disasm_off);       out.insert(out.end(), v, v + n);
        n = put_uvar(v, s.disasm_len);       out.insert(out.end(), v, v + n);
        n = put_uvar(v, uint64_t(uint32_t(s.func_sym) + 1)); out.insert(out.end(), v, v + n);
        n = put_uvar(v, s.module_id);        out.insert(out.end(), v, v + n);
        out.push_back(s.n_ops);
        for (uint8_t i = 0; i < s.n_ops; i++) {
            const OpPlan& p = s.ops[i];
            out.push_back(p.kind);
            out.push_back(uint8_t(p.ctx_idx));
            out.push_back(p.name_id);
            out.push_back(uint8_t(p.simd_idx));
            out.push_back(p.op_flags);
            out.push_back(uint8_t(p.base_ctx_idx));
            out.push_back(uint8_t(p.index_ctx_idx));
            out.push_back(p.shift_type);
            out.push_back(p.shift_amt);
            n = put_var(v, p.disp);          out.insert(out.end(), v, v + n);
            out.push_back(p.size);
        }
    }
}

bool SiteArena::deserialize(const uint8_t* p, size_t len, SiteArena& out,
                            std::vector<std::string>& modules_out) {
    size_t o = 0;
    auto get32 = [&](uint32_t& v) -> bool {
        if (o + 4 > len) return false;
        v = p[o] | (p[o+1] << 8) | (uint32_t(p[o+2]) << 16) | (uint32_t(p[o+3]) << 24);
        o += 4; return true;
    };
    auto getbytes = [&](size_t n, std::string& s) -> bool {
        if (o + n > len) return false;
        s.assign((const char*)p + o, n); o += n; return true;
    };
    // version detection: v2 starts with the magic, v1 starts with the string
    // count (absence of the field means v1)
    bool v2 = false;
    {
        uint32_t first = 0;
        if (len >= 4) {
            size_t saved = o;
            if (get32(first) && first == META_V2_MAGIC) v2 = true;
            else o = saved;
        }
    }
    uint32_t nstr;
    if (!get32(nstr)) return false;
    for (uint32_t i = 0; i < nstr; i++) {
        uint32_t sl;
        if (!get32(sl)) return false;
        std::string s;
        if (!getbytes(sl, s)) return false;
        out.intern_string(s);
    }
    uint32_t nmod;
    if (!get32(nmod)) return false;
    for (uint32_t i = 0; i < nmod; i++) {
        uint32_t sid;
        if (!get32(sid)) return false;
        if (sid >= out.strings_.size()) return false;
        uint64_t base = 0;
        if (v2) {
            if (o + 8 > len) return false;
            for (int k = 0; k < 8; k++) base |= uint64_t(p[o + k]) << (k * 8);
            o += 8;
        }
        const std::string& m = out.strings_[sid];
        out.modules_.push_back(m);
        out.module_ids_[m] = out.modules_.size() - 1;
        out.module_bases_.push_back(base); // 0 for v1 (base unknown)
        modules_out.push_back(m);
    }
    uint32_t pool_sz;
    if (!get32(pool_sz)) return false;
    std::string pool;
    if (!getbytes(pool_sz, pool)) return false;
    out.prefix_pool_ = std::move(pool);
    uint32_t nsite;
    if (!get32(nsite)) return false;
    for (uint32_t i = 0; i < nsite; i++) {
        Site s;
        uint64_t u;
        int64_t sv;
        auto gv = [&]() -> bool {
            size_t n = get_uvar(p + o, len - o, u);
            if (!n) return false;
            o += n; return true;
        };
        auto gsv = [&]() -> bool {
            size_t n = get_var(p + o, len - o, sv);
            if (!n) return false;
            o += n; return true;
        };
        if (!gv()) return false; s.addr = u;
        if (o + 1 > len) return false; s.kind = p[o++];
        if (!gv()) return false; s.branch_imm = u;
        if (!gv()) return false; s.prefix_off = uint32_t(u);
        if (!gv()) return false; s.prefix_len = uint32_t(u);
        if (!gv()) return false; s.disasm_off = uint32_t(u);
        if (!gv()) return false; s.disasm_len = uint32_t(u);
        if (!gv()) return false; s.func_sym = int32_t(u - 1);
        if (v2) { // v1 has no module id: all sites belong to module 0
            if (!gv()) return false;
            s.module_id = uint32_t(u);
            if (s.module_id >= out.modules_.size()) return false;
        } else {
            s.module_id = 0;
        }
        if (o + 1 > len) return false; s.n_ops = p[o++];
        if (s.n_ops > 8) return false;
        for (uint8_t k = 0; k < s.n_ops; k++) {
            OpPlan& op = s.ops[k];
            if (o + 7 > len) return false;
            op.kind = p[o++];
            op.ctx_idx = int8_t(p[o++]);
            op.name_id = p[o++];
            if (v2) {
                if (o + 2 > len) return false;
                op.simd_idx = int8_t(p[o++]);
                op.op_flags = p[o++];
            } // else: defaults simd_idx=-1, op_flags=0
            op.base_ctx_idx = int8_t(p[o++]);
            op.index_ctx_idx = int8_t(p[o++]);
            op.shift_type = p[o++];
            op.shift_amt = p[o++];
            if (!gsv()) return false; op.disp = int32_t(sv);
            if (o + 1 > len) return false; op.size = p[o++];
        }
        out.sites_.push_back(std::move(s));
    }
    return true;
}

} // namespace gt
