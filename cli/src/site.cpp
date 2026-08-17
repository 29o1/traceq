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
    } else {
        module_id = mid->second;
    }
    (void)module_id; // module implied by arena; expansion uses module of trace

    Site s;
    s.addr = addr;
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
            if (idx < 0 || name < 0) continue; // SIMD/psr unsupported in this harness
            bool r = is_cmp || (op.access & CS_AC_READ);
            bool w = !is_cmp && (op.access & CS_AC_WRITE);
            if (r && w) {
                s.ops[s.n_ops].kind = OP_REG_R;  s.ops[s.n_ops].ctx_idx = int8_t(idx);
                s.ops[s.n_ops].name_id = uint8_t(name); s.n_ops++;
                if (s.n_ops < 8) {
                    s.ops[s.n_ops].kind = OP_REG_W;  s.ops[s.n_ops].ctx_idx = int8_t(idx);
                    s.ops[s.n_ops].name_id = uint8_t(name); s.n_ops++;
                }
            } else if (r) {
                s.ops[s.n_ops].kind = OP_REG_R;  s.ops[s.n_ops].ctx_idx = int8_t(idx);
                s.ops[s.n_ops].name_id = uint8_t(name); s.n_ops++;
            } else if (w) {
                s.ops[s.n_ops].kind = OP_REG_W;  s.ops[s.n_ops].ctx_idx = int8_t(idx);
                s.ops[s.n_ops].name_id = uint8_t(name); s.n_ops++;
            }
        } else if (op.type == ARM64_OP_MEM) {
            OpPlan& p = s.ops[s.n_ops];
            p.kind = (op.access & CS_AC_WRITE) ? OP_MEM_W : OP_MEM_R;
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
                s.ops[s.n_ops].kind = OP_REG_W;
                s.ops[s.n_ops].ctx_idx = int8_t(ctx_idx_of(op.mem.base));
                s.ops[s.n_ops].name_id = uint8_t(name_id_of(op.mem.base));
                s.n_ops++;
            }
        }
    }

    by_addr_[addr] = sites_.size();
    sites_.push_back(std::move(s));
    return uint32_t(sites_.size() - 1);
}

// ---------------------------------------------------------------------------
// Serialization
// ---------------------------------------------------------------------------
void SiteArena::serialize(std::vector<uint8_t>& out) const {
    auto put32 = [&](uint32_t v) {
        for (int i = 0; i < 4; i++) out.push_back(uint8_t(v >> (i * 8)));
    };
    // strings
    put32(uint32_t(strings_.size()));
    for (const auto& s : strings_) {
        put32(uint32_t(s.size()));
        out.insert(out.end(), s.begin(), s.end());
    }
    // modules (string ids)
    put32(uint32_t(modules_.size()));
    for (size_t i = 0; i < modules_.size(); i++) {
        put32(module_str_ids_[i]);
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
        out.push_back(s.n_ops);
        for (uint8_t i = 0; i < s.n_ops; i++) {
            const OpPlan& p = s.ops[i];
            out.push_back(p.kind);
            out.push_back(uint8_t(p.ctx_idx));
            out.push_back(p.name_id);
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
        const std::string& m = out.strings_[sid];
        out.modules_.push_back(m);
        out.module_ids_[m] = out.modules_.size() - 1;
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
        if (o + 1 > len) return false; s.n_ops = p[o++];
        if (s.n_ops > 8) return false;
        for (uint8_t k = 0; k < s.n_ops; k++) {
            OpPlan& op = s.ops[k];
            if (o + 7 > len) return false;
            op.kind = p[o++];
            op.ctx_idx = int8_t(p[o++]);
            op.name_id = p[o++];
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
