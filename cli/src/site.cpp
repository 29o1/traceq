#include <traceq/site.h>
#include <traceq/varint.h>
#include <cstring>

namespace gt {

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

int32_t SiteArena::intern_string(const std::string& s) {
    auto it = str_ids_.find(s);
    if (it != str_ids_.end()) return int32_t(it->second);
    str_ids_[s] = strings_.size();
    strings_.push_back(s);
    return int32_t(strings_.size() - 1);
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

// mnemonic -> NZCV flags / site kind for plans built from imported text
static uint8_t mnem_nzcv(const char* m, size_t n) {
    auto is = [&](const char* w) {
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

// mnemonic -> NZCV flags / site kind for plans built from imported text
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
