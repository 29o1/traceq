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

static int taint_reg_slot(const char* p, size_t n) {
    int simd = -1;
    int ctx = text_name_ctx(p, n, &simd);
    if (ctx >= 0) return ctx & 31;
    if (simd >= 0) return 32 + simd;
    return -1;
}

static constexpr uint8_t NZCV_READ = 1;
static constexpr uint8_t NZCV_WRITE = 2;

// Mnemonic -> NZCV dependencies for plans built from imported text.
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
        f |= NZCV_WRITE;
    if (is("ccmp") || is("ccmn")) f |= NZCV_READ | NZCV_WRITE;
    if (pre("b.") || is("csel") || is("csinc") || is("csinv") || is("cset") ||
        is("csetm") || is("cneg") || is("fcsel"))
        f |= NZCV_READ;
    return f;
}

// Mnemonic -> structural instruction kind.
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
    if (is("blr") || pre("blraa") || pre("blrab"))
        return SK_CALL_REG;
    if (is("br") || pre("braa") || pre("brab")) return SK_BR;
    if (is("ret") || pre("retaa") || pre("retab")) return SK_RET;
    if (is("svc")) return SK_SVC;
    if (pre("b.")) return SK_BCOND;
    if (is("b")) return SK_B_IMM;
    return SK_NORMAL;
}

static TaintCat taint_classify(const char* m, size_t n) {
    auto is = [&](const char* w) {
        size_t l = strlen(w);
        return n == l && memcmp(m, w, l) == 0;
    };
    if (is("movz") || is("movn") || is("adr") || is("adrp"))
        return TC_IMM_LOAD;
    if (is("movk")) return TC_PARTIAL;
    if (is("cmp") || is("cmn") || is("tst") || is("ccmp") ||
        is("ccmn") || is("fcmp") || is("fccmp") || is("fcmpe") ||
        is("fccmpe"))
        return TC_COMPARE;
    if (is("ldr") || is("ldrb") || is("ldrh") || is("ldrsw") ||
        is("ldrsb") || is("ldrsh") || is("ldur") || is("ldurb") ||
        is("ldurh") || is("ldursw") || is("ldursb") || is("ldursh") ||
        is("ldp") || is("ldpsw") || is("ldar") || is("ldarb") ||
        is("ldarh") || is("ldxr") || is("ldaxr") || is("ldxrb") ||
        is("ldaxrb") || is("ldxrh") || is("ldaxrh") || is("ldxp") ||
        is("ldaxp") || is("ldnp") || is("ldtr") || is("ldtrb") ||
        is("ldtrh") || is("ldtrsw") || is("ldtrsb") || is("ldtrsh"))
        return TC_LOAD;
    if (is("str") || is("strb") || is("strh") || is("stur") ||
        is("sturb") || is("sturh") || is("stp") || is("stlr") ||
        is("stlrb") || is("stlrh") || is("stxr") || is("stlxr") ||
        is("stxrb") || is("stlxrb") || is("stxrh") || is("stlxrh") ||
        is("stxp") || is("stlxp"))
        return TC_STORE;
    if (is("nop") || is("cbz") || is("cbnz") || is("svc") || is("dmb") ||
        is("dsb") || is("dc") || is("isb") || is("ic") || is("b") ||
        is("bl") || is("br") || is("blr") || is("bti") || is("ret") ||
        is("retaa") || is("retab") || is("paciasp") || is("pacibsp") ||
        is("pacia") || is("pacib") || is("pacda") || is("pacdb") ||
        is("prfm") || is("prfum"))
        return TC_BRANCH;
    if (n >= 5 && memcmp(m, "aut", 3) == 0) return TC_BRANCH;
    if (n >= 2 && m[0] == 'b' && m[1] == '.') return TC_BRANCH;
    return TC_OTHER;
}

static void taint_parse_ops(const char* ops, size_t ops_len, TaintPlan& ts) {
    struct Op { const char* p; size_t n; bool is_mem; };
    Op o[8];
    int no = 0;
    size_t seg = 0;
    int depth = 0;
    for (size_t i = 0; i <= ops_len && no < 8; i++) {
        char c = i < ops_len ? ops[i] : '\0';
        if (c == '[') depth++;
        else if (c == ']') depth--;
        if ((c == ',' && depth == 0) || c == '\0') {
            size_t s = seg, e = i;
            while (s < e && (ops[s] == ' ' || ops[s] == '\t')) s++;
            while (e > s && (ops[e - 1] == ' ' || ops[e - 1] == '\t')) e--;
            if (e > s) o[no++] = {ops + s, e - s, ops[s] == '['};
            seg = i + 1;
        }
    }
    if (!no) return;
    ts.elem = (o[0].n && (o[0].p[0] == 'w' || o[0].p[0] == 'W')) ? 4 : 8;

    auto alnum = [](char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
               (c >= '0' && c <= '9');
    };
    auto lead_tok = [&](const Op& op) {
        size_t i = 0;
        while (i < op.n && alnum(op.p[i])) i++;
        return i ? taint_reg_slot(op.p, i) : -1;
    };
    auto add_src = [&](int slot) {
        if (slot >= 0) ts.src_mask |= 1ULL << slot;
    };
    auto add_dst = [&](int slot) {
        if (slot < 0) return;
        ts.dst_mask |= 1ULL << slot;
        if (ts.n_dsts < 2) ts.dsts[ts.n_dsts++] = uint8_t(slot);
    };
    auto add_st = [&](int slot) {
        if (slot < 0) return;
        if (ts.n_st < 2) ts.st[ts.n_st++] = uint8_t(slot);
        add_src(slot);
    };
    auto bracket_srcs = [&](const Op& op) {
        bool have_base = false;
        uint64_t seen = 0;
        for (size_t j = 0; j < op.n; j++) {
            char c = op.p[j];
            if (c != '[' && c != ',' && c != ' ') continue;
            size_t k = j + 1;
            while (k < op.n && op.p[k] == ' ') k++;
            if (k >= op.n || op.p[k] == '#' || op.p[k] == ']' ||
                op.p[k] == '!')
                continue;
            size_t t = k;
            while (t < op.n && alnum(op.p[t])) t++;
            int slot = taint_reg_slot(op.p + k, t - k);
            if (slot < 0 || (seen & (1ULL << slot))) continue;
            seen |= 1ULL << slot;
            add_src(slot);
            if (have_base) ts.index_mask |= 1ULL << slot;
            else have_base = true;
        }
    };

    switch (ts.cat) {
    case TC_BRANCH:
    case TC_COMPARE:
        for (int i = 0; i < no; i++) {
            if (o[i].is_mem) bracket_srcs(o[i]);
            else add_src(lead_tok(o[i]));
        }
        break;
    case TC_STORE:
        for (int i = 0; i < no; i++) {
            if (o[i].is_mem) bracket_srcs(o[i]);
            else add_st(lead_tok(o[i]));
        }
        break;
    default: {
        bool pair_load = ts.cat == TC_LOAD && ts.pair;
        for (int i = 0; i < no; i++) {
            if (o[i].is_mem) { bracket_srcs(o[i]); continue; }
            int slot = lead_tok(o[i]);
            if (slot < 0) continue;
            if (i == 0 || (pair_load && i == 1)) add_dst(slot);
            else add_src(slot);
        }
        break;
    }
    }
}

static TaintPlan build_taint_plan(const char* dis, size_t dn, size_t mn,
                                  uint8_t nzcv) {
    TaintPlan ts;
    ts.cat = taint_classify(dis, mn);
    auto is = [&](const char* w) {
        size_t l = strlen(w);
        return mn == l && memcmp(dis, w, l) == 0;
    };
    ts.pair = is("stp") || is("ldp") || is("ldpsw") || is("ldxp") ||
              is("ldaxp") || is("ldnp");
    if (mn < dn) taint_parse_ops(dis + mn + 1, dn - mn - 1, ts);
    ts.nzcv_r = (nzcv & NZCV_READ) != 0;
    ts.nzcv_w = (nzcv & NZCV_WRITE) != 0;
    return ts;
}

static int8_t branch_reg(const char* dis, size_t len, size_t mn_len) {
    size_t p = mn_len;
    while (p < len && dis[p] == ' ') p++;
    size_t e = p;
    while (e < len && dis[e] != ',' && dis[e] != ' ') e++;
    int simd = -1;
    int ctx = text_name_ctx(dis + p, e - p, &simd);
    return int8_t(ctx >= 0 && ctx < 32 ? ctx : -1);
}

static uint8_t pair_stride(const char* dis, size_t len, size_t mn_len) {
    bool ldp = mn_len == 3 && !memcmp(dis, "ldp", 3);
    bool stp = mn_len == 3 && !memcmp(dis, "stp", 3);
    bool ldpsw = mn_len == 5 && !memcmp(dis, "ldpsw", 5);
    if (!ldp && !stp && !ldpsw) return 0;
    if (ldpsw) return 4;
    size_t op = mn_len;
    while (op < len && dis[op] == ' ') op++;
    if (op >= len) return 0;
    if (dis[op] == 'w' || dis[op] == 's') return 4;
    if (dis[op] == 'q') return 16;
    return 8;
}

static uint8_t mem_width(const char* dis, size_t len, size_t mn_len) {
    auto starts = [&](const char* pfx) {
        size_t l = strlen(pfx);
        return mn_len >= l && memcmp(dis, pfx, l) == 0;
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
    uint8_t pair = pair_stride(dis, len, mn_len);
    if (pair) return pair;
    size_t op = mn_len;
    while (op < len && dis[op] == ' ') op++;
    if (op >= len) return 0;
    switch (dis[op]) {
    case 'b': case 'B': return 1;
    case 'h': case 'H': return 2;
    case 'w': case 'W': case 's': case 'S': return 4;
    case 'x': case 'X': case 'd': case 'D': return 8;
    case 'q': case 'Q': return 16;
    default: return 0;
    }
}

static uint64_t branch_target(const char* disasm, size_t len, size_t mn_len) {
    size_t p = mn_len;
    while (p < len && disasm[p] == ' ') p++;
    if (p < len && disasm[p] == '#') p++;
    if (p + 2 > len || disasm[p] != '0' ||
        (disasm[p + 1] != 'x' && disasm[p + 1] != 'X'))
        return 0;
    p += 2;
    uint64_t value = 0;
    bool any = false;
    while (p < len) {
        unsigned digit;
        char c = disasm[p];
        if (c >= '0' && c <= '9') digit = unsigned(c - '0');
        else if (c >= 'a' && c <= 'f') digit = unsigned(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') digit = unsigned(c - 'A' + 10);
        else break;
        if (value > (UINT64_MAX - digit) / 16) return 0;
        value = value * 16 + digit;
        any = true;
        p++;
    }
    return any ? value : 0;
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
    s.kind = mnem_kind(prefix + dis_off, mn_len);
    if (s.kind == SK_CALL_IMM || s.kind == SK_B_IMM)
        s.branch_imm = branch_target(prefix + dis_off, dis_len, mn_len);
    if (s.kind == SK_CALL_REG || s.kind == SK_BR)
        s.branch_reg = branch_reg(prefix + dis_off, dis_len, mn_len);
    uint8_t nzcv = mnem_nzcv(prefix + dis_off, mn_len);
    s.mem_width = mem_width(prefix + dis_off, dis_len, mn_len);
    s.pair_stride = pair_stride(prefix + dis_off, dis_len, mn_len);
    s.taint = build_taint_plan(prefix + dis_off, dis_len, mn_len, nzcv);

    // classify every operand first: a failure must not touch arena state
    // (the pool is append-only and the same line will be retried on every
    // occurrence in the log)
    OpPlan plans[8];
    for (int i = 0; i < n_tops; i++) {
        OpPlan& p = plans[i];
        p.kind = tops[i].kind;
        if (tops[i].kind != OP_MEM_R && tops[i].kind != OP_MEM_W) {
            int simd = -1;
            int ctx = text_name_ctx(tops[i].name, tops[i].name_len, &simd);
            if (ctx < 0 && simd < 0) return 0xFFFFFFFFu;
            p.ctx_idx = int8_t(ctx);
        }
    }

    s.prefix_off = prefix_pool_.size();
    prefix_pool_.append(prefix, prefix_len);
    s.prefix_len = uint32_t(prefix_len);
    s.disasm_off = s.prefix_off + uint32_t(dis_off);
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
        n = put_uvar(v, s.module_id);        out.insert(out.end(), v, v + n);
        out.push_back(s.kind);
        out.push_back(uint8_t(s.branch_reg));
        out.push_back(s.mem_width);
        out.push_back(s.pair_stride);
        n = put_uvar(v, s.branch_imm);       out.insert(out.end(), v, v + n);
        n = put_uvar(v, s.prefix_off);       out.insert(out.end(), v, v + n);
        n = put_uvar(v, s.prefix_len);       out.insert(out.end(), v, v + n);
        n = put_uvar(v, s.disasm_off);       out.insert(out.end(), v, v + n);
        n = put_uvar(v, s.disasm_len);       out.insert(out.end(), v, v + n);

        const TaintPlan& t = s.taint;
        out.push_back(t.cat);
        n = put_uvar(v, t.src_mask);         out.insert(out.end(), v, v + n);
        n = put_uvar(v, t.index_mask);       out.insert(out.end(), v, v + n);
        n = put_uvar(v, t.dst_mask);         out.insert(out.end(), v, v + n);
        out.push_back(t.dsts[0]);
        out.push_back(t.dsts[1]);
        out.push_back(t.n_dsts);
        out.push_back(t.st[0]);
        out.push_back(t.st[1]);
        out.push_back(t.n_st);
        out.push_back(t.pair);
        out.push_back(t.elem);
        out.push_back(t.nzcv_r);
        out.push_back(t.nzcv_w);

        out.push_back(s.n_ops);
        for (uint8_t i = 0; i < s.n_ops; i++) {
            const OpPlan& p = s.ops[i];
            out.push_back(p.kind);
            out.push_back(uint8_t(p.ctx_idx));
        }
    }
}

bool SiteArena::deserialize(const uint8_t* p, size_t len, SiteArena& out) {
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
        if (sid >= out.strings_.size()) return false;
        uint64_t base = 0;
        if (o + 8 > len) return false;
        for (int k = 0; k < 8; k++) base |= uint64_t(p[o + k]) << (k * 8);
        o += 8;
        const std::string& m = out.strings_[sid];
        out.modules_.push_back(m);
        out.module_ids_[m] = out.modules_.size() - 1;
        out.module_str_ids_.push_back(sid);
        out.module_bases_.push_back(base);
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
        auto gv = [&]() -> bool {
            size_t n = get_uvar(p + o, len - o, u);
            if (!n) return false;
            o += n; return true;
        };
        if (!gv()) return false; s.addr = u;
        if (!gv() || u >= out.modules_.size()) return false;
        s.module_id = uint32_t(u);
        if (o + 4 > len) return false;
        s.kind = p[o++];
        s.branch_reg = int8_t(p[o++]);
        s.mem_width = p[o++];
        s.pair_stride = p[o++];
        if (!gv()) return false; s.branch_imm = u;
        if (!gv()) return false; s.prefix_off = uint32_t(u);
        if (!gv()) return false; s.prefix_len = uint32_t(u);
        if (!gv()) return false; s.disasm_off = uint32_t(u);
        if (!gv()) return false; s.disasm_len = uint32_t(u);

        TaintPlan& t = s.taint;
        if (o + 1 > len) return false;
        t.cat = p[o++];
        if (!gv()) return false; t.src_mask = u;
        if (!gv()) return false; t.index_mask = u;
        if (!gv()) return false; t.dst_mask = u;
        if (o + 10 > len) return false;
        t.dsts[0] = p[o++];
        t.dsts[1] = p[o++];
        t.n_dsts = p[o++];
        t.st[0] = p[o++];
        t.st[1] = p[o++];
        t.n_st = p[o++];
        t.pair = p[o++];
        t.elem = p[o++];
        t.nzcv_r = p[o++];
        t.nzcv_w = p[o++];
        if (t.cat > TC_BRANCH || t.n_dsts > 2 || t.n_st > 2) return false;

        if (o + 1 > len) return false; s.n_ops = p[o++];
        if (s.n_ops > 8) return false;
        for (uint8_t k = 0; k < s.n_ops; k++) {
            OpPlan& op = s.ops[k];
            if (o + 2 > len) return false;
            op.kind = p[o++];
            op.ctx_idx = int8_t(p[o++]);
            if (op.kind > OP_MEM_W) return false;
        }
        if (uint64_t(s.prefix_off) + s.prefix_len > out.prefix_pool_.size() ||
            uint64_t(s.disasm_off) + s.disasm_len > out.prefix_pool_.size())
            return false;
        out.by_addr_[s.addr] = out.sites_.size();
        out.sites_.push_back(std::move(s));
    }
    return o == len;
}

} // namespace gt
