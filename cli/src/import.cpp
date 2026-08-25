// gt import — upstream GumTrace text log -> .gtb.
//
// The upstream printer's line grammar (observed in real logs):
//   insn:  [mod] 0xABS!0xOFF disasm; tok tok ... [-> tok ...] <EOL>
//          tok = name=0xhex | mem_r=0xhex | mem_w=0xhex   (each followed by ' ')
//   call:  call func: name() | call func: name(0x.., 0x..) <EOL>
//   ret:   ret: 0xhex <EOL>
//   anything else (args0: previews, banners, merged pure-store lines, ...)
//          -> EV_VERBATIM, replayed byte-for-byte
//
// Byte-exactness contract: a line is imported structurally ONLY if the
// upstream renderer (Expander::expand_upstream) reproduces it byte-for-byte.
// Anything off-grammar — non-canonical hex (uppercase, leading zeros), tokens
// without their trailing space, >8 tokens (plan/obs caps), unclassifiable
// register names, unterminated last line — goes to VERBATIM instead. The
// importer never guesses.
//
// Emission per instruction line:
//   EXEC(site)                       site built from the text by intern_text
//   RDVAL(name, val) per read token  rendered read list (incl. old values of
//     + imp_mem for mem_r/mem_w      written regs); mem tokens dual-emit so
//                                    queries see them as MemOps too
//   SIMDV(name, val) per write token the "-> " tail; x/w/fp/lr/sp names also
//     + REGW for classifiable ints   emit REGW so register reconstruction
//                                    (queries, taint, compact export) works
// Call/ret lines ride the preceding group (that is where upstream prints
// them); a second call on an open group closes it (decoder-side).

#include <traceq/import.h>
#include <traceq/site.h>
#include <traceq/common.h>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unordered_map>

namespace gt {

namespace {

struct Tok {
    const char* name;   // slice into the mapped log (NOT null-terminated)
    size_t name_len;
    unsigned __int128 val;
    uint8_t kind;       // OP_REG_R / OP_REG_W / OP_MEM_R / OP_MEM_W
    bool wide;          // value needed > 64 bits
};

bool hex_digit(char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); }

// Canonical lowercase hex: no leading zeros unless the value is 0 ("0" alone),
// lowercase only — exactly what legacy_hex64/128 emit. Anything else must go
// to VERBATIM because the renderer would print it differently.
bool parse_hex_canon(const char* p, const char* end, unsigned __int128& v, bool& wide) {
    size_t n = size_t(end - p);
    if (n == 0 || n > 32) return false;
    if (n > 1 && p[0] == '0') return false; // leading zeros
    uint64_t lo = 0, hi = 0;
    if (n <= 16) {
        for (size_t i = 0; i < n; i++) {
            if (!hex_digit(p[i])) return false;
            char c = p[i];
            lo = (lo << 4) | uint64_t(c <= '9' ? c - '0' : c - 'a' + 10);
        }
        v = lo;
        wide = false;
        return true;
    }
    // 17..32 digits: hi = first n-16 (its top digit is non-zero by the rule
    // above), lo = last 16 exactly (legacy_hex128 prints lo fixed-width)
    size_t nh = n - 16;
    for (size_t i = 0; i < nh; i++) {
        if (!hex_digit(p[i])) return false;
        char c = p[i];
        hi = (hi << 4) | uint64_t(c <= '9' ? c - '0' : c - 'a' + 10);
    }
    for (size_t i = nh; i < n; i++) {
        if (!hex_digit(p[i])) return false;
        char c = p[i];
        lo = (lo << 4) | uint64_t(c <= '9' ? c - '0' : c - 'a' + 10);
    }
    v = ((unsigned __int128)hi << 64) | lo;
    wide = true;
    return true;
}

// name charset for value tokens: [a-z0-9_.]{1,15} ("x8", "w19", "fp", "v0", ...)
bool name_ok(const char* p, size_t n) {
    if (n == 0 || n > 15) return false;
    for (size_t i = 0; i < n; i++) {
        char c = p[i];
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '.'))
            return false;
    }
    return true;
}

struct Importer {
    const char* base;   // mmap base
    size_t len;
    SiteArena arena;
    GtbRecorder rec;
    ImportCounts cnt;
    std::unordered_map<std::string, uint64_t> mod_bases;
    // last-module cache: consecutive lines almost always share the module
    std::string last_mod;
    uint64_t last_base = 0;
    bool crlf = false;
    bool stopped = false;
    bool in_hexdump_ = false; // verbatim lines currently inside a dump block

    Importer(const char* p, size_t n) : base(p), len(n), rec(arena) {}

    uint32_t name_id(const char* s, size_t n) {
        char buf[16];
        memcpy(buf, s, n);
        buf[n] = 0;
        return uint32_t(arena.symbol_id(buf));
    }

    void verbatim(const char* ls, const char* le) { // [ls, le) incl. line ending
        cnt.verbatim++;
        rec.imp_verbatim(ls, size_t(le - ls));
    }

    // Parse one instruction line body [b, be) (line ending excluded).
    // On success emits events and returns true; false = caller sends VERBATIM.
    bool instruction(const char* b, const char* be) {
        const char* p = b;
        const char* e = be;
        // [mod] 0xABS!0xOFF disasm; ...
        if (e - p < 8 || *p != '[') return false;
        const char* rb = (const char*)memchr(p + 1, ']', size_t(e - p - 1));
        if (!rb) return false;
        const char* mod = p + 1;
        size_t mod_len = size_t(rb - mod);
        if (mod_len == 0 || mod_len > 255) return false;
        p = rb + 1;
        if (p + 3 > e || p[0] != ' ' || p[1] != '0' || p[2] != 'x') return false;
        p += 3;
        const char* abs0 = p;
        while (p < e && hex_digit(*p)) p++;
        unsigned __int128 abs_v, off_v;
        bool wide;
        if (!parse_hex_canon(abs0, p, abs_v, wide) || wide) return false;
        if (p + 4 > e || p[0] != '!' || p[1] != '0' || p[2] != 'x') return false;
        p += 3;
        const char* off0 = p;
        while (p < e && hex_digit(*p)) p++;
        if (!parse_hex_canon(off0, p, off_v, wide) || wide) return false;
        uint64_t abs = uint64_t(abs_v), off = uint64_t(off_v);
        if (abs < off) return false;
        if (p >= e || *p != ' ') return false;
        p++;
        // The upstream instruction prefix ends at the first "; ".
        const char* semi = nullptr;
        for (const char* q = p; q + 1 < e; q++)
            if (q[0] == ';' && q[1] == ' ') { semi = q; break; }
        if (!semi || semi == p) return false;
        size_t prefix_len = size_t(semi + 2 - b); // includes the trailing space
        p = semi + 2;

        // tokens
        Tok rd[8], wr[8];
        int n_rd = 0, n_wr = 0;
        bool in_write = false, have_arrow = false;
        while (p < e) {
            const char* q = (const char*)memchr(p, ' ', size_t(e - p));
            if (!q) return false; // every token is followed by a space
            size_t tl = size_t(q - p);
            if (tl == 0) return false;
            if (tl == 2 && p[0] == '-' && p[1] == '>') {
                if (have_arrow) return false;
                have_arrow = true;
                in_write = true;
                p = q + 1;
                continue;
            }
            // name=0xval
            const char* eq = (const char*)memchr(p, '=', tl);
            if (!eq) return false;
            const char* vs = eq + 1;
            if (size_t(q - vs) < 3 || vs[0] != '0' || vs[1] != 'x') return false;
            unsigned __int128 v;
            if (!parse_hex_canon(vs + 2, q, v, wide)) return false;
            size_t nl = size_t(eq - p);
            Tok t{p, nl, v, OP_REG_R, wide};
            uint8_t kind;
            if (nl == 5 && memcmp(p, "mem_r", 5) == 0) kind = OP_MEM_R;
            else if (nl == 5 && memcmp(p, "mem_w", 5) == 0) kind = OP_MEM_W;
            else if (!name_ok(p, nl)) return false;
            else kind = in_write ? OP_REG_W : OP_REG_R;
            t.kind = kind;
            if (kind == OP_MEM_R || kind == OP_MEM_W) {
                if (in_write) return false; // mem tokens never follow "->"
                if (wide) return false;     // an address is 64-bit
            }
            if (in_write) {
                if (n_wr >= 8) return false;
                wr[n_wr++] = t;
            } else {
                if (n_rd >= 8) return false;
                rd[n_rd++] = t;
            }
            p = q + 1;
        }
        // plan holds every printed token in print order (reads incl. mem ops,
        // then writes); site/obs caps make >8 unrepresentable
        if (n_rd + n_wr > 8) return false;

        TextOp tops[8];
        for (int i = 0; i < n_rd; i++)
            tops[i] = TextOp{rd[i].name, rd[i].name_len, rd[i].kind};
        for (int i = 0; i < n_wr; i++)
            tops[n_rd + i] = TextOp{wr[i].name, wr[i].name_len, wr[i].kind};

        std::string mod_s(mod, mod_len);
        uint64_t mbase;
        if (mod_s == last_mod) {
            mbase = last_base;
        } else {
            uint64_t computed = abs - off;
            auto it = mod_bases.find(mod_s);
            if (it == mod_bases.end()) {
                mbase = computed;
                mod_bases[mod_s] = computed;
            } else {
                mbase = it->second; // first-seen base wins (ASLR is per run)
            }
            last_mod = mod_s;
            last_base = mbase;
        }

        uint32_t site = arena.intern_text(abs, b, prefix_len, mod_s.c_str(), mbase,
                                          tops, n_rd + n_wr);
        if (site == 0xFFFFFFFFu) return false;

        cnt.exec++;
        rec.imp_exec(site);
        for (int i = 0; i < n_rd; i++) {
            const Tok& t = rd[i];
            uint32_t nid = name_id(t.name, t.name_len);
            if (t.kind == OP_MEM_R || t.kind == OP_MEM_W) {
                rec.imp_rdval(nid, uint64_t(t.val)); // prints "mem_r=0xADDR "
                rec.imp_mem(t.kind == OP_MEM_W, uint64_t(t.val), 0);
            } else if (t.wide) {
                rec.imp_rdval128(nid, t.val);
            } else {
                rec.imp_rdval(nid, uint64_t(t.val));
            }
        }
        for (int i = 0; i < n_wr; i++) {
            const Tok& t = wr[i];
            uint32_t nid = name_id(t.name, t.name_len);
            if (t.wide) rec.imp_wval128(nid, t.val);
            else rec.imp_wval(nid, uint64_t(t.val));
            if (!t.wide) {
                int simd = -1;
                int ctx = text_name_ctx(t.name, t.name_len, &simd);
                if (ctx >= 0) rec.imp_regw(ctx, uint64_t(t.val));
            }
        }
        return true;
    }

    // call func: / call jni func: name(0x.., 0x..) — bare hex args, 0..8.
    // A private string-pool prefix preserves the JNI spelling without adding
    // another event tag; the expander strips it before exposing call_name.
    bool call_line(const char* b, const char* be) {
        static const char kPre[] = "call func: ";
        static const char kJniPre[] = "call jni func: ";
        static const char kJniSym[] = "\x1fJNI:";
        size_t pl = 0;
        bool is_jni = false;
        if (size_t(be - b) >= sizeof(kPre) - 1 + 3 &&
            memcmp(b, kPre, sizeof(kPre) - 1) == 0) {
            pl = sizeof(kPre) - 1;
        } else if (size_t(be - b) >= sizeof(kJniPre) - 1 + 3 &&
                   memcmp(b, kJniPre, sizeof(kJniPre) - 1) == 0) {
            pl = sizeof(kJniPre) - 1;
            is_jni = true;
        } else {
            return false;
        }
        const char* p = b + pl;
        const char* lp = (const char*)memchr(p, '(', size_t(be - p));
        if (!lp || lp == p) return false;
        const char* name = p;
        size_t name_len = size_t(lp - p);
        p = lp + 1;
        uint64_t args[8];
        int na = 0;
        if (p < be && *p == ')') {
            p++;
        } else {
            while (true) {
                if (na >= 8) return false;
                if (p + 3 > be || p[0] != '0' || p[1] != 'x') return false;
                const char* v0 = p + 2;
                const char* q = v0;
                while (q < be && hex_digit(*q)) q++;
                unsigned __int128 v;
                bool wide;
                if (!parse_hex_canon(v0, q, v, wide) || wide) return false;
                args[na++] = uint64_t(v);
                p = q;
                if (p < be && *p == ')') { p++; break; }
                if (p + 2 <= be && p[0] == ',' && p[1] == ' ') { p += 2; continue; }
                return false;
            }
        }
        if (p != be) return false;
        std::string sym_name;
        if (is_jni) sym_name.assign(kJniSym, sizeof(kJniSym) - 1);
        sym_name.append(name, name_len);
        cnt.call++;
        rec.imp_call(uint32_t(arena.symbol_id(sym_name.c_str())), args, na);
        return true;
    }

    // ret: 0xhex
    bool ret_line(const char* b, const char* be) {
        static const char kPre[] = "ret: 0x";
        size_t pl = sizeof(kPre) - 1;
        if (size_t(be - b) <= pl || memcmp(b, kPre, pl) != 0) return false;
        unsigned __int128 v;
        bool wide;
        if (!parse_hex_canon(b + pl, be, v, wide) || wide) return false;
        cnt.ret++;
        rec.imp_ret(uint64_t(v));
        return true;
    }

    bool run(const std::string& out_path, const RecOptions& opts, ImportResult& res) {
        // Preserve the source line ending for byte-exact replay.
        const char* nl0 = (const char*)memchr(base, '\n', len);
        crlf = nl0 && nl0 > base && nl0[-1] == '\r';
        rec.set_crlf(crlf);
        if (!rec.open(out_path, opts)) return false;
        const char* p = base;
        const char* end = base + len;
        while (p < end) {
            const char* nl = (const char*)memchr(p, '\n', size_t(end - p));
            const char* le = nl ? nl + 1 : end;      // one past the line ending
            const char* be = nl ? nl : end;          // before '\n'
            if (be > p && be[-1] == '\r') be--;      // ... and before '\r'
            cnt.lines++;
            if (!rec.imp_gate()) { stopped = true; break; }
            bool ok = false;
            if (be > p) {
                if (*p == '[') ok = instruction(p, be);
                else if (*p == 'c') ok = call_line(p, be);
                else if (*p == 'r') ok = ret_line(p, be);
            }
            if (!ok) {
                // unterminated last line included: the renderer always
                // appends a line ending, so only VERBATIM replays it exactly.
                // hexdump content observations: inside a dump block each row
                // synthesizes value-known mem READ lanes (full qwords only),
                // recorded BEFORE its verbatim record so they ride the same
                // group (a mem-only group never flushes on its own). The raw
                // line is still stored verbatim — byte-exact replay is kept.
                uint64_t raddr = 0, hlen = 0;
                uint8_t bytes[16];
                int nb = 0;
                if (in_hexdump_ &&
                    parse_hexdump_row(p, size_t(be - p), raddr, bytes, nb)) {
                    for (int k = 0; k + 8 <= nb; k += 8) {
                        uint64_t v;
                        memcpy(&v, bytes + k, 8);
                        rec.imp_mem_val(false, raddr + uint64_t(k), 8, v);
                    }
                } else {
                    in_hexdump_ =
                        parse_hexdump_header(p, size_t(be - p), raddr, hlen);
                }
                verbatim(p, le);
            } else {
                in_hexdump_ = false;
            }
            p = le;
        }
        res.stats = rec.finish();
        res.cnt = cnt;
        res.in_bytes = len;
        res.stopped = stopped;
        struct stat sb;
        res.gtb_bytes = stat(out_path.c_str(), &sb) == 0 ? uint64_t(sb.st_size) : 0;
        return rec.ok();
    }
};

} // namespace

// "hexdump at address 0x<addr> with length 0x<len>:" — upstream dumps the
// SOURCE buffer of a memcpy-class call right after the call line. Shared by
// the importer (row content synthesis) and the query layer (taint bridging,
// find-value payload scan).
bool parse_hexdump_header(const char* p, size_t n, uint64_t& addr,
                          uint64_t& len) {
    static const char kPre[] = "hexdump at address 0x";
    static const char kMid[] = " with length 0x";
    size_t i = 0;
    auto eat = [&](const char* w, size_t l) {
        if (i + l > n || memcmp(p + i, w, l)) return false;
        i += l;
        return true;
    };
    auto hex = [&](uint64_t& v) {
        size_t s = i;
        v = 0;
        while (i < n && ((p[i] >= '0' && p[i] <= '9') ||
                         (p[i] >= 'a' && p[i] <= 'f') ||
                         (p[i] >= 'A' && p[i] <= 'F'))) {
            char c = p[i++];
            v = (v << 4) | uint64_t(c <= '9' ? c - '0'
                                             : (c | 32) - 'a' + 10);
        }
        return i > s;
    };
    return eat(kPre, sizeof(kPre) - 1) && hex(addr) &&
           eat(kMid, sizeof(kMid) - 1) && hex(len);
}

bool parse_hexdump_row(const char* p, size_t n, uint64_t& addr,
                       uint8_t out[16], int& n_out) {
    auto hexval = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    size_t i = 0;
    // address: 4..16 hex digits (the 4-digit floor keeps banner fragments
    // like "ab cd" from parsing as rows), optional ':'
    uint64_t a = 0;
    int hd = 0;
    while (i < n && hd < 16) {
        int v = hexval(p[i]);
        if (v < 0) break;
        a = (a << 4) | uint64_t(v);
        i++;
        hd++;
    }
    if (hd < 4) return false;
    if (i < n && p[i] == ':') i++;
    if (i >= n || p[i] != ' ') return false;
    while (i < n && p[i] == ' ') i++;
    // 1..16 byte pairs, space-separated; '|' gutter or line ending ends it
    int nb = 0;
    while (i < n && nb < 16) {
        if (p[i] == '|' || p[i] == '\r' || p[i] == '\n') break;
        int hi = hexval(p[i]);
        if (hi < 0 || i + 1 >= n) return false;
        int lo = hexval(p[i + 1]);
        if (lo < 0) return false;
        out[nb++] = uint8_t((hi << 4) | lo);
        i += 2;
        if (i >= n || p[i] == '|' || p[i] == '\r' || p[i] == '\n') break;
        if (p[i] != ' ') return false; // adjacent pairs are not the format
        while (i < n && p[i] == ' ') i++;
    }
    if (!nb) return false;
    addr = a;
    n_out = nb;
    return true;
}

bool import_mem(const char* p, size_t len, const std::string& out_path,
                const RecOptions& opts_in, ImportResult& res) {
    Importer imp(p, len);
    return imp.run(out_path, opts_in, res);
}

bool import_log(const std::string& in_path, const std::string& out_path,
                const RecOptions& opts, ImportResult& res) {
    int fd = ::open(in_path.c_str(), O_RDONLY);
    if (fd < 0) return false;
    struct stat sb;
    if (fstat(fd, &sb) != 0 || sb.st_size == 0) {
        ::close(fd);
        return false;
    }
    size_t len = size_t(sb.st_size);
    const char* p = (const char*)mmap(nullptr, len, PROT_READ, MAP_PRIVATE, fd, 0);
    ::close(fd);
    if (p == MAP_FAILED) return false;
    bool ok = import_mem(p, len, out_path, opts, res);
    munmap((void*)p, len);
    return ok;
}

} // namespace gt

// ---------------------------------------------------------------------------
// CLI front-end
// ---------------------------------------------------------------------------
int cmd_import(int argc, char** argv) {
    std::string in, out;
    gt::RecOptions opts;
    for (int i = 1; i < argc; i++) {
        auto next = [&]() -> const char* { return i + 1 < argc ? argv[++i] : ""; };
        if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
            printf("usage: gt import trace.log -o trace.gtb [--max-events N] "
                   "[--max-bytes N] [--max-ms N]\n");
            return 0;
        }
        else if (!strcmp(argv[i], "-o")) out = next();
        else if (!strcmp(argv[i], "--max-events")) opts.max_events = strtoull(next(), nullptr, 10);
        else if (!strcmp(argv[i], "--max-bytes")) opts.max_bytes = strtoull(next(), nullptr, 10);
        else if (!strcmp(argv[i], "--max-ms")) opts.max_ms = strtoull(next(), nullptr, 10);
        else if (argv[i][0] != '-') in = argv[i];
        else {
            fprintf(stderr, "import: unknown option %s\n", argv[i]);
            fprintf(stderr, "try: gt import --help\n");
            return 2;
        }
    }
    if (in.empty() || out.empty()) {
        fprintf(stderr, "usage: gt import trace.log -o trace.gtb [--max-events N]\n");
        return 2;
    }
    gt::ImportResult r;
    uint64_t t0 = gt::now_ns();
    if (!gt::import_log(in, out, opts, r)) {
        fprintf(stderr, "import: cannot read %s or write %s\n", in.c_str(), out.c_str());
        return 1;
    }
    double ms = double(gt::now_ns() - t0) / 1e6;
    printf("{\"import\":{\"lines\":%llu,\"exec\":%llu,\"call\":%llu,\"ret\":%llu,"
           "\"verbatim\":%llu,\"in_bytes\":%llu,\"gtb_bytes\":%llu,\"ms\":%.1f,"
           "\"stop\":%d%s}}\n",
           (unsigned long long)r.cnt.lines, (unsigned long long)r.cnt.exec,
           (unsigned long long)r.cnt.call, (unsigned long long)r.cnt.ret,
           (unsigned long long)r.cnt.verbatim, (unsigned long long)r.in_bytes,
           (unsigned long long)r.gtb_bytes, ms, int(r.stats.reason),
           r.stopped ? ",\"stopped\":true" : "");
    return 0;
}
