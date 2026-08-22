// gt-test — libtraceq correctness suite.
//
// Fixture philosophy: no behavioral simulator. Tests use upstream-dialect
// text logs (hand-written, byte-exact canonical) and exercise the same
// import -> gtb -> query/export path that real GumTrace logs take.
//
// Coverage map (what each group pins down):
//   t_roundtrip  import/export byte-exactness: LF/CRLF, VERBATIM passthrough,
//                128-bit SIMD values, non-canonical hex rejection, determinism
//   t_gumtrace   current upstream JNI call spelling + auxiliary metadata,
//                structured func queries, CRLF byte-exact replay
//   t_dump       hexdump row -> mem_r content lanes; find-value dump scan;
//                verbatim-memcpy taint bridging (dst <- src cells)
//   t_taint      NZCV as source (subs -> csel), q/SIMD propagation, kill on
//                overwrite (movz), pure-dataflow (base reg does not taint),
//                backward walk (demand -> sources), matched counts
//   t_queries    query surface + agent contract on an imported file:
//                stat/find-pc/find-value/mem-access/func-args/calltree, export windows
//                and cursor, JSON Lines shape
//   t_diff       (module, offset) identity: inserted instruction diverges,
//                rebased copy compares identical

#include <traceq/import.h>
#include <traceq/ingest.h>
#include <traceq/queries.h>
#include <traceq/varint.h>

#include <csignal>
#include <cstdio>
#include <cstring>
#include <functional>
#include <string>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

using namespace gt;

static int g_pass = 0, g_fail = 0;

#define CHECK(cond, msg)                                                     \
    do {                                                                     \
        if (cond) { g_pass++; }                                              \
        else {                                                               \
            g_fail++;                                                        \
            printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, msg);           \
        }                                                                    \
    } while (0)

// capture everything fn() writes to stdout (printf-based query layer)
static std::string cap_out(const std::function<void()>& fn) {
    fflush(stdout);
    int saved = dup(1);
    int pp[2];
    if (pipe(pp) != 0) return "";
    dup2(pp[1], 1);
    fn();
    fflush(stdout);
    dup2(saved, 1);
    close(saved);
    close(pp[1]);
    std::string s;
    char b[8192];
    ssize_t n;
    while ((n = read(pp[0], b, sizeof b)) > 0) s.append(b, size_t(n));
    close(pp[0]);
    return s;
}

static std::string read_file(const std::string& path) {
    FILE* f = fopen(path.c_str(), "rb");
    if (!f) return {};
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    std::string s(size_t(n), 0);
    if (n > 0 && fread(&s[0], 1, size_t(n), f) != size_t(n)) s.clear();
    fclose(f);
    return s;
}

static std::string g_dir;
static std::string tmp_path(const char* name) { return g_dir + "/" + name; }

// ---------------------------------------------------------------------------
// fixtures (upstream text dialect; every token canonical hex, trailing space)
// ---------------------------------------------------------------------------

// general round-trip log: exec/mem/call/ret + 128-bit SIMD + 2 verbatim lines
static const char* kLogRT[] = {
    "[libc.so] 0x1000!0x0 mov x8, x9; x9=0x5 -> x8=0x5 ",
    "[libc.so] 0x1004!0x4 ldrb w7, [x4]; x4=0x2000 mem_r=0x2000 -> x7=0xca ",
    "[libc.so] 0x1008!0x8 strb w7, [x10]; x7=0xca x10=0x3000 mem_w=0x3000 ",
    "[libc.so] 0x100c!0xc bl #0x2000; ",
    "call func: memcpy(0x3000, 0x2000)",
    "[libc.so] 0x1010!0x10 ldr q0, [x1]; "
        "q0=0xb400007616e40d50b400007706e7fcc0 x1=0x5000 mem_r=0x5000 -> q0=0x0 ",
    "[libc.so] 0x2000!0x1000 mov x0, xzr; -> x0=0x0 ",
    "[libc.so] 0x2004!0x1004 ret; ",
    "ret: 0x0",
    "GumTrace started on tid=11484",
    "[libc.so] 0x1014!0x14 mov x8, x9; x9=0x05 -> x8=0x05 ", // non-canonical hex
};

static const char* kLogPair[] = {
    "[p.so] 0x8000!0x0 ldp w8, w9, [x0, #8]; "
        "w8=0xaaaa w9=0xbbbb x0=0x2000 mem_r=0x2008 -> w8=0x11 w9=0x22 ",
    "[p.so] 0x8004!0x4 stp x8, x9, [x0]; "
        "x8=0x11 x9=0x22 x0=0x3000 mem_w=0x3000 ",
};

static const char* kLogSimdMem[] = {
    "[s.so] 0xa000!0x0 str d0, [x1]; "
        "d0=0x1122334455667788 x1=0xb000 mem_w=0xb000 ",
    "[s.so] 0xa004!0x4 str q1, [x2]; "
        "q1=0x112233445566778899aabbccddeeff x2=0xc000 mem_w=0xc000 ",
    "[s.so] 0xa008!0x8 ldr q2, [x3]; "
        "x3=0xd000 mem_r=0xd000 -> q2=0xffeeddccbbaa99887766554433221100 ",
};

static const char* kLogCall8[] = {
    "[c.so] 0xd000!0x0 bl #0xd100; ",
    "call func: many(0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8)",
    "[c.so] 0xd100!0x100 ret; ",
    "ret: 0x99",
};

static const char* kLogMemHistory[] = {
    "[m.so] 0xe000!0x0 strb w7, [x10]; x7=0xaa x10=0x4000 mem_w=0x4000 ",
    "[m.so] 0xe004!0x4 ldrb w8, [x10]; x10=0x4000 mem_r=0x4000 -> x8=0xaa ",
    "[m.so] 0xe008!0x8 ldrb w9, [x11]; x11=0x5000 mem_r=0x5000 -> x9=0xbb ",
};

static const char* kLogRepeatedReg[] = {
    "[r.so] 0xf000!0x0 ldr x9, [x25, x9, lsl #3]; "
        "x9=0x92 x25=0x1000 x9=0x92 mem_r=0x1490 -> x9=0x2000 ",
};

static std::string join_log(const char* const* lines, int n, const char* nl) {
    std::string s;
    for (int i = 0; i < n; i++) {
        s += lines[i];
        s += nl;
    }
    return s;
}

// memcpy followed by a source-buffer hexdump (the bridging shape real
// GumTrace logs produce around __memcpy_chk calls)
static const char* kLogDump[] = {
    "[t.so] 0x4000!0x0 mov x10, x11; x11=0x9 -> x10=0x9 ",
    "[t.so] 0x4004!0x4 bl #0x8000; ",
    "call func: __memcpy_chk(0x1000, 0x3000, 0x10)",
    "hexdump at address 0x3000 with length 0x10:",
    "3000: 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f 50 |ABCDEFGHIJKLMNOP|",
    "[t.so] 0x4008!0x8 add x10, x10, #1; x10=0x9 -> x10=0xa ",
};

// Current GumTrace Android JNI shape. The call and arguments are structured;
// rich auxiliary rows stay VERBATIM so upstream replay remains byte-exact.
static const char* kLogGumTrace[] = {
    "[libart.so] 0x7000!0x100 blr x8; x8=0x7100 ",
    "call jni func: GetMethodID(0x1234, 0x5678, 0x9abc, 0xdef0)",
    "args2: nativeMethod",
    "jclass: com/example/Target",
    "jmethod: nativeMethod",
    "ret: 0x42",
};

// taint semantics: NZCV chain, SIMD q chain, kill-on-overwrite, mem round trip
static const char* kLogTaint[] = {
    "[t.so] 0x6000!0x0 mov x8, x9; x9=0x5 -> x8=0x5 ",
    "[t.so] 0x6004!0x4 subs x10, x8, #1; x8=0x5 -> x10=0x4 ",
    "[t.so] 0x6008!0x8 csel x11, x8, x10, ne; x8=0x5 x10=0x4 -> x11=0x5 ",
    "[t.so] 0x600c!0xc movz x8, #0; -> x8=0x0 ",
    "[t.so] 0x6010!0x10 ldr q0, [x11]; x11=0x9000 mem_r=0x9000 -> q0=0x0 ",
    "[t.so] 0x6014!0x14 eor v0, v0, v1; v0=0x0 v1=0x0 -> v0=0x0 ",
    "[t.so] 0x6018!0x18 str q0, [x12]; q0=0x0 x12=0xa000 mem_w=0xa000 ",
    "[t.so] 0x601c!0x1c ldr x13, [x12]; x12=0xa000 mem_r=0xa000 -> x13=0x0 ",
};

// Indexed table lookup: default taint remains GumTrace-compatible; the
// optional index dependency follows x9 -> loaded byte -> arithmetic.
static const char* kLogIndex[] = {
    "[i.so] 0x9000!0x0 mov x9, x10; x10=0x3 -> x9=0x3 ",
    "[i.so] 0x9004!0x4 ldrb w8, [x20, x9]; x20=0xa000 x9=0x3 "
        "mem_r=0xa003 -> x8=0x42 ",
    "[i.so] 0x9008!0x8 add x11, x8, #1; x8=0x42 -> x11=0x43 ",
};

// diff: A vs B (extra instruction at a new offset) vs A rebased (+0x400000)
static const char* kLogA[] = {
    "[d.so] 0x101000!0x0 mov x8, x9; x9=0x1 -> x8=0x1 ",
    "[d.so] 0x101004!0x4 add x8, x8, #1; x8=0x1 -> x8=0x2 ",
    "[d.so] 0x101008!0x8 ret; ",
};
static const char* kLogB[] = {
    "[d.so] 0x101000!0x0 mov x8, x9; x9=0x1 -> x8=0x1 ",
    "[d.so] 0x101004!0x4 add x8, x8, #1; x8=0x1 -> x8=0x2 ",
    "[d.so] 0x101100!0x100 movz x10, #7; -> x10=0x7 ",
    "[d.so] 0x101008!0x8 ret; ",
};
static const char* kLogAR[] = {
    "[d.so] 0x501000!0x0 mov x8, x9; x9=0x1 -> x8=0x1 ",
    "[d.so] 0x501004!0x4 add x8, x8, #1; x8=0x1 -> x8=0x2 ",
    "[d.so] 0x501008!0x8 ret; ",
};

static bool import_str(const std::string& log, const std::string& out,
                       ImportResult& res) {
    RecOptions opts;
    return import_mem(log.data(), log.size(), out, opts, res);
}

// ---------------------------------------------------------------------------
// t_roundtrip
// ---------------------------------------------------------------------------
static void t_roundtrip() {
    printf("t_roundtrip (import/export byte-exactness)\n");
    CHECK(zigzag_enc(-5) == 9 && zigzag_dec(9) == -5,
          "zigzag handles negative deltas without signed left shift");
    std::string lf = join_log(kLogRT, sizeof(kLogRT) / sizeof(kLogRT[0]), "\n");
    std::string crlf =
        join_log(kLogRT, sizeof(kLogRT) / sizeof(kLogRT[0]), "\r\n");

    ImportResult r1, r2;
    CHECK(import_str(lf, tmp_path("rt.gtb"), r1), "import LF log");
    CHECK(r1.cnt.lines == 11 && r1.cnt.exec == 7 && r1.cnt.call == 1 &&
              r1.cnt.ret == 1 && r1.cnt.verbatim == 2,
          "import counts (11 lines, 7 exec, 1 call, 1 ret, 2 verbatim)");
    CHECK(import_str(crlf, tmp_path("rt_crlf.gtb"), r2), "import CRLF log");

    GtbFile f1, f2;
    CHECK(f1.load(tmp_path("rt.gtb")) && f2.load(tmp_path("rt_crlf.gtb")),
          "both gtb files load");
    CHECK(f1.dialect == 1 && f2.dialect == 3,
          "dialect byte: LF=1, CRLF=3 (upstream|CRLF)");

    // byte-exact replay in both dialects
    {
        std::string o1 = tmp_path("rt.out"), o2 = tmp_path("rt_crlf.out");
        FILE* f = fopen(o1.c_str(), "wb");
        Expander(f1).expand_upstream(f);
        fclose(f);
        f = fopen(o2.c_str(), "wb");
        Expander(f2).expand_upstream(f);
        fclose(f);
        CHECK(read_file(o1) == lf, "LF export replays input byte-for-byte");
        CHECK(read_file(o2) == crlf, "CRLF export replays input byte-for-byte");
    }

    // determinism: same input -> same gtb bytes
    ImportResult r3;
    CHECK(import_str(lf, tmp_path("rt2.gtb"), r3), "re-import");
    CHECK(read_file(tmp_path("rt.gtb")) == read_file(tmp_path("rt2.gtb")),
          "import is deterministic (identical gtb bytes)");

    // The only remaining recorder guards apply to text import. A capped file
    // remains valid and replays exactly the accepted prefix.
    RecOptions capped_opts;
    capped_opts.max_events = 3;
    ImportResult capped;
    CHECK(import_mem(lf.data(), lf.size(), tmp_path("capped.gtb"),
                     capped_opts, capped),
          "capped import succeeds");
    CHECK(capped.stopped && capped.stats.reason == STOP_MAX_EVENTS,
          "max_events stops text import");
    GtbFile capped_file;
    CHECK(capped_file.load(tmp_path("capped.gtb")) &&
              capped_file.stop_reason == STOP_MAX_EVENTS,
          "capped import is readable and preserves stop reason");
    std::string capped_out = tmp_path("capped.out");
    FILE* capped_fp = fopen(capped_out.c_str(), "wb");
    Expander(capped_file).expand_upstream(capped_fp);
    fclose(capped_fp);
    CHECK(read_file(capped_out) == join_log(kLogRT, 3, "\n"),
          "capped import replays the accepted prefix");

    RecOptions byte_opts;
    byte_opts.max_bytes = 1;
    ImportResult byte_capped;
    CHECK(import_mem(lf.data(), lf.size(), tmp_path("byte-capped.gtb"),
                     byte_opts, byte_capped) && byte_capped.stopped &&
              byte_capped.stats.reason == STOP_MAX_BYTES,
          "max_bytes accounts for the current import chunk");

    struct rlimit old_limit;
    CHECK(getrlimit(RLIMIT_FSIZE, &old_limit) == 0,
          "read output file-size limit");
    if (old_limit.rlim_max >= 512) {
        struct rlimit small_limit = old_limit;
        small_limit.rlim_cur = 512;
        auto old_handler = signal(SIGXFSZ, SIG_IGN);
        CHECK(setrlimit(RLIMIT_FSIZE, &small_limit) == 0,
              "set output file-size limit");
        std::string large = lf + lf + lf + lf;
        ImportResult io_failed;
        CHECK(!import_str(large, tmp_path("write-failed.gtb"), io_failed),
              "import reports a write failure");
        setrlimit(RLIMIT_FSIZE, &old_limit);
        signal(SIGXFSZ, old_handler);
    }

    // the non-canonical line survived only as verbatim (not parsed as exec)
    CHECK(r1.cnt.exec == 7, "leading-zero hex line excluded from exec count");
}

// ---------------------------------------------------------------------------
// t_gumtrace
// ---------------------------------------------------------------------------
static void t_gumtrace() {
    printf("t_gumtrace (current JNI dialect compatibility)\n");
    std::string log = join_log(kLogGumTrace,
                               sizeof(kLogGumTrace) / sizeof(kLogGumTrace[0]),
                               "\r\n");
    std::string gtb = tmp_path("gumtrace.gtb");
    ImportResult r;
    CHECK(import_str(log, gtb, r), "import current GumTrace JNI dialect");
    CHECK(r.cnt.lines == 6 && r.cnt.exec == 1 && r.cnt.call == 1 &&
              r.cnt.ret == 1 && r.cnt.verbatim == 3,
          "JNI call structured; args/jclass/jmethod remain verbatim");

    GtbFile f;
    CHECK(f.load(gtb) && f.dialect == 3 && f.n_call == 1 && f.n_call2 == 1 &&
              f.n_verbatim == 3,
          "JNI gtb loads with CRLF dialect and CALL2 stats");

    std::string out = tmp_path("gumtrace.out");
    FILE* o = fopen(out.c_str(), "wb");
    Expander(f).expand_upstream(o);
    fclose(o);
    CHECK(read_file(out) == log, "JNI dialect replays byte-for-byte");

    std::string fa = cap_out(
        [&] { q_func_args(gtb, "GetMethodID", 1, 5, true); });
    CHECK(fa.find("\"args\":[\"0x1234\",\"0x5678\",\"0x9abc\",\"0xdef0\"]") !=
              std::string::npos,
          "func-args exposes JNI call arguments");
    CHECK(fa.find("\"ret\":\"0x42\"") != std::string::npos,
          "func-args pairs the JNI return value");
    std::string ct = cap_out(
        [&] { q_calltree_gtb(gtb, "GetMethodID", 2, 20, false); });
    CHECK(ct.find("GetMethodID(x0=0x1234, x1=0x5678, x2=0x9abc, x3=0xdef0)") !=
              std::string::npos,
          "calltree exposes JNI call");

    std::string json_out = tmp_path("gumtrace.jsonl");
    o = fopen(json_out.c_str(), "wb");
    uint64_t json_lines = Expander(f).expand_jsonl(o);
    fclose(o);
    std::string json_text = read_file(json_out);
    CHECK(json_lines == 5 &&
              json_text.find("\n}\n") == std::string::npos &&
              json_text.find("\n,{\"") == std::string::npos &&
              json_text.find("\"verbatim\":true") != std::string::npos &&
              json_text.find("{\"ev\":4,\"ret\":\"0x42\"}") !=
                  std::string::npos,
          "jsonl marks verbatim groups and structures a standalone return");
}

// ---------------------------------------------------------------------------
// t_dump
// ---------------------------------------------------------------------------
static void t_dump() {
    printf("t_dump (hexdump content lanes + memcpy bridging)\n");
    std::string log =
        join_log(kLogDump, sizeof(kLogDump) / sizeof(kLogDump[0]), "\n");
    ImportResult r;
    CHECK(import_str(log, tmp_path("dump.gtb"), r), "import dump log");
    CHECK(r.cnt.exec == 3 && r.cnt.call == 1 && r.cnt.verbatim == 2,
          "counts: 3 exec, 1 call, 2 verbatim (header + row)");

    GtbFile f;
    CHECK(f.load(tmp_path("dump.gtb")), "load dump.gtb");
    // the hexdump row synthesized two value-known mem_r qwords
    CHECK(f.n_mem == 2, "dump row synthesized 2 mem_r content lanes");

    // qword-aligned 64-bit value: mem lane hit, dump lane suppressed
    std::string fv = cap_out([&] {
        q_find_value(tmp_path("dump.gtb"), 0x4847464544434241ULL, 20, 0, false);
    });
    CHECK(fv.find("mem_r") != std::string::npos,
          "find-value hits synthesized mem_r lane");
    CHECK(fv.find("dump:") == std::string::npos,
          "qword-aligned match not double-counted as dump lane");
    // sub-pattern at odd offset: only the dump scan can see it
    fv = cap_out([&] {
        q_find_value(tmp_path("dump.gtb"), 0x4d4cULL, 20, 0, false);
    });
    // payload bytes ...4c 4d... start at dump offset 11, so the LE value
    // 0x4d4c matches at 0x300b (not 0x300c)
    CHECK(fv.find("dump:0x300b") != std::string::npos,
          "find-value locates 2-byte pattern inside dump payload (0x300b)");

    // forward taint through the verbatim memcpy bridge: src cell -> dst cell
    std::string tj = cap_out([&] {
        q_taint(tmp_path("dump.gtb"), 0x3000, -1, -1, false, false, 20, 0, 0,
                0, "", true);
    });
    // JSON output splits the edge "what" field from the "txt" field, so the
    // full label is not contiguous; match the stable "what" payload instead
    CHECK(tj.find("dst <- tainted src cells") != std::string::npos,
          "memcpy bridging edge recorded");
    CHECK(tj.find("\"0x1000\"") != std::string::npos,
          "taint reaches the dst buffer (0x1000)");
}

// ---------------------------------------------------------------------------
// t_taint
// ---------------------------------------------------------------------------
static void t_taint() {
    printf("t_taint (NZCV/SIMD/kill semantics on imported fixtures)\n");
    std::string log =
        join_log(kLogTaint, sizeof(kLogTaint) / sizeof(kLogTaint[0]), "\n");
    ImportResult r;
    CHECK(import_str(log, tmp_path("taint.gtb"), r), "import taint log");
    CHECK(r.cnt.exec == 8, "8 exec events");

    // forward from x8: subs -> nzcv -> csel; movz kills x8. `ldr q0,[x11]`
    // also counts as matched: its base x11 is tainted, so the event is
    // "involved" — involvement is recorded even though it does not propagate
    // taint into q0 (pure data flow through the memory cell only)
    std::string fwd = cap_out([&] {
        q_taint(tmp_path("taint.gtb"), 0, 8, -1, false, false, 20, 0, 0, 0,
                "", true);
    });
    CHECK(fwd.rfind("{\"partial\":false,", 0) == 0 &&
              fwd.find("\"taint\":") == std::string::npos,
          "taint JSON exposes result fields at the top level");
    CHECK(fwd.find("\"matched\":4") != std::string::npos,
          "forward matched = seed + subs + csel + tainted-base ldr (4)");
    CHECK(fwd.find("\"x10\"") != std::string::npos &&
              fwd.find("\"x11\"") != std::string::npos &&
              fwd.find("\"nzcv\"") != std::string::npos,
          "x10, x11, nzcv tainted");
    CHECK(fwd.find("\"x8\"") == std::string::npos,
          "movz killed x8 taint");
    CHECK(fwd.find("\"q0\"") == std::string::npos,
          "tainted base register does not taint the load (pure data flow)");

    // forward from the memory cell: load taints q0, eor keeps it, store taints
    // the dst cell, reload taints x13
    std::string mem = cap_out([&] {
        q_taint(tmp_path("taint.gtb"), 0x9000, -1, -1, false, false, 20, 0, 0,
                0, "", true);
    });
    CHECK(mem.find("\"matched\":5") != std::string::npos,
          "mem-seeded forward matched = seed + ldr/eor/str/ldr (5)");
    CHECK(mem.find("\"q0\"") != std::string::npos,
          "q0 tainted through the SIMD chain");
    CHECK(mem.find("\"0xa000\"") != std::string::npos,
          "store carries q0 taint into memory cell 0xa000");
    CHECK(mem.find("\"x13\"") != std::string::npos,
          "reload carries cell taint back to x13");
    std::string mem_text = cap_out([&] {
        q_taint(tmp_path("taint.gtb"), 0x9000, -1, -1, false, false, 20, 0, 0,
                0, "", false);
    });
    CHECK(mem_text.find("final tainted addrs (") != std::string::npos &&
              mem_text.find("0xa000") != std::string::npos,
          "text taint output lists final memory dependencies");

    // backward from the reloaded cell: demand walks store -> eor -> load
    std::string bwd = cap_out([&] {
        q_taint(tmp_path("taint.gtb"), 0xa000, -1, -1, false, true, 20, 0, 0,
                0, "", true);
    });
    CHECK(bwd.find("source reg q0") != std::string::npos &&
              bwd.find("source mem 0x9000") != std::string::npos,
          "backward walk reaches q0 then the source cell 0x9000");
    CHECK(bwd.find("\"matched\":4") != std::string::npos,
          "backward matched = seed + str/eor/ldr (4)");

    ImportResult ir;
    CHECK(import_str(join_log(kLogIndex, 3, "\n"), tmp_path("index.gtb"), ir),
          "import indexed-load fixture");
    std::string idx_default = cap_out([&] {
        q_taint(tmp_path("index.gtb"), 0, 9, -1, false, false, 20, 0, 0,
                0, "", true);
    });
    CHECK(idx_default.find("\"x8\"") == std::string::npos,
          "default taint does not treat a load index as data");
    std::string idx = cap_out([&] {
        q_taint(tmp_path("index.gtb"), 0, 9, -1, false, false, 20, 0, 0,
                0, "", true, true);
    });
    CHECK(idx.find("x8 <- index") != std::string::npos &&
              idx.find("\"x11\"") != std::string::npos,
          "--index-deps follows indexed lookup into its consumer");
    CHECK(idx.find("\"line\":2") != std::string::npos,
          "taint edge carries the original source-log line");
    std::string idx_back = cap_out([&] {
        q_taint(tmp_path("index.gtb"), 0, 8, -1, false, true, 20, 0, 1,
                0, "", true, true);
    });
    CHECK(idx_back.find("source index x9") != std::string::npos,
          "backward --index-deps exposes the address index register");
}

// ---------------------------------------------------------------------------
// t_queries
// ---------------------------------------------------------------------------
static void t_queries() {
    printf("t_queries (query surface + agent contract)\n");
    std::string gtb = tmp_path("rt.gtb"); // built by t_roundtrip

    std::string st = cap_out([&] { q_stat(gtb, false); });
    CHECK(st.find("exec=7") != std::string::npos &&
              st.find("verbatim=2") != std::string::npos,
          "stat counts exec/verbatim");
    std::string sj = cap_out([&] { q_stat(gtb, true); });
    CHECK(sj.find("\"exec\":7") != std::string::npos &&
              sj.find("\"dialect\":\"upstream\"") != std::string::npos,
          "stat --json shape + dialect");
    CHECK(sj.find("\"next\":null") != std::string::npos &&
              sj.find("\"suggest\"") == std::string::npos,
          "meta contains pagination facts without workflow suggestions");

    std::string fv = cap_out([&] { q_find_value(gtb, 0xca, 20, 0, false); });
    CHECK(fv.find("wr:x7") != std::string::npos &&
              fv.find("rd:x7") != std::string::npos,
          "find-value reports write and read lanes");
    CHECK(fv.find("line=2") != std::string::npos &&
              fv.find("line=3") != std::string::npos,
          "find-value reports original source-log lines");
    std::string fvj = cap_out([&] {
        q_find_value(gtb, 0xca, 20, 0, true);
    });
    CHECK(fvj.find("\"kind\":\"reg\",\"rw\":\"w\",\"reg\":\"x7\"") !=
              std::string::npos &&
              fvj.find("\"kind\":\"mem\",\"rw\":\"w\",\"addr\":\"0x3000\",\"size\":1") !=
                  std::string::npos,
          "find-value JSON identifies register and memory locations");
    std::string addr_hits = cap_out([&] {
        q_find_value(gtb, 0x2000, 20, 0, true);
    });
    CHECK(addr_hits.find("\"reg\":\"x4\"") != std::string::npos &&
              addr_hits.find("\"reg\":\"mem_r\"") == std::string::npos,
          "find-value does not expose memory address observations as registers");
    fvj = cap_out([&] {
        q_find_value(gtb, 0xca, 20, 0, true, 1, 1, true, false);
    });
    CHECK(fvj.find("\"kind\":\"mem\",\"rw\":\"r\",\"addr\":\"0x2000\",\"size\":1") !=
              std::string::npos &&
              fvj.find("\"rw\":\"w\"") == std::string::npos,
          "find-value --read and event bounds select only matching reads");
    fvj = cap_out([&] {
        q_find_value(gtb, 0xca, 1, 0, true, 1, 2, false, true);
    });
    CHECK(fvj.find("gt find-value 0xca --write --from 1 --to 2 --limit 1 "
                   "--offset 1") != std::string::npos,
          "find-value continuation preserves filters and event bounds");

    std::string ma = cap_out([&] {
        q_mem_accesses(gtb, {0x3000}, false, 0, 0, 20, 0, 0,
                       UINT64_MAX, 0, false, true);
    });
    CHECK(ma.find(" w 0x3000 =0xca ") != std::string::npos,
          "mem-access --write reconstructs the stored value");
    CHECK(ma.find("2 line=3") != std::string::npos,
          "mem-access reports the original source-log line");
    std::string maj = cap_out([&] {
        q_mem_accesses(gtb, {0x3000}, false, 0, 0, 20, 0, 0,
                       UINT64_MAX, 0, true, true);
    });
    CHECK(maj.find("\"val\":\"0xca\"") != std::string::npos,
          "mem-access --json includes the reconstructed value");
    ma = cap_out([&] {
        q_mem_accesses(gtb, {0x3000}, false, 0, 0, 20, 0, 0,
                       UINT64_MAX, 0, false, false);
    });
    CHECK(ma.find(" r 0x3000 ") == std::string::npos,
          "no read of 0x3000 exists (honest negative)");

    std::string mab = cap_out([&] {
        q_mem_accesses(gtb, {0x2000, 0x3000}, false, 0, 0, 20, 0, 0,
                       UINT64_MAX, 0, true, false);
    });
    CHECK(mab.find("\"ev\":1") != std::string::npos &&
              mab.find("\"ev\":2") != std::string::npos &&
              mab.find("\"total\":2") != std::string::npos,
          "mem-access batches exact addresses in one scan");
    mab = cap_out([&] {
        q_mem_accesses(gtb, {0x2000, 0x3000}, false, 0, 0, 1, 0, 1, 2, 0,
                       true, false);
    });
    CHECK(mab.find("gt mem-access --addr 0x2000 --addr 0x3000 --from 1 --to 2 "
                   "--limit 1 --offset 1") != std::string::npos,
          "mem-access continuation preserves batched selectors and event bounds");
    mab = cap_out([&] {
        q_mem_accesses(gtb, {0x2000, 0x3000}, false, 0, 0, 20, 0, 0, 2, 1,
                       true, false);
    });
    CHECK(mab.find("\"ev\":2") != std::string::npos &&
              mab.find("\"ev\":1") == std::string::npos &&
              mab.find("\"total\":2,\"shown\":1") != std::string::npos,
          "mem-access --last applies event bounds and returns the final hit");

    ImportResult history_result;
    std::string history_gtb = tmp_path("mem_history.gtb");
    CHECK(import_str(join_log(kLogMemHistory, 3, "\n"), history_gtb,
                     history_result),
          "import memory-history fixture");
    std::string history = cap_out([&] {
        q_mem_accesses(history_gtb, {}, true, 0x3ff0, 0x20, 20, 0, 0,
                       UINT64_MAX, 0, true, false);
    });
    CHECK(history.find("\"off\":\"0x10\"") != std::string::npos &&
              history.find("\"size\":1") != std::string::npos,
          "range mem-access reports relative offset and access size");
    CHECK(history.find("\"prior_write_ev\":0") != std::string::npos &&
              history.find("mem_access_summary") == std::string::npos,
          "mem-access links a read to its writer without summary records");
    CHECK(history.find("\"focus_ev\"") == std::string::npos,
          "mem-access rows carry facts without a selected focus");
    history = cap_out([&] {
        q_mem_accesses(history_gtb, {0x4000}, false, 0, 0, 20, 0, 1,
                       UINT64_MAX, 0, true, false);
    });
    CHECK(history.find("\"ev\":1") != std::string::npos &&
              history.find("\"prior_write_ev\":0") != std::string::npos,
          "prior-write lookup includes writes before --from");
    history = cap_out([&] {
        q_mem_accesses(history_gtb, {}, true, 0x3ff0, 0x20, 20, 0, 0,
                       UINT64_MAX, 0, true, false, true);
    });
    CHECK(history.find("\"ev\":0") == std::string::npos &&
              history.find("\"ev\":1") != std::string::npos &&
              history.find("\"prior_write_ev\":0") != std::string::npos,
          "mem-access --read hides writes but retains prior-write history");
    history = cap_out([&] {
        q_mem_accesses(history_gtb, {0x5000}, false, 0, 0, 20, 0, 0,
                       UINT64_MAX, 0, false, false);
    });
    CHECK(history.find("summary:") == std::string::npos &&
              history.find("prior_write_ev=none") != std::string::npos,
          "read-only address reports that no producer was observed");

    std::string ms = cap_out([&] {
        q_mem_state(gtb, 0x3000, 4, 2, true);
    });
    CHECK(ms.find("\"known\":1") != std::string::npos &&
              ms.find("\"hex\":\"ca??????\"") != std::string::npos,
          "mem-state reconstructs known bytes and marks gaps honestly");

    std::string pc = cap_out([&] {
        q_find_pcs(gtb, {}, {0x8}, "libc.so", 20, 0, 0, UINT64_MAX, true);
    });
    CHECK(pc.find("\"ev\":2") != std::string::npos &&
              pc.find("\"line\":3") != std::string::npos &&
              pc.find("[\"x7\",\"0xca\"]") != std::string::npos &&
              pc.find("\"val\":\"0xca\"") != std::string::npos,
          "find-pc returns executions with register and memory values");
    pc = cap_out([&] {
        q_find_pcs(gtb, {0x1008}, {}, "", 20, 0, 0, UINT64_MAX, false);
    });
    CHECK(pc.find("2 line=3 libc.so!0x8 strb") != std::string::npos,
          "find-pc accepts an absolute address");
    pc = cap_out([&] {
        q_find_pcs(gtb, {}, {0x10}, "libc.so", 20, 0, 0, UINT64_MAX, true);
    });
    CHECK(pc.find("\"line\":6") != std::string::npos,
          "find-pc line accounts for attached call records");
    pc = cap_out([&] {
        q_find_pcs(gtb, {}, {0, 8}, "libc.so", 20, 0, 1, 2, true);
    });
    CHECK(pc.find("\"ev\":2") != std::string::npos &&
              pc.find("\"ev\":0") == std::string::npos,
          "find-pc batches PCs and applies an event range in one pass");

    ImportResult repeated_result;
    std::string repeated_gtb = tmp_path("repeated_reg.gtb");
    CHECK(import_str(join_log(kLogRepeatedReg, 1, "\n"), repeated_gtb,
                     repeated_result),
          "import repeated-register fixture");
    pc = cap_out([&] {
        q_find_pcs(repeated_gtb, {}, {0}, "r.so", 20, 0, 0, UINT64_MAX, true);
    });
    const std::string x9_read = "[\"x9\",\"0x92\"]";
    size_t x9_first = pc.find(x9_read);
    CHECK(x9_first != std::string::npos &&
              pc.find(x9_read, x9_first + x9_read.size()) == std::string::npos,
          "find-pc emits one read observation per register");

    ImportResult pair_result;
    std::string pair_gtb = tmp_path("pair.gtb");
    CHECK(import_str(join_log(kLogPair, 2, "\n"), pair_gtb, pair_result),
          "import pair load/store fixture");
    pc = cap_out([&] {
        q_find_pcs(pair_gtb, {}, {0}, "p.so", 20, 0, 0, UINT64_MAX, true);
    });
    CHECK(pc.find("\"addr\":\"0x2008\",\"val\":\"0x11\"") !=
              std::string::npos &&
              pc.find("\"addr\":\"0x200c\",\"val\":\"0x22\"") !=
              std::string::npos,
          "find-pc exposes both ldp memory lanes");
    pc = cap_out([&] {
        q_find_pcs(pair_gtb, {}, {4}, "p.so", 20, 0, 0, UINT64_MAX, true);
    });
    CHECK(pc.find("\"addr\":\"0x3000\",\"val\":\"0x11\"") !=
              std::string::npos &&
              pc.find("\"addr\":\"0x3008\",\"val\":\"0x22\"") !=
              std::string::npos,
          "find-pc exposes both stp memory lanes");
    ma = cap_out([&] {
        q_mem_accesses(pair_gtb, {0x200c}, false, 0, 0, 20, 0, 0,
                       UINT64_MAX, 0, false, false);
    });
    CHECK(ma.find(" r 0x200c =0x22 ") != std::string::npos,
          "mem-access can query the synthesized second pair lane");

    ImportResult simd_result;
    std::string simd_gtb = tmp_path("simd_mem.gtb");
    CHECK(import_str(join_log(kLogSimdMem, 3, "\n"), simd_gtb, simd_result),
          "import SIMD memory-value fixture");
    ma = cap_out([&] {
        q_mem_accesses(simd_gtb, {0xb000}, false, 0, 0, 20, 0, 0,
                       UINT64_MAX, 0, true, true);
    });
    CHECK(ma.find("\"val\":\"0x1122334455667788\"") != std::string::npos,
          "mem-access reconstructs str d register data, not the address");
    ma = cap_out([&] {
        q_mem_accesses(simd_gtb, {0xc000}, false, 0, 0, 20, 0, 0,
                       UINT64_MAX, 0, true, true);
    });
    CHECK(ma.find("\"val\":\"0x112233445566778899aabbccddeeff\"") !=
              std::string::npos,
          "mem-access preserves a full 128-bit str q value");
    ma = cap_out([&] {
        q_mem_accesses(simd_gtb, {0xd000}, false, 0, 0, 20, 0, 0,
                       UINT64_MAX, 0, true, false);
    });
    CHECK(ma.find("\"val\":\"0xffeeddccbbaa99887766554433221100\"") !=
              std::string::npos,
          "mem-access preserves a full 128-bit ldr q value");
    ms = cap_out([&] { q_mem_state(simd_gtb, 0xc000, 16, 1, true); });
    CHECK(ms.find("\"known\":16") != std::string::npos &&
              ms.find("\"hex\":\"ffeeddccbbaa99887766554433221100\"") !=
                  std::string::npos,
          "mem-state materializes all 16 bytes of a q store");
    ms = cap_out([&] { q_mem_state(simd_gtb, 0xc000, 16, 1, true, true); });
    CHECK(ms.find("{\"addr\":\"0xc000\",\"known\":true,"
                  "\"val\":\"0x8899aabbccddeeff\"}") != std::string::npos &&
              ms.find("{\"addr\":\"0xc008\",\"known\":true,"
                      "\"val\":\"0x11223344556677\"}") != std::string::npos &&
              ms.find("\"total\":2,\"shown\":2") != std::string::npos,
          "mem-state --qword emits little-endian cells and meta");
    ms = cap_out([&] { q_mem_state(gtb, 0x3000, 8, 2, true, true); });
    CHECK(ms.find("{\"addr\":\"0x3000\",\"known\":false,\"val\":null}") !=
              std::string::npos,
          "mem-state --qword marks partial cells unknown");
    pc = cap_out([&] {
        q_find_pcs(simd_gtb, {}, {4}, "s.so", 20, 0, 0, UINT64_MAX, true);
    });
    CHECK(pc.find("\"val\":\"0x112233445566778899aabbccddeeff\"") !=
              std::string::npos,
          "find-pc reports the full SIMD memory value");

    std::string fa = cap_out(
        [&] { q_func_args(gtb, "memcpy", 1, 5, true); });
    CHECK(fa.find("\"args\":[\"0x3000\",\"0x2000\"]") != std::string::npos,
          "func-args reconstructs observed call args");
    CHECK(fa.find("\"line\":5") != std::string::npos,
          "func-args reports the call's original source-log line");
    CHECK(fa.find("\"ret\":\"0x0\"") != std::string::npos &&
              fa.find("\"ret_ev\":6") != std::string::npos,
          "func-args pairs the matching return event and value");

    ImportResult call8_result;
    std::string call8_gtb = tmp_path("call8.gtb");
    CHECK(import_str(join_log(kLogCall8, 4, "\n"), call8_gtb, call8_result),
          "import eight-argument call fixture");
    fa = cap_out([&] { q_func_args(call8_gtb, "many", 1, 1, true); });
    CHECK(fa.find("\"args\":[\"0x1\",\"0x2\",\"0x3\",\"0x4\",\"0x5\",\"0x6\",\"0x7\",\"0x8\"]") !=
              std::string::npos &&
              fa.find("\"ret\":\"0x99\"") != std::string::npos,
          "func-args exposes x0..x7 and the paired return");
    fa = cap_out([&] { q_func_args(gtb, "nosuch", 1, 5, false); });
    CHECK(fa.find("no call to nosuch") != std::string::npos,
          "func-args says plainly when the function is absent");

    std::string ct = cap_out(
        [&] { q_calltree_gtb(gtb, "memcpy", 3, 40, false); });
    CHECK(ct.find("memcpy(x0=0x3000, x1=0x2000)") != std::string::npos,
          "calltree prints the matched call with args");

    // export windows + cursor, driven at the Expander level
    GtbFile f;
    CHECK(f.load(gtb), "reload for export tests");
    {
        std::string out = tmp_path("q_compact.txt");
        FILE* o = fopen(out.c_str(), "wb");
        uint64_t stop = UINT64_MAX;
        uint64_t n = Expander(f).expand_compact(o, 0, UINT64_MAX, 3, &stop);
        fclose(o);
        // the module header `== libc.so ==` consumes one line and each exec
        // event emits one (mem lanes ride the same line), so a 3-line budget
        // covers ev0+ev1 and the cursor lands on the unprocessed ev2
        CHECK(n == 3 && stop == 2,
              "compact --limit 3 emits 3 lines incl. module header");
        std::string s = read_file(out);
        CHECK(s.rfind("== libc.so ==", 0) == 0,
              "compact output opens with a module header");
        CHECK(s.find("!0x4") != std::string::npos,
              "compact uses module-relative addressing");
    }
    {
        std::string out = tmp_path("q.jsonl");
        FILE* o = fopen(out.c_str(), "wb");
        uint64_t stop = UINT64_MAX;
        uint64_t n = Expander(f).expand_jsonl(o, 0, UINT64_MAX, 4, &stop);
        fclose(o);
        CHECK(n == 4 && stop != UINT64_MAX, "jsonl --limit 4 + cursor");
        std::string s = read_file(out);
        CHECK(s.rfind("{\"ev\":0,", 0) == 0, "jsonl lines are ev objects");
        CHECK(s.find("\"txt\":\"mov x8, x9\"") != std::string::npos,
              "jsonl carries the disasm text");
    }
    {
        // windowed export: --from/--to select the event range
        std::string out = tmp_path("q_win.txt");
        FILE* o = fopen(out.c_str(), "wb");
        uint64_t n = Expander(f).expand_compact(o, 2, 3);
        fclose(o);
        std::string s = read_file(out);
        CHECK(s.find("!0x8") != std::string::npos &&
                  s.find("!0xc ") != std::string::npos &&
                  s.find("!0x0 ") == std::string::npos,
              "export window [2,3] emits exactly those events");
        (void)n;
    }
}

// ---------------------------------------------------------------------------
// t_diff
// ---------------------------------------------------------------------------
static void t_diff() {
    printf("t_diff ((module, offset) identity)\n");
    ImportResult r;
    CHECK(import_str(join_log(kLogA, 3, "\n"), tmp_path("da.gtb"), r),
          "import A");
    CHECK(import_str(join_log(kLogB, 4, "\n"), tmp_path("db.gtb"), r),
          "import B");
    CHECK(import_str(join_log(kLogAR, 3, "\n"), tmp_path("dar.gtb"), r),
          "import A rebased");

    std::string d = cap_out(
        [&] { q_diff(tmp_path("da.gtb"), tmp_path("db.gtb"), 3, false); });
    CHECK(d.find("first divergence at exec index 2") != std::string::npos,
          "inserted instruction diverges at exec index 2");
    std::string same = cap_out(
        [&] { q_diff(tmp_path("da.gtb"), tmp_path("dar.gtb"), 3, false); });
    CHECK(same.find("identical execution sequences") != std::string::npos,
          "rebased copy compares identical (ASLR-stable identity)");
}

// ---------------------------------------------------------------------------
int main() {
    char tmpl[] = "/tmp/gt-test-XXXXXX";
    CHECK(mkdtemp(tmpl) != nullptr, "mkdtemp");
    g_dir = tmpl;

    t_roundtrip();
    t_gumtrace();
    t_dump();
    t_taint();
    t_queries();
    t_diff();

    printf("\n%d/%d checks passed\n", g_pass, g_pass + g_fail);
    return g_fail ? 1 : 0;
}
