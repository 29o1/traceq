// Correctness tests for libgumtrace, driven through the synthetic corpus.
//
// These live on the benchmark side because every one of them needs an event
// source to produce input, and the product deliberately has none.

#include "arm64enc.h"
#include "corpus.h"
#include "harness.h"
#include "legacy.h"
#include <gumtrace/common.h>
#include <gumtrace/import.h>
#include <gumtrace/ingest.h>
#include <gumtrace/queries.h>
#include <gumtrace/recorder.h>
#include <gumtrace/site.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <capstone/capstone.h>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <functional>
#include <set>
#include <sstream>
#include <unordered_map>

using namespace gt;
using namespace gt::enc;

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------
static int g_fail = 0;
#define CHECK(cond, msg)                                                     \
    do {                                                                     \
        if (cond) { printf("  PASS  %s\n", msg); }                           \
        else { printf("  FAIL  %s  (%s:%d)\n", msg, __FILE__, __LINE__); g_fail++; } \
    } while (0)

// ---------------------------------------------------------------------------
// T1: encoder round-trip via capstone + plan-vs-simulator cross-check
// ---------------------------------------------------------------------------
static void test_encoder_and_plan() {
    printf("[T1] encoder round-trip + plan vs simulator effects\n");
    CorpusConfig cfg;
    cfg.outer_iters = 3;
    cfg.inner_iters = 4;
    Program p = build_program(cfg);
    site_compiler_init();

    csh cs;
    cs_open(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, &cs);
    cs_option(cs, CS_OPT_DETAIL, CS_OPT_ON);

    int checked = 0, mismatches = 0;
    for (const auto& d : p.insns) {
        cs_insn* arr = nullptr;
        if (cs_disasm(cs, (const uint8_t*)&d.word, 4, d.addr, 1, &arr) != 1) {
            printf("    disasm failed @0x%llx word=0x%08x\n",
                   (unsigned long long)d.addr, d.word);
            mismatches++;
            continue;
        }
        const cs_insn& insn = *arr;
        const cs_arm64* a = &insn.detail->arm64;
        // compare read/write reg sets (x0..x28 only; SP/FP/LR handled by
        // construction), and memory flags
        std::set<int> cap_r, cap_w;
        bool cap_mr = false, cap_mw = false;
        bool is_cmp = insn.id == ARM64_INS_CMP;
        for (uint8_t i = 0; i < a->op_count; i++) {
            const cs_arm64_op& op = a->operands[i];
            if (op.type == ARM64_OP_REG) {
                int r = -1;
                if (op.reg >= ARM64_REG_X0 && op.reg <= ARM64_REG_X28) r = op.reg - ARM64_REG_X0;
                else if (op.reg >= ARM64_REG_W0 && op.reg <= ARM64_REG_W28) r = op.reg - ARM64_REG_W0;
                if (r < 0) continue;
                // capstone marks cmp's source as WRITE (quirk); normalize
                if (is_cmp || (op.access & CS_AC_READ)) cap_r.insert(r);
                if (!is_cmp && (op.access & CS_AC_WRITE)) cap_w.insert(r);
            } else if (op.type == ARM64_OP_MEM) {
                // memory base/index registers are reads (GumTrace prints them)
                auto addbase = [&](arm64_reg rr) {
                    int r = -1;
                    if (rr >= ARM64_REG_X0 && rr <= ARM64_REG_X28) r = rr - ARM64_REG_X0;
                    if (r >= 0) cap_r.insert(r);
                };
                addbase(op.mem.base);
                addbase(op.mem.index);
                if (op.access & CS_AC_READ) cap_mr = true;
                if (op.access & CS_AC_WRITE) cap_mw = true;
            }
        }
        std::set<int> sim_r, sim_w;
        for (int r : d.reads) if (r != 255 && r <= 28) sim_r.insert(r);
        for (int r : d.writes) if (r != 255 && r <= 28) sim_w.insert(r);
        // capstone marks writeback accesses R|W; collapse for comparison
        bool cap_mem = cap_mr || cap_mw;
        bool sim_mem = d.mem_read || d.mem_write;
        if (cap_r != sim_r || cap_w != sim_w || cap_mem != sim_mem) {
            printf("    mismatch @0x%llx (%s %s): cap r/w=%zu/%zu mem=%d/%d "
                   "sim r/w=%zu/%zu mem=%d/%d\n",
                   (unsigned long long)d.addr, insn.mnemonic, insn.op_str,
                   cap_r.size(), cap_w.size(), cap_mr, cap_mw,
                   sim_r.size(), sim_w.size(), d.mem_read, d.mem_write);
            mismatches++;
        }
        checked++;
        cs_free(arr, 1);
    }
    cs_close(&cs);
    CHECK(checked > 200, "program has substantial instruction coverage");
    CHECK(mismatches == 0, "capstone analysis matches simulator effects for every insn");
}

// ---------------------------------------------------------------------------
// T2: ring bug demonstration + arena stability
// ---------------------------------------------------------------------------
static void test_ring_bug() {
    printf("[T2] CallbackContext ring wrap bug vs arena stability\n");
    RingCtxEmu ring;
    RingCtxEmu::Ctx* first = nullptr;
    uint64_t first_addr = 0x1000;
    for (int i = 0; i < 150000; i++) {
        auto* c = ring.pull(0x1000 + i * 4);
        if (i == 0) first = c, first_addr = c->addr;
    }
    // after 150000 pulls (> 102400 slots) the first context was overwritten:
    // a live callout holding `first` now reads the wrong instruction
    CHECK(first->addr != first_addr,
          "ring wraps and overwrites contexts still referenced by live callouts (bug reproduced)");
    CHECK(first->addr == 0x1000 + 102400 * 4,
          "overwritten context now belongs to a different site (silent corruption)");

    SiteArena arena;
    site_compiler_init();
    CorpusConfig cfg;
    cfg.outer_iters = 1;
    cfg.inner_iters = 2;
    Program p = build_program(cfg);
    // "re-translate" every site 3 times: arena must return identical ids
    bool stable = true;
    for (int pass = 0; pass < 3; pass++) {
        for (const auto& d : p.insns)
            if (arena.intern(d.addr, d.word, p.module_name.c_str(), p.base, -1) !=
                arena.by_addr_find(d.addr))
                stable = false;
    }
    CHECK(stable, "arena returns stable site ids across re-translations");
    CHECK(arena.size() == p.insns.size(), "arena dedupes sites by address (no duplicates)");
}

// ---------------------------------------------------------------------------
// T3: format equivalence — gtb expansion must byte-match legacy text
// ---------------------------------------------------------------------------
static void test_equivalence() {
    printf("[T3] gtb expansion == legacy text (byte-identical)\n");
    CorpusConfig cfg;
    cfg.outer_iters = 25;
    cfg.inner_iters = 30;
    cfg.variant_const = 0x2A00;
    Program p = build_program(cfg);
    SiteArena arena = compile_sites(p);

    const char* txt_path = "build/legacy_small.txt";
    const char* gtb_path = "build/new_small.gtb";
    system("mkdir -p build");

    LegacyRecorder lrec(arena, p.module_name.c_str(), p.base);
    lrec.open(txt_path);
    run_program(p, cfg, 0, [](const ExecEvent& ev, void* u) {
        static_cast<LegacyRecorder*>(u)->record_event(ev);
    }, &lrec);
    lrec.finish();

    RecOptions ro; ro.initial_sp = corpus_stack_top(); // FULL detail
    GtbRecorder grec(arena);
    grec.open(gtb_path, ro);
    run_program(p, cfg, 0, [](const ExecEvent& ev, void* u) {
        static_cast<GtbRecorder*>(u)->record_event(ev);
    }, &grec);
    grec.finish();

    GtbFile f;
    CHECK(f.load(gtb_path), "gtb file parses");
    FILE* out = fopen("build/new_small.txt", "wb");
    uint64_t lines = Expander(f).expand_text(out);
    fclose(out);

    FILE* a = fopen(txt_path, "rb");
    FILE* b = fopen("build/new_small.txt", "rb");
    CHECK(a && b, "both outputs readable");
    uint64_t diff_at = UINT64_MAX, pos = 0, la = 0, lb = 0;
    if (a && b) {
        int ca, cb;
        long len_a = 0, len_b = 0;
        while (true) {
            ca = a ? fgetc(a) : EOF;
            cb = b ? fgetc(b) : EOF;
            if (ca != cb) { diff_at = pos; break; }
            if (ca == EOF) break;
            pos++;
        }
        fseek(a, 0, SEEK_END); len_a = ftell(a);
        fseek(b, 0, SEEK_END); len_b = ftell(b);
        if (diff_at == UINT64_MAX) diff_at = len_a == len_b ? UINT64_MAX : pos;
        CHECK(diff_at == UINT64_MAX,
              ("expanded output byte-identical to legacy text (legacy=" +
               std::to_string(len_a) + "B, expanded=" + std::to_string(len_b) +
               "B, lines=" + std::to_string(lines) + ")").c_str());
        if (diff_at != UINT64_MAX) {
            printf("    first diff at byte %llu\n", (unsigned long long)diff_at);
            // show the full differing lines
            fseek(a, diff_at > 400 ? diff_at - 400 : 0, SEEK_SET);
            fseek(b, diff_at > 400 ? diff_at - 400 : 0, SEEK_SET);
            char ba[401] = {0}, bb[401] = {0};
            fread(ba, 1, 400, a);
            fread(bb, 1, 400, b);
            printf("    legacy: ...%s\n    expand: ...%s\n", ba, bb);
        }
        (void)la; (void)lb;
    }
    if (a) fclose(a);
    if (b) fclose(b);
}

// ---------------------------------------------------------------------------
// T4: resource guards
// ---------------------------------------------------------------------------
static void test_guards() {
    printf("[T4] resource guards\n");
    CorpusConfig cfg;
    cfg.outer_iters = 400;
    cfg.inner_iters = 30;
    Program p = build_program(cfg);
    SiteArena arena = compile_sites(p);

    RecOptions ro; ro.initial_sp = corpus_stack_top();
    ro.max_bytes = 64 * 1024; // tiny cap
    GtbRecorder g(arena);
    g.open("build/guard.gtb", ro);
    run_program(p, cfg, 0, [](const ExecEvent& ev, void* u) {
        static_cast<GtbRecorder*>(u)->record_event(ev);
    }, &g);
    g.finish();
    GtbFile f;
    CHECK(f.load("build/guard.gtb"), "guarded file parses");
    CHECK(f.stop_reason == STOP_MAX_BYTES, "guard stops with reason=max_bytes");
    CHECK(f.events_seen > 0 && f.n_exec > 0, "partial events retained after guard stop");
}

// ---------------------------------------------------------------------------
// T5: crash safety (child process segfaults mid-recording)
// ---------------------------------------------------------------------------
static void test_crash() {
    printf("[T5] crash safety (SIGSEGV mid-recording)\n");
    system("mkdir -p build");
    const char* path = "build/crash.gtb";
    unlink(path);
    pid_t pid = fork();
    if (pid == 0) {
        CorpusConfig cfg;
        cfg.outer_iters = 3000;
        cfg.inner_iters = 40;
        Program p = build_program(cfg);
        SiteArena arena = compile_sites(p);
        RecOptions ro; ro.initial_sp = corpus_stack_top();
        GtbRecorder g(arena);
        g.open(path, ro);
        run_program(p, cfg, 0, [](const ExecEvent& ev, void* u) {
            GtbRecorder* r = static_cast<GtbRecorder*>(u);
            r->record_event(ev);
            // simulate the target process dying mid-trace
            if (r->stats().events_seen == 200000) {
                *(volatile int*)0 = 1; // SIGSEGV
            }
        }, &g);
        _exit(0); // not reached
    }
    int status = 0;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status))
        printf("    child exited normally with code %d (expected SIGSEGV)\n",
               WEXITSTATUS(status));
    if (WIFSIGNALED(status))
        printf("    child terminated by signal %d\n", WTERMSIG(status));
    CHECK(WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV,
          "child died from SIGSEGV as scheduled");
    GtbFile f;
    CHECK(f.load(path), "crashed trace file parses (footer + partial chunk present)");
    CHECK(f.stop_reason == STOP_CRASH, "footer records reason=crash");
    CHECK(f.n_exec > 190000, "nearly all events survived the crash (footer written by handler)");
}

// ---------------------------------------------------------------------------
// T6: flight-recorder ring + trigger
// ---------------------------------------------------------------------------
static void test_trigger_ring() {
    printf("[T6] flight-recorder ring + trigger\n");
    CorpusConfig cfg;
    cfg.outer_iters = 600;
    cfg.inner_iters = 30;
    Program p = build_program(cfg);
    SiteArena arena = compile_sites(p);

    RecOptions ro; ro.initial_sp = corpus_stack_top();
    ro.ring_keep_chunks = 2;            // keep last ~512KB of events
    ro.trigger_sym = "transform_block_1"; // called via the trampoline
    GtbRecorder g(arena);
    g.open("build/ring.gtb", ro);
    run_program(p, cfg, 0, [](const ExecEvent& ev, void* u) {
        static_cast<GtbRecorder*>(u)->record_event(ev);
    }, &g);
    RecStats st = g.finish();
    CHECK(st.reason == STOP_TRIGGER, "trigger symbol stops recording");
    GtbFile f;
    CHECK(f.load("build/ring.gtb"), "ring dump parses");
    CHECK(f.n_exec > 0 && f.n_exec < f.events_seen,
          "ring retained only the tail of the stream (early events discarded)");
    struct stat sb;
    stat("build/ring.gtb", &sb);
    CHECK(sb.st_size < 2 * 1024 * 1024, "ring output bounded (~2 chunks)");
}

// ---------------------------------------------------------------------------
// T7: variant divergence (diff foundation)
// ---------------------------------------------------------------------------
static void test_diff() {
    printf("[T7] variant divergence via q_diff\n");
    CorpusConfig c1, c2;
    c1.outer_iters = 30; c1.inner_iters = 20; c1.variant_const = 0x2A00;
    c2 = c1; c2.variant_const = 0x2B00; // different input -> slow path taken
    Program p1 = build_program(c1), p2 = build_program(c2);
    SiteArena a1 = compile_sites(p1);
    // identical static program: c2 changes only a constant; sites identical
    for (const auto& d : p2.insns)
        if (a1.by_addr_find(d.addr) == 0xFFFFFFFFu)
            a1.intern(d.addr, d.word, p1.module_name.c_str(), p1.base, -1);
    {
        RecOptions ro; ro.initial_sp = corpus_stack_top();
        GtbRecorder g(a1);
        g.open("build/v1.gtb", ro);
        run_program(p1, c1, 0, [](const ExecEvent& ev, void* u) {
            static_cast<GtbRecorder*>(u)->record_event(ev);
        }, &g);
        g.finish();
    }
    {
        RecOptions ro; ro.initial_sp = corpus_stack_top();
        GtbRecorder g(a1);
        g.open("build/v2.gtb", ro);
        run_program(p2, c2, 0, [](const ExecEvent& ev, void* u) {
            static_cast<GtbRecorder*>(u)->record_event(ev);
        }, &g);
        g.finish();
    }
    // same-variant diff must be identical
    {
        GtbFile fa, fb;
        fa.load("build/v1.gtb");
        fb.load("build/v1.gtb");
        std::vector<uint32_t> sa, sb;
        Expander(fa).for_each([&](uint64_t, const Group& g) { if (g.has_exec) sa.push_back(g.site_id); return true; });
        Expander(fb).for_each([&](uint64_t, const Group& g) { if (g.has_exec) sb.push_back(g.site_id); return true; });
        CHECK(sa == sb, "identical inputs produce identical exec sequences (determinism)");
    }
    printf("  -- diff output (v1 vs v2):\n");
    q_diff("build/v1.gtb", "build/v2.gtb", 2);
    // expect a divergence after the first worker returns (cmp/b.ne region)
    GtbFile fa, fb;
    fa.load("build/v1.gtb");
    fb.load("build/v2.gtb");
    std::vector<uint32_t> sa, sb;
    Expander(fa).for_each([&](uint64_t, const Group& g) { if (g.has_exec) sa.push_back(g.site_id); return true; });
    Expander(fb).for_each([&](uint64_t, const Group& g) { if (g.has_exec) sb.push_back(g.site_id); return true; });
    size_t n = std::min(sa.size(), sb.size()), div = n;
    for (size_t i = 0; i < n; i++)
        if (sa[i] != sb[i]) { div = i; break; }
    CHECK(div < n, "different inputs diverge at a finite exec index");
    CHECK(div > 10, "divergence happens after prologue (input-dependent branch)");
}

// ---------------------------------------------------------------------------
// stdout capture helper for tests that assert on query output
// ---------------------------------------------------------------------------
static std::string capture_stdout(std::function<void()> fn) {
    fflush(stdout);
    int saved = dup(fileno(stdout));
    FILE* tmp = tmpfile();
    dup2(fileno(tmp), fileno(stdout));
    fn();
    fflush(stdout);
    dup2(saved, fileno(stdout));
    close(saved);
    rewind(tmp);
    std::string out;
    char b[4096];
    size_t n;
    while ((n = fread(b, 1, sizeof b, tmp)) > 0) out.append(b, n);
    fclose(tmp);
    return out;
}

// record a hand-built instruction stream: (word, wr_reg or -1, mem op or none)
struct MiniInsn {
    uint32_t word;
    int wr;           // xN written by this insn (-1 = none; q writes need no lane)
    uint64_t wr_val;
    int mem_is_write; // -1 = no mem, 0 = read, 1 = write
    uint64_t mem_addr;
};
static void record_mini(const char* path, const char* module, uint64_t base,
                        const std::vector<MiniInsn>& prog) {
    SiteArena arena;
    for (size_t i = 0; i < prog.size(); i++)
        arena.intern(base + i * 4, prog[i].word, module, base, -1);
    RecOptions ro;
    ro.initial_sp = 0x70000000;
    GtbRecorder g(arena);
    g.open(path, ro);
    for (size_t i = 0; i < prog.size(); i++) {
        ExecEvent ev{};
        ev.pc = base + i * 4;
        ev.sp = 0x70000000;
        if (prog[i].wr >= 0) {
            ev.n_wr = 1;
            ev.wr_id[0] = prog[i].wr;
            ev.wr_val[0] = prog[i].wr_val;
        }
        if (prog[i].mem_is_write >= 0) {
            ev.n_mem = 1;
            ev.mem[0].is_write = prog[i].mem_is_write == 1;
            ev.mem[0].addr = prog[i].mem_addr;
            ev.mem[0].size = 16;
            ev.mem[0].value = 0;
        }
        g.record_event(ev);
    }
    g.finish();
}

// ---------------------------------------------------------------------------
// T25: diff identity is (module, offset) — a rebased run must compare equal
// ---------------------------------------------------------------------------
static void test_diff_module_offset() {    printf("[T25] diff across rebased module (ASLR) via (module, offset) identity\n");
    CorpusConfig cfg;
    cfg.outer_iters = 20;
    cfg.inner_iters = 15;
    Program p = build_program(cfg);
    SiteArena a1 = compile_sites(p);
    RecOptions ro;
    ro.initial_sp = corpus_stack_top();
    {
        GtbRecorder g(a1);
        g.open("build/d25a.gtb", ro);
        run_program(p, cfg, 0, [](const ExecEvent& ev, void* u) {
            static_cast<GtbRecorder*>(u)->record_event(ev);
        }, &g);
        g.finish();
    }
    // run B: same image relocated 16MB up (same words, same module name)
    const uint64_t slide = 0x1000000;
    SiteArena a2;
    for (const auto& d : p.insns)
        a2.intern(d.addr + slide, d.word, p.module_name.c_str(), p.base + slide, -1);
    {
        GtbRecorder g(a2);
        g.open("build/d25b.gtb", ro);
        run_program(p, cfg, 0, [](const ExecEvent& ev, void* u) {
            ExecEvent e2 = ev;
            e2.pc += 0x1000000;
            static_cast<GtbRecorder*>(u)->record_event(e2);
        }, &g);
        g.finish();
    }
    std::string same = capture_stdout([] { q_diff("build/d25a.gtb", "build/d25b.gtb", 2); });
    CHECK(same.find("identical execution sequences") != std::string::npos,
          "rebased run compares identical under (module, offset) keys");
    // negative control: a variant run rebased must still diverge, at the same
    // exec index as the same-base diff
    CorpusConfig c2;
    c2.outer_iters = cfg.outer_iters;
    c2.inner_iters = cfg.inner_iters;
    c2.variant_const = 0x2B00;
    Program p2 = build_program(c2);
    SiteArena a3;
    for (const auto& d : p2.insns)
        a3.intern(d.addr + slide, d.word, p.module_name.c_str(), p.base + slide, -1);
    {
        GtbRecorder g(a3);
        g.open("build/d25c.gtb", ro);
        run_program(p2, c2, 0, [](const ExecEvent& ev, void* u) {
            ExecEvent e2 = ev;
            e2.pc += 0x1000000;
            static_cast<GtbRecorder*>(u)->record_event(e2);
        }, &g);
        g.finish();
    }
    std::string dSameBase = capture_stdout([] { q_diff("build/v1.gtb", "build/v2.gtb", 2); });
    std::string dRebased = capture_stdout([] { q_diff("build/d25a.gtb", "build/d25c.gtb", 2); });
    auto div_of = [](const std::string& s) -> long {
        size_t p1 = s.find("first divergence at exec index ");
        if (p1 == std::string::npos) return -1;
        return atol(s.c_str() + p1 + 29);
    };
    CHECK(div_of(dSameBase) >= 0 && div_of(dSameBase) == div_of(dRebased),
          "rebased variant diverges at the same exec index as the same-base diff");
}

// ---------------------------------------------------------------------------
// T26: backward taint propagates through NZCV (subs -> csel chain)
// ---------------------------------------------------------------------------
static void test_taint_nzcv() {
    printf("[T26] backward taint through NZCV (subs -> csel)\n");
    uint64_t base = 0x10000;
    std::vector<MiniInsn> prog = {
        {enc::movz(0, 5), 0, 5, -1, 0},                    // movz x0, #5
        {enc::movz(1, 9), 1, 9, -1, 0},                    // movz x1, #9
        {enc::movz(4, 1), 4, 1, -1, 0},                    // movz x4, #1
        {enc::movz(5, 2), 5, 2, -1, 0},                    // movz x5, #2
        {enc::subs_reg(2, 0, 1), 2, 0, -1, 0},             // subs x2, x0, x1  -> NZCV
        {enc::csel(3, 4, 5, 0), 3, 1, -1, 0},              // csel x3, x4, x5, eq
    };
    // self-verify the hand-rolled encodings through capstone
    site_compiler_init();
    SiteArena chk;
    uint32_t s5 = chk.intern(base + 5 * 4, prog[5].word, "mini.so", base, -1);
    const Site& cs = chk.get(s5);
    bool cc_ok = false, uw_ok = false;
    for (uint8_t i = 0; i < cs.n_ops; i++)
        if (cs.ops[i].op_flags & OPF_R_NZCV) cc_ok = true;
    uint32_t s4 = chk.intern(base + 4 * 4, prog[4].word, "mini.so", base, -1);
    for (uint8_t i = 0; i < chk.get(s4).n_ops; i++)
        if (chk.get(s4).ops[i].op_flags & OPF_W_NZCV) uw_ok = true;
    CHECK(cc_ok && uw_ok, "plan marks csel as NZCV reader and subs as NZCV writer");

    record_mini("build/t26.gtb", "mini.so", base, prog);
    std::string out = capture_stdout([] {
        q_taint("build/t26.gtb", 0, 3, -1, false, true, 30, 0, 0, 0, "");
    });
    CHECK(out.find("source reg x0") != std::string::npos &&
              out.find("source reg x1") != std::string::npos,
          "backward from x3 reaches x0/x1 through NZCV");
    CHECK(out.find("source reg nzcv") != std::string::npos,
          "NZCV edge reported explicitly");
}

// ---------------------------------------------------------------------------
// T27: backward taint propagates through SIMD registers (ldr q / eor v / str q)
// ---------------------------------------------------------------------------
static void test_taint_simd() {
    printf("[T27] backward taint through q registers (no SIMD values recorded)\n");
    uint64_t base = 0x20000;
    uint64_t src = 0x4000, dst = 0x5000;
    std::vector<MiniInsn> prog = {
        {enc::ldr_q(1, 20, 0), -1, 0, 0, src},       // ldr q1, [x20]
        {enc::eor_v16b(0, 1, 2), -1, 0, -1, 0},      // eor v0.16b, v1.16b, v2.16b
        {enc::str_q(0, 21, 0), -1, 0, 1, dst},       // str q0, [x21]
    };
    site_compiler_init();
    SiteArena chk;
    bool ok = chk.intern(base, prog[0].word, "mini.so", base, -1) != 0xFFFFFFFFu;
    CHECK(ok, "SIMD encodings disassemble");
    record_mini("build/t27.gtb", "mini.so", base, prog);
    std::string out = capture_stdout([dst] {
        q_taint("build/t27.gtb", dst, -1, -1, false, true, 30, 0, 0, 0, "");
    });
    CHECK(out.find("source reg q0") != std::string::npos &&
              out.find("source reg q1") != std::string::npos,
          "backward from stored mem reaches q0/q1 through the v-reg eor");
    CHECK(out.find("source mem 0x4000") != std::string::npos ||
              out.find("source mem 16384") != std::string::npos,
          "chain ends at the source load address");
}

// ---------------------------------------------------------------------------
// T28: taint coordinates (--at-ev / --off) and loud PARTIAL on window limits
// ---------------------------------------------------------------------------
static void test_taint_coords() {
    printf("[T28] taint --at-ev/--off coordinates + PARTIAL marker\n");
    CorpusConfig cfg;
    cfg.outer_iters = 10;
    cfg.inner_iters = 8;
    Program p = build_program(cfg);
    SiteArena arena = compile_sites(p);
    RecOptions ro;
    ro.initial_sp = corpus_stack_top();
    {
        GtbRecorder g(arena);
        g.open("build/t28.gtb", ro);
        run_program(p, cfg, 0, [](const ExecEvent& ev, void* u) {
            static_cast<GtbRecorder*>(u)->record_event(ev);
        }, &g);
        g.finish();
    }
    // --off: pick a site inside the inner loop (executed many times)
    uint64_t off = p.insns[5].addr - p.base;
    std::string out = capture_stdout([&] {
        q_taint("build/t28.gtb", 0, 0, -1, false, false, 5, 0, 0, off, "");
    });
    CHECK(out.find("(event") != std::string::npos,
          "--off seed resolves to an event coordinate");
    // window-limited forward walk must announce PARTIAL on the first line
    std::string pw = capture_stdout([] {
        q_taint("build/t28.gtb", 0, 0, -1, false, false, 5, 3, 0, 0, "");
    });
    CHECK(pw.rfind("PARTIAL:", 0) == 0, "window-limited forward taint prints PARTIAL first");
    // --at-ev: seeds later in the stream
    std::string ae = capture_stdout([] {
        q_taint("build/t28.gtb", 0, 0, -1, false, false, 5, 0, 1000, 0, "");
    });
    CHECK(ae.find("ev=1000") != std::string::npos || ae.find("(event 1000)") != std::string::npos,
          "--at-ev 1000 seeds at event 1000");
}

// ---------------------------------------------------------------------------
// T29: agent output contract — export compact/jsonl, cursor, --json meta
// ---------------------------------------------------------------------------
static void test_agent_output() {
    printf("[T29] export compact/jsonl + cursor + --json meta line\n");
    // reuses build/t28.gtb (recorded by T28; selftest order guarantees it)
    GtbFile f;
    CHECK(f.load("build/t28.gtb"), "t28.gtb parses (T29 runs after T28)");

    // compact: module header, ev-prefixed event lines, no module repetition
    {
        FILE* o = fopen("build/t29c.txt", "wb");
        Expander(f).expand_compact(o);
        fclose(o);
        std::ifstream sf("build/t29c.txt");
        std::stringstream ss;
        ss << sf.rdbuf();
        std::string txt = ss.str();
        CHECK(txt.rfind("== ", 0) == 0, "compact starts with a '== ' module header");
        bool ok_lines = true, saw_ev = false;
        size_t pos = 0;
        while (pos < txt.size()) {
            size_t e = txt.find('\n', pos);
            std::string ln = txt.substr(pos, e == std::string::npos ? std::string::npos : e - pos);
            pos = e == std::string::npos ? txt.size() : e + 1;
            if (ln.empty()) continue;
            if (ln.rfind("== ", 0) == 0) continue;         // module switch header
            if (ln[0] == '+' || ln[0] == 'n') continue;    // +call/+ret/+svc/next
            if (ln[0] >= '0' && ln[0] <= '9') {
                saw_ev = true;
                if (ln.find(" !0x") == std::string::npos ||
                    ln.find("libtarget.so") != std::string::npos)
                    ok_lines = false;
            } else {
                ok_lines = false;
            }
        }
        CHECK(ok_lines && saw_ev,
              "compact event lines are '<ev> !0x<off> ...' without module names");
    }

    // jsonl: every line is one object carrying an ev field
    {
        FILE* o = fopen("build/t29j.txt", "wb");
        Expander(f).expand_jsonl(o);
        fclose(o);
        std::ifstream sf("build/t29j.txt");
        std::stringstream ss;
        ss << sf.rdbuf();
        std::string txt = ss.str();
        bool ok = !txt.empty();
        int lines = 0;
        size_t pos = 0;
        while (pos < txt.size() && ok) {
            size_t e = txt.find('\n', pos);
            std::string ln = txt.substr(pos, e == std::string::npos ? std::string::npos : e - pos);
            pos = e == std::string::npos ? txt.size() : e + 1;
            if (ln.empty()) continue;
            lines++;
            if (ln[0] != '{' || ln.find("\"ev\":") == std::string::npos) ok = false;
        }
        CHECK(ok && lines > 100, "jsonl lines are objects with \"ev\" (N lines)");
    }

    // cursor: --limit 5 stops and reports the 6th event's ev
    {
        FILE* o = fopen("build/t29l.txt", "wb");
        uint64_t stop = 0;
        uint64_t n = Expander(f).expand_compact(o, 0, UINT64_MAX, 5, &stop);
        fclose(o);
        CHECK(n == 5, "compact --limit 5 emits 5 lines");
        CHECK(stop != 0 && stop != UINT64_MAX, "cursor reports the stop event");
        FILE* o2 = fopen("build/t29n.txt", "wb");
        Expander(f).expand_compact(o2, stop, stop, 0);
        fclose(o2);
        std::ifstream sf("build/t29n.txt");
        std::stringstream ss;
        ss << sf.rdbuf();
        std::string all = ss.str(), first;
        size_t p2 = 0;
        while (p2 < all.size()) { // first event line (page may open with == header)
            size_t e = all.find('\n', p2);
            std::string ln = all.substr(p2, e == std::string::npos ? std::string::npos : e - p2);
            p2 = e == std::string::npos ? all.size() : e + 1;
            if (!ln.empty() && ln[0] >= '0' && ln[0] <= '9') { first = ln; break; }
        }
        char expect[32];
        snprintf(expect, sizeof expect, "%llu ", (unsigned long long)stop);
        CHECK(first.rfind(expect, 0) == 0,
              "cursor ev is the next (6th) event — '--from stop' re-emits exactly it");
    }

    // --json meta line: truncation flag + copy-executable continuation
    {
        std::unordered_map<uint64_t, int> cnt;
        Expander(f).for_each([&](uint64_t, const Group& g) {
            for (int k = 0; k < g.n_mem; k++) cnt[g.mem[k].addr]++;
            return true;
        });
        uint64_t hot = 0;
        int best = 0;
        for (auto& kv : cnt)
            if (kv.second > best) { best = kv.second; hot = kv.first; }
        CHECK(best >= 3, "trace has a hot address with >= 3 accesses");
        std::string out = capture_stdout(
            [&] { q_mem_access("build/t28.gtb", hot, false, 0, 0, 2, 0, true); });
        CHECK(out.find("\"meta\":{\"truncated\":true") != std::string::npos,
              "mem-access --json ends with a meta line, truncated=true");
        CHECK(out.find("\"next\":\"gt mem-access --addr 0x") != std::string::npos &&
                  out.find("--offset 2") != std::string::npos,
              "meta.next is the full continuation command (--offset 2)");
        std::string st = capture_stdout([&] { q_stat("build/t28.gtb", true); });
        CHECK(st.find("\"meta\":{") != std::string::npos &&
                  st.find("\"suggest\":[") != std::string::npos,
              "stat --json meta carries suggested next commands");
        std::string tf = capture_stdout(
            [&] { q_mem_access("build/t28.gtb", hot, false, 0, 0, best, 0, true); });
        CHECK(tf.find("\"truncated\":false") != std::string::npos,
              "meta truncated=false when the window covers every row");
    }
}

// ---------------------------------------------------------------------------
// T30: upstream log import — byte-exact round trip, dialect byte, group decode
// ---------------------------------------------------------------------------
static void test_import() {
    printf("[T30] import upstream log -> gtb -> byte-identical export\n");
    // one line per grammar shape, CRLF endings, plus off-grammar lines that
    // must land in VERBATIM (string preview, banner, non-canonical hex,
    // >8 tokens, mem token after "->")
    static const char log[] =
        "[liba.so] 0x7523a15064!0x1c3064 stp x20, x19, [sp, #0x40]; x20=0x25647380 x19=0x765f0cc050 sp=0x765f0cb8e0 mem_w=0x765f0cb920 \r\n"
        "[liba.so] 0x7523a15068!0x1c3068 mov x29, sp; fp=0x765f0cc920 sp=0x765f0cb8e0 -> fp=0x765f0cb8e0 \r\n"
        "[liba.so] 0x7523a1507c!0x1c307c bl #0x7523ac2d20; \r\n"
        "[liba.so] 0x7523ac2d2c!0x270d2c br x17; x17=0x79ab967260 \r\n"
        "call func: getpid()\r\n"
        "ret: 0x3341\r\n"
        "[liba.so] 0x7523a15084!0x1c3084 movi v0.2d, #0000000000000000; v0=0xa2a2a2a2a2a2a2a2 -> v0=0x0 \r\n"
        "[liba.so] 0x7523a15074!0x1c3074 ldr x8, [x25, #0x28]; x8=0x75239ea168 x25=0x765f0cdac0 mem_r=0x765f0cdae8 -> x8=0xfdfc9d0dd48405de \r\n"
        "[liba.so] 0x7523a15094!0x1c3094 stp q0, q0, [x29, #-0x90]; q0=0x0 q0=0x0 fp=0x765f0cb8e0 mem_w=0x765f0cb850 \r\n"
        "args0: /proc/13121/mounts\r\n"
        "call func: fopen64(0x765f0cb850, 0x75238dc6c5)\r\n"
        "[liba.so] 0x7523a15204!0x1c3204 ret ; \r\n"
        "some weird banner line\r\n"
        "[liba.so] 0x7523a1508c!0x1c308c mov w2, #0x400; w2=0x00 -> w2=0x400 \r\n"   // leading zero -> verbatim
        "[liba.so] 0x7523a15090!0x1c3090 ldr x0, [x1]; x0=0x1 x1=0x2 x2=0x3 x3=0x4 x4=0x5 x5=0x6 x6=0x7 mem_r=0x8 -> x0=0x9 \r\n" // 9 tokens -> verbatim
        "[liba.so] 0x7523a15098!0x1c3098 str x0, [x1]; x0=0x9 x1=0x8 mem_w=0x8 -> mem_w=0x8 \r\n"; // mem after "->" -> verbatim
    ImportResult r;
    RecOptions ro;
    CHECK(import_mem(log, sizeof(log) - 1, "build/t30.gtb", ro, r),
          "import_mem accepts the mini upstream log");
    CHECK(r.cnt.lines == 16 && r.cnt.exec == 8 && r.cnt.call == 2 &&
              r.cnt.ret == 1 && r.cnt.verbatim == 5,
          "line classification counts (16/8/2/1/5)");

    GtbFile f;
    CHECK(f.load("build/t30.gtb"), "imported gtb loads (deferred META)");
    CHECK(f.dialect == 3, "dialect byte = upstream|CRLF (3)");
    std::string out = capture_stdout(
        [&] { Expander(f).expand_upstream(stdout); });
    CHECK(out == std::string(log, sizeof(log) - 1),
          "export --format upstream replays the log byte-for-byte");

    // group decode: REGW reconstruction from the write tail, mem_r decodes as
    // a READ (tag-7 flags regression), call/ret ride the preceding group
    bool saw_fp_write = false, saw_mem_read = false, saw_call_ret = false;
    Expander(f).for_each([&](uint64_t, const Group& g) {
        if (!g.has_exec) return true;
        const Site& s = f.arena.get(g.site_id);
        for (int k = 0; k < g.n_wr; k++)
            if (s.addr == 0x7523a15068 && g.wr_id[k] == 29 &&
                g.wr_val[k] == 0x765f0cb8e0)
                saw_fp_write = true;
        for (int k = 0; k < g.n_mem; k++)
            if (!g.mem[k].is_write && g.mem[k].addr == 0x765f0cdae8)
                saw_mem_read = true;
        if (g.is_call && g.is_ret && g.call_name &&
            strcmp(g.call_name, "getpid") == 0 && g.ret_val == 0x3341)
            saw_call_ret = true;
        return true;
    });
    CHECK(saw_fp_write, "write tail feeds register reconstruction (fp)");
    CHECK(saw_mem_read, "mem_r token decodes as a read MemOp (tag-7 fix)");
    CHECK(saw_call_ret, "call/ret lines ride the preceding group in order");

    // LF dialect + unterminated final line
    static const char log2[] =
        "[m.so] 0x1000!0x0 nop; \n"
        "tail without newline";
    ImportResult r2;
    CHECK(import_mem(log2, sizeof(log2) - 1, "build/t30b.gtb", ro, r2),
          "LF log imports");
    GtbFile f2;
    CHECK(f2.load("build/t30b.gtb") && f2.dialect == 1, "dialect = upstream, LF");
    std::string out2 = capture_stdout(
        [&] { Expander(f2).expand_upstream(stdout); });
    CHECK(out2 == std::string(log2, sizeof(log2) - 1),
          "unterminated tail round-trips via VERBATIM");
}

// ---------------------------------------------------------------------------
// T31: W3b streaming gtb queries — stat / mem-access / find-value / calltree
// ---------------------------------------------------------------------------
static void test_stat_queries() {
    printf("[T31] stat / mem-access / find-value / calltree on gtb\n");
    const uint64_t base = 0x80000, sp = 0x70000000;
    // sites: prologue (mov/str), a call to outer, outer calls inner, returns,
    // then an independent ldr
    const uint32_t words[] = {
        enc::movz(8, 0xbeef),      // 0x80000
        enc::str_x(8, 31, 0x10),   // 0x80004
        enc::bl(0x0c),             // 0x80008 -> 0x80014 (outer)
        enc::ldr_x(9, 31, 0x20),   // 0x8000c
        enc::ret(),                // 0x80010
        enc::movz(9, 0x1234),      // 0x80014 (outer body)
        enc::bl(0x08),             // 0x80018 -> 0x80020 (inner)
        enc::ret(),                // 0x8001c (outer ret)
        enc::nop(),                // 0x80020 (inner body)
        enc::ret(),                // 0x80024 (inner ret)
    };
    SiteArena arena;
    for (size_t i = 0; i < sizeof words / sizeof words[0]; i++)
        arena.intern(base + i * 4, words[i], "mini.so", base, -1);
    {
        RecOptions ro;
        ro.initial_sp = sp;
        GtbRecorder g(arena);
        g.open("build/t31.gtb", ro);
        auto emit = [&](uint64_t pc, int wr, uint64_t wv, int mw, uint64_t ma,
                        bool call, const char* cn, bool isret, uint64_t rv) {
            ExecEvent ev{};
            ev.pc = pc;
            ev.sp = sp;
            if (wr >= 0) { ev.n_wr = 1; ev.wr_id[0] = wr; ev.wr_val[0] = wv; }
            if (mw >= 0) {
                ev.n_mem = 1;
                ev.mem[0].is_write = mw == 1;
                ev.mem[0].addr = ma;
                ev.mem[0].size = 8;
                ev.mem[0].value = mw == 1 ? 0xdeadbeef : 0x5555;
            }
            ev.is_call = call;
            ev.call_name = cn;
            if (call) { ev.x[0] = 0xaa; ev.x[1] = 0xbb; }
            ev.is_ret = isret;
            ev.ret_val = rv;
            g.record_event(ev);
        };
        emit(base + 0x00, 8, 0xdeadbeef, -1, 0, false, nullptr, false, 0);
        emit(base + 0x04, -1, 0, 1, sp + 0x10, false, nullptr, false, 0);
        emit(base + 0x08, -1, 0, -1, 0, true, "outer", false, 0);
        emit(base + 0x14, 9, 0x1234, -1, 0, false, nullptr, false, 0);
        emit(base + 0x18, -1, 0, -1, 0, true, "inner", false, 0);
        emit(base + 0x20, -1, 0, -1, 0, false, nullptr, false, 0);
        emit(base + 0x24, -1, 0, -1, 0, false, nullptr, true, 0xcc);
        emit(base + 0x1c, -1, 0, -1, 0, false, nullptr, true, 0xdd);
        emit(base + 0x0c, 9, 0x5555, 0, sp + 0x20, false, nullptr, false, 0);
        g.finish();
    }
    GtbFile f;
    CHECK(f.load("build/t31.gtb"), "t31.gtb parses");

    std::string st = capture_stdout([] { q_stat("build/t31.gtb", false); });
    CHECK(st.find("exec=9") != std::string::npos &&
              st.find("mini.so") != std::string::npos,
          "stat text shows exec count and module");
    std::string sj = capture_stdout([] { q_stat("build/t31.gtb", true); });
    CHECK(sj.find("\"exec\":9") != std::string::npos &&
              sj.find("\"meta\":{") != std::string::npos,
          "stat --json carries counts and the meta line");

    std::string mw = capture_stdout([sp] {
        q_mem_access("build/t31.gtb", sp + 0x10, false, 0, 0, 10, 0, false);
    });
    CHECK(mw.find(" w 0x") != std::string::npos &&
              mw.find("0x70000010") != std::string::npos,
          "mem-access --addr finds the store");
    std::string mr = capture_stdout([sp] {
        q_mem_access("build/t31.gtb", 0, true, sp, 0x100, 10, 0, false);
    });
    CHECK(mr.find("0x70000010") != std::string::npos &&
              mr.find("0x70000020") != std::string::npos,
          "mem-access --range covers store and load");
    std::string mwonly = capture_stdout([sp] {
        q_mem_access("build/t31.gtb", sp + 0x10, false, 0, 0, 10, 0, false, true);
    });
    CHECK(mwonly.find(" w 0x70000010") != std::string::npos,
          "mem-access --write keeps the store row");
    std::string mrw = capture_stdout([sp] {
        q_mem_access("build/t31.gtb", sp + 0x20, false, 0, 0, 10, 0, false, true);
    });
    CHECK(mrw.find(" r 0x70000020") == std::string::npos &&
              mrw.find("no rows") == std::string::npos,
          "mem-access --write filters out read-only addresses");

    std::string fa = capture_stdout([] {
        q_func_args("build/t31.gtb", "inner", 1, 1, false);
    });
    CHECK(fa.find("ev=") != std::string::npos && fa.find("x0=") != std::string::npos,
          "func-args prints the call's reconstructed arguments");
    std::string fj = capture_stdout([] {
        q_func_args("build/t31.gtb", "inner", 1, 1, true);
    });
    CHECK(fj.find("\"args\":[\"0xaa\",\"0xbb\",\"0x0\",\"0x0\"]") != std::string::npos &&
              fj.find("\"meta\":{") != std::string::npos,
          "func-args --json emits args as hex strings + the meta line");
    std::string fn = capture_stdout([] {
        q_func_args("build/t31.gtb", "nosuch", 1, 1, false);
    });
    CHECK(fn.find("no call to nosuch") != std::string::npos,
          "func-args reports a missing function plainly");

    std::string fv = capture_stdout([] {
        q_find_value("build/t31.gtb", 0xdeadbeef, 10, 0, false);
    });
    CHECK(fv.find("x8") != std::string::npos && fv.find("0xdeadbeef") != std::string::npos,
          "find-value locates the x8 write");
    std::string fv2 = capture_stdout([] {
        q_find_value("build/t31.gtb", 0x5555, 10, 0, false);
    });
    CHECK(fv2.find("x9") != std::string::npos && fv2.find("mem_r") != std::string::npos,
          "find-value sees both the reg write and the load value lanes");

    std::string ct = capture_stdout([] {
        q_calltree_gtb("build/t31.gtb", "outer", 3, 40, false);
    });
    CHECK(ct.find("outer(") != std::string::npos &&
              ct.find("\n  inner(") != std::string::npos,
          "calltree nests inner under outer");
    std::string cn = capture_stdout([] {
        q_calltree_gtb("build/t31.gtb", "nosuch", 3, 40, false);
    });
    CHECK(cn.find("no call to nosuch") != std::string::npos,
          "calltree reports a missing function plainly");
}

// ---------------------------------------------------------------------------
// T32: dynamic detail escalation — calls-only run flips to full on a symbol
// ---------------------------------------------------------------------------
static void test_escalate() {
    printf("[T32] dynamic detail escalation (calls -> full on symbol)\n");
    CorpusConfig cfg;
    cfg.outer_iters = 50;
    cfg.inner_iters = 20;
    Program p = build_program(cfg);
    SiteArena arena = compile_sites(p);
    RecOptions ro;
    ro.initial_sp = corpus_stack_top();
    ro.detail = DETAIL_CALLS;
    ro.escalate_sym = "transform_block_1"; // same trampoline-called func as T6
    ro.escalate_detail = DETAIL_FULL;
    ro.escalate_events = 500;
    GtbRecorder g(arena);
    g.open("build/t32.gtb", ro);
    run_program(p, cfg, 0, [](const ExecEvent& ev, void* u) {
        static_cast<GtbRecorder*>(u)->record_event(ev);
    }, &g);
    RecStats st = g.finish();
    CHECK(g.escalated(), "escalation fired on the trigger symbol");
    CHECK(g.current_detail() == DETAIL_CALLS,
          "budget drained: detail fell back to calls-only");

    GtbFile f;
    CHECK(f.load("build/t32.gtb"), "t32.gtb parses");
    CHECK(f.n_exec >= 100 && f.n_exec <= 600,
          "full-detail window is bounded (~escalate_events)");
    CHECK(f.n_exec < st.events_seen / 10,
          "most of the run stayed calls-only (no EXEC events)");
    CHECK(f.n_regw > 0 && f.n_mem > 0,
          "the escalated window carries register writes and mem ops");
    // the trigger call group precedes the first exec group
    uint64_t first_call_gi = UINT64_MAX, first_exec_gi = UINT64_MAX;
    Expander(f).for_each([&](uint64_t gi, const Group& g2) {
        if (first_call_gi == UINT64_MAX && !g2.has_exec && g2.is_call)
            first_call_gi = gi;
        if (first_exec_gi == UINT64_MAX && g2.has_exec) first_exec_gi = gi;
        return first_exec_gi == UINT64_MAX;
    });
    CHECK(first_call_gi != UINT64_MAX && first_exec_gi != UINT64_MAX &&
              first_call_gi < first_exec_gi,
          "calls-only prefix precedes the escalated full-detail window");
}

// ---------------------------------------------------------------------------
// T33: regressions for the four defects found in the agent-methodology eval —
// obs-preferring legacy export, SIMD-lane taint operands, 128-bit find-value
// lanes, and verbatim-hexdump memcpy bridging in taint
// ---------------------------------------------------------------------------
static void test_import_agent_fixes() {
    printf("[T33] import-fed fixes: obs export / lane taint / 128b lanes / memcpy bridge\n");
    RecOptions ro;

    // (1) legacy export must print the observed reads, not the stale shadow:
    // x0/x9 are produced inside the unrecorded foo() call, so the write-history
    // shadow never saw them (it would print 0x0). NOTE: upstream grammar
    // requires a trailing space after the last token of an instruction line.
    static const char log1[] =
        "[liba.so] 0x7523a15064!0x1c3064 blr x8; x8=0x1000 \n"
        "call func: foo()\n"
        "ret: 0xdead\n"
        "[liba.so] 0x7523a15068!0x1c3068 str x0, [x9]; x0=0xdead x9=0x5000 mem_w=0x5000 \n";
    ImportResult r1;
    CHECK(import_mem(log1, sizeof(log1) - 1, "build/t33a.gtb", ro, r1),
          "fixture 1 imports");
    CHECK(r1.cnt.exec == 2 && r1.cnt.call == 1 && r1.cnt.ret == 1,
          "fixture 1 lines parse as instructions (trailing-space grammar)");
    {
        GtbFile f;
        CHECK(f.load("build/t33a.gtb"), "t33a.gtb loads");
        std::string out =
            capture_stdout([&] { Expander(f).expand_text(stdout); });
        CHECK(out.find("x0=0xdead x9=0x5000") != std::string::npos,
              "legacy export prints observed reads, not the stale shadow");
    }

    // (2) taint propagates through umov/mov vN.lane[i]: the operand parser
    // treated any operand containing '[' as memory, so "v2.b[0]" killed the
    // chain — only operands STARTING with '[' are memory
    static const char log2[] =
        "[m.so] 0x1000!0x0 ldr q2, [x13]; x13=0x6000 mem_r=0x6000 -> q2=0x61616161616161616161616161616161 \n"
        "[m.so] 0x1004!0x4 umov w14, v2.b[0]; w14=0x0 -> w14=0x61 \n"
        "[m.so] 0x1008!0x8 mov v1.h[0], w14; w14=0x61 \n";
    ImportResult r2;
    CHECK(import_mem(log2, sizeof(log2) - 1, "build/t33b.gtb", ro, r2),
          "fixture 2 imports");
    CHECK(r2.cnt.exec == 3, "fixture 2 lines parse as instructions");
    {
        std::string out = capture_stdout([] {
            q_taint("build/t33b.gtb", 0, -1, 2, false, false, 20, 0, 0, 0, "",
                    false);
        });
        CHECK(out.find("x14 <- reg") != std::string::npos,
              "umov w14, v2.b[0] propagates q2 -> x14");
        CHECK(out.find("q1 <- reg") != std::string::npos,
              "mov v1.h[0], w14 propagates x14 -> q1");
    }

    // (3) find-value matches the 64-bit lanes of a 128-bit SIMD observation,
    // reported as .lo / .hi
    static const char log3[] =
        "[m.so] 0x1000!0x0 ldr q5, [x10]; x10=0x7000 mem_r=0x7000 -> q5=0x7f8e175ae2e7edbbaa1cdb90f22c26a8 \n";
    ImportResult r3;
    CHECK(import_mem(log3, sizeof(log3) - 1, "build/t33c.gtb", ro, r3),
          "fixture 3 imports");
    CHECK(r3.cnt.exec == 1, "fixture 3 line parses as an instruction");
    {
        std::string lo = capture_stdout([] {
            q_find_value("build/t33c.gtb", 0xaa1cdb90f22c26a8, 10, 0, false);
        });
        CHECK(lo.find("wr:q5.lo") != std::string::npos,
              "find-value matches the low lane of a 128-bit write obs");
        std::string hi = capture_stdout([] {
            q_find_value("build/t33c.gtb", 0x7f8e175ae2e7edbb, 10, 0, false);
        });
        CHECK(hi.find("wr:q5.hi") != std::string::npos,
              "find-value matches the high lane of a 128-bit write obs");
    }

    // (4) verbatim hexdump after a memcpy-class call bridges taint across the
    // copy, in both directions (the AES-key orphan-address break in the eval)
    static const char log4[] =
        "[m.so] 0x1000!0x0 str x8, [x9]; x8=0x1111 x9=0x5000 mem_w=0x5000 \n"
        "[m.so] 0x1004!0x4 br x16; x16=0x3000 \n"
        "call func: __memcpy_aarch64_simd(0x7000, 0x5000, 0x8)\n"
        "hexdump at address 0x5000 with length 0x8:\n"
        "0000000000005000  11 11 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|\n"
        "ret: 0x7000\n"
        "[m.so] 0x1008!0x8 ldr x10, [x12]; x10=0x0 x12=0x7000 mem_r=0x7000 -> x10=0x1111 \n";
    ImportResult r4;
    CHECK(import_mem(log4, sizeof(log4) - 1, "build/t33d.gtb", ro, r4),
          "fixture 4 imports");
    CHECK(r4.cnt.exec == 3 && r4.cnt.verbatim == 2,
          "fixture 4: 3 instructions + 2 verbatim hexdump lines");
    {
        std::string fwd = capture_stdout([] {
            q_taint("build/t33d.gtb", 0x5000, -1, -1, false, false, 20, 0, 0,
                    0, "", false);
        });
        CHECK(fwd.find("memcpy : dst <- tainted src cells") != std::string::npos,
              "forward: verbatim hexdump bridges the memcpy src -> dst");
        CHECK(fwd.find("x10 <- mem") != std::string::npos,
              "forward: the load from the copy destination is reached");
        std::string bwd = capture_stdout([] {
            q_taint("build/t33d.gtb", 0x7000, -1, -1, false, true, 20, 0, 0, 0,
                    "", false);
        });
        CHECK(bwd.find("memcpy : demand -> src cells") != std::string::npos,
              "backward: demand on the copy destination moves to the source");
        CHECK(bwd.find("source reg x8") != std::string::npos,
              "backward: the chain reaches the original store's source reg");
        // limit 1 truncates the edge list -> meta.next must re-emit the seed
        // address in hex (a decimal "0x20480" would send the agent elsewhere)
        std::string trunc = capture_stdout([] {
            q_taint("build/t33d.gtb", 0x5000, -1, -1, false, false, 1, 0, 0,
                    0, "", false);
        });
        CHECK(trunc.find("next: gt taint --seed-addr 0x5000 --limit") !=
                  std::string::npos,
              "meta.next re-emits --seed-addr in hex, not decimal");
    }
}

int cmd_selftest() {
    site_compiler_init();
    system("mkdir -p build");
    test_encoder_and_plan();
    test_ring_bug();
    test_equivalence();
    test_guards();
    test_crash();
    test_trigger_ring();
    test_diff();
    test_diff_module_offset();
    test_taint_nzcv();
    test_taint_simd();
    test_taint_coords();
    test_agent_output();
    test_import();
    test_stat_queries();
    test_escalate();
    test_import_agent_fixes();
    printf("\n%s (%d failures)\n", g_fail ? "SELFTEST FAILED" : "ALL TESTS PASSED", g_fail);
    site_compiler_shutdown();
    return g_fail ? 1 : 0;
}
