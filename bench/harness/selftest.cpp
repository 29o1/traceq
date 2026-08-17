// Correctness tests for libgumtrace, driven through the synthetic corpus.
//
// These live on the benchmark side because every one of them needs an event
// source to produce input, and the product deliberately has none.

#include "corpus.h"
#include "harness.h"
#include "legacy.h"
#include <gumtrace/common.h>
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

using namespace gt;

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
    printf("\n%s (%d failures)\n", g_fail ? "SELFTEST FAILED" : "ALL TESTS PASSED", g_fail);
    site_compiler_shutdown();
    return g_fail ? 1 : 0;
}
