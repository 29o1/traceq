// gt-harness — the benchmark's event source and in-process timer.
//
// Why this binary exists at all: the benchmark is driven by run.py, which
// shells out to the real `gt` CLI for everything it can measure as a black box
// (volume, query latency, equivalence, guards, crash). Two things cannot be
// measured that way:
//
//   1. per-event recorder cost (ns/event). Timing `gt record` from outside
//      would include the event source's own cost, which is exactly what the
//      A/B comparison must exclude — in a real deployment that cost is the
//      Stalker engine and it is identical on both sides.
//   2. recording itself, because the product has no event source: libgumtrace
//      is deliberately corpus-free, so the synthetic corpus lives here.
//
// Everything this binary prints is machine-readable (JSON) or a test verdict.

#include "corpus.h"
#include "harness.h"
#include "legacy.h"
#include <gumtrace/common.h>
#include <gumtrace/queries.h>
#include <gumtrace/recorder.h>
#include <gumtrace/site.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

using namespace gt;

int cmd_selftest();

namespace {

struct RecArgs {
    std::string fmt = "gtb";
    std::string out = "trace.gtb";
    Detail detail = DETAIL_FULL;
    uint64_t events = 0, max_bytes = 0, max_ms = 0, variant = 0x2A00;
    int outer = 0, inner = 0, ring_chunks = 0;
    const char* trigger = nullptr;
    uint64_t crash_at = 0;
};

RecArgs parse_rec(int argc, char** argv) {
    RecArgs a;
    for (int i = 0; i < argc; i++) {
        auto next = [&]() -> const char* { return i + 1 < argc ? argv[++i] : ""; };
        if (!strcmp(argv[i], "--format")) a.fmt = next();
        else if (!strcmp(argv[i], "--detail")) {
            std::string d = next();
            a.detail = d == "mem" ? DETAIL_MEM : d == "calls" ? DETAIL_CALLS : DETAIL_FULL;
        }
        else if (!strcmp(argv[i], "--events")) a.events = strtoull(next(), nullptr, 10);
        else if (!strcmp(argv[i], "--outer")) a.outer = atoi(next());
        else if (!strcmp(argv[i], "--inner")) a.inner = atoi(next());
        else if (!strcmp(argv[i], "--variant")) a.variant = strtoull(next(), nullptr, 0);
        else if (!strcmp(argv[i], "--max-mb")) a.max_bytes = strtoull(next(), nullptr, 10) * 1024 * 1024;
        else if (!strcmp(argv[i], "--max-ms")) a.max_ms = strtoull(next(), nullptr, 10);
        else if (!strcmp(argv[i], "--ring-chunks")) a.ring_chunks = atoi(next());
        else if (!strcmp(argv[i], "--trigger")) a.trigger = next();
        else if (!strcmp(argv[i], "--crash-at")) a.crash_at = strtoull(next(), nullptr, 10);
        else if (!strcmp(argv[i], "-o")) a.out = next();
    }
    return a;
}

CorpusConfig cfg_of(const RecArgs& a) {
    CorpusConfig cfg;
    cfg.variant_const = a.variant;
    if (a.outer) cfg.outer_iters = a.outer;
    if (a.inner) cfg.inner_iters = a.inner;
    return cfg;
}

RecOptions opts_of(const RecArgs& a) {
    RecOptions ro;
    ro.detail = a.detail;
    ro.max_events = a.events;
    ro.max_bytes = a.max_bytes;
    ro.max_ms = a.max_ms;
    ro.ring_keep_chunks = a.ring_chunks;
    ro.trigger_sym = a.trigger;
    ro.initial_sp = corpus_stack_top();
    return ro;
}

// ---------------------------------------------------------------------------
// record: produce a trace from the synthetic corpus
// ---------------------------------------------------------------------------
int cmd_record(int argc, char** argv) {
    RecArgs a = parse_rec(argc, argv);
    site_compiler_init();
    CorpusConfig cfg = cfg_of(a);
    Program prog = build_program(cfg);
    SiteArena arena = compile_sites(prog);

    if (a.fmt == "text") {
        LegacyRecorder rec(arena, prog.module_name.c_str(), prog.base);
        if (!rec.open(a.out)) { fprintf(stderr, "open failed\n"); return 1; }
        run_program(prog, cfg, a.events, [](const ExecEvent& ev, void* u) {
            static_cast<LegacyRecorder*>(u)->record_event(ev);
        }, &rec);
        rec.finish();
        printf("{\"format\":\"text\",\"events\":%llu,\"bytes\":%llu}\n",
               (unsigned long long)rec.events, (unsigned long long)rec.bytes_out);
        return 0;
    }

    RecOptions ro = opts_of(a);
    GtbRecorder rec(arena);
    if (!rec.open(a.out, ro)) { fprintf(stderr, "open failed\n"); return 1; }
    struct Ctx { GtbRecorder* r; uint64_t crash_at; } ctx{&rec, a.crash_at};
    run_program(prog, cfg, 0, [](const ExecEvent& ev, void* u) {
        Ctx* c = static_cast<Ctx*>(u);
        c->r->record_event(ev);
        // simulate the traced process dying mid-trace (durability measurement)
        if (c->crash_at && c->r->stats().events_seen == c->crash_at)
            *(volatile int*)0 = 1;
    }, &ctx);
    RecStats st = rec.finish();
    printf("{\"format\":\"gtb\",\"events_seen\":%llu,\"events_recorded\":%llu,"
           "\"bytes\":%llu,\"reason\":%u,\"stall_ns\":%llu,\"worst_stall_ns\":%llu}\n",
           (unsigned long long)st.events_seen, (unsigned long long)st.events_recorded,
           (unsigned long long)st.bytes_written, unsigned(st.reason),
           (unsigned long long)st.producer_stall_ns,
           (unsigned long long)st.worst_stall_ns);
    return 0;
}

// ---------------------------------------------------------------------------
// hotpath: the one measurement that must happen in-process
// ---------------------------------------------------------------------------
struct Timed { uint64_t rec_ns = 0; };

int cmd_hotpath(int argc, char** argv) {
    RecArgs a = parse_rec(argc, argv);
    std::string legacy_out = "build/bench_legacy.txt";
    std::string gtb_out = "build/bench_full.gtb";
    for (int i = 0; i < argc; i++) {
        auto next = [&]() -> const char* { return i + 1 < argc ? argv[++i] : ""; };
        if (!strcmp(argv[i], "--legacy-out")) legacy_out = next();
        else if (!strcmp(argv[i], "--gtb-out")) gtb_out = next();
    }
    site_compiler_init();
    CorpusConfig cfg = cfg_of(a);

    uint64_t t0 = now_ns();
    Program prog = build_program(cfg);
    uint64_t corpus_ns = now_ns() - t0;
    t0 = now_ns();
    SiteArena arena = compile_sites(prog);
    uint64_t sites_ns = now_ns() - t0;

    // ---- A: legacy text ----
    uint64_t a_events = 0, a_bytes = 0, a_rec_ns = 0, a_wall_ns = 0, a_pending = 0;
    {
        LegacyRecorder l(arena, prog.module_name.c_str(), prog.base);
        l.open(legacy_out);
        std::pair<LegacyRecorder*, Timed*> sink{&l, nullptr};
        Timed ts;
        sink.second = &ts;
        t0 = now_ns();
        run_program(prog, cfg, 0, [](const ExecEvent& ev, void* u) {
            auto* s = static_cast<std::pair<LegacyRecorder*, Timed*>*>(u);
            uint64_t b = now_ns();
            s->first->record_event(ev);
            s->second->rec_ns += now_ns() - b;
        }, &sink);
        a_events = l.events;
        a_bytes = l.bytes_out;
        // bytes still sitting in the 50MB buffer = lost if the process dies now
        a_pending = l.pending();
        l.finish();
        a_wall_ns = now_ns() - t0;
        a_rec_ns = ts.rec_ns;
    }

    // ---- B: gtb binary ----
    uint64_t b_events = 0, b_bytes = 0, b_rec_ns = 0, b_wall_ns = 0;
    {
        RecOptions ro = opts_of(a);
        GtbRecorder g(arena);
        g.open(gtb_out, ro);
        std::pair<GtbRecorder*, Timed*> sink{&g, nullptr};
        Timed ts;
        sink.second = &ts;
        t0 = now_ns();
        run_program(prog, cfg, 0, [](const ExecEvent& ev, void* u) {
            auto* s = static_cast<std::pair<GtbRecorder*, Timed*>*>(u);
            uint64_t b = now_ns();
            s->first->record_event(ev);
            s->second->rec_ns += now_ns() - b;
        }, &sink);
        RecStats st = g.finish();
        b_wall_ns = now_ns() - t0;
        b_rec_ns = ts.rec_ns;
        b_events = st.events_seen;
        b_bytes = st.bytes_written;
    }

    printf("{\n");
    printf("  \"events\": %llu,\n", (unsigned long long)a_events);
    printf("  \"inner_iters\": %d,\n", cfg.inner_iters);
    printf("  \"outer_iters\": %d,\n", cfg.outer_iters);
    printf("  \"sites\": %zu,\n", arena.size());
    printf("  \"corpus_build_ns\": %llu,\n", (unsigned long long)corpus_ns);
    printf("  \"site_compile_ns\": %llu,\n", (unsigned long long)sites_ns);
    printf("  \"legacy\": {\"events\": %llu, \"bytes\": %llu, \"rec_ns\": %llu, "
           "\"wall_ns\": %llu, \"pending_bytes\": %llu},\n",
           (unsigned long long)a_events, (unsigned long long)a_bytes,
           (unsigned long long)a_rec_ns, (unsigned long long)a_wall_ns,
           (unsigned long long)a_pending);
    printf("  \"gtb\": {\"events\": %llu, \"bytes\": %llu, \"rec_ns\": %llu, "
           "\"wall_ns\": %llu}\n",
           (unsigned long long)b_events, (unsigned long long)b_bytes,
           (unsigned long long)b_rec_ns, (unsigned long long)b_wall_ns);
    printf("}\n");
    return 0;
}

void usage() {
    printf(
        "gt-harness — GumTrace-ng benchmark event source + in-process timer\n"
        "\n"
        "  record   --format text|gtb --detail full|mem|calls [--outer N] [--inner N]\n"
        "           [--variant V] [--events N] [--max-mb N] [--max-ms N]\n"
        "           [--ring-chunks N --trigger FUNC] [--crash-at N] -o FILE\n"
        "  hotpath  [--outer N] [--inner N] [--legacy-out F] [--gtb-out F]   -> JSON\n"
        "  selftest\n"
        "\n"
        "Driven by run.py; the queryable side is the `gt` CLI from ../cli.\n");
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) { usage(); return 2; }
    std::string cmd = argv[1];
    if (cmd == "record") return cmd_record(argc - 2, argv + 2);
    if (cmd == "hotpath") return cmd_hotpath(argc - 2, argv + 2);
    if (cmd == "selftest") return cmd_selftest();
    usage();
    return 2;
}
