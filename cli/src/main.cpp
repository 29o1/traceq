#include <gumtrace/common.h>
#include <gumtrace/ingest.h>
#include <gumtrace/queries.h>
#include <gumtrace/recorder.h>
#include <gumtrace/site.h>
#include <cstdio>
#include <cstring>
#include <string>

int cmd_ingest(int argc, char** argv);
int cmd_export(int argc, char** argv);
int cmd_query(int argc, char** argv);
int cmd_taint(int argc, char** argv);
int cmd_diff(int argc, char** argv);
int cmd_fold(int argc, char** argv);
int cmd_calltree(int argc, char** argv);

#ifdef GT_NO_SQLITE
// sqlite-backed commands are host-side conveniences; the on-device build
// records and runs the streaming queries (taint/diff/fold/export) only
int cmd_ingest(int, char**) { fprintf(stderr, "ingest: requires host sqlite build\n"); return 2; }
int cmd_query(int, char**) { fprintf(stderr, "query: requires host sqlite build\n"); return 2; }
#endif

#ifndef GT_NO_SQLITE
int cmd_query(int argc, char** argv) {
    if (argc < 2) { fprintf(stderr, "query stats|mem-writes|func-args ... db\n"); return 2; }
    // argv[0] is "query" itself (main dispatches with argv+1), so the
    // subcommand is argv[1] and option scanning starts after it
    std::string sub = argv[1], db;
    uint64_t addr = 0;
    int limit = 10;
    std::string func;
    int nth = 0;
    for (int i = 2; i < argc; i++) {
        auto next = [&]() -> const char* { return i + 1 < argc ? argv[++i] : ""; };
        if (!strcmp(argv[i], "--addr")) addr = strtoull(next(), nullptr, 0);
        else if (!strcmp(argv[i], "--limit")) limit = atoi(next());
        else if (!strcmp(argv[i], "--func")) func = next();
        else if (!strcmp(argv[i], "--nth")) nth = atoi(next());
        else if (argv[i][0] != '-') db = argv[i];
    }
    if (sub == "stats") return q_stats(db);
    if (sub == "mem-writes") return q_mem_writes(db, addr, limit);
    if (sub == "func-args") return q_func_args(db, func, nth, limit);
    fprintf(stderr, "unknown query: %s\n", sub.c_str());
    return 2;
}

#endif // GT_NO_SQLITE
int cmd_taint(int argc, char** argv) {
    uint64_t seed_addr = 0, window = 100000;
    int seed_reg = -1, limit = 20;
    bool back = false;
    std::string gtb;
    for (int i = 1; i < argc; i++) {
        auto next = [&]() -> const char* { return i + 1 < argc ? argv[++i] : ""; };
        if (!strcmp(argv[i], "--seed-addr")) seed_addr = strtoull(next(), nullptr, 0);
        else if (!strcmp(argv[i], "--seed-reg")) seed_reg = atoi(next());
        else if (!strcmp(argv[i], "--back")) back = true;
        else if (!strcmp(argv[i], "--limit")) limit = atoi(next());
        else if (!strcmp(argv[i], "--window")) window = strtoull(next(), nullptr, 10);
        else if (argv[i][0] != '-') gtb = argv[i];
    }
    return q_taint(gtb, seed_addr, seed_reg, back, limit, window);
}

int cmd_diff(int argc, char** argv) {
    std::string a, b;
    int ctx = 3;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--context") && i + 1 < argc) ctx = atoi(argv[++i]);
        else if (argv[i][0] != '-' && a.empty()) a = argv[i];
        else if (argv[i][0] != '-') b = argv[i];
    }
    return q_diff(a, b, ctx);
}

int cmd_fold(int argc, char** argv) {
    std::string gtb;
    int top = 5;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--top") && i + 1 < argc) top = atoi(argv[++i]);
        else if (argv[i][0] != '-') gtb = argv[i];
    }
    return q_fold(gtb, top);
}

int cmd_calltree(int argc, char** argv) {
    std::string db, func = "driver_main";
    int depth = 3, limit = 40;
    for (int i = 1; i < argc; i++) {
        auto next = [&]() -> const char* { return i + 1 < argc ? argv[++i] : ""; };
        if (!strcmp(argv[i], "--func")) func = next();
        else if (!strcmp(argv[i], "--depth")) depth = atoi(next());
        else if (!strcmp(argv[i], "--limit")) limit = atoi(next());
        else if (argv[i][0] != '-') db = argv[i];
    }
#ifdef GT_NO_SQLITE
    fprintf(stderr, "calltree requires a sqlite build (host-side)\n");
    return 2;
#else
    return q_calltree(db, func, depth, limit);
#endif
}

static void usage() {
    printf(
        "gt — GumTrace-ng: agent-facing trace CLI\n"
        "usage:\n"
        "  gt ingest    trace.gtb -o trace.db\n"
        "  gt export    [--from E --to E --idx --limit N] trace.gtb [-o FILE]\n"
        "  gt query     stats|mem-writes|func-args trace.db [filters]\n"
        "  gt taint     (--seed-addr A|--seed-reg R) [--back] [--limit N] trace.gtb\n"
        "  gt diff      a.gtb b.gtb\n"
        "  gt fold      --top N trace.gtb\n"
        "  gt calltree  --func NAME [--depth D] trace.db\n"
        "\n"
        "recording: this build has no event source. Tracing a live process needs\n"
        "a Stalker-backed source; the synthetic A/B corpus lives in the separate\n"
        "benchmark project (bench/, see `make bench`).\n");
}

int main(int argc, char** argv) {
    if (argc < 2) { usage(); return 2; }
    std::string cmd = argv[1];
    if (cmd == "ingest") return cmd_ingest(argc - 1, argv + 1);
    if (cmd == "export") return cmd_export(argc - 1, argv + 1);
    if (cmd == "query") return cmd_query(argc - 1, argv + 1);
    if (cmd == "taint") return cmd_taint(argc - 1, argv + 1);
    if (cmd == "diff") return cmd_diff(argc - 1, argv + 1);
    if (cmd == "fold") return cmd_fold(argc - 1, argv + 1);
    if (cmd == "calltree") return cmd_calltree(argc - 1, argv + 1);
    usage();
    return 2;
}

#ifndef GT_NO_SQLITE
int cmd_ingest(int argc, char** argv) {
    std::string in, db = "trace.db";
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-o") && i + 1 < argc) db = argv[++i];
        else if (argv[i][0] != '-') in = argv[i];
    }
    gt::GtbFile f;
    if (!f.load(in)) { fprintf(stderr, "load %s failed\n", in.c_str()); return 1; }
    uint64_t t0 = gt::now_ns();
    gt::IngestResult r = gt::ingest_sqlite(f, db);
    fprintf(stderr, "ingest: exec=%llu regw=%llu mem=%llu call=%llu svc=%llu ret=%llu, %.1f ms\n",
            (unsigned long long)r.n_exec, (unsigned long long)r.n_regw,
            (unsigned long long)r.n_mem, (unsigned long long)r.n_call,
            (unsigned long long)r.n_svc, (unsigned long long)r.n_ret,
            double(gt::now_ns() - t0) / 1e6);
    return 0;
}

#endif // GT_NO_SQLITE
int cmd_export(int argc, char** argv) {
    std::string in, out = "-";
    uint64_t from = 0, to = UINT64_MAX, limit = 0;
    bool idx = false;
    for (int i = 1; i < argc; i++) {
        auto next = [&]() -> const char* { return i + 1 < argc ? argv[++i] : ""; };
        if (!strcmp(argv[i], "--from")) from = strtoull(next(), nullptr, 10);
        else if (!strcmp(argv[i], "--to")) to = strtoull(next(), nullptr, 10);
        else if (!strcmp(argv[i], "--limit")) limit = strtoull(next(), nullptr, 10);
        else if (!strcmp(argv[i], "--idx")) idx = true;
        else if (!strcmp(argv[i], "-o")) out = next();
        else if (argv[i][0] != '-') in = argv[i];
    }
    gt::GtbFile f;
    if (!f.load(in)) { fprintf(stderr, "load failed\n"); return 1; }
    FILE* o = out == "-" ? stdout : fopen(out.c_str(), "wb");
    if (!o) return 1;
    gt::Expander ex(f);
    uint64_t n = ex.expand_text(o, from, to, idx, limit);
    if (out != "-") fclose(o);
    fprintf(stderr, "%llu lines\n", (unsigned long long)n);
    return 0;
}
