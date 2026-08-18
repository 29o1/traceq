#include <gumtrace/common.h>
#include <gumtrace/ingest.h>
#include <gumtrace/queries.h>
#include <gumtrace/recorder.h>
#include <gumtrace/site.h>
#include "emit.h"
#include <cstdio>
#include <cstring>
#include <string>

int cmd_ingest(int argc, char** argv);
int cmd_import(int argc, char** argv);
int cmd_export(int argc, char** argv);
int cmd_query(int argc, char** argv);
int cmd_taint(int argc, char** argv);
int cmd_diff(int argc, char** argv);
int cmd_fold(int argc, char** argv);
int cmd_calltree(int argc, char** argv);
int cmd_schema(int argc, char** argv);

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
    uint64_t addr = 0, offset = 0;
    int limit = 10;
    std::string func;
    int nth = 0;
    bool json = false;
    for (int i = 2; i < argc; i++) {
        auto next = [&]() -> const char* { return i + 1 < argc ? argv[++i] : ""; };
        if (!strcmp(argv[i], "--addr")) addr = strtoull(next(), nullptr, 0);
        else if (!strcmp(argv[i], "--limit")) limit = atoi(next());
        else if (!strcmp(argv[i], "--offset")) offset = strtoull(next(), nullptr, 10);
        else if (!strcmp(argv[i], "--func")) func = next();
        else if (!strcmp(argv[i], "--nth")) nth = atoi(next());
        else if (!strcmp(argv[i], "--json")) json = true;
        else if (argv[i][0] != '-') db = argv[i];
    }
    if (sub == "stats") return q_stats(db, offset, json);
    if (sub == "mem-writes") return q_mem_writes(db, addr, limit, offset, json);
    if (sub == "func-args") return q_func_args(db, func, nth, limit, offset, json);
    fprintf(stderr, "unknown query: %s\n", sub.c_str());
    return 2;
}

#endif // GT_NO_SQLITE
int cmd_taint(int argc, char** argv) {
    uint64_t seed_addr = 0, window = 0, at_ev = 0, off = 0;
    int seed_reg = -1, seed_q = -1, limit = 20;
    bool back = false, seed_nzcv = false, json = false;
    std::string gtb, mod;
    for (int i = 1; i < argc; i++) {
        auto next = [&]() -> const char* { return i + 1 < argc ? argv[++i] : ""; };
        if (!strcmp(argv[i], "--seed-addr")) seed_addr = strtoull(next(), nullptr, 0);
        else if (!strcmp(argv[i], "--seed-reg")) seed_reg = atoi(next());
        else if (!strcmp(argv[i], "--seed-q")) seed_q = atoi(next());
        else if (!strcmp(argv[i], "--seed-nzcv")) seed_nzcv = true;
        else if (!strcmp(argv[i], "--back")) back = true;
        else if (!strcmp(argv[i], "--limit")) limit = atoi(next());
        else if (!strcmp(argv[i], "--window")) window = strtoull(next(), nullptr, 10);
        else if (!strcmp(argv[i], "--at-ev")) at_ev = strtoull(next(), nullptr, 10);
        else if (!strcmp(argv[i], "--off")) off = strtoull(next(), nullptr, 0);
        else if (!strcmp(argv[i], "--mod")) mod = next();
        else if (!strcmp(argv[i], "--json")) json = true;
        else if (argv[i][0] != '-') gtb = argv[i];
    }
    return q_taint(gtb, seed_addr, seed_reg, seed_q, seed_nzcv, back, limit, window,
                   at_ev, off, mod, json);
}

int cmd_diff(int argc, char** argv) {
    std::string a, b;
    int ctx = 3;
    bool json = false;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--context") && i + 1 < argc) ctx = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--json")) json = true;
        else if (argv[i][0] != '-' && a.empty()) a = argv[i];
        else if (argv[i][0] != '-') b = argv[i];
    }
    return q_diff(a, b, ctx, json);
}

int cmd_fold(int argc, char** argv) {
    std::string gtb;
    int top = 5;
    bool json = false;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--top") && i + 1 < argc) top = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--json")) json = true;
        else if (argv[i][0] != '-') gtb = argv[i];
    }
    return q_fold(gtb, top, json);
}

int cmd_stat(int argc, char** argv) {
    std::string gtb;
    bool json = false;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--json")) json = true;
        else if (argv[i][0] != '-') gtb = argv[i];
    }
    if (gtb.empty()) { fprintf(stderr, "usage: gt stat trace.gtb [--json]\n"); return 2; }
    return q_stat(gtb, json);
}

int cmd_mem_access(int argc, char** argv) {
    std::string gtb;
    uint64_t addr = 0, range_base = 0, range_len = 0, offset = 0;
    int limit = 20;
    bool use_range = false, json = false;
    for (int i = 1; i < argc; i++) {
        auto next = [&]() -> const char* { return i + 1 < argc ? argv[++i] : ""; };
        if (!strcmp(argv[i], "--addr")) addr = strtoull(next(), nullptr, 0);
        else if (!strcmp(argv[i], "--range")) {
            if (sscanf(next(), "0x%llx,0x%llx", (unsigned long long*)&range_base,
                       (unsigned long long*)&range_len) != 2 &&
                sscanf(argv[i], "%llu,%llu", (unsigned long long*)&range_base,
                       (unsigned long long*)&range_len) != 2) {
                fprintf(stderr, "mem-access: --range B,L (hex or dec)\n");
                return 2;
            }
            use_range = true;
        }
        else if (!strcmp(argv[i], "--limit")) limit = atoi(next());
        else if (!strcmp(argv[i], "--offset")) offset = strtoull(next(), nullptr, 10);
        else if (!strcmp(argv[i], "--json")) json = true;
        else if (argv[i][0] != '-') gtb = argv[i];
    }
    if (gtb.empty() || (!use_range && addr == 0)) {
        fprintf(stderr, "usage: gt mem-access trace.gtb (--addr A | --range B,L) "
                        "[--limit N] [--offset M] [--json]\n");
        return 2;
    }
    return q_mem_access(gtb, addr, use_range, range_base, range_len, limit, offset,
                        json);
}

int cmd_find_value(int argc, char** argv) {
    std::string gtb;
    uint64_t val = 0, offset = 0;
    int limit = 20;
    bool have_val = false, json = false;
    std::string pos[2];
    int npos = 0;
    for (int i = 1; i < argc; i++) {
        auto next = [&]() -> const char* { return i + 1 < argc ? argv[++i] : ""; };
        if (!strcmp(argv[i], "--limit")) limit = atoi(next());
        else if (!strcmp(argv[i], "--offset")) offset = strtoull(next(), nullptr, 10);
        else if (!strcmp(argv[i], "--json")) json = true;
        else if (argv[i][0] != '-' && npos < 2) pos[npos++] = argv[i];
    }
    // value and file are accepted in either order: the positional that parses
    // as a number in full is the value
    for (int k = 0; k < npos; k++) {
        char* end = nullptr;
        uint64_t v = strtoull(pos[k].c_str(), &end, 0);
        if (end && *end == 0 && end != pos[k].c_str() && !have_val) {
            val = v;
            have_val = true;
        } else if (gtb.empty()) {
            gtb = pos[k];
        }
    }
    if (gtb.empty() || !have_val) {
        fprintf(stderr, "usage: gt find-value V trace.gtb [--limit N] [--offset M] [--json]\n");
        return 2;
    }
    return q_find_value(gtb, val, limit, offset, json);
}

// the positional argument decides the backend: GTB1 magic -> streaming gtb,
// anything else -> sqlite db
static bool looks_like_gtb(const std::string& path) {
    FILE* f = fopen(path.c_str(), "rb");
    if (!f) return false;
    uint8_t m[4] = {0};
    size_t n = fread(m, 1, 4, f);
    fclose(f);
    return n == 4 && m[0] == '1' && m[1] == 'B' && m[2] == 'T' && m[3] == 'G';
}

int cmd_calltree(int argc, char** argv) {
    std::string db, func;
    int depth = 3, limit = 40;
    bool json = false;
    for (int i = 1; i < argc; i++) {
        auto next = [&]() -> const char* { return i + 1 < argc ? argv[++i] : ""; };
        if (!strcmp(argv[i], "--func")) func = next();
        else if (!strcmp(argv[i], "--depth")) depth = atoi(next());
        else if (!strcmp(argv[i], "--limit")) limit = atoi(next());
        else if (!strcmp(argv[i], "--json")) json = true;
        else if (argv[i][0] != '-') db = argv[i];
    }
    if (func.empty()) { fprintf(stderr, "calltree: --func NAME is required\n"); return 2; }
    if (looks_like_gtb(db)) return q_calltree_gtb(db, func, depth, limit, json);
#ifdef GT_NO_SQLITE
    fprintf(stderr, "calltree on a db requires a sqlite build (host-side)\n");
    return 2;
#else
    return q_calltree(db, func, depth, limit, json);
#endif
}

// gt schema [db]: with a db, dump DDL + row counts + example SQL; without,
// summarize every subcommand and its --json support.
int cmd_schema(int argc, char** argv) {
    std::string db;
    bool json = false;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--json")) json = true;
        else if (argv[i][0] != '-') db = argv[i];
    }
    if (!db.empty()) {
#ifdef GT_NO_SQLITE
        fprintf(stderr, "schema requires a sqlite build (host-side)\n");
        return 2;
#else
        return q_schema(db, json);
#endif
    }
    struct CmdInfo { const char* name; const char* what; bool json; };
    static const CmdInfo cmds[] = {
        {"ingest",    "gtb -> sqlite db (stats line on stderr as JSON)", false},
        {"import",    "upstream GumTrace text log -> gtb (stats as JSON)", false},
        {"export",    "dump events: --format auto|legacy|compact|jsonl|upstream", true},
        {"query",     "stats | mem-writes | func-args over an ingested db", true},
        {"taint",     "forward/backward taint from a seed (gtb)", true},
        {"diff",      "first divergence of two gtb exec sequences", true},
        {"fold",      "loop regions of the exec stream (gtb)", true},
        {"stat",      "file counters, modules, dialect, stop reason (gtb)", true},
        {"mem-access","mem reads/writes by address or range (gtb)", true},
        {"find-value","find events where a value appears (gtb)", true},
        {"calltree",  "call tree under a function (gtb or db)", true},
        {"schema",    "this listing, or a db's DDL + row counts + SQL examples", true},
    };
    if (json) {
        std::string o = "\"commands\":[";
        for (size_t i = 0; i < sizeof cmds / sizeof cmds[0]; i++) {
            if (i) o += ',';
            o += '{';
            gt::emit::kv_str(o, "cmd", cmds[i].name);
            o += ',';
            gt::emit::kv_str(o, "what", cmds[i].what);
            o += ',';
            gt::emit::kv_bool(o, "json", cmds[i].json);
            o += '}';
        }
        o += ']';
        printf("{\"schema\":{%s}}\n", o.c_str());
    } else {
        printf("gt subcommands (--json column = JSON Lines mode support):\n");
        for (auto& c : cmds)
            printf("  %-10s [--json: %s]  %s\n", c.name, c.json ? "yes" : "no ", c.what);
        printf("run `gt schema <db>` for the db schema (DDL, row counts, example SQL)\n");
    }
    return 0;
}

static void usage() {
    printf(
        "gt — GumTrace-ng: agent-facing trace CLI\n"
        "usage:\n"
        "  gt ingest    trace.gtb -o trace.db\n"
        "  gt import    trace.log -o trace.gtb   (upstream GumTrace text log)\n"
        "  gt export    [--format auto|legacy|compact|jsonl|upstream]\n"
        "               [--from E --to E --idx --limit N] trace.gtb [-o FILE]\n"
        "  gt query     stats|mem-writes|func-args trace.db [filters] [--json]\n"
        "  gt taint     (--seed-addr A|--seed-reg R|--seed-q Q) [--back]\n"
        "               [--at-ev N] [--off O [--mod M]] [--window N] trace.gtb\n"
        "  gt diff      a.gtb b.gtb\n"
        "  gt fold      --top N trace.gtb\n"
        "  gt stat      trace.gtb [--json]\n"
        "  gt mem-access trace.gtb (--addr A | --range B,L) [--limit N] [--json]\n"
        "  gt find-value V trace.gtb [--limit N] [--json]\n"
        "  gt calltree  --func NAME [--depth D] trace.gtb|trace.db\n"
        "  gt schema    [trace.db]\n"
        "\n"
        "most commands take --json (JSON Lines, one object per line + a final\n"
        "{\"meta\":{...}} cursor line; u64 values as hex strings).\n"
        "\n"
        "recording: this build has no event source. Tracing a live process needs\n"
        "a Stalker-backed source; the synthetic A/B corpus lives in the separate\n"
        "benchmark project (bench/, see `make bench`).\n");
}

int main(int argc, char** argv) {
    if (argc < 2) { usage(); return 2; }
    std::string cmd = argv[1];
    if (cmd == "ingest") return cmd_ingest(argc - 1, argv + 1);
    if (cmd == "import") return cmd_import(argc - 1, argv + 1);
    if (cmd == "export") return cmd_export(argc - 1, argv + 1);
    if (cmd == "query") return cmd_query(argc - 1, argv + 1);
    if (cmd == "taint") return cmd_taint(argc - 1, argv + 1);
    if (cmd == "diff") return cmd_diff(argc - 1, argv + 1);
    if (cmd == "fold") return cmd_fold(argc - 1, argv + 1);
    if (cmd == "stat") return cmd_stat(argc - 1, argv + 1);
    if (cmd == "mem-access") return cmd_mem_access(argc - 1, argv + 1);
    if (cmd == "find-value") return cmd_find_value(argc - 1, argv + 1);
    if (cmd == "calltree") return cmd_calltree(argc - 1, argv + 1);
    if (cmd == "schema") return cmd_schema(argc - 1, argv + 1);
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
    // progress/diagnostics stay on stderr; the line is a JSON object so the
    // agent can parse it even when mixed into a captured stderr stream
    fprintf(stderr,
            "{\"ingest\":{\"exec\":%llu,\"regw\":%llu,\"mem\":%llu,\"call\":%llu,"
            "\"svc\":%llu,\"ret\":%llu,\"db\":\"%s\",\"ms\":%.1f}}\n",
            (unsigned long long)r.n_exec, (unsigned long long)r.n_regw,
            (unsigned long long)r.n_mem, (unsigned long long)r.n_call,
            (unsigned long long)r.n_svc, (unsigned long long)r.n_ret, db.c_str(),
            double(gt::now_ns() - t0) / 1e6);
    return 0;
}

#endif // GT_NO_SQLITE
int cmd_export(int argc, char** argv) {
    std::string in, out = "-", fmt = "auto";
    uint64_t from = 0, to = UINT64_MAX, limit = 0;
    bool idx = false, json = false, have_to = false;
    for (int i = 1; i < argc; i++) {
        auto next = [&]() -> const char* { return i + 1 < argc ? argv[++i] : ""; };
        if (!strcmp(argv[i], "--from")) from = strtoull(next(), nullptr, 10);
        else if (!strcmp(argv[i], "--to")) { to = strtoull(next(), nullptr, 10); have_to = true; }
        else if (!strcmp(argv[i], "--limit")) limit = strtoull(next(), nullptr, 10);
        else if (!strcmp(argv[i], "--idx")) idx = true;
        else if (!strcmp(argv[i], "--format")) fmt = next();
        else if (!strcmp(argv[i], "--json")) json = true;
        else if (!strcmp(argv[i], "-o")) out = next();
        else if (argv[i][0] != '-') in = argv[i];
    }
    if (fmt != "auto" && fmt != "legacy" && fmt != "compact" && fmt != "jsonl" &&
        fmt != "upstream") {
        fprintf(stderr, "export: unknown --format %s (auto|legacy|compact|jsonl|upstream)\n",
                fmt.c_str());
        return 2;
    }
    gt::GtbFile f;
    if (!f.load(in)) { fprintf(stderr, "load failed\n"); return 1; }
    // auto resolves by the footer dialect byte: imported logs replay their
    // original upstream text, recorded corpora replay legacy text
    if (fmt == "auto") fmt = (f.dialect & 1) ? "upstream" : "legacy";
    if (json && (fmt == "legacy" || fmt == "upstream"))
        fmt = "jsonl"; // --json selects the JSON Lines format
    FILE* o = out == "-" ? stdout : fopen(out.c_str(), "wb");
    if (!o) return 1;
    gt::Expander ex(f);
    uint64_t stop_gi = UINT64_MAX, n = 0;
    if (fmt == "legacy") n = ex.expand_text(o, from, to, idx, limit, &stop_gi);
    else if (fmt == "upstream") n = ex.expand_upstream(o, from, to, limit, &stop_gi);
    else if (fmt == "compact") n = ex.expand_compact(o, from, to, limit, &stop_gi);
    else n = ex.expand_jsonl(o, from, to, limit, &stop_gi);
    if (out != "-") fclose(o);
    bool truncated = stop_gi != UINT64_MAX;
    std::string next_cmd;
    if (truncated) {
        // cursor: the full continuation command. legacy output is byte-guarded
        // (T3), so its cursor rides stderr with the other diagnostics; the
        // agent formats print it as the trailing line of the content stream.
        next_cmd = "gt export --from " + std::to_string(stop_gi);
        if (limit) next_cmd += " --limit " + std::to_string(limit);
        if (have_to) next_cmd += " --to " + std::to_string(to);
        if (fmt != "legacy") next_cmd += " --format " + fmt;
        next_cmd += " " + in;
        if (fmt == "compact") fprintf(stdout, "next: %s\n", next_cmd.c_str());
        else if (fmt == "legacy" || fmt == "upstream")
            fprintf(stderr, "next: %s\n", next_cmd.c_str());
    }
    if (fmt == "jsonl") {
        gt::emit::Meta meta;
        meta.truncated = truncated;
        uint64_t total;
        if (truncated) {
            // events remaining in the window (counting pass over the tail)
            total = 0;
            gt::Expander(f).for_each([&](uint64_t gi, const gt::Group&) {
                if (gi >= from && gi <= to) total++;
                return true;
            });
        } else {
            total = from + n; // jsonl emits exactly one line per event
        }
        meta.total = total;
        meta.shown = truncated ? stop_gi - from : n;
        meta.next = next_cmd;
        gt::emit::finish(meta, true, stdout);
    }
    fprintf(stderr, "%llu lines\n", (unsigned long long)n);
    return 0;
}
