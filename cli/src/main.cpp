#include <traceq/common.h>
#include <traceq/ingest.h>
#include <traceq/queries.h>
#include <traceq/recorder.h>
#include <traceq/site.h>
#include "emit.h"
#include <cstdio>
#include <cstring>
#include <string>

int cmd_import(int argc, char** argv);
int cmd_export(int argc, char** argv);
int cmd_taint(int argc, char** argv);
int cmd_diff(int argc, char** argv);
int cmd_fold(int argc, char** argv);
int cmd_calltree(int argc, char** argv);

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
    bool use_range = false, json = false, writes_only = false;
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
        else if (!strcmp(argv[i], "--write")) writes_only = true;
        else if (!strcmp(argv[i], "--limit")) limit = atoi(next());
        else if (!strcmp(argv[i], "--offset")) offset = strtoull(next(), nullptr, 10);
        else if (!strcmp(argv[i], "--json")) json = true;
        else if (argv[i][0] != '-') gtb = argv[i];
    }
    if (gtb.empty() || (!use_range && addr == 0)) {
        fprintf(stderr, "usage: gt mem-access trace.gtb (--addr A | --range B,L) "
                        "[--write] [--limit N] [--offset M] [--json]\n");
        return 2;
    }
    return q_mem_access(gtb, addr, use_range, range_base, range_len, limit, offset,
                        json, writes_only);
}

int cmd_func_args(int argc, char** argv) {
    std::string gtb, func;
    int nth = 1, limit = 1;
    bool json = false;
    for (int i = 1; i < argc; i++) {
        auto next = [&]() -> const char* { return i + 1 < argc ? argv[++i] : ""; };
        if (!strcmp(argv[i], "--func")) func = next();
        else if (!strcmp(argv[i], "--nth")) nth = atoi(next());
        else if (!strcmp(argv[i], "--limit")) limit = atoi(next());
        else if (!strcmp(argv[i], "--json")) json = true;
        else if (argv[i][0] != '-') gtb = argv[i];
    }
    if (gtb.empty() || func.empty()) {
        fprintf(stderr, "usage: gt func-args --func NAME [--nth N] [--limit L] "
                        "trace.gtb [--json]\n");
        return 2;
    }
    return q_func_args(gtb, func, nth, limit, json);
}

int cmd_find_value(int argc, char** argv) {
    std::string gtb;
    uint64_t val = 0, offset = 0;
    int limit = 20;
    bool have_val = false, json = false;
    for (int i = 1; i < argc; i++) {
        auto next = [&]() -> const char* { return i + 1 < argc ? argv[++i] : ""; };
        if (!strcmp(argv[i], "--limit")) limit = atoi(next());
        else if (!strcmp(argv[i], "--offset")) offset = strtoull(next(), nullptr, 10);
        else if (!strcmp(argv[i], "--json")) json = true;
        else if (argv[i][0] != '-') {
            // fixed positional order: value first, then the gtb path
            if (!have_val) { val = strtoull(argv[i], nullptr, 0); have_val = true; }
            else if (gtb.empty()) gtb = argv[i];
        }
    }
    if (gtb.empty() || !have_val) {
        fprintf(stderr, "usage: gt find-value V trace.gtb [--limit N] [--offset M] [--json]\n");
        return 2;
    }
    return q_find_value(gtb, val, limit, offset, json);
}

int cmd_calltree(int argc, char** argv) {
    std::string gtb, func;
    int depth = 3, limit = 40;
    bool json = false;
    for (int i = 1; i < argc; i++) {
        auto next = [&]() -> const char* { return i + 1 < argc ? argv[++i] : ""; };
        if (!strcmp(argv[i], "--func")) func = next();
        else if (!strcmp(argv[i], "--depth")) depth = atoi(next());
        else if (!strcmp(argv[i], "--limit")) limit = atoi(next());
        else if (!strcmp(argv[i], "--json")) json = true;
        else if (argv[i][0] != '-') gtb = argv[i];
    }
    if (func.empty()) { fprintf(stderr, "calltree: --func NAME is required\n"); return 2; }
    return q_calltree_gtb(gtb, func, depth, limit, json);
}

static void usage() {
    printf(
        "gt — traceq: agent-facing trace CLI\n"
        "usage:\n"
        "  gt import    trace.log -o trace.gtb   (upstream GumTrace text log)\n"
        "  gt export    [--format auto|compact|jsonl|upstream]\n"
        "               [--from E --to E --limit N] trace.gtb [-o FILE]\n"
        "  gt taint     (--seed-addr A|--seed-reg R|--seed-q Q) [--back]\n"
        "               [--at-ev N] [--off O [--mod M]] [--window N] trace.gtb\n"
        "  gt diff      a.gtb b.gtb\n"
        "  gt fold      --top N trace.gtb\n"
        "  gt stat      trace.gtb [--json]\n"
        "  gt mem-access trace.gtb (--addr A | --range B,L) [--write]\n"
        "               [--limit N] [--json]\n"
        "  gt find-value V trace.gtb [--limit N] [--json]\n"
        "  gt func-args --func NAME [--nth N] [--limit L] trace.gtb [--json]\n"
        "  gt calltree  --func NAME [--depth D] trace.gtb\n"
        "\n"
        "most commands take --json (JSON Lines, one object per line + a final\n"
        "{\"meta\":{...}} cursor line; u64 values as hex strings).\n"
        "all queries stream the .gtb directly — there is no ingest step.\n"
        "\n"
        "recording: this build has no event source. Tracing a live process needs\n"
        "a Stalker-backed source; existing GumTrace text logs convert with\n"
        "`gt import`. Benchmarks run on real trace files (see bench/).\n");
}

int main(int argc, char** argv) {
    if (argc < 2) { usage(); return 2; }
    std::string cmd = argv[1];
    if (cmd == "import") return cmd_import(argc - 1, argv + 1);
    if (cmd == "export") return cmd_export(argc - 1, argv + 1);
    if (cmd == "taint") return cmd_taint(argc - 1, argv + 1);
    if (cmd == "diff") return cmd_diff(argc - 1, argv + 1);
    if (cmd == "fold") return cmd_fold(argc - 1, argv + 1);
    if (cmd == "stat") return cmd_stat(argc - 1, argv + 1);
    if (cmd == "mem-access") return cmd_mem_access(argc - 1, argv + 1);
    if (cmd == "find-value") return cmd_find_value(argc - 1, argv + 1);
    if (cmd == "func-args") return cmd_func_args(argc - 1, argv + 1);
    if (cmd == "calltree") return cmd_calltree(argc - 1, argv + 1);
    usage();
    return 2;
}

int cmd_export(int argc, char** argv) {
    std::string in, out = "-", fmt = "auto";
    uint64_t from = 0, to = UINT64_MAX, limit = 0;
    bool json = false, have_to = false;
    for (int i = 1; i < argc; i++) {
        auto next = [&]() -> const char* { return i + 1 < argc ? argv[++i] : ""; };
        if (!strcmp(argv[i], "--from")) from = strtoull(next(), nullptr, 10);
        else if (!strcmp(argv[i], "--to")) { to = strtoull(next(), nullptr, 10); have_to = true; }
        else if (!strcmp(argv[i], "--limit")) limit = strtoull(next(), nullptr, 10);
        else if (!strcmp(argv[i], "--format")) fmt = next();
        else if (!strcmp(argv[i], "--json")) json = true;
        else if (!strcmp(argv[i], "-o")) out = next();
        else if (argv[i][0] != '-') in = argv[i];
    }
    if (fmt != "auto" && fmt != "compact" && fmt != "jsonl" && fmt != "upstream") {
        fprintf(stderr, "export: unknown --format %s (auto|compact|jsonl|upstream)\n",
                fmt.c_str());
        return 2;
    }
    gt::GtbFile f;
    if (!f.load(in)) { fprintf(stderr, "load failed\n"); return 1; }
    // auto resolves by the footer dialect byte: imported logs replay their
    // original upstream text, native recordings render compact
    if (fmt == "auto") fmt = (f.dialect & 1) ? "upstream" : "compact";
    if (json && fmt == "upstream")
        fmt = "jsonl"; // --json selects the JSON Lines format
    FILE* o = out == "-" ? stdout : fopen(out.c_str(), "wb");
    if (!o) return 1;
    gt::Expander ex(f);
    uint64_t stop_gi = UINT64_MAX, n = 0;
    if (fmt == "upstream") n = ex.expand_upstream(o, from, to, limit, &stop_gi);
    else if (fmt == "compact") n = ex.expand_compact(o, from, to, limit, &stop_gi);
    else n = ex.expand_jsonl(o, from, to, limit, &stop_gi);
    if (out != "-") fclose(o);
    bool truncated = stop_gi != UINT64_MAX;
    std::string next_cmd;
    if (truncated) {
        // cursor: the full continuation command. upstream output is
        // byte-guarded (roundtrip contract), so its cursor rides stderr with
        // the other diagnostics; the agent formats print it as the trailing
        // line of the content stream.
        next_cmd = "gt export --from " + std::to_string(stop_gi);
        if (limit) next_cmd += " --limit " + std::to_string(limit);
        if (have_to) next_cmd += " --to " + std::to_string(to);
        next_cmd += " --format " + fmt;
        next_cmd += " " + in;
        if (fmt == "compact") fprintf(stdout, "next: %s\n", next_cmd.c_str());
        else if (fmt == "upstream")
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
