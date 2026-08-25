#include <traceq/common.h>
#include <traceq/ingest.h>
#include <traceq/queries.h>
#include "emit.h"
#include "export.h"
#include <cstdio>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

int cmd_import(int argc, char** argv);
int cmd_export(int argc, char** argv);
int cmd_taint(int argc, char** argv);
int cmd_diff(int argc, char** argv);
int cmd_fold(int argc, char** argv);
int cmd_calltree(int argc, char** argv);

static bool is_help(const char* s) {
    return !strcmp(s, "--help") || !strcmp(s, "-h");
}

static int unknown_option(const char* cmd, const char* arg) {
    fprintf(stderr, "%s: unknown option %s\n", cmd, arg);
    fprintf(stderr, "try: gt %s --help\n", cmd);
    return 2;
}

static bool parse_range(const char* s, uint64_t& base, uint64_t& len) {
    const char* comma = strchr(s, ',');
    if (!comma || comma == s || !comma[1]) return false;
    char* end = nullptr;
    base = strtoull(s, &end, 0);
    if (end != comma) return false;
    len = strtoull(comma + 1, &end, 0);
    return *end == '\0';
}

static void usage_taint(FILE* o) {
    fprintf(o,
            "usage: gt taint (--seed-addr A | --seed-reg R | --seed-q Q | "
            "--seed-nzcv) [--back] [--index-deps] [--at-ev N] "
            "[--off O [--mod M]] [--window N] [--limit N] trace.gtb [--json]\n"
            "  --index-deps  include load index registers (table/S-box lookups)\n");
}

int cmd_taint(int argc, char** argv) {
    uint64_t seed_addr = 0, window = 0, at_ev = 0, off = 0;
    int seed_reg = -1, seed_q = -1, limit = gt::DEFAULT_OUTPUT_ROWS;
    bool back = false, seed_nzcv = false, json = false, index_deps = false;
    std::string gtb, mod;
    for (int i = 1; i < argc; i++) {
        auto next = [&]() -> const char* { return i + 1 < argc ? argv[++i] : ""; };
        if (is_help(argv[i])) { usage_taint(stdout); return 0; }
        else if (!strcmp(argv[i], "--seed-addr")) seed_addr = strtoull(next(), nullptr, 0);
        else if (!strcmp(argv[i], "--seed-reg")) seed_reg = atoi(next());
        else if (!strcmp(argv[i], "--seed-q")) seed_q = atoi(next());
        else if (!strcmp(argv[i], "--seed-nzcv")) seed_nzcv = true;
        else if (!strcmp(argv[i], "--back")) back = true;
        else if (!strcmp(argv[i], "--index-deps")) index_deps = true;
        else if (!strcmp(argv[i], "--limit")) limit = atoi(next());
        else if (!strcmp(argv[i], "--window")) window = strtoull(next(), nullptr, 10);
        else if (!strcmp(argv[i], "--at-ev")) at_ev = strtoull(next(), nullptr, 10);
        else if (!strcmp(argv[i], "--off")) off = strtoull(next(), nullptr, 0);
        else if (!strcmp(argv[i], "--mod")) mod = next();
        else if (!strcmp(argv[i], "--json")) json = true;
        else if (argv[i][0] != '-') gtb = argv[i];
        else return unknown_option("taint", argv[i]);
    }
    if (seed_reg > 31) {
        fprintf(stderr, "taint: --seed-reg %d out of range (0..31)\n", seed_reg);
        return 2;
    }
    if (seed_q > 31) {
        fprintf(stderr, "taint: --seed-q %d out of range (0..31)\n", seed_q);
        return 2;
    }
    if (gtb.empty() || (!seed_addr && seed_reg < 0 && seed_q < 0 && !seed_nzcv)) {
        usage_taint(stderr);
        return 2;
    }
    TaintOptions options;
    options.seed_addr = seed_addr;
    options.seed_reg = seed_reg;
    options.seed_q = seed_q;
    options.seed_nzcv = seed_nzcv;
    options.backward = back;
    options.limit = limit;
    options.window = window;
    options.at_ev = at_ev;
    options.off = off;
    options.mod = std::move(mod);
    options.json = json;
    options.index_deps = index_deps;
    return q_taint(gtb, options);
}

int cmd_diff(int argc, char** argv) {
    std::string a, b;
    int ctx = 3;
    bool json = false;
    for (int i = 1; i < argc; i++) {
        if (is_help(argv[i])) {
            printf("usage: gt diff a.gtb b.gtb [--context N] [--json]\n");
            return 0;
        }
        else if (!strcmp(argv[i], "--context") && i + 1 < argc) ctx = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--json")) json = true;
        else if (argv[i][0] != '-' && a.empty()) a = argv[i];
        else if (argv[i][0] != '-') b = argv[i];
        else return unknown_option("diff", argv[i]);
    }
    if (a.empty() || b.empty()) {
        fprintf(stderr, "usage: gt diff a.gtb b.gtb [--context N] [--json]\n");
        return 2;
    }
    return q_diff(a, b, ctx, json);
}

int cmd_fold(int argc, char** argv) {
    std::string gtb;
    int top = 5;
    bool json = false;
    for (int i = 1; i < argc; i++) {
        if (is_help(argv[i])) {
            printf("usage: gt fold trace.gtb [--top N] [--json]\n");
            return 0;
        }
        else if (!strcmp(argv[i], "--top") && i + 1 < argc) top = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--json")) json = true;
        else if (argv[i][0] != '-') gtb = argv[i];
        else return unknown_option("fold", argv[i]);
    }
    if (gtb.empty()) {
        fprintf(stderr, "usage: gt fold trace.gtb [--top N] [--json]\n");
        return 2;
    }
    return q_fold(gtb, top, json);
}

int cmd_stat(int argc, char** argv) {
    std::string gtb;
    bool json = false;
    for (int i = 1; i < argc; i++) {
        if (is_help(argv[i])) {
            printf("usage: gt stat trace.gtb [--json]\n");
            return 0;
        }
        else if (!strcmp(argv[i], "--json")) json = true;
        else if (argv[i][0] != '-') gtb = argv[i];
        else return unknown_option("stat", argv[i]);
    }
    if (gtb.empty()) { fprintf(stderr, "usage: gt stat trace.gtb [--json]\n"); return 2; }
    return q_stat(gtb, json);
}

int cmd_mem_access(int argc, char** argv) {
    std::string gtb;
    std::vector<uint64_t> addrs;
    uint64_t range_base = 0, range_len = 0, offset = 0;
    uint64_t from_ev = 0, to_ev = UINT64_MAX;
    int limit = gt::DEFAULT_OUTPUT_ROWS, last = 0;
    bool use_range = false, json = false, writes_only = false, reads_only = false;
    bool have_limit = false, have_offset = false, have_last = false;
    bool have_from = false, have_to = false;
    for (int i = 1; i < argc; i++) {
        auto next = [&]() -> const char* { return i + 1 < argc ? argv[++i] : ""; };
        if (is_help(argv[i])) {
            printf("usage: gt mem-access trace.gtb (--addr A... | --range B,L) "
                   "[--read | --write] [--from E] [--to E] "
                   "([--limit N] [--offset M] | --last N) [--json]\n"
                   "       gt mem-access trace.gtb --write --from E --to E "
                   "([--limit N] [--offset M] | --last N) [--json]\n"
                   "  the selectorless form lists writes only inside an explicit "
                   "finite event window\n");
            return 0;
        }
        else if (!strcmp(argv[i], "--addr"))
            addrs.push_back(strtoull(next(), nullptr, 0));
        else if (!strcmp(argv[i], "--range")) {
            if (!parse_range(next(), range_base, range_len)) {
                fprintf(stderr, "mem-access: --range B,L (hex or dec)\n");
                return 2;
            }
            use_range = true;
        }
        else if (!strcmp(argv[i], "--read")) reads_only = true;
        else if (!strcmp(argv[i], "--write")) writes_only = true;
        else if (!strcmp(argv[i], "--from")) {
            from_ev = strtoull(next(), nullptr, 0);
            have_from = true;
        }
        else if (!strcmp(argv[i], "--to")) {
            to_ev = strtoull(next(), nullptr, 0);
            have_to = true;
        }
        else if (!strcmp(argv[i], "--limit")) {
            limit = atoi(next());
            have_limit = true;
        }
        else if (!strcmp(argv[i], "--offset")) {
            offset = strtoull(next(), nullptr, 10);
            have_offset = true;
        }
        else if (!strcmp(argv[i], "--last")) {
            last = atoi(next());
            have_last = true;
        }
        else if (!strcmp(argv[i], "--json")) json = true;
        else if (argv[i][0] != '-') gtb = argv[i];
        else return unknown_option("mem-access", argv[i]);
    }
    bool all_writes = addrs.empty() && !use_range && writes_only &&
                      have_from && have_to;
    if (gtb.empty() || (!all_writes && addrs.empty() == !use_range) ||
        from_ev > to_ev ||
        (reads_only && writes_only) ||
        (have_last && last <= 0) || (have_last && (have_limit || have_offset))) {
        fprintf(stderr, "usage: gt mem-access trace.gtb (--addr A... | --range B,L) "
                        "[--read | --write] [--from E] [--to E] "
                        "([--limit N] [--offset M] | --last N) [--json]\n"
                        "       gt mem-access trace.gtb --write --from E --to E "
                        "([--limit N] [--offset M] | --last N) [--json]\n");
        return 2;
    }
    MemAccessOptions options;
    options.addrs = std::move(addrs);
    options.use_range = use_range;
    options.all_writes = all_writes;
    options.range_base = range_base;
    options.range_len = range_len;
    options.limit = limit;
    options.offset = offset;
    options.from_ev = from_ev;
    options.to_ev = to_ev;
    options.last = last;
    options.json = json;
    options.writes_only = writes_only;
    options.reads_only = reads_only;
    return q_mem_accesses(gtb, options);
}

int cmd_mem_state(int argc, char** argv) {
    std::string gtb;
    std::vector<MemStateRange> ranges;
    std::vector<uint64_t> at_evs;
    bool json = false, qword = false;
    for (int i = 1; i < argc; i++) {
        auto next = [&]() -> const char* { return i + 1 < argc ? argv[++i] : ""; };
        if (is_help(argv[i])) {
            printf("usage: gt mem-state trace.gtb --range B,L... --at-ev N... "
                   "[--qword] [--json]\n"
                   "  repeat --range and/or --at-ev to reconstruct their Cartesian "
                   "product in one trace pass\n"
                   "  reconstruct known bytes from observed reads/writes up to event N; "
                   "unknown bytes print as ??\n"
                   "  --qword emits 8-byte little-endian cells from the range base\n");
            return 0;
        }
        else if (!strcmp(argv[i], "--range")) {
            uint64_t base = 0, len = 0;
            if (!parse_range(next(), base, len)) {
                fprintf(stderr, "mem-state: --range B,L (hex or dec)\n");
                return 2;
            }
            ranges.push_back({base, len});
        }
        else if (!strcmp(argv[i], "--at-ev") || !strcmp(argv[i], "--at")) {
            at_evs.push_back(strtoull(next(), nullptr, 10));
        }
        else if (!strcmp(argv[i], "--qword")) qword = true;
        else if (!strcmp(argv[i], "--json")) json = true;
        else if (argv[i][0] != '-') gtb = argv[i];
        else return unknown_option("mem-state", argv[i]);
    }
    if (gtb.empty() || ranges.empty() || at_evs.empty()) {
        fprintf(stderr, "usage: gt mem-state trace.gtb --range B,L... --at-ev N... "
                        "[--qword] [--json]\n");
        return 2;
    }
    MemStateOptions options;
    options.ranges = std::move(ranges);
    options.at_evs = std::move(at_evs);
    options.json = json;
    options.qword = qword;
    return q_mem_states(gtb, options);
}

int cmd_find_pc(int argc, char** argv) {
    std::string gtb, mod;
    std::vector<uint64_t> addrs, offs;
    uint64_t offset = 0, from_ev = 0, to_ev = UINT64_MAX;
    int limit = gt::DEFAULT_OUTPUT_ROWS, last = 0;
    bool json = false, have_limit = false, have_offset = false, have_last = false;
    for (int i = 1; i < argc; i++) {
        auto next = [&]() -> const char* { return i + 1 < argc ? argv[++i] : ""; };
        if (is_help(argv[i])) {
            printf("usage: gt find-pc trace.gtb (--addr A... | --off O... [--mod M]) "
                   "[--from E] [--to E] ([--limit N] [--offset M] | --last N) "
                   "[--json]\n"
                   "  repeat --addr or --off to find several PCs in one trace pass\n");
            return 0;
        }
        else if (!strcmp(argv[i], "--addr")) addrs.push_back(strtoull(next(), nullptr, 0));
        else if (!strcmp(argv[i], "--off")) {
            offs.push_back(strtoull(next(), nullptr, 0));
        }
        else if (!strcmp(argv[i], "--mod")) mod = next();
        else if (!strcmp(argv[i], "--from")) from_ev = strtoull(next(), nullptr, 10);
        else if (!strcmp(argv[i], "--to")) to_ev = strtoull(next(), nullptr, 10);
        else if (!strcmp(argv[i], "--limit")) {
            limit = atoi(next());
            have_limit = true;
        }
        else if (!strcmp(argv[i], "--offset")) {
            offset = strtoull(next(), nullptr, 10);
            have_offset = true;
        }
        else if (!strcmp(argv[i], "--last")) {
            last = atoi(next());
            have_last = true;
        }
        else if (!strcmp(argv[i], "--json")) json = true;
        else if (argv[i][0] != '-') gtb = argv[i];
        else return unknown_option("find-pc", argv[i]);
    }
    if (gtb.empty() || addrs.empty() == offs.empty() ||
        (!addrs.empty() && !mod.empty()) || from_ev > to_ev ||
        (have_last && last <= 0) || (have_last && (have_limit || have_offset))) {
        fprintf(stderr, "usage: gt find-pc trace.gtb (--addr A... | --off O... [--mod M]) "
                        "[--from E] [--to E] ([--limit N] [--offset M] | --last N) "
                        "[--json]\n");
        return 2;
    }
    FindPcOptions options;
    options.addrs = std::move(addrs);
    options.offs = std::move(offs);
    options.mod = std::move(mod);
    options.limit = limit;
    options.offset = offset;
    options.from_ev = from_ev;
    options.to_ev = to_ev;
    options.last = last;
    options.json = json;
    return q_find_pcs(gtb, options);
}

int cmd_calls(int argc, char** argv) {
    std::string gtb, mod;
    std::vector<std::string> names;
    std::vector<uint64_t> target_addrs, target_offs;
    uint64_t offset = 0, from_ev = 0, to_ev = UINT64_MAX;
    int top = 0, limit = gt::DEFAULT_OUTPUT_ROWS, last = 0;
    bool json = false, have_top = false, have_limit = false;
    bool have_offset = false, have_last = false;
    for (int i = 1; i < argc; i++) {
        auto next = [&]() -> const char* { return i + 1 < argc ? argv[++i] : ""; };
        if (is_help(argv[i])) {
            printf("usage: gt calls trace.gtb [--top N]\n"
                   "       gt calls trace.gtb [--name NAME...] "
                   "[--target-addr A...] [--target-off O... [--mod M]]\n"
                   "                [--from E] [--to E] "
                   "([--limit N] [--offset M] | --last N) [--json]\n"
                   "  scans executed BL/BLR/BLRAA/BLRAB instructions; call "
                   "annotations enrich names, arguments, and paired returns\n");
            return 0;
        }
        else if (!strcmp(argv[i], "--name")) names.emplace_back(next());
        else if (!strcmp(argv[i], "--target-addr"))
            target_addrs.push_back(strtoull(next(), nullptr, 0));
        else if (!strcmp(argv[i], "--target-off"))
            target_offs.push_back(strtoull(next(), nullptr, 0));
        else if (!strcmp(argv[i], "--mod")) mod = next();
        else if (!strcmp(argv[i], "--top")) {
            top = atoi(next());
            have_top = true;
        }
        else if (!strcmp(argv[i], "--from")) from_ev = strtoull(next(), nullptr, 0);
        else if (!strcmp(argv[i], "--to")) to_ev = strtoull(next(), nullptr, 0);
        else if (!strcmp(argv[i], "--limit")) {
            limit = atoi(next());
            have_limit = true;
        }
        else if (!strcmp(argv[i], "--offset")) {
            offset = strtoull(next(), nullptr, 10);
            have_offset = true;
        }
        else if (!strcmp(argv[i], "--last")) {
            last = atoi(next());
            have_last = true;
        }
        else if (!strcmp(argv[i], "--json")) json = true;
        else if (argv[i][0] != '-') gtb = argv[i];
        else return unknown_option("calls", argv[i]);
    }
    if (gtb.empty() || from_ev > to_ev || (have_top && top <= 0) ||
        (have_last && last <= 0) ||
        (have_top && (have_last || have_limit || have_offset)) ||
        (have_last && (have_limit || have_offset)) ||
        (!mod.empty() && target_offs.empty())) {
        fprintf(stderr, "usage: gt calls trace.gtb [--top N] | [selectors] "
                        "([--limit N] [--offset M] | --last N) [--json]\n");
        return 2;
    }
    CallsOptions options;
    options.names = std::move(names);
    options.target_addrs = std::move(target_addrs);
    options.target_offs = std::move(target_offs);
    options.mod = std::move(mod);
    options.top = top;
    options.limit = limit;
    options.offset = offset;
    options.from_ev = from_ev;
    options.to_ev = to_ev;
    options.last = last;
    options.json = json;
    return q_calls(gtb, options);
}

int cmd_find_value(int argc, char** argv) {
    std::string gtb;
    std::vector<std::string> positional;
    std::vector<uint64_t> values;
    uint64_t offset = 0, from_ev = 0, to_ev = UINT64_MAX;
    int limit = gt::DEFAULT_OUTPUT_ROWS, last = 0;
    bool value_option = false, json = false;
    bool reads_only = false, writes_only = false;
    bool have_limit = false, have_offset = false, have_last = false;
    for (int i = 1; i < argc; i++) {
        auto next = [&]() -> const char* { return i + 1 < argc ? argv[++i] : ""; };
        if (is_help(argv[i])) {
            printf("usage: gt find-value V trace.gtb [--read | --write] "
                   "[--from E] [--to E] ([--limit N] [--offset M] | --last N) "
                   "[--json]\n"
                   "       gt find-value trace.gtb --value V... [same options]\n"
                   "  repeat --value to search multiple values in one trace pass; "
                   "limits, offsets, and --last apply per value\n");
            return 0;
        }
        else if (!strcmp(argv[i], "--value")) {
            values.push_back(strtoull(next(), nullptr, 0));
            value_option = true;
        }
        else if (!strcmp(argv[i], "--read")) reads_only = true;
        else if (!strcmp(argv[i], "--write")) writes_only = true;
        else if (!strcmp(argv[i], "--from")) from_ev = strtoull(next(), nullptr, 0);
        else if (!strcmp(argv[i], "--to")) to_ev = strtoull(next(), nullptr, 0);
        else if (!strcmp(argv[i], "--limit")) {
            limit = atoi(next());
            have_limit = true;
        }
        else if (!strcmp(argv[i], "--offset")) {
            offset = strtoull(next(), nullptr, 10);
            have_offset = true;
        }
        else if (!strcmp(argv[i], "--last")) {
            last = atoi(next());
            have_last = true;
        }
        else if (!strcmp(argv[i], "--json")) json = true;
        else if (argv[i][0] != '-') positional.emplace_back(argv[i]);
        else return unknown_option("find-value", argv[i]);
    }
    if (value_option && positional.size() == 1) {
        gtb = std::move(positional[0]);
    } else if (!value_option && positional.size() == 2) {
        values.push_back(strtoull(positional[0].c_str(), nullptr, 0));
        gtb = std::move(positional[1]);
    }
    if (gtb.empty() || values.empty() || from_ev > to_ev ||
        (reads_only && writes_only) || (have_last && last <= 0) ||
        (have_last && (have_limit || have_offset))) {
        fprintf(stderr,
                "usage: gt find-value V trace.gtb [--read | --write] "
                "[--from E] [--to E] ([--limit N] [--offset M] | --last N) "
                "[--json]\n"
                "       gt find-value trace.gtb --value V... [same options]\n");
        return 2;
    }
    FindValueOptions options;
    options.values = std::move(values);
    options.limit = limit;
    options.offset = offset;
    options.json = json;
    options.from_ev = from_ev;
    options.to_ev = to_ev;
    options.reads_only = reads_only;
    options.writes_only = writes_only;
    options.last = last;
    return q_find_value(gtb, options);
}

int cmd_calltree(int argc, char** argv) {
    std::string gtb, func;
    int depth = 3, limit = gt::DEFAULT_OUTPUT_ROWS;
    bool json = false;
    for (int i = 1; i < argc; i++) {
        auto next = [&]() -> const char* { return i + 1 < argc ? argv[++i] : ""; };
        if (is_help(argv[i])) {
            printf("usage: gt calltree [--func NAME] [--depth D] [--limit N] "
                   "trace.gtb [--json]\n"
                   "  omit --func to print the bounded call forest from the "
                   "trace root\n");
            return 0;
        }
        else if (!strcmp(argv[i], "--func")) func = next();
        else if (!strcmp(argv[i], "--depth")) depth = atoi(next());
        else if (!strcmp(argv[i], "--limit")) limit = atoi(next());
        else if (!strcmp(argv[i], "--json")) json = true;
        else if (argv[i][0] != '-') gtb = argv[i];
        else return unknown_option("calltree", argv[i]);
    }
    if (gtb.empty()) {
        fprintf(stderr, "usage: gt calltree [--func NAME] [--depth D] [--limit N] "
                        "trace.gtb [--json]\n");
        return 2;
    }
    return q_calltree_gtb(gtb, func, depth, limit, json);
}

static void usage() {
    printf(
        "gt — traceq: agent-facing trace CLI\n"
        "usage:\n"
        "  gt import    trace.log -o trace.gtb   (upstream GumTrace text log)\n"
        "  gt export    [--format compact|jsonl|upstream]\n"
        "               [--from E --to E] [--limit N | --all] trace.gtb [-o FILE]\n"
        "  gt taint     (--seed-addr A|--seed-reg R|--seed-q Q) [--back]\n"
        "               [--at-ev N] [--off O [--mod M]] [--window N] trace.gtb\n"
        "  gt diff      a.gtb b.gtb\n"
        "  gt fold      --top N trace.gtb\n"
        "  gt stat      trace.gtb [--json]\n"
        "  gt mem-access trace.gtb (--addr A... | --range B,L) [--read | --write]\n"
        "               [--from E] [--to E] ([--limit N] | --last N) [--json]\n"
        "  gt mem-access trace.gtb --write --from E --to E "
        "([--limit N] | --last N) [--json]\n"
        "  gt mem-state trace.gtb --range B,L... --at-ev N... [--qword] [--json]\n"
        "  gt find-pc  trace.gtb (--addr A... | --off O... [--mod M])\n"
        "               [--from E] [--to E] ([--limit N] | --last N) [--json]\n"
        "  gt find-value V trace.gtb | trace.gtb --value V... [--read | --write]\n"
        "               [--from E] [--to E] ([--limit N] | --last N) [--json]\n"
        "  gt calls     trace.gtb [--top N | --name NAME | --target-addr A |\n"
        "               --target-off O [--mod M]] [--limit N | --last N] [--json]\n"
        "  gt calltree  [--func NAME] [--depth D] trace.gtb\n"
        "\n"
        "query --json output is one {\"data\":[...],\"meta\":{...}} document;\n"
        "u64 values are hex strings. export --format jsonl remains streaming.\n"
        "query and export output defaults to 20 rows; export --all is explicit.\n"
        "all queries scan the loaded .gtb event buffer — there is no index step.\n"
        "\n"
        "capture live traces with GumTrace, then convert them with `gt import`.\n"
        "traceq does not capture processes or expose a record command.\n"
        "benchmarks run on real trace files (see bench/).\n");
}

int main(int argc, char** argv) {
    if (argc < 2) { usage(); return 2; }
    std::string cmd = argv[1];
    if (cmd == "--help" || cmd == "-h" || cmd == "help") {
        usage();
        return 0;
    }
    if (cmd == "import") return cmd_import(argc - 1, argv + 1);
    if (cmd == "export") return cmd_export(argc - 1, argv + 1);
    if (cmd == "taint") return cmd_taint(argc - 1, argv + 1);
    if (cmd == "diff") return cmd_diff(argc - 1, argv + 1);
    if (cmd == "fold") return cmd_fold(argc - 1, argv + 1);
    if (cmd == "stat") return cmd_stat(argc - 1, argv + 1);
    if (cmd == "mem-access") return cmd_mem_access(argc - 1, argv + 1);
    if (cmd == "mem-state") return cmd_mem_state(argc - 1, argv + 1);
    if (cmd == "find-pc") return cmd_find_pc(argc - 1, argv + 1);
    if (cmd == "find-value") return cmd_find_value(argc - 1, argv + 1);
    if (cmd == "calls") return cmd_calls(argc - 1, argv + 1);
    if (cmd == "calltree" || cmd == "call-tree")
        return cmd_calltree(argc - 1, argv + 1);
    fprintf(stderr, "gt: unknown command %s\n", cmd.c_str());
    usage();
    return 2;
}

int cmd_export(int argc, char** argv) {
    std::string in, out = "-", fmt = "compact";
    uint64_t from = 0, to = UINT64_MAX;
    uint64_t limit = gt::DEFAULT_OUTPUT_ROWS;
    bool have_to = false, have_limit = false, all = false;
    for (int i = 1; i < argc; i++) {
        auto next = [&]() -> const char* { return i + 1 < argc ? argv[++i] : ""; };
        if (is_help(argv[i])) {
            printf("usage: gt export [--format compact|jsonl|upstream] "
                   "[--from E] [--to E] [--limit N | --all] "
                   "trace.gtb [-o FILE]\n"
                   "  output defaults to 20 lines; use --all for a complete "
                   "export\n");
            return 0;
        }
        else if (!strcmp(argv[i], "--from")) from = strtoull(next(), nullptr, 10);
        else if (!strcmp(argv[i], "--to")) { to = strtoull(next(), nullptr, 10); have_to = true; }
        else if (!strcmp(argv[i], "--limit")) {
            limit = strtoull(next(), nullptr, 10);
            have_limit = true;
        }
        else if (!strcmp(argv[i], "--all")) all = true;
        else if (!strcmp(argv[i], "--format")) fmt = next();
        else if (!strcmp(argv[i], "-o")) out = next();
        else if (argv[i][0] != '-') in = argv[i];
        else return unknown_option("export", argv[i]);
    }
    if (in.empty() || from > to || (have_limit && limit == 0) ||
        (all && have_limit)) {
        fprintf(stderr, "usage: gt export [--format compact|jsonl|upstream] "
                        "[--from E] [--to E] [--limit N | --all] "
                        "trace.gtb [-o FILE]\n");
        return 2;
    }
    if (fmt != "compact" && fmt != "jsonl" && fmt != "upstream") {
        fprintf(stderr, "export: unknown --format %s (compact|jsonl|upstream)\n",
                fmt.c_str());
        return 2;
    }
    gt::GtbFile f;
    if (!f.load(in, false)) { fprintf(stderr, "load failed\n"); return 1; }
    FILE* o = out == "-" ? stdout : fopen(out.c_str(), "wb");
    if (!o) return 1;
    if (all) limit = 0;
    uint64_t stop_gi = UINT64_MAX, n = 0, total_selected = 0;
    if (fmt == "upstream")
        n = gt::export_upstream(f, o, from, to, limit, &stop_gi);
    else if (fmt == "compact")
        n = gt::export_compact(f, o, from, to, limit, &stop_gi);
    else
        n = gt::export_jsonl(f, o, from, to, limit, &stop_gi,
                             &total_selected);
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
        if (fmt == "compact") fprintf(o, "next: %s\n", next_cmd.c_str());
        else if (fmt == "upstream")
            fprintf(stderr, "next: %s\n", next_cmd.c_str());
    }
    if (fmt == "jsonl") {
        gt::emit::Meta meta;
        meta.truncated = truncated;
        meta.total = total_selected;
        meta.shown = n;
        meta.next = next_cmd;
        gt::emit::finish(meta, true, o);
    }
    if (out != "-") fclose(o);
    fprintf(stderr, "%llu lines\n", (unsigned long long)n);
    return 0;
}
