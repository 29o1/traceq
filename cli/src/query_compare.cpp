#include <traceq/queries.h>
#include <traceq/ingest.h>
#include <traceq/site.h>
#include "emit.h"
#include <algorithm>
#include <cstdio>
#include <vector>

using namespace gt;

// ---------------------------------------------------------------------------
// diff (gtb exec sequence)
//
// Comparison key is (module name, module-relative offset), not the arena site
// id: site ids are allocation-order artifacts of each run and only align when
// both runs interned sites in the same order, while (module, offset) is stable
// across ASLR and load-order differences.
// ---------------------------------------------------------------------------
int q_diff(const std::string& a_p, const std::string& b_p, int context, bool json) {
    if (context < 0) {
        fprintf(stderr, "diff: --context must not be negative\n");
        return 2;
    }
    GtbFile a, b;
    if (!a.load(a_p, false)) {
        fprintf(stderr, "load failed\n");
        return 1;
    }
    struct Exec { uint32_t site; uint64_t ev; };
    std::vector<Exec> sa, sb;
    sa.reserve(size_t(std::min<uint64_t>(a.events_seen, a.events.size())));
    TraceScan(a).for_each([&](uint64_t ev, const Group& g) {
        if (g.has_exec) sa.push_back({g.site_id, ev});
        return true;
    });
    // The comparison only needs A's arena and compact execution sequence from
    // this point onward. Release its large event payload before loading B so
    // diff does not hold two full traces plus both derived sequences at once.
    std::vector<uint8_t>().swap(a.events);
    if (!b.load(b_p, false)) {
        fprintf(stderr, "load failed\n");
        return 1;
    }
    emit::QueryWriter writer(json);
    sb.reserve(size_t(std::min<uint64_t>(b.events_seen, b.events.size())));
    TraceScan(b).for_each([&](uint64_t ev, const Group& g) {
        if (g.has_exec) sb.push_back({g.site_id, ev});
        return true;
    });
    std::vector<uint8_t>().swap(b.events);
    auto key = [](const GtbFile& f, uint32_t site, std::string& mod_out, uint64_t& off_out) {
        const Site& s = f.arena.get(site);
        mod_out = s.module_id < f.arena.modules().size()
                      ? f.arena.modules()[s.module_id] : std::string("?");
        off_out = s.addr - f.arena.module_base(s.module_id);
    };
    auto same = [&](const Exec& x, const Exec& y) {
        std::string ma, mb;
        uint64_t oa, ob;
        key(a, x.site, ma, oa);
        key(b, y.site, mb, ob);
        return ma == mb && oa == ob;
    };
    size_t n = std::min(sa.size(), sb.size());
    size_t div = n;
    for (size_t i = 0; i < n; i++)
        if (!same(sa[i], sb[i])) { div = i; break; }
    bool identical = div == n && sa.size() == sb.size();
    auto txt = [&](const GtbFile& f, uint32_t site) -> std::string {
        const Site& s = f.arena.get(site);
        return std::string(f.arena.pool_ptr() + s.disasm_off, s.disasm_len);
    };
    auto loc = [&](const GtbFile& f, uint32_t site) -> std::string {
        std::string m;
        uint64_t o;
        key(f, site, m, o);
        char b2[32];
        snprintf(b2, sizeof b2, "!0x%llx", (unsigned long long)o);
        return m + b2;
    };
    if (json) {
        std::string o;
        emit::kv_u64(o, "exec_a", sa.size());
        o += ',';
        emit::kv_u64(o, "exec_b", sb.size());
        o += ',';
        emit::kv_bool(o, "identical", identical);
        if (!identical) {
            o += ',';
            emit::kv_u64(o, "diverge_exec", div);
            o += ",\"a_ev\":";
            if (div < sa.size()) o += std::to_string(sa[div].ev);
            else o += "null";
            o += ",\"b_ev\":";
            if (div < sb.size()) o += std::to_string(sb[div].ev);
            else o += "null";
            size_t from = div >= size_t(context) ? div - size_t(context) : 0;
            size_t to = div + size_t(context) + 1;
            o += ",\"ctx\":[";
            bool first = true;
            for (size_t i = from; i < to; i++) {
                if (i >= sa.size() && i >= sb.size()) continue;
                if (!first) o += ',';
                first = false;
                o += '{';
                emit::kv_u64(o, "exec", i);
                o += ",\"a_ev\":";
                if (i < sa.size()) o += std::to_string(sa[i].ev);
                else o += "null";
                o += ",\"b_ev\":";
                if (i < sb.size()) o += std::to_string(sb[i].ev);
                else o += "null";
                o += ',';
                emit::kv_str(o, "a", i < sa.size() ? loc(a, sa[i].site) : "-");
                o += ',';
                emit::kv_str(o, "a_txt",
                             i < sa.size() ? txt(a, sa[i].site) : "<end>");
                o += ',';
                emit::kv_str(o, "b", i < sb.size() ? loc(b, sb[i].site) : "-");
                o += ',';
                emit::kv_str(o, "b_txt",
                             i < sb.size() ? txt(b, sb[i].site) : "<end>");
                o += ',';
                emit::kv_bool(o, "diverges", i == div);
                o += '}';
            }
            o += ']';
        }
        writer.row("{\"diff\":{" + o + "}}");
    } else {
        printf("exec counts: A=%zu B=%zu\n", sa.size(), sb.size());
        if (identical) {
            printf("identical execution sequences\n");
            emit::Meta meta;
            writer.finish(meta);
            return 0;
        }
        printf("first divergence at exec index %zu (0-based)", div);
        if (div < sa.size()) printf(" A_ev=%llu", (unsigned long long)sa[div].ev);
        else printf(" A_ev=end");
        if (div < sb.size()) printf(" B_ev=%llu", (unsigned long long)sb[div].ev);
        else printf(" B_ev=end");
        putchar('\n');
        printf("context:\n");
        size_t from = div >= size_t(context) ? div - size_t(context) : 0;
        size_t to = div + size_t(context) + 1;
        for (size_t i = from; i < to; i++) {
            if (i < sa.size() || i < sb.size()) {
                printf("  [%5zu] A_ev=%-8s A: %-22s %-34s B_ev=%-8s B: %-22s %s%s\n",
                       i,
                       i < sa.size() ? std::to_string(sa[i].ev).c_str() : "-",
                       i < sa.size() ? loc(a, sa[i].site).c_str() : "-",
                       i < sa.size() ? txt(a, sa[i].site).c_str() : "<end>",
                       i < sb.size() ? std::to_string(sb[i].ev).c_str() : "-",
                       i < sb.size() ? loc(b, sb[i].site).c_str() : "-",
                       i < sb.size() ? txt(b, sb[i].site).c_str() : "<end>",
                       i == div ? "   <-- DIVERGES" : "");
            }
        }
    }
    emit::Meta meta;
    writer.finish(meta);
    return 0;
}

// ---------------------------------------------------------------------------
// fold (loop detection over the exec stream)
// ---------------------------------------------------------------------------
int q_fold(const std::string& gtb, int top, bool json) {
    if (top <= 0) {
        fprintf(stderr, "fold: --top must be greater than zero\n");
        return 2;
    }
    GtbFile f;
    if (!f.load(gtb, false)) return 1;
    emit::QueryWriter writer(json);
    struct Exec { uint32_t site; uint64_t ev; };
    std::vector<Exec> s;
    s.reserve(size_t(std::min<uint64_t>(f.events_seen, f.events.size())));
    TraceScan(f).for_each([&](uint64_t ev, const Group& g) {
        if (g.has_exec) s.push_back({g.site_id, ev});
        return true;
    });
    struct Loop { size_t start; size_t period; size_t reps; };
    std::vector<Loop> loops;
    size_t i = 0;
    while (i + 2 < s.size()) {
        bool found = false;
        size_t maxp = s.size() - i >= 3 * 64 ? 64 : (s.size() - i) / 3;
        for (size_t p = 1; p <= maxp; p++) {
            bool ok = true;
            for (size_t k = 0; k < 2 * p && ok; k++)
                if (s[i + k].site != s[i + p + k].site) ok = false;
            if (!ok) continue;
            size_t reps = 2;
            while (i + (reps + 1) * p <= s.size()) {
                bool eq = true;
                for (size_t k = 0; k < p; k++)
                    if (s[i + k].site != s[i + reps * p + k].site) {
                        eq = false;
                        break;
                    }
                if (!eq) break;
                reps++;
            }
            loops.push_back({i, p, reps});
            i += reps * p;
            found = true;
            break;
        }
        if (!found) i++;
    }
    std::sort(loops.begin(), loops.end(), [](const Loop& a, const Loop& b) {
        return a.reps * a.period > b.reps * b.period;
    });
    size_t shown = std::min<size_t>(loops.size(), top > 0 ? top : 0);
    if (json) {
        std::string o = "\"loops\":[";
        for (size_t k = 0; k < shown; k++) {
            const Loop& L = loops[k];
            size_t end_exec = L.start + L.reps * L.period;
            if (k) o += ',';
            o += '{';
            emit::kv_u64(o, "start_exec", L.start);
            o += ',';
            emit::kv_u64(o, "end_exec", end_exec);
            o += ',';
            emit::kv_u64(o, "start_ev", s[L.start].ev);
            o += ',';
            emit::kv_u64(o, "end_ev", s[end_exec - 1].ev);
            o += ',';
            emit::kv_u64(o, "period", L.period);
            o += ',';
            emit::kv_u64(o, "reps", L.reps);
            o += ",\"body\":[";
            for (size_t j = 0; j < L.period && j < 8; j++) {
                if (j) o += ',';
                const Site& body_site = f.arena.get(s[L.start + j].site);
                std::string body(f.arena.pool_ptr() + body_site.disasm_off,
                                 body_site.disasm_len);
                emit::esc_append(o, body.c_str());
            }
            o += "]}";
        }
        o += ']';
        writer.row("{\"fold\":{" + o + "}}");
    } else {
        printf("detected %zu loop regions (top %d by executed instructions):\n", loops.size(), top);
        for (size_t k = 0; k < shown; k++) {
            const Loop& L = loops[k];
            size_t end_exec = L.start + L.reps * L.period;
            printf("  exec [%zu, %zu) events [%llu, %llu]: period=%zu reps=%zu "
                   "(%zu insn execs)\n",
                   L.start, end_exec,
                   (unsigned long long)s[L.start].ev,
                   (unsigned long long)s[end_exec - 1].ev,
                   L.period, L.reps, L.reps * L.period);
            for (size_t j = 0; j < L.period && j < 8; j++) {
                const Site& st = f.arena.get(s[L.start + j].site);
                printf("    %s\n", std::string(f.arena.pool_ptr() + st.disasm_off,
                                               st.disasm_len).c_str());
            }
            if (L.period > 8) printf("    ... (%zu more)\n", L.period - 8);
        }
    }
    emit::Meta meta;
    meta.total = loops.size();
    meta.shown = shown;
    meta.truncated = loops.size() > shown;
    writer.finish(meta);
    return 0;
}
