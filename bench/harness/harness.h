#pragma once
// Shared helpers for the benchmark harness: build the synthetic corpus and
// compile its sites the way a Stalker transformer would.
#include "corpus.h"
#include <gumtrace/site.h>

namespace gt {

// Compiles every instruction of the program into the arena (transform time),
// attributing each site to its containing function symbol.
inline SiteArena compile_sites(const Program& p) {
    SiteArena a;
    for (const auto& d : p.insns) {
        int32_t sym = -1;
        uint64_t best = 0;
        for (const auto& fs : p.funcs)
            if (fs.addr <= d.addr && fs.addr >= best) {
                best = fs.addr;
                sym = a.intern_string(fs.name);
            }
        a.intern(d.addr, d.word, p.module_name.c_str(), p.base, sym);
    }
    return a;
}

} // namespace gt
