#pragma once
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <ctime>
#include <string>
#include <vector>
#include <cstdio>

namespace gt {

// Deterministic PRNG (xorshift64*) so corpora are reproducible by seed.
struct Rng {
    uint64_t s;
    explicit Rng(uint64_t seed) : s(seed ? seed : 0x9E3779B97F4A7C15ULL) {}
    uint64_t next() {
        s ^= s >> 12; s ^= s << 25; s ^= s >> 27;
        return s * 0x2545F4914F6CDD1DULL;
    }
    uint64_t below(uint64_t n) { return n ? next() % n : 0; }
};

inline uint64_t now_ns() {
    timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return uint64_t(ts.tv_sec) * 1000000000ull + uint64_t(ts.tv_nsec);
}

} // namespace gt
