#pragma once
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <ctime>
#include <string>
#include <vector>
#include <cstdio>

namespace gt {

inline uint64_t now_ns() {
    timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return uint64_t(ts.tv_sec) * 1000000000ull + uint64_t(ts.tv_nsec);
}

} // namespace gt
