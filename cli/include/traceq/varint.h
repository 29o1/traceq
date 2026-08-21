#pragma once
#include <cstdint>
#include <cstring>

namespace gt {

// LEB128-style unsigned varint with zigzag option for signed deltas.
inline size_t put_uvar(uint8_t* p, uint64_t v) {
    size_t n = 0;
    while (v >= 0x80) { p[n++] = uint8_t(v) | 0x80; v >>= 7; }
    p[n++] = uint8_t(v);
    return n;
}

inline size_t get_uvar(const uint8_t* p, size_t len, uint64_t& out) {
    uint64_t v = 0; int shift = 0; size_t n = 0;
    while (n < len && shift < 64) {
        uint8_t b = p[n++];
        v |= uint64_t(b & 0x7F) << shift;
        if (!(b & 0x80)) { out = v; return n; }
        shift += 7;
    }
    return 0; // truncated
}

inline uint64_t zigzag_enc(int64_t v) {
    return (uint64_t(v) << 1) ^ uint64_t(-(v < 0));
}
inline int64_t zigzag_dec(uint64_t v) {
    return int64_t(v >> 1) ^ -int64_t(v & 1);
}
inline size_t put_var(uint8_t* p, int64_t v) { return put_uvar(p, zigzag_enc(v)); }
inline size_t get_var(const uint8_t* p, size_t len, int64_t& out) {
    uint64_t u; size_t n = get_uvar(p, len, u);
    if (n) out = zigzag_dec(u);
    return n;
}

} // namespace gt
