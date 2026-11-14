#pragma once
// Experimental GTSW v1: a single-thread, fixed-code-range write-evidence stream.
// Explicit little endian fields; no native struct layout is written to disk.
// The profile records EXEC dispatch and completed ordinary stores. It does not
// assert global memory provenance, read values, or full register coverage.
#include <cstdint>
#include <cstdio>
#include <cstring>

namespace traceq::writes {
constexpr size_t FRAME_SIZE = 64;
constexpr char MAGIC[8] = {'G','T','S','W','0','0','1','\0'};
enum Kind : uint64_t { EXEC = 1, WRITE = 2, GAP = 3, END = 4 };
// Profile 2 extends the same framing. Profile 1 remains readable unchanged.
constexpr uint64_t REG_PRE=5, REG_POST=6, READ=7, SITE=8, COMMIT=9;
// Optional profile-2 extension. Old streams remain readable; old readers reject
// the explicit feature record instead of silently dropping boundary evidence.
constexpr uint64_t MODULE=10, SCOPE_EXIT=11, SCOPE_REENTER=12, FEATURES=13;
constexpr uint64_t FEATURE_BOUNDARIES=1;
enum Transfer : uint64_t { CALL=1, BRANCH=2, RETURN=3 };
constexpr unsigned REGISTER_COUNT=65; // x0..x30, sp, nzcv, v0..v31
enum Reason : uint64_t {
    UNSUPPORTED = 1, UNCONFIRMED_STORE = 2, FOREIGN_THREAD = 3,
    EXCLUSIVE_REGION = 4, OUTSIDE_DATA_RANGE = 5, OUTSIDE_CODE_RANGE = 6
};
struct Header {
    uint64_t code_base, code_size, data_base, data_size, thread_id;
    uint64_t profile = 1; // controlled single call; little-endian ARM64
};
struct Event {
    uint64_t kind, seq, pc, address, size, low, high, detail;
};
inline void put64(unsigned char* p, uint64_t v) {
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    // memcpy permits unaligned output without violating aliasing rules. Some
    // compilers keep the byte loop as eight separate stores in the hot encoder.
    memcpy(p, &v, sizeof v);
#else
    for (unsigned i = 0; i < 8; ++i) p[i] = uint8_t(v >> (8 * i));
#endif
}
inline uint64_t get64(const unsigned char* p) {
    uint64_t v = 0;
    for (unsigned i = 0; i < 8; ++i) v |= uint64_t(p[i]) << (8 * i);
    return v;
}
inline bool write_header(FILE* out, const Header& h) {
    unsigned char b[FRAME_SIZE]{};
    memcpy(b, MAGIC, 8);
    const uint64_t v[] = {h.code_base, h.code_size, h.data_base, h.data_size,
                          h.thread_id, h.profile, FRAME_SIZE};
    for (unsigned i = 0; i < 7; ++i) put64(b + 8 + i * 8, v[i]);
    return fwrite(b, 1, sizeof b, out) == sizeof b;
}
inline bool write_event(FILE* out, const Event& e) {
    unsigned char b[FRAME_SIZE];
    const uint64_t v[] = {e.kind,e.seq,e.pc,e.address,e.size,e.low,e.high,e.detail};
    for (unsigned i = 0; i < 8; ++i) put64(b + i * 8, v[i]);
    return fwrite(b, 1, sizeof b, out) == sizeof b;
}
inline Event decode_event(const unsigned char* b) {
    return {get64(b),get64(b+8),get64(b+16),get64(b+24),get64(b+32),
            get64(b+40),get64(b+48),get64(b+56)};
}
} // namespace traceq::writes
