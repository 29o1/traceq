#pragma once

// Internal on-disk GTB format constants shared by the reader and writer.
// Keep this header private to libtraceq: the public API exposes semantic
// groups, not event tag numbers or chunk framing details.

#include <cstdint>

namespace traceq::format {

inline constexpr uint32_t CHUNK_MAGIC = 0x47544348u; // "GTCH"
inline constexpr uint32_t GTB_MAGIC = 0x47544232u;   // "GTB2"

enum ChunkType : uint32_t {
    CH_META = 1,
    CH_EVENTS = 2,
    CH_FOOTER = 3,
};

enum EventTag : uint8_t {
    EV_EXEC = 1,
    EV_REGW = 2,
    EV_MEM = 3,
    EV_MEMW_NV = 4,
    EV_RDVAL = 5,
    EV_SIMDV = 6,
    EV_CALL = 7,
    EV_RET = 8,
    EV_VERBATIM = 9,
};

} // namespace traceq::format
