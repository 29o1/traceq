#pragma once

// Internal on-disk GTB format constants shared by the reader and writer.
// Keep this header private to libtraceq: the public API exposes semantic
// groups, not event tag numbers or chunk framing details.

#include <cstdint>

namespace gt::format {

inline constexpr uint32_t CHUNK_MAGIC = 0x47544348u; // "GTCH"
inline constexpr uint32_t GTB_MAGIC = 0x47544231u;   // "GTB1"

enum ChunkType : uint32_t {
    CH_META = 1,
    CH_EVENTS = 2,
    CH_FOOTER = 3,
};

// Tags 4, 6 and inline REGW are retained for legacy native-recording files.
// The current text importer emits the remaining tags.
enum EventTag : uint8_t {
    EV_EXEC = 1,
    EV_REGW = 2,
    EV_MEM = 3,
    EV_CALL = 4,
    EV_RET = 5,
    EV_SVC = 6,
    EV_MEMW_NV = 7,
    EV_RDVAL = 8,
    EV_SIMDV = 9,
    EV_VERBATIM = 10,
    EV_CALL2 = 11,
};

} // namespace gt::format
