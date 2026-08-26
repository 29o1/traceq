#pragma once
// Upstream GumTrace text log -> .gtb importer (see src/import.cpp for the
// byte-exactness contract).
#include "recorder.h"
#include <cstdint>
#include <string>

namespace gt {

struct ImportCounts {
    uint64_t lines = 0, exec = 0;
    uint64_t call_instructions = 0, return_instructions = 0;
    // Source-level "call func:" / "call jni func:" and "ret:" records.
    // The short member names remain source-compatible with existing library
    // callers; CLI output labels them explicitly as annotations.
    uint64_t call = 0, ret = 0;
    uint64_t verbatim = 0;
};

struct ImportResult {
    ImportCounts cnt;
    RecStats stats;
    uint64_t in_bytes = 0, gtb_bytes = 0;
    bool stopped = false; // a max-* guard cut the import short
};

// Parse an upstream log held in memory and record it as a gtb. Returns false
// on output I/O failure.
bool import_mem(const char* p, size_t len, const std::string& out_path,
                const RecOptions& opts, ImportResult& res);
// mmaps in_path and feeds it to import_mem.
bool import_log(const std::string& in_path, const std::string& out_path,
                const RecOptions& opts, ImportResult& res);

// Upstream text-dialect hexdump parsing (shared by the importer, which
// synthesizes content-observation mem events from dump rows, and by the
// query layer, which searches dump payloads byte-exactly).
//   header: "hexdump at address 0x<addr> with length 0x<len>:"
//   row:    "<hexaddr>: 68 74 ... 6f |ascii|" / "<hexaddr>  11 11 ... |...|"
// parse_hexdump_header needs only the header prefix; trailing text is ignored.
bool parse_hexdump_header(const char* p, size_t n, uint64_t& addr,
                          uint64_t& len);
// parse_hexdump_row parses one body row: address (4-16 hex digits, optional
// ':'), then 1..16 space-separated byte pairs, stopped by the '|' gutter,
// line end, or CRLF. Bytes land in out (LE memory order), n_out = count.
bool parse_hexdump_row(const char* p, size_t n, uint64_t& addr,
                       uint8_t out[16], int& n_out);

} // namespace gt
