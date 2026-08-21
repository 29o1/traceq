#pragma once
// GtbRecorder: the .gtb writer used by `gt import`.
//
//   [META chunk]   site arena (static instruction table + precompiled plans)
//   [EVENTS chunk]* varint event stream:
//       EXEC  zigzag delta(site_id)
//       REGW  reg + zigzag delta(value)      (per-register last-value table)
//       MEM   flags + zigzag delta(addr) + zigzag delta(value)
//       CALL  sym + 4 arg deltas
//       RET   x0 delta
//       SVC   num + x0..x2 deltas
//       MEMNV flags + zigzag delta(addr)     (mem access without a value:
//                                             bit0 of flags = write)
//       RDVAL uvar name_id + u8 kind + ...   (importer only: observed READ
//                                             value; name_id indexes the arena
//                                             string pool — "fp", "w19", "v0")
//       SIMDV uvar name_id + u8 kind + ...   (importer only: observed WRITE
//                                             value behind "-> ", SIMD or
//                                             aliased GPR name)
//             kind bit0: 0 = zigzag delta(value) against a per-name
//                          last-value table, 1 = 16 raw little-endian bytes
//                          (128-bit value, printed as >16 hex digits upstream)
//       VERBATIM uvar len + len raw bytes    (importer only: unstructured line
//                                             including its line ending,
//                                             replayed byte-for-byte)
//       CALL2 sym + u8 nargs + nargs arg deltas (importer only: call with the
//                                             observed argument count 0..8)
//   [FOOTER chunk] stop reason + counters + initial_sp + u8 dialect
//                  (dialect bit0: 1 = upstream text dialect; bit1: CRLF line
//                  endings. Absent in older files = 0 = native recording.)
//
// `gt import` grows the arena while parsing, so it writes EVENTS first and META
// just before the FOOTER. The loader accepts chunks in any order and still
// reads older native-recording files.
//
// Integer register history is delta-encoded. RDVAL/SIMDV retain values that
// GumTrace explicitly observed. Memory events retain an address and, when the
// source log provides one, the accessed value.
//
#include "site.h"
#include <string>
#include <unordered_map>
#include <vector>

namespace gt {

enum StopReason : uint8_t {
    STOP_NONE = 0,
    STOP_NORMAL,
    STOP_MAX_BYTES,
    STOP_MAX_EVENTS,
    STOP_MAX_MS,
    STOP_CRASH,   // retained for reading older native-recording files
    STOP_TRIGGER, // retained for reading older native-recording files
};

struct RecOptions {
    uint64_t max_events = 0;   // 0 = unlimited
    uint64_t max_bytes = 0;    // 0 = unlimited (encoded event bytes)
    uint64_t max_ms = 0;       // 0 = unlimited
};

struct RecStats {
    uint64_t events_seen = 0;
    uint64_t events_recorded = 0;
    uint64_t bytes_written = 0;
    StopReason reason = STOP_NONE;
    uint64_t elapsed_ns = 0;
};

class GtbRecorder {
public:
    GtbRecorder(SiteArena& arena) : arena_(arena) {}
    ~GtbRecorder() { finish(); }

    bool open(const std::string& path, const RecOptions& opts);
    RecStats finish();

    // Upstream text log -> gtb event emitters. imp_gate() applies the
    // max_events/max_bytes/max_ms guards once per input line.
    bool imp_gate();
    void imp_exec(uint32_t site_id);
    void imp_regw(int reg, uint64_t v);
    void imp_mem(bool is_write, uint64_t addr, uint8_t size);
    // mem event WITH a known value (hexdump content observations)
    void imp_mem_val(bool is_write, uint64_t addr, uint8_t size,
                     uint64_t value);
    void imp_rdval(uint32_t name_id, uint64_t v);
    void imp_rdval128(uint32_t name_id, unsigned __int128 v);
    void imp_wval(uint32_t name_id, uint64_t v);
    void imp_wval128(uint32_t name_id, unsigned __int128 v);
    void imp_call(uint32_t sym_id, const uint64_t* args, int nargs);
    void imp_ret(uint64_t v);
    void imp_verbatim(const void* p, size_t n);
    void set_dialect(uint8_t d) { dialect_ = d; }

    const RecStats& stats() const { return stats_; }
    bool ok() const { return io_ok_; }

private:
    struct Chunk {
        std::vector<uint8_t> buf;
        size_t n = 0;
    };
    void ensure_space(size_t need);
    void push_u8(uint8_t b) { cur_->buf[cur_->n++] = b; }
    void hand_chunk();
    bool write_chunk_to_fd(int fd, const uint8_t* p, size_t n, uint32_t type);
    void write_footer_locked(uint8_t reason);

    SiteArena& arena_;
    RecOptions opt_;
    RecStats stats_;
    bool open_ = false;
    bool finished_ = false;
    bool io_ok_ = true;

    int fd_ = -1;
    uint64_t start_ns_ = 0;

    Chunk chunk_;
    Chunk* cur_ = &chunk_;

    // event encoding state
    int64_t last_site_id_ = 0;
    uint64_t last_reg_val_[32] = {0};
    uint64_t last_mem_addr_ = 0;
    uint64_t last_mem_val_[2] = {0};   // [0]=read [1]=write
    uint64_t last_arg_val_[8] = {0};   // x0..x7 call args
    uint64_t last_ret_val_ = 0;
    // import state: per-name last observed value (RDVAL/SIMDV delta chain) and
    // the footer dialect byte
    std::unordered_map<uint32_t, uint64_t> last_obs_;
    uint8_t dialect_ = 0;
};

// svc number -> name (Linux/aarch64 subset; matches the upstream text table)
const char* svc_name(uint64_t n);

} // namespace gt
