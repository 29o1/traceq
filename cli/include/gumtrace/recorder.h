#pragma once
// GtbRecorder: the new hot path. Consumes the same ExecEvents as the legacy
// text recorder but emits a compact binary stream:
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
//                  endings. Absent in older files = 0 = corpus.)
//
// Chunk order: recording writes META first; `gt import` (defer_meta) grows the
// arena while streaming and therefore writes EVENTS first and META just
// before the FOOTER — the loader accepts chunks in any order.
//
// Read values are NOT stored: they are reconstructed from the REGW history at
// expansion time (a value read is the last value written). Memory read/write
// values ARE stored (initial memory state is unknowable).
//
// Runtime properties under test:
//   - double-buffered chunk pool + background writer thread (hot path never
//     blocks on I/O while free chunks remain; stalls are measured)
//   - resource guards: max_bytes / max_events / max_ms with graceful stop
//   - crash safety: SIGSEGV/SIGBUS/SIGABRT/SIGILL handler flushes the current
//     partial chunk + FOOTER(reason=crash) with async-signal-safe write()
//   - flight-recorder mode: keep the last N chunks in memory, discard older,
//     dump everything when a trigger symbol is called (or on finish)
#include "event.h"
#include "site.h"
#include <atomic>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace gt {

enum Detail : uint8_t { DETAIL_FULL = 0, DETAIL_MEM = 1, DETAIL_CALLS = 2 };

enum StopReason : uint8_t {
    STOP_NONE = 0,
    STOP_NORMAL,
    STOP_MAX_BYTES,
    STOP_MAX_EVENTS,
    STOP_MAX_MS,
    STOP_CRASH,
    STOP_TRIGGER,
};

struct RecOptions {
    Detail detail = DETAIL_FULL;
    uint64_t max_events = 0;   // 0 = unlimited
    uint64_t max_bytes = 0;    // 0 = unlimited (bytes handed to writer/dump)
    uint64_t max_ms = 0;       // 0 = unlimited
    int ring_keep_chunks = 0;  // >0 enables flight-recorder mode
    const char* trigger_sym = nullptr; // dump+stop when this symbol is called
    size_t chunk_size = 256 * 1024;
    int n_pool_chunks = 8;
    // Initial stack pointer of the traced thread. Recorded in the footer so the
    // expander can reconstruct sp-relative reads without knowing anything about
    // the event source. 0 = unknown.
    uint64_t initial_sp = 0;
    // import mode: the arena is still growing while events stream in, so the
    // META chunk is written at finish() (after all EVENTS chunks) instead of
    // at open().
    bool defer_meta = false;
    // dynamic detail escalation: run cheap (e.g. DETAIL_CALLS) until a call to
    // escalate_sym is observed, then switch to escalate_detail for the next
    // escalate_events events (0 = until the end) and fall back. One-shot.
    // Replaces the re-record loop when the interesting window is located by a
    // symbol but not by an address range.
    const char* escalate_sym = nullptr;
    Detail escalate_detail = DETAIL_FULL;
    uint64_t escalate_events = 0;
};

struct RecStats {
    uint64_t events_seen = 0;
    uint64_t events_recorded = 0;
    uint64_t bytes_written = 0;
    uint64_t chunks_written = 0;
    uint64_t producer_stall_ns = 0;   // time blocked waiting for a free chunk
    uint64_t worst_stall_ns = 0;
    StopReason reason = STOP_NONE;
    uint64_t elapsed_ns = 0;
};

class GtbRecorder {
public:
    GtbRecorder(SiteArena& arena) : arena_(arena) {}
    ~GtbRecorder() {
        finish();
        for (Chunk* c : all_) delete c;
    }

    bool open(const std::string& path, const RecOptions& opts);
    // hot path
    void record_event(const ExecEvent& ev);
    RecStats finish();

    // ---- import cold path (upstream text log -> gtb; see gt import) ----
    // These emit the importer-only event tags. Nothing here runs in the
    // Stalker hot path. imp_gate() applies the max_events/max_bytes/max_ms
    // guards once per input line and turns the recorder off when tripped.
    bool imp_gate();
    void imp_exec(uint32_t site_id);
    void imp_regw(int reg, uint64_t v);
    void imp_mem(bool is_write, uint64_t addr, uint8_t size);
    // mem event WITH a known value (hexdump content observations); the import
    // twin of the native path's EV_MEM emission in record_event
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
    void set_initial_sp(uint64_t v) { if (opt_.initial_sp == 0) opt_.initial_sp = v; }

    const RecStats& stats() const { return stats_; }

    // escalation runtime state (valid while/after recording)
    bool escalated() const { return escalated_; }
    Detail current_detail() const { return cur_detail_; }

    // crash-flush support (called from signal handler)
    static void crash_flush_current();

private:
    struct Chunk {
        std::vector<uint8_t> buf;
        size_t n = 0;
    };
    void ensure_space(size_t need);
    void push_u8(uint8_t b) { cur_->buf[cur_->n++] = b; }
    void hand_chunk();
    void writer_loop();
    bool write_chunk_to_fd(int fd, const uint8_t* p, size_t n, uint32_t type);
    void write_footer_locked(uint8_t reason);

    SiteArena& arena_;
    RecOptions opt_;
    RecStats stats_;
    bool open_ = false;
    bool finished_ = false;

    int fd_ = -1;
    uint64_t start_ns_ = 0;

    // chunk lifetime: all_ owns everything; pool_free_/queue_/ring_ move raw
    // pointers between producer, writer and (in ring mode) retention
    std::vector<Chunk*> all_;
    std::vector<Chunk*> pool_free_;
    std::deque<Chunk*> queue_;
    std::deque<Chunk*> ring_;
    Chunk* cur_ = nullptr;
    std::mutex qm_;
    std::condition_variable qcv_, pool_cv_;
    bool writer_stop_ = false;
    std::thread writer_;
    std::atomic<bool> crashed_{false};

    // event encoding state
    int64_t last_site_id_ = 0;
    uint64_t last_reg_val_[32] = {0};
    uint64_t last_mem_addr_ = 0;
    uint64_t last_mem_val_[2] = {0};   // [0]=read [1]=write
    uint64_t last_arg_val_[7] = {0};   // x0..x3 call args, x0..x2 svc args
    uint64_t last_ret_val_ = 0;
    uint64_t last_site_cache_addr_ = 0;
    uint32_t last_site_cache_id_ = 0;
    uint64_t guard_check_ctr_ = 0;
    // import state: per-name last observed value (RDVAL/SIMDV delta chain) and
    // the footer dialect byte
    std::unordered_map<uint32_t, uint64_t> last_obs_;
    uint8_t dialect_ = 0;
    // arena occupancy when the upfront META was written; finish() rewrites META
    // if the arena grew meanwhile (call symbols intern during recording, and
    // the decode-side arena must know their string ids)
    size_t open_sites_ = 0, open_strings_ = 0;
    // escalation runtime state
    Detail cur_detail_ = DETAIL_FULL;
    uint64_t escalate_budget_ = 0;
    bool escalated_ = false;

    // static state for the signal handler (single active recorder)
    static GtbRecorder* active_;
    friend struct CrashGate;
};

// svc number -> name (subset used by the corpus; matches legacy table)
const char* svc_name(uint64_t n);

} // namespace gt
