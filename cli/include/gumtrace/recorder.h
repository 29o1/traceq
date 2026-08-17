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
//   [FOOTER chunk] stop reason + counters
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

    const RecStats& stats() const { return stats_; }

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

    // static state for the signal handler (single active recorder)
    static GtbRecorder* active_;
    friend struct CrashGate;
};

// svc number -> name (subset used by the corpus; matches legacy table)
const char* svc_name(uint64_t n);

} // namespace gt
