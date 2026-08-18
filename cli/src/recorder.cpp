#include <traceq/recorder.h>
#include <traceq/common.h>
#include <traceq/varint.h>
#include <cassert>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>
#include <sys/uio.h>
#include <csignal>

namespace gt {

static constexpr uint32_t CHUNK_MAGIC = 0x47544348u; // "GTCH"
static constexpr uint32_t GTB_MAGIC   = 0x47544231u; // "GTB1"

enum : uint8_t {
    CH_META = 1, CH_EVENTS = 2, CH_FOOTER = 3,
    EV_EXEC = 1, EV_REGW = 2, EV_MEM = 3, EV_CALL = 4, EV_RET = 5, EV_SVC = 6,
    EV_MEMW_NV = 7, // store without value: value == source register's REGW
    // REGW small-delta inline encoding: 0x80 | reg<<3 | zigzag-code
    // (code 0-6 covers deltas -3..+3, 7 = escape to EV_REGW)
    EV_REGW_INLINE = 0x80,
    // importer-only tags (never emitted by the Stalker hot path)
    EV_RDVAL = 8,    // observed read value: uvar name_id + u8 kind + value
    EV_SIMDV = 9,    // observed write value: uvar name_id + u8 kind + value
    EV_VERBATIM = 10, // unstructured line: uvar len + raw bytes
    EV_CALL2 = 11,   // call with observed arg count: uvar sym+1 + u8 n + n deltas
};

GtbRecorder* GtbRecorder::active_ = nullptr;

const char* svc_name(uint64_t n) {
    switch (n) {
        case 29: return "ioctl";
        case 56: return "openat";
        case 57: return "close";
        case 63: return "read";
        case 64: return "write";
        case 222: return "mmap";
        case 226: return "mprotect";
        case 78: return "readlinkat";
        default: return nullptr;
    }
}

static void crash_signal_handler(int sig) {
    // async-signal-safe: flush partial chunk + footer, then die honestly
    GtbRecorder::crash_flush_current();
    signal(sig, SIG_DFL);
    raise(sig);
}

bool GtbRecorder::open(const std::string& path, const RecOptions& opts) {
    opt_ = opts;
    if (opt_.ring_keep_chunks >= opt_.n_pool_chunks)
        opt_.ring_keep_chunks = opt_.n_pool_chunks - 1;
    fd_ = ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd_ < 0) return false;
    // file header
    uint32_t hdr[2] = {GTB_MAGIC, 0};
    if (::write(fd_, hdr, sizeof(hdr)) != sizeof(hdr)) return false;

    for (int i = 0; i < opt_.n_pool_chunks; i++) {
        Chunk* c = new Chunk();
        c->buf.resize(opt_.chunk_size);
        all_.push_back(c);
        pool_free_.push_back(c);
    }

    // META chunk (import mode defers it: the arena is still growing)
    if (!opt_.defer_meta) {
        std::vector<uint8_t> meta;
        arena_.serialize(meta);
        write_chunk_to_fd(fd_, meta.data(), meta.size(), CH_META);
        open_sites_ = arena_.size();
        open_strings_ = arena_.strings().size();
    }

    // grab first chunk
    cur_ = pool_free_.back();
    pool_free_.pop_back();
    cur_->n = 0;

    start_ns_ = now_ns();
    stats_ = RecStats{};
    open_ = true;

    if (opt_.ring_keep_chunks == 0) {
        writer_ = std::thread([this] { writer_loop(); });
    }
    active_ = this;
    struct sigaction sa{};
    sa.sa_handler = crash_signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESETHAND;
    sigaction(SIGSEGV, &sa, nullptr);
    sigaction(SIGBUS, &sa, nullptr);
    sigaction(SIGABRT, &sa, nullptr);
    sigaction(SIGILL, &sa, nullptr);
    return true;
}

void GtbRecorder::ensure_space(size_t need) {
    if (cur_->n + need <= cur_->buf.size()) return;
    hand_chunk();
}

void GtbRecorder::hand_chunk() {
    stats_.chunks_written++;
    stats_.bytes_written += cur_->n + 8;

    if (opt_.ring_keep_chunks > 0) {
        // flight-recorder: retain last N chunks in memory
        ring_.push_back(cur_);
        if (int(ring_.size()) > opt_.ring_keep_chunks) {
            pool_free_.push_back(ring_.front());
            ring_.pop_front();
        }
        cur_ = pool_free_.empty() ? nullptr : pool_free_.back();
        if (cur_) pool_free_.pop_back();
    } else {
        std::unique_lock<std::mutex> lk(qm_);
        queue_.push_back(cur_);
        qcv_.notify_one();
        // wait for a free chunk from the pool (stall = I/O not hidden)
        uint64_t t0 = now_ns();
        pool_cv_.wait(lk, [this] { return !pool_free_.empty(); });
        uint64_t dt = now_ns() - t0;
        stats_.producer_stall_ns += dt;
        if (dt > stats_.worst_stall_ns) stats_.worst_stall_ns = dt;
        cur_ = pool_free_.back();
        pool_free_.pop_back();
        lk.unlock();
    }
    if (cur_) cur_->n = 0;
}

void GtbRecorder::writer_loop() {
    std::unique_lock<std::mutex> lk(qm_);
    while (true) {
        qcv_.wait(lk, [this] { return !queue_.empty() || writer_stop_; });
        if (queue_.empty() && writer_stop_) break;
        Chunk* c = queue_.front();
        queue_.pop_front();
        lk.unlock();
        write_chunk_to_fd(fd_, c->buf.data(), c->n, CH_EVENTS);
        lk.lock();
        pool_free_.push_back(c);
        pool_cv_.notify_one();
    }
}

bool GtbRecorder::write_chunk_to_fd(int fd, const uint8_t* p, size_t n, uint32_t type) {
    uint32_t hdr[2] = {CHUNK_MAGIC, type};
    if (::write(fd, hdr, sizeof(hdr)) != sizeof(hdr)) return false;
    uint32_t len = uint32_t(n);
    if (::write(fd, &len, 4) != 4) return false;
    size_t off = 0;
    while (off < n) {
        ssize_t w = ::write(fd, p + off, n - off);
        if (w <= 0) return false;
        off += size_t(w);
    }
    return true;
}

void GtbRecorder::record_event(const ExecEvent& ev) {
    stats_.events_seen++;
    if (!open_) return;

    // ---- guards (cheap counters; time/bytes check amortized) ----
    if (++guard_check_ctr_ >= 4096) {
        guard_check_ctr_ = 0;
        if (opt_.max_ms && now_ns() - start_ns_ > opt_.max_ms * 1000000ULL) {
            stats_.reason = STOP_MAX_MS;
            open_ = false;
            return;
        }
        if (opt_.max_bytes && stats_.bytes_written > opt_.max_bytes) {
            stats_.reason = STOP_MAX_BYTES;
            open_ = false;
            return;
        }
    }
    if (opt_.max_events && stats_.events_seen > opt_.max_events) {
        stats_.reason = STOP_MAX_EVENTS;
        open_ = false;
        return;
    }

    // ---- trigger (flight-recorder dump) ----
    if (opt_.trigger_sym && ev.is_call && ev.call_name &&
        strcmp(ev.call_name, opt_.trigger_sym) == 0) {
        stats_.reason = STOP_TRIGGER;
        open_ = false;
        return;
    }

    // resolve site id (one-entry cache: tight loops hit every time)
    uint64_t addr = ev.pc;
    if (addr != last_site_cache_addr_) {
        auto it = arena_.by_addr_find(addr);
        if (it == 0xFFFFFFFFu) return; // unmapped site: skip event
        last_site_cache_addr_ = addr;
        last_site_cache_id_ = it;
    }
    uint32_t site_id = last_site_cache_id_;

    uint8_t tmp[64];
    const bool is_calls_only = opt_.detail == DETAIL_CALLS;
    const bool log_mem = opt_.detail != DETAIL_CALLS;
    const bool log_regs = opt_.detail == DETAIL_FULL;

    bool interesting =
        (!is_calls_only) || ev.is_call || ev.is_svc || ev.is_ret;

    if (interesting && (!is_calls_only || ev.is_call || ev.is_svc || ev.is_ret)) {
        if (!is_calls_only) {
            // EXEC
            int64_t d = int64_t(site_id) - last_site_id_;
            size_t n = put_var(tmp, d);
            ensure_space(1 + n);
            push_u8(EV_EXEC);
            memcpy(cur_->buf.data() + cur_->n, tmp, n);
            cur_->n += n;
            last_site_id_ = int64_t(site_id);
        }

        if (log_regs) {
            // writes are derived from the precompiled plan (upstream builds
            // write_reg_list from operand analysis, not from an independent
            // source); values come from the event's write set
            const Site& site = arena_.get(site_id);
            for (uint8_t pi = 0; pi < site.n_ops; pi++) {
                if (site.ops[pi].kind != OP_REG_W) continue;
                int reg = site.ops[pi].ctx_idx;
                if (reg < 0) continue;
                uint64_t v = 0;
                bool found = false;
                for (int k = 0; k < ev.n_wr; k++) {
                    if (ev.wr_id[k] == reg) { v = ev.wr_val[k]; found = true; break; }
                }
                if (!found) continue;
                uint8_t reg8 = uint8_t(reg);
                int64_t d = int64_t(v) - int64_t(last_reg_val_[reg8 & 31]);
                // pointer walkers dominate: |delta|<=3 fits a single byte
                int64_t z = zigzag_enc(d);
                if (reg8 <= 15 && z >= 0 && z <= 6) {
                    ensure_space(1);
                    push_u8(uint8_t(EV_REGW_INLINE | (reg8 << 3) | z));
                } else {
                    size_t n = put_var(tmp, d);
                    ensure_space(2 + n);
                    push_u8(EV_REGW);
                    push_u8(reg8);
                    memcpy(cur_->buf.data() + cur_->n, tmp, n);
                    cur_->n += n;
                }
                last_reg_val_[reg8 & 31] = v;
            }
            // BL/BLR write x30 implicitly (not an operand in capstone)
            if (site.kind == SK_CALL_IMM || site.kind == SK_CALL_REG) {
                for (int k = 0; k < ev.n_wr; k++) {
                    if (ev.wr_id[k] == 30) {
                        uint64_t v = ev.wr_val[k];
                        int64_t d = int64_t(v) - int64_t(last_reg_val_[30]);
                        // reg 30 > 15: always extended encoding
                        size_t n = put_var(tmp, d);
                        ensure_space(2 + n);
                        push_u8(EV_REGW);
                        push_u8(30);
                        memcpy(cur_->buf.data() + cur_->n, tmp, n);
                        cur_->n += n;
                        last_reg_val_[30] = v;
                        break;
                    }
                }
            }
        }

        if (log_mem) {
            for (int i = 0; i < ev.n_mem; i++) {
                const auto& m = ev.mem[i];
                int64_t ad = int64_t(m.addr) - int64_t(last_mem_addr_);
                size_t n1 = put_var(tmp, ad);
                if (log_regs && m.is_write) {
                    // store value == source register value, already recorded as
                    // REGW: skip it (reconstructed at expansion)
                    ensure_space(2 + n1);
                    push_u8(EV_MEMW_NV);
                    push_u8(uint8_t(m.size << 1) | 1);
                    memcpy(cur_->buf.data() + cur_->n, tmp, n1);
                    cur_->n += n1;
                } else {
                    int64_t vd = int64_t(m.value) - int64_t(last_mem_val_[m.is_write ? 1 : 0]);
                    uint8_t tmp2[16];
                    size_t n2 = put_var(tmp2, vd);
                    ensure_space(2 + n1 + n2);
                    push_u8(EV_MEM);
                    push_u8(uint8_t(m.is_write ? 1 : 0) | uint8_t(m.size << 1));
                    memcpy(cur_->buf.data() + cur_->n, tmp, n1);
                    cur_->n += n1;
                    memcpy(cur_->buf.data() + cur_->n, tmp2, n2);
                    cur_->n += n2;
                    last_mem_val_[m.is_write ? 1 : 0] = m.value;
                }
                last_mem_addr_ = m.addr;
            }
        }
    }

    if (ev.is_call) {
        int32_t sym = ev.call_name ? arena_.symbol_id(ev.call_name) : -1;
        size_t n0 = put_uvar(tmp, uint64_t(uint32_t(sym) + 1));
        ensure_space(1 + n0 + 4 * 12);
        push_u8(EV_CALL);
        memcpy(cur_->buf.data() + cur_->n, tmp, n0);
        cur_->n += n0;
        if (sym < 0) {
            size_t na = put_var(tmp, int64_t(ev.call_target));
            memcpy(cur_->buf.data() + cur_->n, tmp, na);
            cur_->n += na;
        }
        for (int i = 0; i < 4; i++) {
            uint64_t v = ev.x[i];
            int64_t d = int64_t(v) - int64_t(last_arg_val_[i]);
            size_t n = put_var(tmp, d);
            ensure_space(n + 1);
            memcpy(cur_->buf.data() + cur_->n, tmp, n);
            cur_->n += n;
            last_arg_val_[i] = v;
        }
        stats_.events_recorded++;
    } else if (interesting && ev.is_ret) {
        int64_t d = int64_t(ev.ret_val) - int64_t(last_ret_val_);
        size_t n = put_var(tmp, d);
        ensure_space(1 + n);
        push_u8(EV_RET);
        memcpy(cur_->buf.data() + cur_->n, tmp, n);
        cur_->n += n;
        last_ret_val_ = ev.ret_val;
        stats_.events_recorded++;
    } else if (ev.is_svc) {
        size_t n0 = put_uvar(tmp, ev.svc_num);
        ensure_space(1 + n0 + 3 * 12);
        push_u8(EV_SVC);
        memcpy(cur_->buf.data() + cur_->n, tmp, n0);
        cur_->n += n0;
        for (int i = 0; i < 3; i++) {
            uint64_t v = ev.x[i];
            int64_t d = int64_t(v) - int64_t(last_arg_val_[4 + i]);
            size_t n = put_var(tmp, d);
            ensure_space(n + 1);
            memcpy(cur_->buf.data() + cur_->n, tmp, n);
            cur_->n += n;
            last_arg_val_[4 + i] = v;
        }
        stats_.events_recorded++;
    } else if (interesting) {
        stats_.events_recorded++;
    }
}

void GtbRecorder::write_footer_locked(uint8_t reason) {
    uint8_t f[96];
    size_t n = 0;
    f[n++] = reason;
    n += put_uvar(f + n, stats_.events_seen);
    n += put_uvar(f + n, stats_.events_recorded);
    n += put_uvar(f + n, stats_.bytes_written);
    n += put_uvar(f + n, opt_.initial_sp);
    f[n++] = dialect_; // absent in older files -> 0 -> native recording
    write_chunk_to_fd(fd_, f, n, CH_FOOTER);
}

RecStats GtbRecorder::finish() {
    if (finished_ || fd_ < 0) return stats_;
    finished_ = true;
    open_ = false;
    stats_.elapsed_ns = now_ns() - start_ns_;

    uint8_t reason = stats_.reason ? uint8_t(stats_.reason) : uint8_t(STOP_NORMAL);
    if (stats_.reason == STOP_NONE) stats_.reason = STOP_NORMAL;

    if (opt_.ring_keep_chunks > 0) {
        // dump retained ring
        if (cur_ && cur_->n) {
            ring_.push_back(cur_);
            cur_ = nullptr;
        }
        for (Chunk* c : ring_) {
            write_chunk_to_fd(fd_, c->buf.data(), c->n, CH_EVENTS);
            stats_.chunks_written++;
            stats_.bytes_written += c->n + 8;
        }
        ring_.clear();
    } else {
        // hand the final partial chunk BEFORE signalling the writer to stop
        if (cur_ && cur_->n) {
            std::unique_lock<std::mutex> lk(qm_);
            queue_.push_back(cur_);
            cur_ = nullptr;
            qcv_.notify_one();
            lk.unlock();
        }
        if (writer_.joinable()) {
            {
                std::unique_lock<std::mutex> lk(qm_);
                writer_stop_ = true;
                qcv_.notify_all();
            }
            writer_.join();
        }
    }

    // import mode: the arena finished growing, emit META before the footer
    if (opt_.defer_meta) {
        std::vector<uint8_t> meta;
        arena_.serialize(meta);
        write_chunk_to_fd(fd_, meta.data(), meta.size(), CH_META);
    } else if (arena_.size() != open_sites_ || arena_.strings().size() != open_strings_) {
        // the arena grew after the upfront META (call-site symbols intern lazily
        // during recording) — the loader takes the LAST meta chunk, so a fresh
        // full one here makes those string ids resolvable
        std::vector<uint8_t> meta;
        arena_.serialize(meta);
        write_chunk_to_fd(fd_, meta.data(), meta.size(), CH_META);
    }

    write_footer_locked(reason);
    ::close(fd_);
    fd_ = -1;

    if (active_ == this) active_ = nullptr;
    struct sigaction sa{};
    sa.sa_handler = SIG_DFL;
    sigaction(SIGSEGV, &sa, nullptr);
    sigaction(SIGBUS, &sa, nullptr);
    sigaction(SIGABRT, &sa, nullptr);
    sigaction(SIGILL, &sa, nullptr);
    return stats_;
}

// ---------------------------------------------------------------------------
// import cold path
// ---------------------------------------------------------------------------
bool GtbRecorder::imp_gate() {
    if (!open_) return false;
    stats_.events_seen++; // one input line per gate call
    if (opt_.max_ms && now_ns() - start_ns_ > opt_.max_ms * 1000000ULL) {
        stats_.reason = STOP_MAX_MS;
        open_ = false;
        return false;
    }
    if (opt_.max_bytes && stats_.bytes_written > opt_.max_bytes) {
        stats_.reason = STOP_MAX_BYTES;
        open_ = false;
        return false;
    }
    if (opt_.max_events && stats_.events_seen > opt_.max_events) {
        stats_.reason = STOP_MAX_EVENTS;
        open_ = false;
        return false;
    }
    return true;
}

void GtbRecorder::imp_exec(uint32_t site_id) {
    if (!open_) return;
    uint8_t tmp[16];
    int64_t d = int64_t(site_id) - last_site_id_;
    size_t n = put_var(tmp, d);
    ensure_space(1 + n);
    push_u8(EV_EXEC);
    memcpy(cur_->buf.data() + cur_->n, tmp, n);
    cur_->n += n;
    last_site_id_ = int64_t(site_id);
    stats_.events_recorded++;
}

void GtbRecorder::imp_regw(int reg, uint64_t v) {
    if (!open_) return;
    uint8_t tmp[16];
    uint8_t reg8 = uint8_t(reg);
    int64_t d = int64_t(v) - int64_t(last_reg_val_[reg8 & 31]);
    size_t n = put_var(tmp, d);
    ensure_space(2 + n);
    push_u8(EV_REGW);
    push_u8(reg8);
    memcpy(cur_->buf.data() + cur_->n, tmp, n);
    cur_->n += n;
    last_reg_val_[reg8 & 31] = v;
}

void GtbRecorder::imp_mem(bool is_write, uint64_t addr, uint8_t size) {
    if (!open_) return;
    uint8_t tmp[16];
    int64_t ad = int64_t(addr) - int64_t(last_mem_addr_);
    size_t n = put_var(tmp, ad);
    ensure_space(2 + n);
    push_u8(EV_MEMW_NV); // no-value mem access; flags bit0 says read or write
    push_u8(uint8_t(size << 1) | uint8_t(is_write ? 1 : 0));
    memcpy(cur_->buf.data() + cur_->n, tmp, n);
    cur_->n += n;
    last_mem_addr_ = addr;
    stats_.events_recorded++;
}

void GtbRecorder::imp_mem_val(bool is_write, uint64_t addr, uint8_t size,
                              uint64_t value) {
    if (!open_) return;
    uint8_t tmp[16], tmp2[16];
    int64_t ad = int64_t(addr) - int64_t(last_mem_addr_);
    size_t n1 = put_var(tmp, ad);
    int64_t vd = int64_t(value) - int64_t(last_mem_val_[is_write ? 1 : 0]);
    size_t n2 = put_var(tmp2, vd);
    ensure_space(2 + n1 + n2);
    push_u8(EV_MEM); // same tag/flags layout the native path emits
    push_u8(uint8_t(size << 1) | uint8_t(is_write ? 1 : 0));
    memcpy(cur_->buf.data() + cur_->n, tmp, n1);
    cur_->n += n1;
    memcpy(cur_->buf.data() + cur_->n, tmp2, n2);
    cur_->n += n2;
    last_mem_addr_ = addr;
    last_mem_val_[is_write ? 1 : 0] = value;
    stats_.events_recorded++;
}

// shared body of RDVAL/SIMDV (kind 0: delta-coded <=64-bit observed value)
void GtbRecorder::imp_rdval(uint32_t name_id, uint64_t v) {
    if (!open_) return;
    uint8_t tmp[24];
    size_t nn = put_uvar(tmp, name_id);
    uint64_t& last = last_obs_[name_id];
    int64_t d = int64_t(v) - int64_t(last);
    uint8_t tmp2[16];
    size_t nd = put_var(tmp2, d);
    ensure_space(1 + nn + 1 + nd);
    push_u8(EV_RDVAL);
    memcpy(cur_->buf.data() + cur_->n, tmp, nn);
    cur_->n += nn;
    push_u8(0);
    memcpy(cur_->buf.data() + cur_->n, tmp2, nd);
    cur_->n += nd;
    last = v;
}

void GtbRecorder::imp_rdval128(uint32_t name_id, unsigned __int128 v) {
    if (!open_) return;
    uint8_t tmp[8];
    size_t nn = put_uvar(tmp, name_id);
    ensure_space(1 + nn + 1 + 16);
    push_u8(EV_RDVAL);
    memcpy(cur_->buf.data() + cur_->n, tmp, nn);
    cur_->n += nn;
    push_u8(1);
    memcpy(cur_->buf.data() + cur_->n, &v, 16);
    cur_->n += 16;
}

void GtbRecorder::imp_wval(uint32_t name_id, uint64_t v) {
    if (!open_) return;
    uint8_t tmp[24];
    size_t nn = put_uvar(tmp, name_id);
    uint64_t& last = last_obs_[name_id];
    int64_t d = int64_t(v) - int64_t(last);
    uint8_t tmp2[16];
    size_t nd = put_var(tmp2, d);
    ensure_space(1 + nn + 1 + nd);
    push_u8(EV_SIMDV);
    memcpy(cur_->buf.data() + cur_->n, tmp, nn);
    cur_->n += nn;
    push_u8(0);
    memcpy(cur_->buf.data() + cur_->n, tmp2, nd);
    cur_->n += nd;
    last = v;
}

void GtbRecorder::imp_wval128(uint32_t name_id, unsigned __int128 v) {
    if (!open_) return;
    uint8_t tmp[8];
    size_t nn = put_uvar(tmp, name_id);
    ensure_space(1 + nn + 1 + 16);
    push_u8(EV_SIMDV);
    memcpy(cur_->buf.data() + cur_->n, tmp, nn);
    cur_->n += nn;
    push_u8(1);
    memcpy(cur_->buf.data() + cur_->n, &v, 16);
    cur_->n += 16;
}

void GtbRecorder::imp_call(uint32_t sym_id, const uint64_t* args, int nargs) {
    if (!open_ || nargs < 0 || nargs > 8) return;
    uint8_t tmp[16];
    size_t n0 = put_uvar(tmp, uint64_t(sym_id) + 1);
    ensure_space(1 + n0 + 1 + size_t(nargs) * 12);
    push_u8(EV_CALL2);
    memcpy(cur_->buf.data() + cur_->n, tmp, n0);
    cur_->n += n0;
    push_u8(uint8_t(nargs));
    for (int i = 0; i < nargs; i++) {
        uint64_t v = args[i];
        int64_t d = int64_t(v) - int64_t(last_arg_val_[i]);
        size_t n = put_var(tmp, d);
        ensure_space(n + 1);
        memcpy(cur_->buf.data() + cur_->n, tmp, n);
        cur_->n += n;
        last_arg_val_[i] = v;
    }
    stats_.events_recorded++;
}

void GtbRecorder::imp_ret(uint64_t v) {
    if (!open_) return;
    uint8_t tmp[16];
    int64_t d = int64_t(v) - int64_t(last_ret_val_);
    size_t n = put_var(tmp, d);
    ensure_space(1 + n);
    push_u8(EV_RET);
    memcpy(cur_->buf.data() + cur_->n, tmp, n);
    cur_->n += n;
    last_ret_val_ = v;
    stats_.events_recorded++;
}

void GtbRecorder::imp_verbatim(const void* p, size_t n) {
    if (!open_) return;
    if (n > 60000) return; // cannot fit a chunk; importer counts it as dropped
    uint8_t tmp[8];
    size_t nl = put_uvar(tmp, n);
    ensure_space(1 + nl + n);
    push_u8(EV_VERBATIM);
    memcpy(cur_->buf.data() + cur_->n, tmp, nl);
    cur_->n += nl;
    memcpy(cur_->buf.data() + cur_->n, p, n);
    cur_->n += n;
    stats_.events_recorded++;
}

void GtbRecorder::crash_flush_current() {
    GtbRecorder* r = active_;
    if (!r || r->crashed_.exchange(true)) return;
    // async-signal-safe: single write() of partial chunk + footer, no locks
    if (r->cur_ && r->cur_->n) {
        uint32_t hdr[3] = {CHUNK_MAGIC, CH_EVENTS, uint32_t(r->cur_->n)};
        struct iovec iov[4];
        iov[0].iov_base = hdr;             iov[0].iov_len = 12;
        iov[1].iov_base = r->cur_->buf.data(); iov[1].iov_len = r->cur_->n;
        uint8_t f[64];
        size_t n = 0;
        f[n++] = uint8_t(STOP_CRASH);
        n += put_uvar(f + n, r->stats_.events_seen);
        n += put_uvar(f + n, r->stats_.events_recorded);
        n += put_uvar(f + n, r->stats_.bytes_written);
        n += put_uvar(f + n, r->opt_.initial_sp);
        uint32_t fh[3] = {CHUNK_MAGIC, CH_FOOTER, uint32_t(n)};
        iov[2].iov_base = fh;              iov[2].iov_len = 12;
        iov[3].iov_base = f;               iov[3].iov_len = n;
        writev(r->fd_, iov, 4);
    } else {
        uint8_t f[64];
        size_t n = 0;
        f[n++] = uint8_t(STOP_CRASH);
        n += put_uvar(f + n, r->stats_.events_seen);
        n += put_uvar(f + n, r->stats_.events_recorded);
        n += put_uvar(f + n, r->stats_.bytes_written);
        n += put_uvar(f + n, r->opt_.initial_sp);
        uint32_t fh[3] = {CHUNK_MAGIC, CH_FOOTER, uint32_t(n)};
        struct iovec iov[2] = {{fh, 12}, {f, n}};
        writev(r->fd_, iov, 2);
    }
}

} // namespace gt
