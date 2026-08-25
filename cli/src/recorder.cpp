#include <traceq/recorder.h>
#include <traceq/common.h>
#include <traceq/varint.h>
#include "gtb_format.h"
#include <cstring>
#include <fcntl.h>
#include <unistd.h>

namespace gt {

static constexpr size_t EVENT_CHUNK_SIZE = 256 * 1024;

using namespace format;

bool GtbRecorder::open(const std::string& path, const RecOptions& opts) {
    opt_ = opts;
    io_ok_ = true;
    fd_ = ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd_ < 0) return false;

    uint32_t hdr[2] = {GTB_MAGIC, 0};
    if (::write(fd_, hdr, sizeof(hdr)) != sizeof(hdr)) {
        ::close(fd_);
        fd_ = -1;
        return false;
    }

    cur_->buf.resize(EVENT_CHUNK_SIZE);
    cur_->n = 0;
    start_ns_ = now_ns();
    stats_ = RecStats{};
    finished_ = false;
    open_ = true;
    return true;
}

void GtbRecorder::ensure_space(size_t need) {
    if (cur_->n + need <= cur_->buf.size()) return;
    hand_chunk();
    if (need > cur_->buf.size()) cur_->buf.resize(need);
}

void GtbRecorder::hand_chunk() {
    if (cur_->n == 0) return;
    if (write_chunk_to_fd(fd_, cur_->buf.data(), cur_->n, CH_EVENTS))
        stats_.bytes_written += cur_->n + 12;
    else
        io_ok_ = false;
    cur_->n = 0;
}

bool GtbRecorder::write_chunk_to_fd(int fd, const uint8_t* p, size_t n,
                                    uint32_t type) {
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

void GtbRecorder::write_footer_locked(uint8_t reason) {
    uint8_t f[96];
    size_t n = 0;
    f[n++] = reason;
    n += put_uvar(f + n, stats_.events_seen);
    n += put_uvar(f + n, stats_.events_recorded);
    n += put_uvar(f + n, stats_.bytes_written);
    f[n++] = crlf_ ? 1 : 0;
    if (!write_chunk_to_fd(fd_, f, n, CH_FOOTER)) io_ok_ = false;
}

RecStats GtbRecorder::finish() {
    if (finished_ || fd_ < 0) return stats_;
    finished_ = true;
    open_ = false;
    stats_.elapsed_ns = now_ns() - start_ns_;

    uint8_t reason = stats_.reason ? uint8_t(stats_.reason)
                                   : uint8_t(STOP_NORMAL);
    if (stats_.reason == STOP_NONE) stats_.reason = STOP_NORMAL;

    hand_chunk();
    std::vector<uint8_t> meta;
    arena_.serialize(meta);
    if (!write_chunk_to_fd(fd_, meta.data(), meta.size(), CH_META)) io_ok_ = false;
    write_footer_locked(reason);
    ::close(fd_);
    fd_ = -1;
    return stats_;
}

bool GtbRecorder::imp_gate() {
    if (!open_) return false;
    if (!io_ok_) { open_ = false; return false; }
    stats_.events_seen++; // one input line per gate call
    if (opt_.max_ms && now_ns() - start_ns_ > opt_.max_ms * 1000000ULL) {
        stats_.reason = STOP_MAX_MS;
        open_ = false;
        return false;
    }
    // Include the current synchronous event chunk. The current input line may
    // cross the threshold; the next line is then rejected.
    if (opt_.max_bytes &&
        stats_.bytes_written + cur_->n >= opt_.max_bytes) {
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
    push_u8(EV_MEMW_NV);
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
    push_u8(EV_MEM);
    push_u8(uint8_t(size << 1) | uint8_t(is_write ? 1 : 0));
    memcpy(cur_->buf.data() + cur_->n, tmp, n1);
    cur_->n += n1;
    memcpy(cur_->buf.data() + cur_->n, tmp2, n2);
    cur_->n += n2;
    last_mem_addr_ = addr;
    last_mem_val_[is_write ? 1 : 0] = value;
    stats_.events_recorded++;
}

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
    size_t n0 = put_uvar(tmp, sym_id);
    ensure_space(1 + n0 + 1 + size_t(nargs) * 12);
    push_u8(EV_CALL);
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
    if (!open_ || n > 60000) return;
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

} // namespace gt
