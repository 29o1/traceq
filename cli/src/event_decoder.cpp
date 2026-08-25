#include "event_decoder.h"
#include "gtb_format.h"

#include <traceq/varint.h>
#include <cstring>

namespace gt {

bool EventCursor::take_u8(uint8_t& out) {
    if (off_ >= len_) return false;
    out = p_[off_++];
    return true;
}

bool EventCursor::take_uvar(uint64_t& out) {
    size_t n = get_uvar(p_ + off_, len_ - off_, out);
    if (!n) return false;
    off_ += n;
    return true;
}

bool EventCursor::take_var(int64_t& out) {
    size_t n = get_var(p_ + off_, len_ - off_, out);
    if (!n) return false;
    off_ += n;
    return true;
}

bool EventCursor::next(RawEvent& out) {
    using namespace format;
    out = RawEvent{};
    if (!take_u8(out.tag)) return false;

    if (out.tag == EV_EXEC) {
        int64_t delta;
        if (!take_var(delta)) return false;
        last_site_ += delta;
        out.site_id = uint32_t(last_site_);
        return true;
    }

    if (out.tag == EV_REGW) {
        int64_t delta;
        if (!take_u8(out.reg) || !take_var(delta)) return false;
        uint8_t slot = out.reg & 31;
        last_reg_[slot] = uint64_t(int64_t(last_reg_[slot]) + delta);
        out.value = last_reg_[slot];
        return true;
    }

    if (out.tag == EV_MEM || out.tag == EV_MEMW_NV) {
        uint8_t flags;
        int64_t addr_delta;
        if (!take_u8(flags) || !take_var(addr_delta)) return false;
        out.is_write = (flags & 1) != 0;
        out.size = uint8_t(flags >> 1);
        last_addr_ = uint64_t(int64_t(last_addr_) + addr_delta);
        out.addr = last_addr_;
        out.value_known = out.tag == EV_MEM;
        if (out.value_known) {
            int64_t value_delta;
            if (!take_var(value_delta)) return false;
            size_t lane = out.is_write ? 1 : 0;
            last_mem_value_[lane] =
                uint64_t(int64_t(last_mem_value_[lane]) + value_delta);
            out.value = last_mem_value_[lane];
        }
        return true;
    }

    if (out.tag == EV_CALL) {
        uint64_t symbol_id;
        if (!take_uvar(symbol_id) || symbol_id > UINT32_MAX ||
            !take_u8(out.nargs) || out.nargs > 8)
            return false;
        out.symbol_id = uint32_t(symbol_id);
        for (uint8_t i = 0; i < out.nargs; i++) {
            int64_t delta;
            if (!take_var(delta)) return false;
            last_arg_[i] = uint64_t(int64_t(last_arg_[i]) + delta);
            out.args[i] = last_arg_[i];
        }
        return true;
    }

    if (out.tag == EV_RET) {
        int64_t delta;
        if (!take_var(delta)) return false;
        last_ret_ = uint64_t(int64_t(last_ret_) + delta);
        out.value = last_ret_;
        return true;
    }

    if (out.tag == EV_RDVAL || out.tag == EV_SIMDV) {
        uint64_t name;
        uint8_t kind;
        if (!take_uvar(name) || !take_u8(kind)) return false;
        out.name_id = uint32_t(name);
        if (kind == 0) {
            int64_t delta;
            if (!take_var(delta)) return false;
            uint64_t value =
                uint64_t(int64_t(last_observed_[out.name_id]) + delta);
            last_observed_[out.name_id] = value;
            out.observed = value;
        } else if (kind == 1) {
            if (off_ + 16 > len_) return false;
            memcpy(&out.observed, p_ + off_, 16);
            off_ += 16;
        } else {
            return false;
        }
        return true;
    }

    if (out.tag == EV_VERBATIM) {
        uint64_t size;
        if (!take_uvar(size) || size > UINT32_MAX || size > len_ - off_)
            return false;
        out.verbatim = p_ + off_;
        out.verbatim_len = uint32_t(size);
        off_ += size_t(size);
        return true;
    }

    return false;
}

size_t EventCursor::next_batch(RawEvent* out, size_t capacity) {
    if (batch_done_) return 0;
    size_t count = 0;
    while (count < capacity) {
        if (!next(out[count])) {
            batch_done_ = true;
            break;
        }
        count++;
    }
    return count;
}

} // namespace gt
