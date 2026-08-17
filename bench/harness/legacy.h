#pragma once
// Faithful host port of GumTrace's text hot path (GumTrace.cpp
// callout_callback + Utils formatting) used as the A/B baseline. Deliberate
// upstream behaviours preserved:
//   - 50 MB char buffer, flushed to FILE* when > CAP-1024
//   - write-register values deferred to the next event ("-> xN=0x.. \n" line
//     tail)
//   - register names formatted with snprintf per operand
//     (Utils::get_arm64_reg_name)
//   - instruction prefix rebuilt per execution: "[" module "] 0x" pc "!0x" off
//     " " mnemonic " " op_str "; "
//   - function/svc info blocks written directly to the FILE* mid-callback
// Upstream detail intentionally NOT replicated (documented in the report):
//   - the double hash lookup (count + operator[]) for known functions is
//     replaced by a single lookup, which makes the baseline slightly FASTER,
//     i.e. conservative in GumTrace's favour.
#include "corpus.h"
#include <gumtrace/site.h>
#include <cstdio>
#include <string>
#include <vector>

namespace gt {

class LegacyRecorder {
public:
    LegacyRecorder(SiteArena& arena, const char* module_name, uint64_t module_base)
        : arena_(arena), module_(module_name), base_(module_base) {}
    ~LegacyRecorder() { if (f_) finish(); }

    bool open(const std::string& path);
    void record_event(const ExecEvent& ev);   // hot path
    void finish();
    // simulate the process dying: close without flushing (crash-loss metric)
    void abandon() { if (f_) { fclose(f_); f_ = nullptr; } }

    uint64_t events = 0;
    uint64_t flushes = 0;
    uint64_t bytes_out = 0;
    size_t pending() const { return buf_n_; }   // bytes lost if the process dies now

private:
    void append(const char* s, size_t n) {
        if (buf_n_ + n > buf_.size()) { flushbuf(); }
        memcpy(buf_.data() + buf_n_, s, n);
        buf_n_ += n;
    }
    void append_c(char c) { buf_[buf_n_++] = c; }
    void append_hex64(uint64_t v) {
        char tmp[16];
        size_t n = legacy_hex64(tmp, v);
        append(tmp, n);
    }
    void flushbuf() {
        if (buf_n_) { fwrite(buf_.data(), 1, buf_n_, f_); bytes_out += buf_n_; flushes++; }
        buf_n_ = 0;
    }
    const char* reg_name(int ctx_idx);   // snprintf cost preserved

    SiteArena& arena_;
    std::string module_;
    uint64_t base_;
    FILE* f_ = nullptr;
    std::vector<char> buf_;
    size_t buf_n_ = 0;
    static constexpr size_t CAP = 50u * 1024 * 1024;

    // deferred write list (upstream REG_LIST): regs + their post-execution
    // values, printed at the start of the next event
    int wr_num_ = 0;
    int wr_reg_[31];
    uint64_t wr_val_[31] = {0};

    // pending info blocks (upstream last_func_context)
    bool pend_call_ = false;
    std::string pend_name_;
    uint64_t pend_args_[4] = {0};
    bool pend_svc_ = false;
    uint64_t pend_svc_num_ = 0;
    uint64_t pend_svc_args_[3] = {0};
    bool pend_ret_ = false;
    uint64_t pend_ret_val_ = 0;

public:
    // exposed for the equivalence harness
    using BufPtr = const char*;
};

} // namespace gt
