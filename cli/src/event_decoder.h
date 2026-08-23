#pragma once

// Stateful decoder for the delta-encoded GTB EVENTS payload. This is the one
// place that knows how raw event tags are represented; statistics and semantic
// group expansion both consume it.

#include <cstddef>
#include <cstdint>
#include <unordered_map>
#include <vector>

namespace gt {

struct RawEvent {
    uint8_t tag = 0;

    uint32_t site_id = 0;
    uint8_t reg = 0;
    uint64_t value = 0;

    bool is_write = false;
    bool value_known = false;
    uint8_t size = 0;
    uint64_t addr = 0;

    uint32_t name_id = 0;
    unsigned __int128 observed = 0;

    // CALL/CALL2: symbol_plus_one is zero for a numeric target, otherwise it
    // is the arena string id plus one. Legacy CALL has nargs == 4; CALL2 has
    // the observed argument count.
    uint64_t symbol_plus_one = 0;
    uint64_t target = 0;
    uint8_t nargs = 0;
    uint64_t args[8] = {0};

    uint64_t svc_num = 0;

    const uint8_t* verbatim = nullptr;
    uint32_t verbatim_len = 0;
};

class EventCursor {
public:
    explicit EventCursor(const std::vector<uint8_t>& events)
        : p_(events.data()), len_(events.size()) {}

    // Returns false at end-of-stream or at the first malformed/truncated
    // event, matching the historical reader's stop-at-corruption behavior.
    bool next(RawEvent& out);
    // Amortizes the decoder call boundary for full-trace scans. `out` must
    // point to capacity RawEvent slots; returns the number decoded.
    size_t next_batch(RawEvent* out, size_t capacity);

private:
    bool take_u8(uint8_t& out);
    bool take_uvar(uint64_t& out);
    bool take_var(int64_t& out);

    const uint8_t* p_ = nullptr;
    size_t len_ = 0;
    size_t off_ = 0;

    int64_t last_site_ = 0;
    uint64_t last_reg_[32] = {0};
    uint64_t last_addr_ = 0;
    uint64_t last_mem_value_[2] = {0};
    uint64_t last_arg_[8] = {0};
    uint64_t last_ret_ = 0;
    std::unordered_map<uint32_t, uint64_t> last_observed_;
    bool batch_done_ = false;
};

} // namespace gt
