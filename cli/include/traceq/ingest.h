#pragma once
// .gtb parsing, semantic group scanning, and output expansion.
#include "recorder.h"
#include "site.h"
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace gt {

struct MemOp {
    bool is_write;
    uint64_t addr;
    uint8_t size;
    uint64_t value;
    bool value_known = true;
};

struct GtbFile {
    SiteArena arena;
    // concatenated EVENTS payload (bounded by guards; loaded once)
    std::vector<uint8_t> events;
    uint8_t stop_reason = 0;
    bool crlf = false;
    uint64_t events_seen = 0, events_recorded = 0, bytes_written = 0;

    // On failure, err (when given) receives a human-readable reason without
    // the path, so callers can print "<path>: <reason>".
    bool load(const std::string& path, std::string* err = nullptr);
};

// One reconstructed execution group: everything that happened at one EXEC,
// or at a standalone CALL/RET annotation.
struct Group {
    // Physical source-log lines. A group can print an exec line followed by
    // call/ret lines, so retain each identity separately.
    uint64_t source_line = 0;
    uint64_t call_source_line = 0;
    uint64_t ret_source_line = 0;
    bool has_exec = false;
    uint32_t site_id = 0;
    int n_wr = 0;
    int wr_id[8];
    uint64_t wr_val[8];
    int n_mem = 0;
    MemOp mem[2];
    // importer-only: observed value tokens in print order (RDVAL = reads incl.
    // old values of written regs, WVAL = "-> " write tail). Values may exceed
    // 64 bits (SIMD lanes print up to 32 hex digits).
    static constexpr int MAX_OBS = 8;
    struct Obs {
        uint32_t name_id;              // arena string pool ("fp", "w19", "v0")
        unsigned __int128 val;         // zero-extended when <= 64 bits
    };
    int n_obs = 0, n_wobs = 0;
    Obs obs[MAX_OBS], wobs[MAX_OBS];
    // Verbatim group: a non-owning view into GtbFile::events. It is valid for
    // the duration of the callback and the lifetime of the loaded GtbFile.
    bool has_verbatim = false;
    const char* verbatim = nullptr;
    uint32_t verbatim_len = 0;
    uint8_t n_call_args = 0;
    bool is_call = false;
    bool is_jni_call = false; // imported "call jni func:" spelling
    const char* call_name = nullptr;
    uint64_t args[8] = {0};
    bool is_ret = false;
    uint64_t ret_val = 0;
};

// Agent-facing values reconstructed for one execution group. The supplied
// register file is the pre-execution state exposed by TraceScan::for_each.
struct AgentRegVal { int ctx; uint64_t val; };
struct AgentMemVal {
    bool is_w;
    uint64_t addr;
    unsigned __int128 val;
    bool known;
    uint8_t size;
};

const char* agent_reg_name(int ctx_idx);
void reconstruct_agent_memory(const Site& site, const Group& group,
                              const uint64_t* regs, const uint8_t* known,
                              std::vector<AgentMemVal>& mems);
void reconstruct_agent_values(const Site& site, const Group& group,
                              const uint64_t* regs, const uint8_t* known,
                              std::vector<AgentRegVal>& reads,
                              std::vector<AgentRegVal>& writes,
                              std::vector<AgentMemVal>& mems);

// Streams groups from a GtbFile. Register reads are reconstructed from known
// writes and explicit observations; unknown state stays unknown.
class TraceScan {
public:
    // Metadata-only consumers can skip register reconstruction without changing
    // group boundaries, source coordinates, observations, or decode validation.
    explicit TraceScan(const GtbFile& f, bool track_registers = true)
        : f_(f), track_registers_(track_registers) {}
    // cb(group_index 0-based, group); callback false stops successfully.
    // for_each returns false if the scanned EVENTS prefix is malformed.
    bool for_each(const std::function<bool(uint64_t, const Group&)>& cb);
    const uint64_t* regfile() const { return regs_; }
    const uint8_t* reg_known() const { return known_; }

private:
    const GtbFile& f_;
    bool track_registers_ = true;
    uint64_t regs_[32] = {0};
    uint8_t known_[32] = {0};
};

} // namespace gt
