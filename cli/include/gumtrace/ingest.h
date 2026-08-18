#pragma once
// .gtb parsing and the Expander (upstream/compact/jsonl expansion).
#include "event.h"
#include "recorder.h"
#include "site.h"
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace gt {

struct GtbFile {
    SiteArena arena;
    std::vector<std::string> modules;
    std::string path;
    // concatenated EVENTS payload (bounded by guards; loaded once)
    std::vector<uint8_t> events;
    // verbatim line payload (EV_VERBATIM bodies), referenced by Group.
    // mutable: the Expander appends bodies on the fly (a lazy cache of the
    // events payload — append-only, idempotent per file) while the logical
    // content of the file stays const.
    mutable std::string verbatim;
    uint8_t stop_reason = 0;
    uint8_t dialect = 0;       // footer dialect byte: bit0=upstream, bit1=CRLF
    uint64_t events_seen = 0, events_recorded = 0, bytes_written = 0;
    uint64_t initial_sp = 0;   // from footer (0 = not recorded / unknown)
    uint64_t n_exec = 0, n_regw = 0, n_mem = 0, n_call = 0, n_svc = 0, n_ret = 0;
    uint64_t n_rdval = 0, n_simdv = 0, n_verbatim = 0, n_call2 = 0;

    bool load(const std::string& path);
};

// One reconstructed execution group: everything that happened at one EXEC
// (or at a CALL/SVC/RET when detail strips EXECs).
struct Group {
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
    // verbatim group: the raw line replays byte-for-byte
    bool has_verbatim = false;
    uint32_t verbatim_off = 0, verbatim_len = 0;
    // CALL2 (upstream dialect): observed argument count
    int n_call_args = -1;     // -1 = legacy CALL (always 4)
    bool is_call = false;
    const char* call_name = nullptr;
    uint64_t call_target = 0;
    uint64_t args[8] = {0};
    bool is_svc = false;
    uint64_t svc_num = 0;
    uint64_t svc_args[3] = {0};
    bool is_ret = false;
    uint64_t ret_val = 0;
};

// Streams groups from a GtbFile, reconstructing register values (reads are
// rebuilt from write history; sp initialized from the footer, 0 = unknown).
// One GtbFile is served by at most one Expander at a time.
class Expander {
public:
    explicit Expander(const GtbFile& f) : f_(f) {}
    // cb(group_index 0-based, group); returns false to stop
    bool for_each(const std::function<bool(uint64_t, const Group&)>& cb);
    // upstream dialect (footer dialect bit0): observed read values incl. old
    // values of written registers, mem_r/mem_w address-only, "-> " write
    // tails, call with bare hex args, ret with a bare hex value, verbatim
    // lines replayed raw, and the no-newline-after-pure-store quirk.
    uint64_t expand_upstream(FILE* out, uint64_t from_idx = 0,
                             uint64_t to_idx = UINT64_MAX, uint64_t max_lines = 0,
                             uint64_t* stop_gi = nullptr);
    // agent-facing expansions over the same groups: compact text (module
    // header lines + !0xoffset addressing, no column padding) and JSON Lines
    // (one object per event, u64 values as hex strings). Same window/limit/
    // stop semantics as expand_upstream; max_lines counts emitted lines.
    uint64_t expand_compact(FILE* out, uint64_t from_idx = 0,
                            uint64_t to_idx = UINT64_MAX, uint64_t max_lines = 0,
                            uint64_t* stop_gi = nullptr);
    uint64_t expand_jsonl(FILE* out, uint64_t from_idx = 0,
                          uint64_t to_idx = UINT64_MAX, uint64_t max_lines = 0,
                          uint64_t* stop_gi = nullptr);

    const uint64_t* regfile() const { return regs_; }

private:
    const GtbFile& f_;
    uint64_t regs_[32] = {0};
};

} // namespace gt
