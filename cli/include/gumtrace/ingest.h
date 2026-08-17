#pragma once
// .gtb parsing, legacy-identical text expansion, SQLite ingest.
#include "event.h"
#include "recorder.h"
#include "site.h"
#include <cstdint>
#include <functional>
#ifndef GT_NO_SQLITE
#include <sqlite3.h>
#endif
#include <string>
#include <vector>

namespace gt {

struct GtbFile {
    SiteArena arena;
    std::vector<std::string> modules;
    std::string path;
    // concatenated EVENTS payload (bounded by guards; loaded once)
    std::vector<uint8_t> events;
    uint8_t stop_reason = 0;
    uint64_t events_seen = 0, events_recorded = 0, bytes_written = 0;
    uint64_t initial_sp = 0;   // from footer (0 = not recorded / unknown)
    uint64_t n_exec = 0, n_regw = 0, n_mem = 0, n_call = 0, n_svc = 0, n_ret = 0;

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
    bool is_call = false;
    const char* call_name = nullptr;
    uint64_t call_target = 0;
    uint64_t args[4] = {0};
    bool is_svc = false;
    uint64_t svc_num = 0;
    uint64_t svc_args[3] = {0};
    bool is_ret = false;
    uint64_t ret_val = 0;
};

// Streams groups from a GtbFile, reconstructing register values (reads are
// rebuilt from write history; sp initialized to the corpus stack top).
class Expander {
public:
    explicit Expander(const GtbFile& f) : f_(f) {}
    // cb(group_index 0-based, group); returns false to stop
    bool for_each(const std::function<bool(uint64_t, const Group&)>& cb);
    // legacy-identical text expansion into out
    uint64_t expand_text(FILE* out, uint64_t from_idx = 0, uint64_t to_idx = UINT64_MAX,
                         bool print_idx = false, uint64_t max_lines = 0);

    const uint64_t* regfile() const { return regs_; }

private:
    const GtbFile& f_;
    uint64_t regs_[32] = {0};
};

// SQLite ingest. Returns rows inserted per table via out-params.
struct IngestResult {
    uint64_t n_exec = 0, n_regw = 0, n_mem = 0, n_call = 0, n_svc = 0, n_ret = 0;
};
#ifndef GT_NO_SQLITE
IngestResult ingest_sqlite(const GtbFile& f, const std::string& db_path);
#endif

#ifndef GT_NO_SQLITE
sqlite3* db_open(const std::string& path, bool read_only);
#endif

} // namespace gt
