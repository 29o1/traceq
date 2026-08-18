#pragma once
// Site compiler + arena.
//
// At transform time (once per unique instruction, like a Stalker transformer)
// the compiler disassembles each instruction and precomputes everything the
// hot path needs: the disasm text ("mnem ops"), the operand plan (which
// registers to read/format, memory operand shape, branch kind). The arena
// dedupes sites by address and hands out stable ids — unlike GumTrace's
// CallbackContext ring (102400 slots, wraps and overwrites contexts still
// referenced by live callouts on large modules), a re-translated block gets
// the same site id back.
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>

#include <capstone/capstone.h>

namespace gt {

enum SiteKind : uint8_t {
    SK_NORMAL = 0,
    SK_CALL_IMM,   // BL  #imm
    SK_CALL_REG,   // BLR Xn
    SK_BR,         // BR Xn (indirect, may be a tailcall)
    SK_B_IMM,      // B #imm
    SK_BCOND,      // B.cond
    SK_RET,
    SK_SVC,
};

enum OpKind : uint8_t {
    OP_NONE = 0,
    OP_REG_R,     // read a register (format value)
    OP_REG_W,     // write a register (record value for next instruction)
    OP_MEM_R,     // read memory (compute address, record)
    OP_MEM_W,
};

enum OpFlags : uint8_t {
    OPF_R_NZCV = 1,  // instruction reads NZCV (b.cond/csel/cset/ccmp/fcsel/...)
    OPF_W_NZCV = 2,  // instruction writes NZCV (adds/subs/cmp/fcmp/ccmp/...)
};

struct OpPlan {
    uint8_t kind = OP_NONE;
    int8_t ctx_idx = -1;        // index into runtime uint64_t regfile (0..30), -1 = unsupported (SIMD)
    uint8_t name_id = 0;        // into arena string pool ("x5", "w3", ...)
    // SIMD/FP register index 0..31 (q/d/s/h/b/vN share one index space by N),
    // set when ctx_idx == -1 and the operand is a SIMD/FP register.
    //
    // Design tradeoff: SIMD/NZCV *values* are deliberately never recorded —
    // ExecEvent has no lanes for them and the recorder stays unchanged. The
    // dependence info here is purely static (capstone detail at compile time),
    // which is all taint needs to propagate through q registers and flags.
    int8_t simd_idx = -1;
    uint8_t op_flags = 0;       // OPF_* — NZCV dependence of the whole
                                // instruction, repeated on every op
    // memory shape
    int8_t base_ctx_idx = -1;
    int8_t index_ctx_idx = -1;
    uint8_t shift_type = 0;     // ARM64_SFT_*
    uint8_t shift_amt = 0;
    int32_t disp = 0;
    uint8_t size = 0;           // access size in bytes (best effort)
};

struct Site {
    uint64_t addr = 0;
    uint8_t kind = SK_NORMAL;
    uint64_t branch_imm = 0;         // absolute target for CALL_IMM / B_IMM
    uint32_t module_id = 0;          // into arena modules() (name + base at record time)
    uint32_t prefix_off = 0, prefix_len = 0;   // "[mod] 0xPC!0xOFF mnem ops; " (intern_text only:
                                               // the verbatim source-log slice; 0 for capstone sites)
    uint32_t disasm_off = 0, disasm_len = 0;   // "mnem ops" without prefix
    uint8_t n_ops = 0;
    OpPlan ops[8];
    int32_t func_sym = -1;           // string id of containing function name
};

struct TextOp; // defined below (text-built sites, gt import)

class SiteArena {
public:
    // Disassembles `word` at `addr` (capstone) and interns the site.
    // Returns the stable site id. Second translation of the same address
    // returns the existing id.
    uint32_t intern(uint64_t addr, uint32_t word, const char* module_name,
                    uint64_t module_base, int32_t func_sym);
    uint32_t intern_disasm(uint64_t addr, const cs_insn* insn, const char* module_name,
                           uint64_t module_base, int32_t func_sym);
    // Intern a site from an upstream log line. prefix is the verbatim
    // "[mod] 0xABS!0xOFF mnem ops; " text; the disasm slice is recovered from
    // it. Site kind and NZCV flags come from a mnemonic table. Returns the
    // site id, 0xFFFFFFFF if the line cannot be represented (>8 ops, unknown
    // operand name, malformed prefix).
    uint32_t intern_text(uint64_t addr, const char* prefix, size_t prefix_len,
                         const char* module_name, uint64_t module_base,
                         const TextOp* tops, int n_tops);

    const Site& get(uint32_t id) const { return sites_[id]; }
    size_t size() const { return sites_.size(); }
    int32_t intern_string(const std::string& s);
    const std::string& str(uint32_t id) const { return strings_[id]; }
    size_t pool_bytes() const { return prefix_pool_.size(); }
    // base the module was loaded at when the arena was compiled (0 = unknown,
    // e.g. arenas read from v1 META payloads)
    uint64_t module_base(uint32_t id) const {
        return id < module_bases_.size() ? module_bases_[id] : 0;
    }

    // hot-path lookup: 0xFFFFFFFF if not interned
    uint32_t by_addr_find(uint64_t addr) const {
        auto it = by_addr_.find(addr);
        return it == by_addr_.end() ? 0xFFFFFFFFu : it->second;
    }
    int32_t symbol_id(const char* name) { return intern_string(name); }

    // ---- serialization (META chunk payload) ----
    // v2 payload layout (v1 = same but with no magic, no module bases, no
    // module_id, no simd_idx/op_flags; detected by the absence of the magic):
    //   u32 META_V2_MAGIC ("GTM2")
    //   strings, modules (string id + u64 base each), prefix pool — as v1
    //   sites: v1 fields + uvar module_id; ops: v1 fields + simd_idx + op_flags
    void serialize(std::vector<uint8_t>& out) const;
    static bool deserialize(const uint8_t* p, size_t len, SiteArena& out,
                            std::vector<std::string>& modules_out);

    const std::vector<Site>& sites() const { return sites_; }
    const std::vector<std::string>& strings() const { return strings_; }
    const std::vector<std::string>& modules() const { return modules_; }
    const char* pool_ptr() const { return prefix_pool_.data(); }

private:
    std::vector<Site> sites_;
    std::unordered_map<uint64_t, uint32_t> by_addr_;
    std::vector<std::string> strings_;
    std::unordered_map<std::string, uint32_t> str_ids_;
    std::string prefix_pool_;
    std::vector<std::string> modules_;
    std::vector<uint32_t> module_str_ids_;
    std::vector<uint64_t> module_bases_;
    std::unordered_map<std::string, uint32_t> module_ids_;
};

// Shared capstone handle (CS_MODE_ARM, little endian, detail on).
bool site_compiler_init();
void site_compiler_shutdown();

// ---- text-built sites (gt import; no instruction word available) ----
// One plan operand per printed value token, in print order. name points into
// the caller's buffer (usually the mmapped log) and is copied by intern_text.
struct TextOp {
    const char* name;
    size_t name_len;
    uint8_t kind;   // OP_REG_R / OP_REG_W / OP_MEM_R / OP_MEM_W
    uint8_t size;   // access size hint for mem ops (0 = default)
};

// classify a printed operand name ("x5", "w19", "fp", "lr", "sp", "v0", ...).
// Returns the ctx_idx (0..31, fp=29 lr=30 sp=31) and the SIMD index via out.
// Both -1 = unclassifiable.
int text_name_ctx(const char* s, size_t n, int* simd_idx);


// Legacy-identical hex formatting (leading zeros trimmed, 0 -> "0").
size_t legacy_hex64(char* p, uint64_t v);
size_t legacy_hex128(char* p, unsigned __int128 v);

} // namespace gt
