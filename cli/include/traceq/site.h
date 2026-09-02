#pragma once
// Site arena for instructions parsed from GumTrace text logs. Each unique
// address owns its module identity, disassembly text, and operand plan.
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>

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

struct OpPlan {
    uint8_t kind = OP_NONE;
    // GPR runtime slot (x0..x30/sp), or -1 for memory and SIMD observations.
    // SIMD identity and data-flow roles live in TaintPlan; observed values keep
    // their original names in Group::Obs.
    int8_t ctx_idx = -1;
};

enum TaintCat : uint8_t {
    TC_OTHER = 0,
    TC_IMM_LOAD,
    TC_PARTIAL,
    TC_LOAD,
    TC_STORE,
    TC_COMPARE,
    TC_BRANCH,
};

// Static data-flow facts compiled once from a site's disassembly. Register
// mask bits 0..31 are x0..x30/sp; bits 32..63 are q0..q31.
struct TaintPlan {
    uint8_t cat = TC_OTHER;
    uint64_t src_mask = 0;
    uint64_t index_mask = 0;
    uint64_t dst_mask = 0;
    uint8_t dsts[2] = {0, 0};
    uint8_t n_dsts = 0;
    uint8_t st[2] = {0, 0};
    uint8_t n_st = 0;
    uint8_t pair = 0;
    uint8_t elem = 8;
    uint8_t nzcv_r = 0;
    uint8_t nzcv_w = 0;
};

struct Site {
    uint64_t addr = 0;
    uint8_t kind = SK_NORMAL;
    uint64_t branch_imm = 0;         // absolute target for CALL_IMM / B_IMM
    int8_t branch_reg = -1;          // runtime GPR slot for CALL_REG / BR
    uint8_t mem_width = 0;           // inferred access width in bytes
    uint8_t pair_stride = 0;         // second ldp/stp lane stride, 0 if scalar
    uint32_t module_id = 0;          // into arena modules() (name + base at record time)
    uint32_t prefix_off = 0, prefix_len = 0;   // "[mod] 0xPC!0xOFF mnem ops; "
                                               // verbatim source-log slice
    uint32_t disasm_off = 0, disasm_len = 0;   // "mnem ops" without prefix
    uint8_t n_ops = 0;
    OpPlan ops[8];
    TaintPlan taint;
};

struct TextOp; // defined below (text-built sites, gt import)

class SiteArena {
public:
    // Intern a site from an upstream log line. prefix is the verbatim
    // "[mod] 0xABS!0xOFF mnem ops; " text; the disasm slice is recovered from
    // it. Site kind and NZCV flags come from a mnemonic table. Returns the
    // site id, 0xFFFFFFFF if the line cannot be represented (>8 ops, unknown
    // operand name, malformed prefix).
    uint32_t intern_text(uint64_t addr, const char* prefix, size_t prefix_len,
                         const char* module_name, uint64_t module_base,
                         const TextOp* tops, int n_tops);

    const Site& get(uint32_t id) const { return sites_[id]; }
    int32_t intern_string(const std::string& s);
    const std::string& str(uint32_t id) const { return strings_[id]; }
    // Base the module was loaded at when the arena was compiled.
    uint64_t module_base(uint32_t id) const {
        return id < module_bases_.size() ? module_bases_[id] : 0;
    }

    // ---- serialization (META chunk payload) ----
    // GTB2 META payload: strings, modules with bases, prefix/disassembly pool,
    // then sites with their compact observation plan and compiled semantics.
    void serialize(std::vector<uint8_t>& out) const;
    static bool deserialize(const uint8_t* p, size_t len, SiteArena& out);

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

// ---- text-built sites (gt import) ----
// One plan operand per printed value token, in print order. name points into
// the caller's buffer (usually the mmapped log) and is copied by intern_text.
struct TextOp {
    const char* name;
    size_t name_len;
    uint8_t kind;   // OP_REG_R / OP_REG_W / OP_MEM_R / OP_MEM_W
};

// classify a printed operand name ("x5", "w19", "fp", "lr", "sp", "v0", ...).
// Returns the ctx_idx (0..31, fp=29 lr=30 sp=31) and the SIMD index via out.
// Both -1 = unclassifiable.
int text_name_ctx(const char* s, size_t n, int* simd_idx);


// Legacy-identical hex formatting (leading zeros trimmed, 0 -> "0").
size_t legacy_hex64(char* p, uint64_t v);
size_t legacy_hex128(char* p, unsigned __int128 v);

} // namespace gt
