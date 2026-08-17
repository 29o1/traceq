#pragma once
// Site compiler + arena.
//
// At transform time (once per unique instruction, like a Stalker transformer)
// the compiler disassembles each instruction and precomputes everything the
// hot path needs: the text prefix ("[mod] 0xPC!0xOFF mnemonic ops; "), the
// operand plan (which registers to read/format, memory operand shape, branch
// kind). The arena dedupes sites by address and hands out stable ids — unlike
// GumTrace's CallbackContext ring (102400 slots, wraps and overwrites contexts
// still referenced by live callouts on large modules), a re-translated block
// gets the same site id back.
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

struct OpPlan {
    uint8_t kind = OP_NONE;
    int8_t ctx_idx = -1;        // index into runtime uint64_t regfile (0..30), -1 = unsupported (SIMD)
    uint8_t name_id = 0;        // into arena string pool ("x5", "w3", ...)
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
    uint32_t prefix_off = 0, prefix_len = 0;   // "[mod] 0xPC!0xOFF mnem ops; " (legacy-identical)
    uint32_t disasm_off = 0, disasm_len = 0;   // "mnem ops" without prefix
    uint8_t n_ops = 0;
    OpPlan ops[8];
    int32_t func_sym = -1;           // string id of containing function name
};

// Faithful re-implementation of GumTrace's CallbackContext ring
// (CallbackContext.cpp). Kept only to demonstrate the wrap bug in selftest.
struct RingCtxEmu {
    static constexpr int CALLBACK_CTX_SIZE = 102400;
    struct Ctx { uint64_t addr; uint64_t stamp; };
    Ctx list[CALLBACK_CTX_SIZE];
    int curr_index = 0;
    uint64_t stamp = 0;
    Ctx* pull(uint64_t addr) {
        if (curr_index >= CALLBACK_CTX_SIZE) curr_index = 0;
        Ctx* ctx = &list[curr_index++];
        ctx->addr = addr;
        ctx->stamp = ++stamp;
        return ctx;
    }
};

class SiteArena {
public:
    // Disassembles `word` at `addr` (capstone) and interns the site.
    // Returns the stable site id. Second translation of the same address
    // returns the existing id.
    uint32_t intern(uint64_t addr, uint32_t word, const char* module_name,
                    uint64_t module_base, int32_t func_sym);
    uint32_t intern_disasm(uint64_t addr, const cs_insn* insn, const char* module_name,
                           uint64_t module_base, int32_t func_sym);

    const Site& get(uint32_t id) const { return sites_[id]; }
    size_t size() const { return sites_.size(); }
    int32_t intern_string(const std::string& s);
    const std::string& str(uint32_t id) const { return strings_[id]; }
    size_t pool_bytes() const { return prefix_pool_.size(); }

    // hot-path lookup: 0xFFFFFFFF if not interned
    uint32_t by_addr_find(uint64_t addr) const {
        auto it = by_addr_.find(addr);
        return it == by_addr_.end() ? 0xFFFFFFFFu : it->second;
    }
    int32_t symbol_id(const char* name) { return intern_string(name); }

    // ---- serialization (META chunk payload) ----
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
    std::unordered_map<std::string, uint32_t> module_ids_;
};

// Shared capstone handle (CS_MODE_ARM, little endian, detail on).
bool site_compiler_init();
void site_compiler_shutdown();

// Legacy-identical hex formatting (leading zeros trimmed, 0 -> "0").
size_t legacy_hex64(char* p, uint64_t v);
size_t legacy_hex128(char* p, unsigned __int128 v);

} // namespace gt
