#pragma once
// Corpus: generates a small synthetic ARM64 program (real encodings) plus a
// faithful abstract simulation of its execution. The simulator emits one
// ExecEvent per executed instruction carrying the same information a Stalker
// callout could observe: register reads (pre), register writes (post),
// memory accesses with actual values, calls/svc. Both the legacy text
// recorder and the new binary recorder consume identical ExecEvent streams,
// which is what makes the A/B comparison apples-to-apples.
#include <gumtrace/event.h>
#include <cstdint>
#include <string>
#include <vector>

namespace gt {

enum SemKind {
    S_NOP, S_MOVZ, S_MOVK, S_MOV_REG, S_ADDI, S_SUBI, S_ADD, S_EOR, S_AND,
    S_CMP, S_CMPREG, S_LDRX, S_STRX, S_LDRW, S_STRW, S_LDRB, S_STRB,
    S_B, S_BCOND, S_BL, S_BR, S_BLR, S_RET, S_SVC,
    S_STP, S_LDP
};

struct InsnDesc {
    uint64_t addr;
    uint32_t word;
    SemKind sem;
    int rd = 0, rn = 0, rm = 0;   // register operands as encoded
    uint64_t imm = 0;             // imm12 / offset bytes / branch offset bytes
    int cond = 0;
    // Independent statement of register/memory effects used to cross-check the
    // Capstone-derived site plans in selftest. 255 = slot unused (x0 is a
    // legitimate register id).
    int reads[4] = {255, 255, 255, 255};
    int writes[4] = {255, 255, 255, 255};
    bool mem_read = false, mem_write = false;
    uint8_t mem_size = 0;
};

struct FuncSym {
    uint64_t addr;
    std::string name;
};

struct Program {
    std::string module_name = "libtarget.so";
    uint64_t base = 0x7000000000ULL;
    std::vector<InsnDesc> insns;      // sorted by addr
    std::vector<FuncSym> funcs;
    uint64_t entry = 0;
    const InsnDesc* at(uint64_t addr) const;
};

struct CorpusConfig {
    uint64_t seed = 42;
    int n_funcs = 10;                 // worker functions called in the driver loop
    int outer_iters = 40;             // driver iterations
    int inner_iters = 60;             // memcpy-style inner loop iterations
    int key_stream_len = 256;         // bytes transformed per outer iteration
    int svc_every = 8192;             // emit an svc every N executed instructions (0=off)
    uint64_t variant_const = 0x2A00;  // constant that differs between variants (for diff tests)
    bool svc_on = true;
};

// Builds the program. Deterministic given cfg.seed.
Program build_program(const CorpusConfig& cfg);

// Executes the program deterministically, delivering events to `sink`.
// Returns number of events emitted. `max_events` = 0 means unlimited.
using EventSink = void (*)(const ExecEvent& ev, void* user);
uint64_t run_program(const Program& p, const CorpusConfig& cfg, uint64_t max_events,
                     EventSink sink, void* user, uint64_t* out_ticks = nullptr);

// memory layout constants used by the simulator (exposed for tests)
uint64_t corpus_mem_base();
uint64_t corpus_stack_top();
uint64_t corpus_src_addr();
uint64_t corpus_key_addr();
uint64_t corpus_out_addr();

} // namespace gt
