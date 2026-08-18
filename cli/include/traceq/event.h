#pragma once
// The recorder input contract.
//
// This is the ONE type that crosses the boundary between an event source and
// the recorders. A source is anything that can observe instruction execution —
// the real target is a Frida Stalker callout.
//
// Deliberately free of any source-specific types: the recorder needs the PC to
// resolve a site id, the register state a callout would see, and the observed
// effects. It does NOT need to know how the instruction was described or who
// produced it — the library is independent of any particular source.

#include <cstdint>

namespace gt {

struct MemOp {
    bool is_write;
    uint64_t addr;
    uint8_t size;
    uint64_t value;           // memory content after (write) / before (read)
    bool value_known = true;  // store values can be reconstructed from REGW
};

struct ExecEvent {
    uint64_t pc;                      // address of the executed instruction
    // register state as a Stalker callout would see it (pre-execution)
    uint64_t x[31];
    uint64_t sp;                      // pre-execution sp (base of mem ops)
    int n_rd = 0;                     // number of register reads
    int rd_id[8];
    // writes with post-execution values (a callout observes them at the next
    // instruction; the value is the same post value)
    int n_wr = 0;
    int wr_id[8];
    uint64_t wr_val[8];
    int n_mem = 0;
    MemOp mem[2];
    bool is_call = false;             // BL/BLR executed
    uint64_t call_target = 0;
    const char* call_name = nullptr;  // resolved symbol if known
    bool is_svc = false;
    uint64_t svc_num = 0;
    bool is_ret = false;              // RET executed (closes the innermost CALL)
    uint64_t ret_val = 0;             // x0 at RET
    uint64_t tick;                    // monotonic tick from the source
};

} // namespace gt
