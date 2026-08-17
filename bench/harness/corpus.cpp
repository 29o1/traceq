#include "corpus.h"
#include "arm64enc.h"
#include <gumtrace/common.h>
#include <algorithm>
#include <unordered_map>
#include <cassert>
#include <cstring>

namespace gt {

// ---------------------------------------------------------------------------
// Code builder: lays out instructions, patches branch offsets at the end.
// ---------------------------------------------------------------------------
struct Builder {
    std::vector<InsnDesc> insns;
    std::vector<std::pair<size_t, std::string>> patches; // insn idx -> label
    std::unordered_map<std::string, uint64_t> labels;
    uint64_t base;

    explicit Builder(uint64_t base_) : base(base_) {}

    size_t emit(const InsnDesc& d) {
        insns.push_back(d);
        insns.back().addr = base + (insns.size() - 1) * 4;
        return insns.size() - 1;
    }
    void label(const std::string& name) { labels[name] = base + insns.size() * 4; }
    uint64_t here() const { return base + insns.size() * 4; }

    void patch_branches() {
        for (auto& [idx, lname] : patches) {
            auto it = labels.find(lname);
            assert(it != labels.end());
            int64_t off = int64_t(it->second) - int64_t(insns[idx].addr);
            insns[idx].imm = uint64_t(off);
            switch (insns[idx].sem) {
                case S_B:     insns[idx].word = enc::b(off); break;
                case S_BCOND: insns[idx].word = enc::bcond(insns[idx].cond, off); break;
                case S_BL:    insns[idx].word = enc::bl(off); break;
                default: break;
            }
        }
    }

    // full 64-bit materialization (always exactly 4 insns; used for values that
    // get rewritten after layout so the chain length is fixed)
    void mov_const4(int rd, uint64_t v) {
        for (int hw = 0; hw < 4; hw++) {
            uint16_t part = uint16_t((v >> (hw * 16)) & 0xFFFF);
            uint32_t w = (hw == 0) ? enc::movz(rd, part, 0) : enc::movk(rd, part, hw);
            InsnDesc d = mk_raw(w, hw == 0 ? S_MOVZ : S_MOVK);
            d.rd = rd; d.imm = part;
            emit(d);
        }
    }
    // compact materialization for known constants
    void mov_const(int rd, uint64_t v) {
        bool first = true;
        for (int hw = 0; hw < 4; hw++) {
            uint16_t part = uint16_t((v >> (hw * 16)) & 0xFFFF);
            if (!part && !first) continue;
            uint32_t w = first ? enc::movz(rd, part, hw) : enc::movk(rd, part, hw);
            InsnDesc d = mk_raw(w, first ? S_MOVZ : S_MOVK);
            d.rd = rd; d.imm = part;
            emit(d);
            first = false;
        }
        if (first) {
            InsnDesc d = mk_raw(enc::movz(rd, 0, 0), S_MOVZ);
            d.rd = rd; d.imm = 0;
            emit(d);
        }
    }

    static InsnDesc mk_raw(uint32_t word, SemKind sem) {
        InsnDesc d;
        d.word = word; d.sem = sem;
        return d;
    }
};

static InsnDesc mk(uint32_t word, SemKind sem, int rd = 0, int rn = 0, int rm = 0,
                   uint64_t imm = 0) {
    InsnDesc d;
    d.word = word; d.sem = sem; d.rd = rd; d.rn = rn; d.rm = rm; d.imm = imm;
    return d;
}

// Fill reads/writes/mem flags per semantics. This is the *independent*
// statement of effects; selftest compares it against Capstone's analysis.
static void annotate_effects(InsnDesc& d) {
    auto rd = [&](int n, int r) { if (n < 4) d.reads[n] = r; };
    auto wr = [&](int n, int r) { if (n < 4) d.writes[n] = r; };
    switch (d.sem) {
        case S_NOP: break;
        case S_MOVZ: wr(0, d.rd); break;
        case S_MOVK: rd(0, d.rd); wr(0, d.rd); break; // movk reads and writes
        case S_MOV_REG: rd(0, d.rm); wr(0, d.rd); break;
        case S_ADDI: case S_SUBI:
            rd(0, d.rn);
            wr(0, d.rd);
            break;
        case S_ADD: case S_EOR: case S_AND:
            rd(0, d.rn); rd(1, d.rm); wr(0, d.rd); break;
        case S_CMP: rd(0, d.rn); break; // + nzcv write (not a GPR)
        case S_CMPREG: rd(0, d.rn); rd(1, d.rm); break;
        case S_LDRX: case S_LDRW: case S_LDRB:
            rd(0, d.rn); wr(0, d.rd);
            d.mem_read = true;
            d.mem_size = d.sem == S_LDRX ? 8 : (d.sem == S_LDRW ? 4 : 1);
            break;
        case S_STRX: case S_STRW: case S_STRB:
            rd(0, d.rn); rd(1, d.rd);
            d.mem_write = true;
            d.mem_size = d.sem == S_STRX ? 8 : (d.sem == S_STRW ? 4 : 1);
            break;
        case S_B: case S_BCOND: case S_SVC: break;
        case S_BL: wr(0, 30); break;
        case S_BR: rd(0, d.rn); break;
        case S_BLR: rd(0, d.rn); wr(0, 30); break;
        case S_RET: rd(0, 30); break;
        case S_STP: // stp x29,x30,[sp,#-16]!
            rd(0, 29); rd(1, 30); rd(2, 31);
            wr(0, 29); wr(1, 30); wr(2, 31);
            d.mem_write = true; d.mem_size = 16;
            break;
        case S_LDP: // ldp x29,x30,[sp],#16
            rd(0, 31);
            wr(0, 29); wr(1, 30); wr(2, 31);
            d.mem_read = true; d.mem_size = 16;
            break;
    }
}

// ---------------------------------------------------------------------------
// Program construction
// ---------------------------------------------------------------------------
static constexpr uint64_t MEM_BASE = 0x100000000000ULL;
static constexpr uint64_t SRC_OFF = 0x10000;
static constexpr uint64_t KEY_OFF = 0x20000;
static constexpr uint64_t OUT_OFF = 0x30000;
static constexpr uint64_t STACK_TOP = 0x7000100000ULL;
static constexpr size_t KEY_TOTAL = 1u << 20; // covers all configs

uint64_t corpus_mem_base() { return MEM_BASE; }
uint64_t corpus_stack_top() { return STACK_TOP; }
uint64_t corpus_src_addr() { return MEM_BASE + SRC_OFF; }
uint64_t corpus_key_addr() { return MEM_BASE + KEY_OFF; }
uint64_t corpus_out_addr() { return MEM_BASE + OUT_OFF; }

struct Program build_program(const CorpusConfig& cfg) {
    Program p;
    p.base = 0x7000000000ULL;
    Builder B(p.base);

    // ---- helper (leaf): xor fixed constant into x0, svc ----
    B.label("helper");
    B.mov_const(9, 0x5A000);
    B.emit(mk(enc::eor_reg(0, 0, 9), S_EOR, 0, 0, 9));
    B.emit(mk(enc::svc(222), S_SVC, 0, 0, 0, 222));
    B.emit(mk(enc::ret(), S_RET));

    // ---- trampoline: br x25 ----
    B.label("trampoline");
    B.emit(mk(enc::br(25), S_BR, 0, 25));

    // ---- workers ----
    std::vector<std::string> worker_labels;
    std::vector<std::string> worker_names;
    for (int f = 0; f < cfg.n_funcs; f++) {
        std::string nm = "transform_block_" + std::to_string(f);
        std::string lb = "func_" + std::to_string(f);
        worker_labels.push_back(lb);
        worker_names.push_back(nm);
        B.label(lb);
        B.emit(mk(enc::stp_x29_push(), S_STP));
        B.emit(mk(enc::add_imm(29, 31, 0), S_ADDI, 29, 31, 0, 0)); // mov x29, sp
        B.emit(mk(enc::mov_reg(4, 0), S_MOV_REG, 4, 0, 0));
        B.emit(mk(enc::mov_reg(5, 1), S_MOV_REG, 5, 0, 1));
        B.emit(mk(enc::mov_reg(6, 2), S_MOV_REG, 6, 0, 2));
        B.emit(mk(enc::mov_reg(10, 3), S_MOV_REG, 10, 0, 3));
        B.label(lb + "_loop");
        B.emit(mk(enc::ldrb(7, 4, 0), S_LDRB, 7, 4, 0, 0));
        B.emit(mk(enc::ldrb(8, 5, 0), S_LDRB, 8, 5, 0, 0));
        B.emit(mk(enc::eor_w(7, 7, 8), S_EOR, 7, 7, 8));
        B.emit(mk(enc::strb(7, 10, 0), S_STRB, 7, 10, 0, 0));
        B.emit(mk(enc::add_imm(4, 4, 1), S_ADDI, 4, 4, 0, 1));
        B.emit(mk(enc::add_imm(5, 5, 1), S_ADDI, 5, 5, 0, 1));
        B.emit(mk(enc::add_imm(10, 10, 1), S_ADDI, 10, 10, 0, 1));
        B.emit(mk(enc::sub_imm(6, 6, 1), S_SUBI, 6, 6, 0, 1));
        {
            InsnDesc d = mk(0, S_BCOND, 0, 0, 0, 0); d.cond = 1;
            size_t i = B.emit(d);
            B.patches.push_back({i, lb + "_loop"});
        }
        B.emit(mk(enc::str_x(7, 10, 0), S_STRX, 7, 10, 0, 0));
        B.emit(mk(enc::ldr_x(11, 10, 0), S_LDRX, 11, 10, 0, 0));
        B.emit(mk(enc::eor_reg(11, 11, 7), S_EOR, 11, 11, 7));
        B.mov_const4(9, 0);               // helper addr placeholder (rewritten)
        B.emit(mk(enc::blr(9), S_BLR, 0, 9));
        {
            InsnDesc d = mk(0, S_BL, 0, 0, 0, 0);
            size_t i = B.emit(d);
            B.patches.push_back({i, "helper"});
        }
        B.emit(mk(enc::ldp_x29_pop(), S_LDP));
        B.emit(mk(enc::ret(), S_RET));
    }

    // ---- driver ----
    B.label("driver");
    p.entry = B.here();
    B.emit(mk(enc::stp_x29_push(), S_STP));
    B.emit(mk(enc::add_imm(29, 31, 0), S_ADDI, 29, 31, 0, 0));
    B.mov_const(20, corpus_src_addr());
    B.mov_const(21, corpus_key_addr());
    B.mov_const(22, corpus_out_addr());
    B.mov_const(23, uint16_t(cfg.variant_const));
    B.mov_const(24, uint64_t(cfg.outer_iters));
    B.mov_const(19, 0x2A00);              // reference constant (callee-saved)
    B.label("outer");
    B.emit(mk(enc::mov_reg(0, 20), S_MOV_REG, 0, 0, 20));
    B.emit(mk(enc::mov_reg(1, 21), S_MOV_REG, 1, 0, 21));
    B.emit(mk(enc::movz(2, uint16_t(cfg.key_stream_len)), S_MOVZ, 2, 0, 0, uint64_t(cfg.key_stream_len)));
    B.emit(mk(enc::mov_reg(3, 22), S_MOV_REG, 3, 0, 22));
    {
        InsnDesc d = mk(0, S_BL, 0, 0, 0, 0);
        size_t i = B.emit(d);
        B.patches.push_back({i, worker_labels[0]});
    }
    B.mov_const4(25, 0);                 // worker1 addr placeholder (rewritten)
    {
        InsnDesc d = mk(0, S_BL, 0, 0, 0, 0);
        size_t i = B.emit(d);
        B.patches.push_back({i, "trampoline"});
    }
    B.emit(mk(enc::cmp_reg(23, 19), S_CMPREG, 0, 23, 19));
    {
        InsnDesc d = mk(0, S_BCOND, 0, 0, 0, 0); d.cond = 0; // b.eq
        size_t i = B.emit(d);
        B.patches.push_back({i, "outer_tail"});
    }
    for (int k = 0; k < 6; k++) {        // slow path (taken only when variant differs)
        B.emit(mk(enc::eor_reg(11, 11, 23), S_EOR, 11, 11, 23));
        B.emit(mk(enc::add_imm(11, 11, 3), S_ADDI, 11, 11, 0, 3));
    }
    B.label("outer_tail");
    B.emit(mk(enc::sub_imm(24, 24, 1), S_SUBI, 24, 24, 0, 1));
    {
        InsnDesc d = mk(0, S_BCOND, 0, 0, 0, 0); d.cond = 1;
        size_t i = B.emit(d);
        B.patches.push_back({i, "outer"});
    }
    B.emit(mk(enc::ldp_x29_pop(), S_LDP));
    B.emit(mk(enc::ret(), S_RET));

    B.patch_branches();

    // Post-layout: rewrite the two 4-insn address placeholders.
    //  1) mov_const4(x9) directly before `blr x9`      -> helper
    //  2) mov_const4(x25) directly before `bl trampoline` -> worker 1
    auto rewrite_chain = [&](size_t begin, int reg, uint64_t value) {
        for (int hw = 0; hw < 4; hw++) {
            InsnDesc& d = B.insns[begin + hw];
            uint16_t part = uint16_t((value >> (hw * 16)) & 0xFFFF);
            d.word = (hw == 0) ? enc::movz(reg, part, 0) : enc::movk(reg, part, hw);
            d.sem = (hw == 0) ? S_MOVZ : S_MOVK;
            d.rd = reg; d.imm = part;
        }
    };
    uint64_t helper_addr = B.labels["helper"];
    uint64_t worker1_addr = B.labels[worker_labels[1 % size_t(worker_labels.size())]];
    uint64_t tramp_addr = B.labels["trampoline"];
    for (size_t i = 0; i < B.insns.size(); i++) {
        if (B.insns[i].sem == S_BLR && B.insns[i].rn == 9)
            rewrite_chain(i - 4, 9, helper_addr);
        if (B.insns[i].sem == S_BL && B.insns[i].imm == uint64_t(int64_t(tramp_addr) - int64_t(B.insns[i].addr)))
            rewrite_chain(i - 4, 25, worker1_addr);
    }

    // symbols
    p.funcs.push_back({B.labels["helper"], "xor_helper"});
    p.funcs.push_back({tramp_addr, "call_via_x9"});
    p.funcs.push_back({p.entry, "driver_main"});
    for (size_t f = 0; f < worker_labels.size(); f++)
        p.funcs.push_back({B.labels[worker_labels[f]], worker_names[f]});

    p.insns = std::move(B.insns);
    for (auto& d : p.insns) annotate_effects(d);
    std::sort(p.insns.begin(), p.insns.end(),
              [](const InsnDesc& a, const InsnDesc& b) { return a.addr < b.addr; });
    (void)KEY_TOTAL;
    return p;
}

const InsnDesc* Program::at(uint64_t addr) const {
    size_t lo = 0, hi = insns.size();
    while (lo < hi) {
        size_t mid = (lo + hi) / 2;
        if (insns[mid].addr < addr) lo = mid + 1;
        else hi = mid;
    }
    if (lo < insns.size() && insns[lo].addr == addr) return &insns[lo];
    return nullptr;
}

// ---------------------------------------------------------------------------
// Execution simulation
// ---------------------------------------------------------------------------
namespace {
struct Mem {
    // two regions: the data buffers and the thread stack
    std::vector<uint8_t> bytes;      // data buffers @ MEM_BASE
    std::vector<uint8_t> stack_mem;  // stack below STACK_TOP
    uint64_t base;
    uint64_t stack_top;
    static constexpr uint64_t STACK_SPAN = 1u << 20;
    explicit Mem(uint64_t b, uint64_t st) : base(b), stack_top(st) {
        bytes.assign(1 << 20, 0);
        stack_mem.assign(STACK_SPAN, 0);
    }
    ssize_t off(uint64_t addr, uint8_t size) const {
        if (addr >= base && addr + size <= base + bytes.size())
            return ssize_t(addr - base);
        if (addr >= stack_top - STACK_SPAN && addr + size <= stack_top)
            return ssize_t(STACK_SPAN - (stack_top - addr)) + ssize_t(bytes.size());
        return -1;
    }
    uint64_t read(uint64_t addr, uint8_t size) const {
        ssize_t o = off(addr, size);
        if (o < 0) return 0; // out-of-arena reads (defensive)
        const uint8_t* p = o < ssize_t(bytes.size()) ? &bytes[size_t(o)]
                                                     : &stack_mem[size_t(o - bytes.size())];
        uint64_t v = 0;
        for (uint8_t i = 0; i < size; i++) v |= uint64_t(p[i]) << (i * 8);
        return v;
    }
    void write(uint64_t addr, uint8_t size, uint64_t v) {
        ssize_t o = off(addr, size);
        if (o < 0) return;
        uint8_t* p = o < ssize_t(bytes.size()) ? &bytes[size_t(o)]
                                               : &stack_mem[size_t(o - bytes.size())];
        for (uint8_t i = 0; i < size; i++) p[i] = uint8_t(v >> (i * 8));
    }
};
} // namespace

uint64_t run_program(const Program& p, const CorpusConfig& cfg, uint64_t max_events,
                     EventSink sink, void* user, uint64_t* out_ticks) {
    (void)cfg;
    uint64_t x[31] = {0};
    uint64_t sp = STACK_TOP;
    bool zf = false;
    Mem mem(MEM_BASE, STACK_TOP);
    {
        Rng r(cfg.seed * 7919 + 13);
        for (size_t i = 0; i < mem.bytes.size(); i++)
            mem.bytes[i] = uint8_t(r.next());
    }
    std::vector<uint64_t> call_stack;
    std::unordered_map<uint64_t, const char*> sym_by_addr;
    for (const auto& f : p.funcs) sym_by_addr[f.addr] = f.name.c_str();
    auto find_sym = [&](uint64_t a) -> const char* {
        auto it = sym_by_addr.find(a);
        return it != sym_by_addr.end() ? it->second : nullptr;
    };

    uint64_t tick = 0, executed = 0;
    uint64_t pc = p.entry;
    bool ret_had_caller = false;
    while (true) {
        const InsnDesc* d = p.at(pc);
        if (!d) break;
        if (max_events && executed >= max_events) break;

        ExecEvent ev;
        ev.pc = d->addr;
        memcpy(ev.x, x, sizeof(x));
        ev.sp = sp;
        int nr = 0;
        for (int r : d->reads)
            if (r != 255 && nr < 8) ev.rd_id[nr++] = r;
        ev.n_rd = nr;

        auto log_mem = [&](bool is_w, uint64_t addr, uint8_t size, uint64_t value) {
            if (ev.n_mem < 2) ev.mem[ev.n_mem++] = {is_w, addr, size, value};
        };

        uint64_t next = pc + 4;
        switch (d->sem) {
            case S_NOP: break;
            case S_MOVZ: { int hw = int((d->word >> 21) & 3);
                x[d->rd] = d->imm << (hw * 16); break; }
            case S_MOVK: { int hw = int((d->word >> 21) & 3);
                uint64_t m = 0xFFFFULL << (hw * 16);
                x[d->rd] = (x[d->rd] & ~m) | (d->imm << (hw * 16)); break; }
            case S_MOV_REG: x[d->rd] = x[d->rm]; break;
            case S_ADDI: x[d->rd] = (d->rn == 31 ? sp : x[d->rn]) + d->imm; break;
            case S_SUBI: {
                uint64_t v = (d->rn == 31 ? sp : x[d->rn]) - d->imm;
                x[d->rd] = v;
                zf = v == 0; // subs sets the flags
                break;
            }
            case S_ADD: x[d->rd] = x[d->rn] + x[d->rm]; break;
            case S_EOR: x[d->rd] = x[d->rn] ^ x[d->rm]; break;
            case S_AND: x[d->rd] = x[d->rn] & x[d->rm]; break;
            case S_CMP: zf = ((d->rn == 31 ? sp : x[d->rn]) - d->imm) == 0; break;
            case S_CMPREG: zf = ((d->rn == 31 ? sp : x[d->rn]) ==
                                 (d->rm == 31 ? sp : x[d->rm])); break;
            case S_LDRX: case S_LDRW: case S_LDRB: {
                uint64_t base = d->rn == 31 ? sp : x[d->rn];
                uint64_t addr = base + d->imm;
                uint64_t v = mem.read(addr, d->mem_size);
                if (d->sem == S_LDRB) v &= 0xFF;
                if (d->sem == S_LDRW) v &= 0xFFFFFFFF;
                log_mem(false, addr, d->mem_size, v);
                x[d->rd] = v;
                break;
            }
            case S_STRX: case S_STRW: case S_STRB: {
                uint64_t base = d->rn == 31 ? sp : x[d->rn];
                uint64_t addr = base + d->imm;
                uint64_t v = d->sem == S_STRB ? (x[d->rd] & 0xFF) :
                             d->sem == S_STRW ? (x[d->rd] & 0xFFFFFFFF) : x[d->rd];
                mem.write(addr, d->mem_size, v);
                log_mem(true, addr, d->mem_size, v);
                break;
            }
            case S_B: next = pc + uint64_t(int64_t(d->imm)); break;
            case S_BCOND:
                if ((d->cond == 0 && zf) || (d->cond == 1 && !zf))
                    next = pc + uint64_t(int64_t(d->imm));
                break;
            case S_BL:
                x[30] = pc + 4;
                next = pc + uint64_t(int64_t(d->imm));
                ev.is_call = true; ev.call_target = next; ev.call_name = find_sym(next);
                call_stack.push_back(pc + 4);
                break;
            case S_BR: {
                next = x[d->rn];
                // engines resolve BR targets against known symbols (tailcall);
                // report as a call when it lands on one
                if (find_sym(next)) {
                    ev.is_call = true;
                    ev.call_target = next;
                    ev.call_name = find_sym(next);
                }
                break;
            }
            case S_BLR:
                x[30] = pc + 4;
                next = x[d->rn];
                ev.is_call = true; ev.call_target = next; ev.call_name = find_sym(next);
                call_stack.push_back(pc + 4);
                break;
            case S_RET: {
                bool had_caller = !call_stack.empty();
                if (had_caller) { next = call_stack.back(); call_stack.pop_back(); }
                else next = 0;
                ev.is_ret = true; ev.ret_val = x[0];
                ret_had_caller = had_caller;
                break;
            }
            case S_SVC: ev.is_svc = true; ev.svc_num = d->imm; break;
            case S_STP: {
                sp -= 16;
                mem.write(sp, 8, x[29]);       // low: x29
                mem.write(sp + 8, 8, x[30]);   // high: x30
                log_mem(true, sp, 16, uint64_t(x[29]));
                break;
            }
            case S_LDP: {
                uint64_t lo = mem.read(sp, 8);
                uint64_t hi = mem.read(sp + 8, 8);
                log_mem(false, sp, 16, lo);
                x[29] = lo;
                x[30] = hi;
                sp += 16;
                break;
            }
        }

        int nw = 0;
        for (int r : d->writes) {
            if (r == 255 || nw >= 8) continue;
            ev.wr_id[nw] = r;
            ev.wr_val[nw] = (r == 31) ? sp : x[r];
            nw++;
        }
        ev.n_wr = nw;
        ev.tick = tick++;
        sink(ev, user);
        executed++;
        if (d->sem == S_RET && !ret_had_caller) break; // driver returned
        pc = next;
    }
    if (out_ticks) *out_ticks = tick;
    return executed;
}

} // namespace gt
