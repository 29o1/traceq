#include "WriteStream.h"
#include <traceq/write_stream.h>
#include <fcntl.h>
#include <limits>
#include <unordered_set>
#include <memory>
#include <atomic>

namespace {
using namespace traceq::writes;
struct Session {
    FILE* out = nullptr;
    Header header{};
    uint64_t instructions = 0, writes = 0, gaps = 0;
    uint64_t reads = 0, commits = 0;
    unsigned __int128 state[REGISTER_COUNT]{};
    bool state_known[REGISTER_COUNT]{};
    std::unordered_set<uint64_t> sites;
    bool failed = false, translated_exclusive = false;
    char buffer[64 * 1024];
    TraceqStorageOptions storage{};
    TraceqRecordBuffer* records=nullptr;
    TraceqObservation observation=TraceqObservation::Reference;
    uint64_t gpr_bank[29]{};
    bool registers_complete=false;
    bool outside=false,return_exit=false;
    uint64_t exit_seq=0,exit_pc=0;
    uint64_t generation=0;
    std::atomic<bool> foreign_thread{false};
} session;
thread_local std::unique_ptr<TraceqRecordBuffer> thread_records;
thread_local uint64_t thread_generation=0;
struct Plan {
    uint64_t pc = 0, seq = 0, address = 0;
    cs_arm64_op mem{};
    arm64_reg sources[2]{};
    unsigned width = 0, count = 0;
    unsigned __int128 values[2]{};
    bool unsupported = false, pending = false;
    bool load = false, post = false, memory_valid = false;
    uint32_t word = 0;
    bool check_target=false;
    arm64_reg target_register=ARM64_REG_INVALID;
    uint64_t target_address=0;
    uint64_t transfer=0;
};
Plan* pending = nullptr;
#ifdef TRACEQ_CAPTURE_PERF
TraceqProbe probe_mode = TraceqProbe::Full;
TraceqObservationStats observation_stats;
bool thread_id_probe=false;
#endif

bool owns_session() {return thread_generation!=0 && thread_generation==session.generation;}
bool check_owner(bool legacy_allowed=true) {
    bool valid;
#ifdef TRACEQ_CAPTURE_PERF
    if(legacy_allowed && thread_id_probe)valid=gum_process_get_current_thread_id()==session.header.thread_id;
    else
#endif
    valid=owns_session();
    if(valid)return true;
    session.foreign_thread.store(true,std::memory_order_relaxed);return false;
}

void emit(Event e) {
#ifdef TRACEQ_CAPTURE_PERF
    if (probe_mode != TraceqProbe::Full) return;
#endif
    if(session.records) {
        if(!session.failed && !session.records->append(e))session.failed=true;
        return;
    }
    if (!session.failed && !write_event(session.out, e)) session.failed = true;
}
void gap(uint64_t seq, uint64_t pc, Reason reason) {
    ++session.gaps;
    emit({GAP,seq,pc,0,0,0,0,reason});
    memset(session.state_known,0,sizeof session.state_known);
    session.registers_complete=false;
}
bool contains(uint64_t base, uint64_t length, uint64_t addr, uint64_t size) {
    return addr >= base && size <= length && addr - base <= length - size;
}
bool reg_value(arm64_reg reg, GumCpuContext* c, unsigned __int128& v) {
    if (reg == ARM64_REG_XZR || reg == ARM64_REG_WZR) { v = 0; return true; }
    if (reg == ARM64_REG_SP || reg == ARM64_REG_WSP) {
        v = reg == ARM64_REG_SP ? c->sp : uint32_t(c->sp); return true;
    }
    if (reg == ARM64_REG_FP) { v = c->fp; return true; }
    if (reg == ARM64_REG_LR) { v = c->lr; return true; }
    if (reg >= ARM64_REG_X0 && reg <= ARM64_REG_X28) {
        v = c->x[reg - ARM64_REG_X0]; return true;
    }
    if (reg >= ARM64_REG_W0 && reg <= ARM64_REG_W30) {
        unsigned n = reg - ARM64_REG_W0;
        v = uint32_t(n < 29 ? c->x[n] : n == 29 ? c->fp : c->lr); return true;
    }
    // FP scalar registers hold bit patterns, not integer-converted floats.
    struct Bank { arm64_reg first, last; unsigned bytes; };
    const Bank banks[] = {{ARM64_REG_Q0,ARM64_REG_Q31,16},
        {ARM64_REG_D0,ARM64_REG_D31,8},{ARM64_REG_S0,ARM64_REG_S31,4},
        {ARM64_REG_H0,ARM64_REG_H31,2},{ARM64_REG_B0,ARM64_REG_B31,1},
        {ARM64_REG_V0,ARM64_REG_V31,16}};
    for (const auto& bank : banks) if (reg >= bank.first && reg <= bank.last) {
        v = 0; memcpy(&v, c->v[reg-bank.first].q, bank.bytes); return true;
    }
    return false;
}
unsigned reg_width(arm64_reg r) {
    if ((r >= ARM64_REG_Q0 && r <= ARM64_REG_Q31) ||
        (r >= ARM64_REG_V0 && r <= ARM64_REG_V31)) return 16;
    if ((r >= ARM64_REG_D0 && r <= ARM64_REG_D31) ||
        (r >= ARM64_REG_X0 && r <= ARM64_REG_X28) ||
        r == ARM64_REG_FP || r == ARM64_REG_LR || r == ARM64_REG_XZR) return 8;
    if ((r >= ARM64_REG_S0 && r <= ARM64_REG_S31) ||
        (r >= ARM64_REG_W0 && r <= ARM64_REG_W30) || r == ARM64_REG_WZR) return 4;
    if (r >= ARM64_REG_H0 && r <= ARM64_REG_H31) return 2;
    if (r >= ARM64_REG_B0 && r <= ARM64_REG_B31) return 1;
    return 0;
}
Plan* make_plan(const cs_insn* ins) {
    auto* p = new Plan(); p->pc = ins->address;
    if (!ins->detail) { p->unsupported = true; return p; }
    const auto& a = ins->detail->arm64;
    const std::string m = ins->mnemonic;
    const bool pair = m == "stp" || m == "stnp";
    const bool store = pair || m == "str" || m == "stur" || m == "strb" ||
        m == "strh" || m == "sturb" || m == "sturh";
    if (store) {
        unsigned count = pair ? 2 : 1;
        if (a.op_count < count+1 || a.operands[count].type != ARM64_OP_MEM) {
            p->unsupported = true; return p;
        }
        p->mem = a.operands[count];
        for (unsigned i = 0; i < count; ++i) {
            if (a.operands[i].type != ARM64_OP_REG) { p->unsupported = true; return p; }
            p->sources[i] = a.operands[i].reg;
        }
        p->width = reg_width(p->sources[0]);
        if (m == "strb" || m == "sturb") p->width = 1;
        if (m == "strh" || m == "sturh") p->width = 2;
        if (!p->width || (pair && reg_width(p->sources[1]) != p->width) ||
            (p->mem.shift.type != ARM64_SFT_INVALID && p->mem.shift.type != ARM64_SFT_LSL) ||
            p->mem.shift.value >= 64) { p->unsupported = true; return p; }
        switch (p->mem.ext) {
            case ARM64_EXT_INVALID: case ARM64_EXT_UXTW: case ARM64_EXT_SXTW:
            case ARM64_EXT_UXTX: case ARM64_EXT_SXTX: break;
            default: p->unsupported = true; return p;
        }
        p->count = count; return p;
    }
    // This initial profile only declares known non-writing instruction classes.
    // Unknown opcodes produce an explicit gap instead of an invented write set.
    const char* allowed[] = {"add","adds","sub","subs","eor","and","orr",
        "adr","adrp","ands","bfi","bfxil","mvn","ccmp","csetm","udiv",
        "ext","ushl","uzp1","zip1","mrs","dmb","bti","paciasp","autiasp","xpaclri",
        "mul","madd","msub","mneg","neg","negs","bic","eon","orn","ubfx","sbfx","ubfiz","sbfiz",
        "uxtb","uxth","uxtw","sxtb","sxth","sxtw","extr","cinc","cinv","cneg","csinc","csinv","csneg",
        "mov","movz","movn","movk","cmp","cmn","tst","cset","csel",
        "rev","rev16","rev32","lsl","lsr","asr","ror","movi","dup",
        "umov","fmov","nop","ret","b","cbz","cbnz","tbz","tbnz",
        "ldr","ldrb","ldrh","ldrsb","ldrsh","ldrsw","ldur","ldurb",
        "ldurh","ldursb","ldursh","ldursw","ldp","ldnp","ldar","ldarb","ldarh"};
    p->unsupported = m.rfind("b.", 0) != 0;
    for (const char* name : allowed) if (m == name) p->unsupported = false;
    if (m == "b" || m.rfind("b.",0) == 0 || m == "cbz" || m == "cbnz" || m == "tbz" || m == "tbnz") {
        if (!a.op_count) { p->unsupported = true; return p; }
        const auto& target = a.operands[a.op_count-1];
        if (target.type != ARM64_OP_IMM || !contains(session.header.code_base,
            session.header.code_size,uint64_t(target.imm),4)) p->unsupported = true;
    }
    return p;
}

// Register deltas are observed snapshots, not inferred instruction effects.
void observe_slot(unsigned i,unsigned __int128 value,Plan* p,uint64_t kind) {
    if(!session.state_known[i] || session.state[i]!=value) {
        emit({kind,p->seq,p->pc,i,i<33?8u:16u,uint64_t(value),uint64_t(value>>64),1});
        session.state[i]=value;session.state_known[i]=true;
    }
}
void state_delta_banked(GumCpuContext* c,Plan* p,uint64_t kind) {
    static_assert(sizeof c->x==29*sizeof(uint64_t),"GPR bank layout changed");
    static_assert(sizeof c->v==32*sizeof(unsigned __int128),"SIMD bank layout changed");
    const bool complete=session.registers_complete;
    if(!complete || memcmp(session.gpr_bank,c->x,sizeof c->x)!=0) {
#ifdef TRACEQ_CAPTURE_PERF
        observation_stats.scalar_comparisons+=29;
#endif
        for(unsigned i=0;i<29;++i)observe_slot(i,c->x[i],p,kind);
        memcpy(session.gpr_bank,c->x,sizeof c->x);
    }
#ifdef TRACEQ_CAPTURE_PERF
    observation_stats.scalar_comparisons+=4;
#endif
    observe_slot(29,c->fp,p,kind);observe_slot(30,c->lr,p,kind);
    observe_slot(31,c->sp,p,kind);observe_slot(32,c->nzcv,p,kind);
    if(!complete || memcmp(session.state+33,c->v,sizeof c->v)!=0) {
#ifdef TRACEQ_CAPTURE_PERF
        observation_stats.vector_comparisons+=32;
#endif
        for(unsigned i=0;i<32;++i) {
            unsigned __int128 value;memcpy(&value,c->v[i].q,sizeof value);
            observe_slot(i+33,value,p,kind);
        }
    }
    session.registers_complete=true;
}
void state_delta(GumCpuContext* c, Plan* p, uint64_t kind) {
#ifdef TRACEQ_CAPTURE_PERF
    ++observation_stats.snapshots;
#endif
    if(session.observation!=TraceqObservation::Reference){state_delta_banked(c,p,kind);return;}
#ifdef TRACEQ_CAPTURE_PERF
    observation_stats.scalar_comparisons+=33;observation_stats.vector_comparisons+=32;
#endif
    for (unsigned i=0;i<REGISTER_COUNT;++i) {
        unsigned __int128 value=0;
        if (i<29) value=c->x[i];
        else if (i==29) value=c->fp;
        else if (i==30) value=c->lr;
        else if (i==31) value=c->sp;
        else if (i==32) value=c->nzcv;
        else memcpy(&value,c->v[i-33].q,16);
        if (!session.state_known[i] || session.state[i]!=value) {
            emit({kind,p->seq,p->pc,i,i<33?8u:16u,uint64_t(value),uint64_t(value>>64),1});
            session.state[i]=value;session.state_known[i]=true;
        }
    }
}
void extend_plan(Plan* p,const cs_insn* ins) {
    memcpy(&p->word,ins->bytes,4);
    if (session.sites.insert(p->pc).second) {
        std::string text=std::string(ins->mnemonic)+" "+ins->op_str;
        for (size_t offset=0;offset<text.size();offset+=24) {
            unsigned char bytes[24]{};size_t n=std::min(size_t(24),text.size()-offset);
            memcpy(bytes,text.data()+offset,n);
            emit({SITE,offset,p->pc,p->word,n,get64(bytes),get64(bytes+8),get64(bytes+16)});
        }
    }
    const std::string m=ins->mnemonic;
    const char* loads[]={"ldr","ldrb","ldrh","ldrsb","ldrsh","ldrsw",
        "ldur","ldurb","ldurh","ldursb","ldursh","ldursw","ldp","ldnp","ldpsw","ldar","ldarb","ldarh"};
    for (const char* name:loads) if (m==name) p->load=true;
    if (p->load && ins->detail) {
        const auto& a=ins->detail->arm64;
        unsigned count=(m=="ldp" || m=="ldnp" || m=="ldpsw")?2:1;
        p->unsupported=true;
        if (a.op_count>=count+1 && a.operands[count].type==ARM64_OP_MEM) {
            p->mem=a.operands[count];
            bool valid=true;
            for(unsigned i=0;i<count;++i) {
                valid &= a.operands[i].type==ARM64_OP_REG;
                p->sources[i]=a.operands[i].reg;
                if(a.writeback && p->sources[i]==p->mem.mem.base) valid=false;
            }
            p->width=reg_width(p->sources[0]);
            if(m.back()=='b')p->width=1;
            if(m.back()=='h')p->width=2;
            if(m=="ldrsw" || m=="ldursw" || m=="ldpsw")p->width=4;
            valid &= p->width>0 && p->mem.shift.value<64;
            valid &= p->mem.shift.type==ARM64_SFT_INVALID || p->mem.shift.type==ARM64_SFT_LSL;
            valid &= p->mem.ext==ARM64_EXT_INVALID || p->mem.ext==ARM64_EXT_UXTW ||
                p->mem.ext==ARM64_EXT_SXTW || p->mem.ext==ARM64_EXT_UXTX || p->mem.ext==ARM64_EXT_SXTX;
            if(count==2 && p->sources[0]==p->sources[1])valid=false;
            if(valid){p->count=count;p->unsupported=false;}
        }
    }
    bool control=ins->id==ARM64_INS_B || ins->id==ARM64_INS_BR || ins->id==ARM64_INS_BL ||
        ins->id==ARM64_INS_BLR || ins->id==ARM64_INS_RET || ins->id==ARM64_INS_CBZ ||
        ins->id==ARM64_INS_CBNZ || ins->id==ARM64_INS_TBZ || ins->id==ARM64_INS_TBNZ;
    // In-scope indirect dispatch and calls are observable through their actual
    // successor pre-state. External targets remain explicit memory-history gaps.
    if(ins->detail && (ins->id==ARM64_INS_BR || ins->id==ARM64_INS_BLR || ins->id==ARM64_INS_BL ||
                      ins->id==ARM64_INS_RET || m=="b")) {
        const auto& a=ins->detail->arm64;
        if(a.op_count==1 && a.operands[0].type==ARM64_OP_REG && ins->id!=ARM64_INS_BL) {
            p->check_target=true;p->target_register=a.operands[0].reg;p->unsupported=false;
        } else if(a.op_count==1 && a.operands[0].type==ARM64_OP_IMM && (ins->id==ARM64_INS_BL || m=="b")) {
            p->check_target=true;p->target_address=uint64_t(a.operands[0].imm);p->unsupported=false;
        } else if(ins->id==ARM64_INS_RET && a.op_count==0) {
            p->check_target=true;p->target_register=ARM64_REG_LR;p->unsupported=false;
        }
        p->transfer=ins->id==ARM64_INS_RET?RETURN:
                    (ins->id==ARM64_INS_BL || ins->id==ARM64_INS_BLR)?CALL:BRANCH;
    }
    // Writeback overlapping a transfer register is architecturally constrained
    // unpredictable for these forms. Wn and Xn alias the same physical GPR.
    auto physical=[](arm64_reg r)->int {
        if(r>=ARM64_REG_W0 && r<=ARM64_REG_W30)return r-ARM64_REG_W0;
        if(r>=ARM64_REG_X0 && r<=ARM64_REG_X28)return r-ARM64_REG_X0;
        if(r==ARM64_REG_FP)return 29;if(r==ARM64_REG_LR)return 30;
        if(r==ARM64_REG_SP || r==ARM64_REG_WSP)return 31;return -1;
    };
    if(ins->detail && ins->detail->arm64.writeback && p->count) {
        int base=physical(p->mem.mem.base);
        for(unsigned i=0;i<p->count;++i)if(base>=0 && physical(p->sources[i])==base)p->unsupported=true;
    }
    p->post=!p->unsupported && !control;
}
void before_state(GumCpuContext* c,Plan* p,bool shared_snapshot=false) {
    if(pending){gap(pending->seq,pending->pc,UNCONFIRMED_STORE);pending->pending=false;pending=nullptr;}
    // A terminal RET describes the final observed pre-state. If execution
    // subsequently reenters the range, the unobserved interval becomes a GAP.
    // Pair scope intervals, not presumed function calls: this also handles callbacks.
    bool reenter=session.outside;
    if(reenter && session.return_exit)gap(session.exit_seq,session.exit_pc,OUTSIDE_CODE_RANGE);
    p->seq=session.instructions++;
    emit({EXEC,p->seq,p->pc,p->word,0,0,0,p->post?1u:0u});
    if(shared_snapshot && session.registers_complete) {
#ifdef TRACEQ_CAPTURE_PERF
        ++observation_stats.reused_pre;
#endif
    } else state_delta(c,p,REG_PRE);
    if(reenter) {
        emit({SCOPE_REENTER,p->seq,p->pc,session.exit_seq,0,0,0,1});
        session.outside=false;
    }
    p->memory_valid=false;
    if(p->unsupported){gap(p->seq,p->pc,UNSUPPORTED);return;}
    if(p->check_target) {
        unsigned __int128 target=p->target_address;
        if(p->target_register!=ARM64_REG_INVALID && !reg_value(p->target_register,c,target)) {
            gap(p->seq,p->pc,UNSUPPORTED);return;
        }
        if(!contains(session.header.code_base,session.header.code_size,uint64_t(target),4)) {
            emit({SCOPE_EXIT,p->seq,p->pc,uint64_t(target),p->transfer,
                  p->transfer==CALL?p->pc+4:0,0,1});
            session.outside=true;session.return_exit=p->transfer==RETURN;
            session.exit_seq=p->seq;session.exit_pc=p->pc;
            if(!session.return_exit)gap(p->seq,p->pc,OUTSIDE_CODE_RANGE);
            return;
        }
    }
    if(p->post){p->pending=true;pending=p;}
    if(!p->count)return;
    unsigned __int128 base=0,index=0;
    if(!reg_value(p->mem.mem.base,c,base) ||
       (p->mem.mem.index!=ARM64_REG_INVALID && !reg_value(p->mem.mem.index,c,index))) {
        gap(p->seq,p->pc,UNSUPPORTED);return;
    }
    uint64_t ix=uint64_t(index);
    if(p->mem.ext==ARM64_EXT_UXTW)ix=uint32_t(ix);
    if(p->mem.ext==ARM64_EXT_SXTW)ix=uint64_t(int64_t(int32_t(ix)));
    p->address=uint64_t(base)+(ix<<p->mem.shift.value)+uint64_t(p->mem.mem.disp);
    if(!contains(session.header.data_base,session.header.data_size,p->address,p->width*p->count)) {
        gap(p->seq,p->pc,OUTSIDE_DATA_RANGE);return;
    }
    if(!p->load) for(unsigned i=0;i<p->count;++i) if(!reg_value(p->sources[i],c,p->values[i])) {
        gap(p->seq,p->pc,UNSUPPORTED);return;
    }
    p->memory_valid=true;
}
void after_state(GumCpuContext* c,Plan* p) {
    if(!p->pending || pending!=p)return;
    if(p->memory_valid) for(unsigned i=0;i<p->count;++i) {
        unsigned __int128 value=p->values[i];bool known=true;
        if(p->load) {
            known=p->sources[i]!=ARM64_REG_XZR && p->sources[i]!=ARM64_REG_WZR &&
                reg_value(p->sources[i],c,value);
            if(!known)value=0;
        }
        if(p->width<16)value&=(static_cast<unsigned __int128>(1)<<(p->width*8))-1;
        emit({p->load?READ:WRITE,p->seq,p->pc,p->address+i*p->width,p->width,
            uint64_t(value),uint64_t(value>>64),known?1u:0u});
        if(p->load)++session.reads;else ++session.writes;
    }
    state_delta(c,p,REG_POST);
    emit({COMMIT,p->seq,p->pc,0,0,0,0,1});++session.commits;
    p->pending=false;pending=nullptr;
}
void before(GumCpuContext* c, gpointer opaque) {
    auto* p = static_cast<Plan*>(opaque);
    if (!session.out) return;
#ifdef TRACEQ_CAPTURE_PERF
    ++observation_stats.before_calls;
    if (probe_mode == TraceqProbe::Callbacks || probe_mode == TraceqProbe::ThreadCheck || probe_mode == TraceqProbe::OwnerCheck) {
        if(probe_mode==TraceqProbe::ThreadCheck && gum_process_get_current_thread_id()!=session.header.thread_id)session.failed=true;
        if(probe_mode==TraceqProbe::OwnerCheck && !check_owner())return;
        ++session.instructions;return;
    }
#endif
    if(!check_owner())return;
    if(session.header.profile==2){before_state(c,p);return;}
    if (pending) { gap(pending->seq,pending->pc,UNCONFIRMED_STORE); pending->pending=false; pending=nullptr; }
    p->seq = session.instructions++;
    emit({EXEC,p->seq,p->pc,0,0,0,0,0});
    if (p->unsupported) { gap(p->seq,p->pc,UNSUPPORTED); return; }
    if (!p->count) return;
    unsigned __int128 base = 0, index = 0;
    if (!reg_value(p->mem.mem.base,c,base) ||
        (p->mem.mem.index != ARM64_REG_INVALID && !reg_value(p->mem.mem.index,c,index))) {
        gap(p->seq,p->pc,UNSUPPORTED); return;
    }
    uint64_t ix = uint64_t(index);
    if (p->mem.ext == ARM64_EXT_UXTW) ix = uint32_t(ix);
    if (p->mem.ext == ARM64_EXT_SXTW) ix = uint64_t(int64_t(int32_t(ix)));
    p->address = uint64_t(base) + (ix << p->mem.shift.value) + uint64_t(p->mem.mem.disp);
    if (!contains(session.header.data_base,session.header.data_size,p->address,p->width*p->count)) {
        gap(p->seq,p->pc,OUTSIDE_DATA_RANGE); return;
    }
    for (unsigned i=0; i<p->count; ++i) if (!reg_value(p->sources[i],c,p->values[i])) {
        gap(p->seq,p->pc,UNSUPPORTED); return;
    }
    p->pending = true; pending = p;
}
void after(GumCpuContext* c, gpointer opaque) {
    auto* p = static_cast<Plan*>(opaque);
#ifdef TRACEQ_CAPTURE_PERF
    ++observation_stats.after_calls;
#endif
    if (!session.out) return;
#ifdef TRACEQ_CAPTURE_PERF
    if(probe_mode==TraceqProbe::Callbacks || probe_mode==TraceqProbe::ThreadCheck || probe_mode==TraceqProbe::OwnerCheck)return;
#endif
    if(!check_owner(false) || !p->pending)return;
    if(session.header.profile==2){after_state(c,p);return;}
    if (pending != p) { gap(p->seq,p->pc,UNCONFIRMED_STORE); return; }
    for (unsigned i=0; i<p->count; ++i) {
        unsigned __int128 v = p->values[i];
        if (p->width < 16) v &= (static_cast<unsigned __int128>(1) << (p->width*8))-1;
        emit({WRITE,p->seq,p->pc,p->address+i*p->width,p->width,
              uint64_t(v),uint64_t(v>>64),1}); // pre source bits, post confirmed
        ++session.writes;
    }
    p->pending = false; pending = nullptr;
}
void free_plan(gpointer p) { delete static_cast<Plan*>(p); }
struct Boundary { Plan* previous;Plan* current; };
void shared_boundary(GumCpuContext* c,gpointer opaque) {
    auto* b=static_cast<Boundary*>(opaque);
    if(!session.out)return;
#ifdef TRACEQ_CAPTURE_PERF
    ++observation_stats.fused_calls;
    if(probe_mode==TraceqProbe::Callbacks || probe_mode==TraceqProbe::ThreadCheck || probe_mode==TraceqProbe::OwnerCheck) {
        if(probe_mode==TraceqProbe::ThreadCheck && gum_process_get_current_thread_id()!=session.header.thread_id)session.failed=true;
        if(probe_mode==TraceqProbe::OwnerCheck && !check_owner())return;
        ++session.instructions;return;
    }
#endif
    if(!check_owner())return;
    // Reuse only the actual just-observed post state. A pending mismatch falls
    // back to before_state's existing gap handling and full observation.
    bool confirmed=b->previous->pending && pending==b->previous;
    if(confirmed)after_state(c,b->previous);
    before_state(c,b->current,confirmed);
}
void free_boundary(gpointer opaque) {
    auto* b=static_cast<Boundary*>(opaque);
    // previous is owned by its own pre callback in the same compiled block.
    delete b->current;delete b;
}
gboolean record_module(GumModule* module,gpointer) {
    const auto* range=gum_module_get_range(module);
    const char* name=gum_module_get_name(module);size_t length=strlen(name);
    for(size_t offset=0;offset<length;offset+=24) {
        unsigned char bytes[24]{};size_t n=std::min(size_t(24),length-offset);
        memcpy(bytes,name+offset,n);
        emit({MODULE,offset,range->base_address,range->size,n,get64(bytes),get64(bytes+8),get64(bytes+16)});
    }
    return TRUE;
}
} // namespace

bool traceq_writes_begin(const char* path, uintptr_t code, size_t code_size,
                          uintptr_t data, size_t data_size, bool execution_state,bool external_followed) {
    if(!execution_state && (session.storage.storage==TraceqStorage::ChunkCpp ||
                           session.storage.storage==TraceqStorage::ChunkRust))return false;
    if (session.out || !code_size || !data_size || code_size > UINT64_MAX-code ||
        data_size > UINT64_MAX-data) return false;
    int fd = ::open(path,O_CREAT|O_EXCL|O_WRONLY,0600);
    if (fd < 0) return false;
    session.out = fdopen(fd,"wb");
    if (!session.out) { close(fd); return false; }
    setvbuf(session.out,session.buffer,_IOFBF,sizeof session.buffer);
    session.header = {code,code_size,data,data_size,gum_process_get_current_thread_id(),1};
    if(++session.generation==0)++session.generation;
    thread_generation=session.generation;session.foreign_thread.store(false,std::memory_order_relaxed);
    if(execution_state)session.header.profile=2;
    session.reads=session.commits=0;session.sites.clear();
    session.registers_complete=false;
#ifdef TRACEQ_CAPTURE_PERF
    observation_stats={};
#endif
    memset(session.state_known,0,sizeof session.state_known);
    session.instructions=session.writes=session.gaps=0;
    session.failed=false; session.translated_exclusive=false; pending=nullptr;
    session.outside=session.return_exit=false;
    session.records=nullptr;
    if(session.storage.storage!=TraceqStorage::Legacy) {
        if(!thread_records)thread_records=std::make_unique<TraceqRecordBuffer>();
        session.records=thread_records.get();session.records->begin(session.out,session.storage);
    }
    if(session.storage.storage==TraceqStorage::ChunkCpp || session.storage.storage==TraceqStorage::ChunkRust)
        session.failed=!traceq::chunks::write_header(session.out,session.header);
    else session.failed = !write_header(session.out,session.header);
    if(execution_state) {
        emit({FEATURES,0,0,FEATURE_BOUNDARIES,0,external_followed?1u:0u,0,0});
        gum_process_enumerate_modules(record_module,nullptr);
    }
    return !session.failed;
}
bool traceq_writes_active() { return session.out != nullptr; }
bool traceq_writes_end() {
    if (!session.out || !owns_session()) return false;
    if(session.foreign_thread.load(std::memory_order_relaxed))session.failed=true;
    if (pending) { gap(pending->seq,pending->pc,UNCONFIRMED_STORE); pending->pending=false; pending=nullptr; }
    // No callout may be inserted inside an exclusive region. Conservative
    // final gap invalidates all provenance if such a region was translated.
    if (session.translated_exclusive) gap(session.instructions,0,EXCLUSIVE_REGION);
    emit({END,session.instructions,0,session.writes,session.gaps,session.reads,session.commits,session.header.profile});
    if(session.records && !session.failed && !session.records->flush())session.failed=true;
    bool ok = !session.failed;
    if (fclose(session.out) != 0) ok = false;
    session.out = nullptr;
    thread_generation=0;
    return ok;
}

bool traceq_writes_storage(TraceqStorageOptions options) {
    if(session.out || (options.storage==TraceqStorage::Legacy && options.discard))return false;
#ifndef TRACEQ_RUST_CODEC
    if(options.storage==TraceqStorage::ChunkRust)return false;
#endif
    session.storage=options;return true;
}

bool traceq_writes_observation(TraceqObservation mode) {
    if(session.out)return false;
    session.observation=mode;return true;
}
TraceqCaptureSummary traceq_writes_summary() {
    return {session.instructions,session.reads,session.writes,session.gaps,session.commits};
}
bool traceq_writes_transform_block(GumStalkerIterator* it) {
    if(!session.out || session.header.profile!=2 || session.observation!=TraceqObservation::Fused)return false;
#ifdef TRACEQ_CAPTURE_PERF
    if(probe_mode==TraceqProbe::Engine)return false;
#endif
    // get_memory_access is a block property in the supported Gum backend.
    // Keep the original exclusive-region path, with no inserted callouts.
    if(gum_stalker_iterator_get_memory_access(it)==GUM_MEMORY_ACCESS_EXCLUSIVE)return false;
    const cs_insn* ins;Plan* deferred=nullptr;
    while(gum_stalker_iterator_next(it,&ins)) {
        if(!contains(session.header.code_base,session.header.code_size,ins->address,4)) {
            if(deferred){gum_stalker_iterator_put_callout(it,after,deferred,nullptr);deferred=nullptr;}
            gum_stalker_iterator_keep(it);continue;
        }
        Plan* p=make_plan(ins);extend_plan(p,ins);
        if(deferred && deferred->pc+4==p->pc && !p->unsupported) {
            auto* boundary=new Boundary{deferred,p};
            gum_stalker_iterator_put_callout(it,shared_boundary,boundary,free_boundary);
            deferred=nullptr;
        } else {
            if(deferred){gum_stalker_iterator_put_callout(it,after,deferred,nullptr);deferred=nullptr;}
            gum_stalker_iterator_put_callout(it,before,p,free_plan);
        }
        gum_stalker_iterator_keep(it);
        if(p->post)deferred=p;
    }
    // The iterator can stop on code-cache capacity, even without a branch.
    // Emit the last post before Gum appends the continuation transfer.
    if(deferred) {
        gum_stalker_iterator_put_callout(it,after,deferred,nullptr);
#ifdef TRACEQ_CAPTURE_PERF
        ++observation_stats.block_tail_flushes;
#endif
    }
    return true;
}
void traceq_writes_instrument(GumStalkerIterator* it, const cs_insn* ins) {
#ifdef TRACEQ_CAPTURE_PERF
    if (probe_mode == TraceqProbe::Engine) { gum_stalker_iterator_keep(it); return; }
#endif
    if (!contains(session.header.code_base,session.header.code_size,ins->address,4)) {
        gum_stalker_iterator_keep(it); return;
    }
    if (gum_stalker_iterator_get_memory_access(it) == GUM_MEMORY_ACCESS_EXCLUSIVE) {
        session.translated_exclusive = true;
        gum_stalker_iterator_keep(it); return;
    }
    Plan* p = make_plan(ins);
    if(session.header.profile==2)extend_plan(p,ins);
    gum_stalker_iterator_put_callout(it,before,p,free_plan);
    gum_stalker_iterator_keep(it);
    if (session.header.profile==2 ? p->post : (p->count && !p->unsupported))
        gum_stalker_iterator_put_callout(it,after,p,nullptr);
}

#ifdef TRACEQ_CAPTURE_PERF
void traceq_writes_probe(TraceqProbe mode) { if (!session.out) probe_mode = mode; }
void traceq_writes_thread_id_probe(bool enabled) {if(!session.out)thread_id_probe=enabled;}
uint64_t traceq_writes_instruction_count() { return session.instructions; }
TraceqObservationStats traceq_writes_observation_stats(){return observation_stats;}
TraceqStorageStats traceq_writes_storage_stats() {
    if(!session.records)return {};
    return {session.records->blocks,session.records->events,session.records->encoded_bytes,
            session.records->encode_ns,session.records->write_ns};
}
#endif
