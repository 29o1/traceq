#include "legacy.h"
#include <gumtrace/recorder.h>
#include <cassert>
#include <cstring>

namespace gt {

bool LegacyRecorder::open(const std::string& path) {
    f_ = fopen(path.c_str(), "wb");
    if (!f_) return false;
    buf_.assign(CAP, 0);
    buf_n_ = 0;
    return true;
}

const char* LegacyRecorder::reg_name(int ctx_idx) {
    // upstream Utils::get_arm64_reg_name: thread_local buffer + snprintf,
    // called once per printed operand. Cost preserved deliberately.
    static thread_local char name[16];
    if (ctx_idx == 31) return "sp";
    if (ctx_idx <= 30) {
        snprintf(name, sizeof(name), "x%d", ctx_idx);
        return name;
    }
    return "unk";
}

void LegacyRecorder::record_event(const ExecEvent& ev) {
    events++;
    if (!f_) return;

    // 1. buffer flush check (upstream: > BUFFER_SIZE-1024)
    if (buf_n_ > CAP - 1024) flushbuf();

    // 2. flush deferred write list from the previous instruction
    //    (upstream prints these with the values observed at this callout,
    //    which equal the writer's post-execution values)
    if (wr_num_ > 0) {
        append("-> ", 3);
        for (int i = 0; i < wr_num_; i++) {
            const char* nm = reg_name(wr_reg_[i]);
            append(nm, strlen(nm));
            append("=0x", 3);
            append_hex64(wr_val_[i]);
            append(" ", 1);
        }
        append("\n", 1);
        wr_num_ = 0;
    }

    // 3. pending info blocks (written directly to FILE*, mid-callback)
    if (pend_call_ || pend_svc_ || pend_ret_) {
        flushbuf(); // upstream writes the current buffer first
        if (pend_call_) {
            fprintf(f_, "call func: %s(x0=0x%llx, x1=0x%llx, x2=0x%llx, x3=0x%llx)\n",
                    pend_name_.c_str(),
                    (unsigned long long)pend_args_[0], (unsigned long long)pend_args_[1],
                    (unsigned long long)pend_args_[2], (unsigned long long)pend_args_[3]);
        }
        if (pend_svc_) {
            const char* nm = svc_name(pend_svc_num_);
            if (nm) fprintf(f_, "svc %s(x0=0x%llx, x1=0x%llx, x2=0x%llx)\n", nm,
                            (unsigned long long)pend_svc_args_[0],
                            (unsigned long long)pend_svc_args_[1],
                            (unsigned long long)pend_svc_args_[2]);
            else fprintf(f_, "svc #%llu(x0=0x%llx)\n",
                         (unsigned long long)pend_svc_num_,
                         (unsigned long long)pend_svc_args_[0]);
        }
        if (pend_ret_) {
            fprintf(f_, "ret: x0=0x%llx\n", (unsigned long long)pend_ret_val_);
        }
        pend_call_ = pend_svc_ = pend_ret_ = false;
    }

    // resolve site (upstream: callback_ctx prepared at transform time; the
    // baseline pays the map lookup once per event — one-entry cache like the
    // new recorder would be a change we are measuring, so none here)
    uint32_t site_id = arena_.by_addr_find(ev.pc);
    if (site_id == 0xFFFFFFFFu) return;
    const Site& s = arena_.get(site_id);

    // 4. instruction prefix rebuilt per execution
    append("[", 1);
    append(module_.c_str(), module_.size());
    append("] 0x", 4);
    append_hex64(s.addr);
    append("!0x", 3);
    append_hex64(s.addr - base_);
    append(" ", 1);
    append(arena_.pool_ptr() + s.disasm_off, s.disasm_len);
    append("; ", 2);

    // 5. operand walk. Upstream interleaves register and memory operands in
    //    Capstone operand order; every corpus encoding places memory operands
    //    last, so a reg pass followed by a mem pass emits identical bytes.
    bool is_write = false;
    wr_num_ = 0;
    for (uint8_t i = 0; i < s.n_ops; i++) {
        const OpPlan& op = s.ops[i];
        if (op.kind == OP_REG_R) {
            const char* nm = reg_name(op.ctx_idx);
            append(nm, strlen(nm));
            append("=0x", 3);
            append_hex64(op.ctx_idx == 31 ? ev.sp : ev.x[op.ctx_idx & 31]);
            append(" ", 1);
        } else if (op.kind == OP_REG_W) {
            is_write = true;
        }
    }
    int mem_idx = 0;
    for (uint8_t i = 0; i < s.n_ops; i++) {
        const OpPlan& op = s.ops[i];
        if (op.kind != OP_MEM_R && op.kind != OP_MEM_W) continue;
        if (mem_idx >= ev.n_mem) break;
        const MemOp& m = ev.mem[mem_idx++];
        if (op.base_ctx_idx >= 0) {
            const char* nm = reg_name(op.base_ctx_idx);
            append(nm, strlen(nm));
            append("=0x", 3);
            append_hex64(op.base_ctx_idx == 31 ? ev.sp : ev.x[op.base_ctx_idx & 31]);
            append(" ", 1);
        }
        append(op.kind == OP_MEM_W ? "mem_w=0x" : "mem_r=0x", 8);
        append_hex64(m.addr);
        append(" ", 1);
        if (op.kind == OP_MEM_W) is_write = true;
    }

    // deferred writes: regs from the plan, values from this event's write set
    {
        int n = 0;
        for (uint8_t i = 0; i < s.n_ops && n < 31; i++) {
            if (s.ops[i].kind != OP_REG_W) continue;
            for (int k = 0; k < ev.n_wr; k++) {
                if (ev.wr_id[k] == s.ops[i].ctx_idx) {
                    wr_reg_[n] = s.ops[i].ctx_idx;
                    wr_val_[n] = ev.wr_val[k];
                    n++;
                    break;
                }
            }
        }
        wr_num_ = n;
        if (n > 0) is_write = true;
    }

    // 6. newline logic
    if (!is_write) append("\n", 1);

    // 7. branch/svc bookkeeping
    if (ev.is_call) {
        pend_call_ = true;
        pend_name_ = ev.call_name ? ev.call_name : "<unknown>";
        for (int i = 0; i < 4; i++) pend_args_[i] = ev.x[i];
    }
    if (ev.is_svc) {
        pend_svc_ = true;
        pend_svc_num_ = ev.svc_num;
        for (int i = 0; i < 3; i++) pend_svc_args_[i] = ev.x[i];
    }
    if (ev.is_ret) {
        pend_ret_ = true;
        pend_ret_val_ = ev.ret_val;
    }
}

void LegacyRecorder::finish() {
    if (!f_) return;
    // tail: flush deferred writes of the last instruction without a following
    // event (upstream loses this tail on unrun without a final flush; we write
    // it so the text is complete for the equivalence test — documented)
    if (wr_num_ > 0) {
        append("-> ", 3);
        for (int i = 0; i < wr_num_; i++) {
            const char* nm = reg_name(wr_reg_[i]);
            append(nm, strlen(nm));
            append("=0x", 3);
            append_hex64(wr_val_[i]);
            append(" ", 1);
        }
        append("\n", 1);
        wr_num_ = 0;
    }
    if (pend_call_) {
        flushbuf();
        fprintf(f_, "call func: %s(x0=0x%llx, x1=0x%llx, x2=0x%llx, x3=0x%llx)\n",
                pend_name_.c_str(),
                (unsigned long long)pend_args_[0], (unsigned long long)pend_args_[1],
                (unsigned long long)pend_args_[2], (unsigned long long)pend_args_[3]);
        pend_call_ = false;
    }
    if (pend_svc_) {
        flushbuf();
        const char* nm = svc_name(pend_svc_num_);
        if (nm) fprintf(f_, "svc %s(x0=0x%llx)\n", nm, (unsigned long long)pend_svc_args_[0]);
        else fprintf(f_, "svc #%llu(x0=0x%llx)\n",
                     (unsigned long long)pend_svc_num_,
                     (unsigned long long)pend_svc_args_[0]);
        pend_svc_ = false;
    }
    if (pend_ret_) {
        flushbuf();
        fprintf(f_, "ret: x0=0x%llx\n", (unsigned long long)pend_ret_val_);
        pend_ret_ = false;
    }
    flushbuf();
    fclose(f_);
    f_ = nullptr;
}

} // namespace gt
