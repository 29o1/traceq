//
// Created by lidongyooo on 2026/2/6.
//

#include "TraceqCapture.h"
#include "Utils.h"
#include "FuncPrinter.h"

#if defined(TRACEQ_WRITE_STREAM)
#include "WriteStream.h"
#endif

TraceqCapture *TraceqCapture::get_instance() {
    static TraceqCapture instance;
    return &instance;
}

TraceqCapture::TraceqCapture() {
    _transformer = gum_stalker_transformer_make_from_callback(transform_callback, nullptr, nullptr);
}

TraceqCapture::~TraceqCapture() {
    if (_stalker) g_object_unref(_stalker);
    if (_transformer) g_object_unref(_transformer);
}

void TraceqCapture::reset_session() {
    if (trace_file.is_open()) {
        trace_file.close();
    }
    if (_stalker) {
        gum_stalker_stop(_stalker);
        g_object_unref(_stalker);
        _stalker = nullptr;
    }

    modules.clear();
    func_maps.clear();
    func_fds.clear();
    svc_func_maps.clear();
    last_module_cache = {nullptr, 0, 0};
    buffer_offset = 0;
    trace_flush = 0;
    write_reg_list.num = 0;
    last_func_context.info_n = 0;
    last_func_context.call = false;
    last_func_context.is_jni = false;
    call_stack.clear();

#if PLATFORM_ANDROID
    jni_env = nullptr;
    jni_env_init = false;
    jni_func_maps.clear();
    jni_classes.clear();
    jni_methods.clear();
    jni_methods_classes.clear();
#endif
}

#if PLATFORM_ANDROID

JNIEnv *TraceqCapture::get_run_time_env() {
    if (java_vm == nullptr) {
        return nullptr;
    }

    if (jni_env == nullptr) {
        java_vm->GetEnv((void**)&jni_env, JNI_VERSION_1_6);
    }

    if (jni_env != nullptr && jni_env_init == false) {
        jni_env_init = true;

        auto jni_func_table = (uint64_t)jni_env->functions;
        int index = 0;
        for (const auto &func_name: jni_func_names) {
            auto func_addr_ptr = (void **)(jni_func_table + index * sizeof(void *));
            auto func_addr = (uint64_t)(*func_addr_ptr);
            jni_func_maps[func_addr] = func_name;
            index++;
        }
    }
    return jni_env;
}

#endif



namespace {

void flush_trace_buffer(TraceqCapture *self) {
    if (self->buffer_offset > 0) {
        self->trace_file.write(self->buffer, self->buffer_offset);
        self->buffer_offset = 0;
    }
}

void write_function_output(TraceqCapture *self) {
    if (self->last_func_context.info_n == 0) return;
    flush_trace_buffer(self);
    self->trace_file.write(self->last_func_context.info, self->last_func_context.info_n);
    self->last_func_context.info_n = 0;
}

bool memory_address(const cs_arm64_op &op, GumCpuContext *cpu_context,
                    uintptr_t &address, char *buff, int &buff_n) {
    __uint128_t base = 0;
    __uint128_t index = 0;
    bool valid = true;

    if (op.mem.base != ARM64_REG_INVALID) {
        bool ok = Utils::get_register_value(op.mem.base, cpu_context, base);
        valid = valid && ok;
        if (ok) {
            Utils::append_string(buff, buff_n, Utils::get_arm64_reg_name(op.mem.base));
            Utils::append_string(buff, buff_n, "=0x");
            Utils::format_uint128_hex(base, buff_n, buff);
            Utils::append_char(buff, buff_n, ' ');
        }
    }
    if (op.mem.index != ARM64_REG_INVALID) {
        bool ok = Utils::get_register_value(op.mem.index, cpu_context, index);
        valid = valid && ok;
        if (ok) {
            Utils::append_string(buff, buff_n, Utils::get_arm64_reg_name(op.mem.index));
            Utils::append_string(buff, buff_n, "=0x");
            Utils::format_uint128_hex(index, buff_n, buff);
            Utils::append_char(buff, buff_n, ' ');
        }
    }
    if (!valid) return false;

    uintptr_t offset = Utils::apply_extend_and_shift(index, op.ext, op.shift.type,
                                                     op.shift.value);
    address = static_cast<uintptr_t>(base) + offset + op.mem.disp;
    return true;
}

} // namespace

void TraceqCapture::callout_callback(GumCpuContext *cpu_context, gpointer user_data) {
    auto self = get_instance();
    auto callback_ctx = static_cast<CALLBACK_CTX *>(user_data);
    char *buff = self->buffer;
    int &buff_n = self->buffer_offset;

    if (buff_n > BUFFER_SIZE - 1024) {
        flush_trace_buffer(self);
    }

    if (self->write_reg_list.num > 0) {
        bool has_value = false;
        for (int i = 0; i < self->write_reg_list.num; i++) {
            __uint128_t reg_value = 0;
            if (!Utils::get_register_value(self->write_reg_list.regs[i], cpu_context, reg_value)) {
                continue;
            }
            if (!has_value) {
                Utils::append_string(buff, buff_n, "-> ");
                has_value = true;
            }
            Utils::append_string(buff, buff_n,
                                 Utils::get_arm64_reg_name(self->write_reg_list.regs[i]));
            Utils::append_string(buff, buff_n, "=0x");
            Utils::format_uint128_hex(reg_value, buff_n, buff);
            Utils::append_char(buff, buff_n, ' ');
        }
        Utils::append_char(buff, buff_n, '\n');
        self->write_reg_list.num = 0;
    }

    if (self->last_func_context.call) {
        self->last_func_context.call = false;
        write_function_output(self);
    }

    if (!self->call_stack.empty() &&
        self->call_stack.back().return_address == cpu_context->pc) {
        CALL_FRAME frame = std::move(self->call_stack.back());
        self->call_stack.pop_back();
        auto &func = self->last_func_context;
        func.info_n = 0;
        func.name = frame.name.c_str();
        func.cpu_context = frame.cpu_context;
        func.is_jni = frame.is_jni;
#if PLATFORM_ANDROID
        if (frame.is_jni) {
            FuncPrinter::jni_after(&func, cpu_context);
        } else {
            FuncPrinter::after(&func, cpu_context);
        }
#else
        FuncPrinter::after(&func, cpu_context);
#endif
        write_function_output(self);
        func.is_jni = false;
    }

    Utils::append_char(buff, buff_n, '[');
    Utils::append_string(buff, buff_n, callback_ctx->module_name.c_str());
    Utils::append_string(buff, buff_n, "] 0x");
    Utils::append_uint64_hex(buff, buff_n, cpu_context->pc);
    Utils::append_string(buff, buff_n, "!0x");
    Utils::append_uint64_hex(buff, buff_n, cpu_context->pc - callback_ctx->module_base);
    Utils::append_char(buff, buff_n, ' ');
    Utils::append_string(buff, buff_n, callback_ctx->mnemonic);
    Utils::append_char(buff, buff_n, ' ');
    Utils::append_string(buff, buff_n, callback_ctx->op_str);
    Utils::append_string(buff, buff_n, "; ");

    const cs_arm64 &arm64 = callback_ctx->arm64;
    for (int i = 0; i < arm64.op_count; i++) {
        const cs_arm64_op &op = arm64.operands[i];
        if (op.type == ARM64_OP_REG) {
            __uint128_t reg_value = 0;
            if ((op.access & (CS_AC_READ | CS_AC_WRITE)) &&
                Utils::get_register_value(op.reg, cpu_context, reg_value)) {
                Utils::append_string(buff, buff_n, Utils::get_arm64_reg_name(op.reg));
                Utils::append_string(buff, buff_n, "=0x");
                Utils::format_uint128_hex(reg_value, buff_n, buff);
                Utils::append_char(buff, buff_n, ' ');
            }
            if (op.access & CS_AC_WRITE) {
                self->write_reg_list.add(op.reg);
            }
        } else if (op.type == ARM64_OP_MEM) {
            uintptr_t address = 0;
            if (memory_address(op, cpu_context, address, buff, buff_n)) {
                bool reads_memory = (op.access & CS_AC_READ) != 0;
                bool writes_memory = (op.access & CS_AC_WRITE) != 0;
                Utils::memory_direction(callback_ctx->mnemonic, reads_memory, writes_memory);
                if (reads_memory && writes_memory && callback_ctx->mnemonic[0] == 's' &&
                    callback_ctx->mnemonic[1] == 't') {
                    reads_memory = false;
                }
                if (reads_memory) {
                    Utils::append_string(buff, buff_n, "mem_r=0x");
                    Utils::append_uint64_hex(buff, buff_n, address);
                    Utils::append_char(buff, buff_n, ' ');
                }
                if (writes_memory) {
                    Utils::append_string(buff, buff_n, "mem_w=0x");
                    Utils::append_uint64_hex(buff, buff_n, address);
                    Utils::append_char(buff, buff_n, ' ');
                }
            }
            if (arm64.writeback) {
                self->write_reg_list.add(op.mem.base);
            }
        }
    }

    if (self->write_reg_list.num == 0) {
        Utils::append_char(buff, buff_n, '\n');
    }

    const char *function_name = nullptr;
    bool is_jni = false;
    bool link_register_return = false;
    __uint128_t jump_addr = 0;
    if (callback_ctx->instruction_id == ARM64_INS_SVC) {
        auto svc_it = self->svc_func_maps.find(cpu_context->x[8]);
        if (svc_it != self->svc_func_maps.end()) {
            function_name = svc_it->second.c_str();
        }
    } else if (arm64.op_count > 0 && callback_ctx->instruction_id == ARM64_INS_BL &&
               arm64.operands[0].type == ARM64_OP_IMM) {
        jump_addr = arm64.operands[0].imm;
    } else if (arm64.op_count > 0 && callback_ctx->instruction_id == ARM64_INS_BLR &&
               arm64.operands[0].type == ARM64_OP_REG) {
        Utils::get_register_value(arm64.operands[0].reg, cpu_context, jump_addr);
    } else if (arm64.op_count > 0 && callback_ctx->instruction_id == ARM64_INS_BR &&
               arm64.operands[0].type == ARM64_OP_REG) {
        Utils::get_register_value(arm64.operands[0].reg, cpu_context, jump_addr);
        link_register_return = true;
    } else if (arm64.op_count > 0 && callback_ctx->instruction_id == ARM64_INS_B &&
               arm64.operands[0].type == ARM64_OP_IMM) {
        jump_addr = arm64.operands[0].imm;
        link_register_return = true;
    }

    if (jump_addr > 0) {
        if (link_register_return &&
            self->in_range_module(static_cast<size_t>(jump_addr)) != nullptr) {
            jump_addr = 0;
        }
    }

    if (jump_addr > 0) {
        auto func_it = self->func_maps.find(static_cast<size_t>(jump_addr));
        if (func_it != self->func_maps.end()) {
            function_name = func_it->second.c_str();
        }
#if PLATFORM_ANDROID
        else if (self->get_run_time_env() != nullptr) {
            auto jni_it = self->jni_func_maps.find(static_cast<size_t>(jump_addr));
            if (jni_it != self->jni_func_maps.end()) {
                function_name = jni_it->second.c_str();
                is_jni = true;
            }
        }
#endif
    }

    if (function_name != nullptr) {
        auto &func = self->last_func_context;
        func.info_n = 0;
        func.address = static_cast<uint64_t>(jump_addr);
        func.name = function_name;
        func.cpu_context = *cpu_context;
        func.is_jni = is_jni;
#if PLATFORM_ANDROID
        if (is_jni) {
            FuncPrinter::jni_before(&func);
        } else {
            FuncPrinter::before(&func);
        }
#else
        FuncPrinter::before(&func);
#endif
        func.call = true;
        uint64_t return_address = link_register_return ? cpu_context->lr
                                                       : cpu_context->pc + 4;
        self->call_stack.push_back({return_address, function_name, is_jni, *cpu_context});
    }

    self->trace_flush++;
    if (self->options.mode == TRACEQ_MODE_DEBUG && self->trace_flush > 20) {
        flush_trace_buffer(self);
        self->trace_file.flush();
        self->trace_flush = 0;
    }
}

void TraceqCapture::transform_callback(GumStalkerIterator *iterator, GumStalkerOutput *output, gpointer user_data) {
    const auto self = get_instance();
#if defined(TRACEQ_WRITE_STREAM)
    if(traceq_writes_transform_block(iterator))return;
#endif

    cs_insn *p_insn;
    auto *it = iterator;
    while (gum_stalker_iterator_next(it, (const cs_insn **) &p_insn)) {
#if defined(TRACEQ_WRITE_STREAM)
        if (traceq_writes_active()) {
            traceq_writes_instrument(it, p_insn);
            continue;
        }
#endif
        const std::string *module_name_ptr = self->in_range_module(p_insn->address);
        if (module_name_ptr == nullptr) {
            gum_stalker_iterator_keep(it);
            continue;
        }

        if (gum_stalker_iterator_get_memory_access(it) != GUM_MEMORY_ACCESS_EXCLUSIVE) {
            const auto& module = self->get_module_by_name(*module_name_ptr);

            auto callback_ctx = CallbackContext::create(p_insn, module_name_ptr->c_str(),
                                                        module.at("base"));

            gum_stalker_iterator_put_callout(it, callout_callback, callback_ctx,
                                             CallbackContext::destroy);
        }

        gum_stalker_iterator_keep(it);
    }
}

const std::string *TraceqCapture::in_range_module(size_t address) {
    if (last_module_cache.name != nullptr && address >= last_module_cache.base && address < last_module_cache.end) {
        return last_module_cache.name;
    }

    for (const auto &pair: modules) {
        const auto &module_map = pair.second;
        size_t base = module_map.at("base");
        size_t size = module_map.at("size");
        size_t end = base + size;
        if (address >= base && address < end) {
            last_module_cache.name = &pair.first;
            last_module_cache.base = base;
            last_module_cache.end = end;
            return &pair.first;
        }
    }
    return nullptr;
}

const std::map<std::string, std::size_t>& TraceqCapture::get_module_by_name(const std::string &module_name) {
    return modules[module_name];
}

void TraceqCapture::follow() {
    trace_thread_id > 0
        ? gum_stalker_follow(_stalker, trace_thread_id, _transformer, nullptr)
        : gum_stalker_follow_me(_stalker, _transformer, nullptr);
}


void TraceqCapture::unfollow() {
    trace_thread_id > 0 ? gum_stalker_unfollow(_stalker, trace_thread_id) : gum_stalker_unfollow_me(_stalker);

    if (trace_file.is_open()) {
        if (write_reg_list.num > 0) {
            Utils::append_char(buffer, buffer_offset, '\n');
            write_reg_list.num = 0;
        }
        if (last_func_context.call) {
            last_func_context.call = false;
            write_function_output(this);
        }
        flush_trace_buffer(this);
        trace_file.flush();
        trace_file.close();
    }
    call_stack.clear();
}
