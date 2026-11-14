//
// Created by lidongyooo on 2026/2/6.
//

#include "FuncPrinter.h"
#include <cstdio>

namespace {
const char *resolve_syscall_name(TraceqCapture *instance, uint64_t syscall_nr, char *fallback, size_t fallback_size) {
    auto it = instance->svc_func_maps.find(syscall_nr);
    if (it != instance->svc_func_maps.end() && !it->second.empty()) {
        return it->second.c_str();
    }

    snprintf(fallback, fallback_size, "syscall_%llu", static_cast<unsigned long long>(syscall_nr));
    return fallback;
}

void shift_syscall_wrapper_args(GumCpuContext *cpu_context) {
    for (int i = 0; i < 7; i++) {
        cpu_context->x[i] = cpu_context->x[i + 1];
    }
    cpu_context->x[7] = 0;
}
}

const std::unordered_set<std::string> call_jni_methods = {
    "CallStaticObjectMethod", "CallStaticObjectMethodV", "CallStaticObjectMethodA",
    "CallStaticBooleanMethod", "CallStaticBooleanMethodV", "CallStaticBooleanMethodA",
    "CallStaticByteMethod", "CallStaticByteMethodV", "CallStaticByteMethodA",
    "CallStaticCharMethod", "CallStaticCharMethodV", "CallStaticCharMethodA",
    "CallStaticShortMethod", "CallStaticShortMethodV", "CallStaticShortMethodA",
    "CallStaticIntMethod", "CallStaticIntMethodV", "CallStaticIntMethodA",
    "CallStaticLongMethod", "CallStaticLongMethodV", "CallStaticLongMethodA",
    "CallStaticFloatMethod", "CallStaticFloatMethodV", "CallStaticFloatMethodA",
    "CallStaticDoubleMethod", "CallStaticDoubleMethodV", "CallStaticDoubleMethodA",
    "CallStaticVoidMethod", "CallStaticVoidMethodV", "CallStaticVoidMethodA",
    "CallObjectMethod", "CallObjectMethodV", "CallObjectMethodA",
    "CallBooleanMethod", "CallBooleanMethodV", "CallBooleanMethodA",
    "CallByteMethod", "CallByteMethodV", "CallByteMethodA",
    "CallCharMethod", "CallCharMethodV", "CallCharMethodA",
    "CallShortMethod", "CallShortMethodV", "CallShortMethodA",
    "CallIntMethod", "CallIntMethodV", "CallIntMethodA",
    "CallLongMethod", "CallLongMethodV", "CallLongMethodA",
    "CallFloatMethod", "CallFloatMethodV", "CallFloatMethodA",
    "CallDoubleMethod", "CallDoubleMethodV", "CallDoubleMethodA",
    "CallVoidMethod", "CallVoidMethodV", "CallVoidMethodA",
    "CallNonvirtualObjectMethod", "CallNonvirtualObjectMethodV", "CallNonvirtualObjectMethodA",
    "CallNonvirtualBooleanMethod", "CallNonvirtualBooleanMethodV", "CallNonvirtualBooleanMethodA",
    "CallNonvirtualByteMethod", "CallNonvirtualByteMethodV", "CallNonvirtualByteMethodA",
    "CallNonvirtualCharMethod", "CallNonvirtualCharMethodV", "CallNonvirtualCharMethodA",
    "CallNonvirtualShortMethod", "CallNonvirtualShortMethodV", "CallNonvirtualShortMethodA",
    "CallNonvirtualIntMethod", "CallNonvirtualIntMethodV", "CallNonvirtualIntMethodA",
    "CallNonvirtualLongMethod", "CallNonvirtualLongMethodV", "CallNonvirtualLongMethodA",
    "CallNonvirtualFloatMethod", "CallNonvirtualFloatMethodV", "CallNonvirtualFloatMethodA",
    "CallNonvirtualDoubleMethod", "CallNonvirtualDoubleMethodV", "CallNonvirtualDoubleMethodA",
    "CallNonvirtualVoidMethod", "CallNonvirtualVoidMethodV", "CallNonvirtualVoidMethodA",
};

const std::unordered_map<std::string, BeforeFuncConfig> func_configs = {
    // 字符串操作
    {"strstr", {PARAMS_NUMBER_TWO, {STR_INDEX_ZERO, STR_INDEX_ONE}, {}}},
    {"strlen", {PARAMS_NUMBER_ONE, {STR_INDEX_ZERO}, {}}},
    {"__strlen_chk", {PARAMS_NUMBER_ONE, {STR_INDEX_ZERO}, {}}},
    {"__strlen_aarch64", {PARAMS_NUMBER_ONE, {STR_INDEX_ZERO}, {}}},
    {"strcmp", {PARAMS_NUMBER_TWO, {STR_INDEX_ZERO, STR_INDEX_ONE}, {}}},
    {"strncmp", {PARAMS_NUMBER_TWO, {STR_INDEX_ZERO, STR_INDEX_ONE}, {}}},
    {"__strncmp_aarch64", {PARAMS_NUMBER_TWO, {STR_INDEX_ZERO, STR_INDEX_ONE}, {}}},
    {"strcpy", {PARAMS_NUMBER_TWO, {STR_INDEX_ZERO, STR_INDEX_ONE}, {}}},
    {"__strcpy_chk", {PARAMS_NUMBER_TWO, {STR_INDEX_ZERO, STR_INDEX_ONE}, {}}},
    {"strncpy", {PARAMS_NUMBER_TWO, {STR_INDEX_ZERO, STR_INDEX_ONE}, {}}},
    {"__strncpy_chk", {PARAMS_NUMBER_TWO, {STR_INDEX_ZERO, STR_INDEX_ONE}, {}}},
    {"strcat", {PARAMS_NUMBER_TWO, {STR_INDEX_ZERO, STR_INDEX_ONE}, {}}},
    {"__strcat_chk", {PARAMS_NUMBER_TWO, {STR_INDEX_ZERO, STR_INDEX_ONE}, {}}},
    {"strncat", {PARAMS_NUMBER_TWO, {STR_INDEX_ZERO, STR_INDEX_ONE}, {}}},
    {"__strncat_chk", {PARAMS_NUMBER_TWO, {STR_INDEX_ZERO, STR_INDEX_ONE}, {}}},
    {"strdup", {PARAMS_NUMBER_ONE, {STR_INDEX_ZERO}, {}}},
    {"__strdup_chk", {PARAMS_NUMBER_ONE, {STR_INDEX_ZERO}, {}}},
    {"strndup", {PARAMS_NUMBER_ONE, {STR_INDEX_ZERO}, {}}},
    {"__strndup_chk", {PARAMS_NUMBER_ONE, {STR_INDEX_ZERO}, {}}},
    {"strchr", {PARAMS_NUMBER_ONE, {STR_INDEX_ZERO}, {}}},
    {"strrchr", {PARAMS_NUMBER_ONE, {STR_INDEX_ZERO}, {}}},
    {"strspn", {PARAMS_NUMBER_ONE, {STR_INDEX_ZERO}, {}}},
    {"strcspn", {PARAMS_NUMBER_ONE, {STR_INDEX_ZERO}, {}}},
    {"strcasestr", {PARAMS_NUMBER_ONE, {STR_INDEX_ZERO}, {}}},
    {"strlcpy", {PARAMS_NUMBER_THREE, {STR_INDEX_ZERO, STR_INDEX_ONE}, {}}},
    {"__strlcpy_chk", {PARAMS_NUMBER_THREE, {STR_INDEX_ZERO, STR_INDEX_ONE}, {}}},
    {"strlcat", {PARAMS_NUMBER_THREE, {STR_INDEX_ZERO, STR_INDEX_ONE}, {}}},
    {"__strlcat_chk", {PARAMS_NUMBER_THREE, {STR_INDEX_ZERO, STR_INDEX_ONE}, {}}},

    // 内存操作
    {"memcpy", {PARAMS_NUMBER_THREE, {}, {{HEX_INDEX_ONE, HEX_INDEX_TWO}}}},
    {"__memcpy_chk", {PARAMS_NUMBER_THREE, {}, {{HEX_INDEX_ONE, HEX_INDEX_TWO}}}},
    {"__memcpy_aarch64_simd", {PARAMS_NUMBER_THREE, {}, {{HEX_INDEX_ONE, HEX_INDEX_TWO}}}},
    {"memmove", {PARAMS_NUMBER_THREE, {}, {{HEX_INDEX_ONE, HEX_INDEX_TWO}}}},
    {"__memmove_chk", {PARAMS_NUMBER_THREE, {}, {{HEX_INDEX_ONE, HEX_INDEX_TWO}}}},
    {"memset", {PARAMS_NUMBER_THREE, {}, {}}},
    {"__memset_chk", {PARAMS_NUMBER_THREE, {}, {}}},
    {"__memset_aarch64", {PARAMS_NUMBER_THREE, {}, {}}},
    {"memmem", {PARAMS_NUMBER_FOUR, {}, {{HEX_INDEX_ZERO, HEX_INDEX_ONE}, {HEX_INDEX_TWO, HEX_INDEX_THREE}}}},
    {"memcmp", {PARAMS_NUMBER_THREE, {}, {{HEX_INDEX_ZERO, HEX_INDEX_TWO}, {HEX_INDEX_ONE, HEX_INDEX_TWO}}}},
    {"__memcmp_aarch64", {PARAMS_NUMBER_THREE, {}, {{HEX_INDEX_ZERO, HEX_INDEX_TWO}, {HEX_INDEX_ONE, HEX_INDEX_TWO}}}},
    {"memchr", {PARAMS_NUMBER_THREE, {STR_INDEX_ZERO}, {}}},
    {"__memchr_aarch64", {PARAMS_NUMBER_THREE, {STR_INDEX_ZERO}, {}}},

    // 文件操作
    {"fopen", {PARAMS_NUMBER_TWO, {STR_INDEX_ZERO, STR_INDEX_ONE}, {}}},
    {"fopen64", {PARAMS_NUMBER_TWO, {STR_INDEX_ZERO, STR_INDEX_ONE}, {}}},
    {"read", {PARAMS_NUMBER_THREE, {}, {{HEX_INDEX_ONE, HEX_INDEX_TWO}}}},
    {"pread64", {PARAMS_NUMBER_THREE, {}, {{HEX_INDEX_ONE, HEX_INDEX_TWO}}}},
    {"open", {PARAMS_NUMBER_TWO, {STR_INDEX_ZERO}, {}}},
    {"openat", {PARAMS_NUMBER_FOUR, {STR_INDEX_ONE}, {}}},
    {"close", {PARAMS_NUMBER_ONE, {}, {}}},
    {"write", {PARAMS_NUMBER_THREE, {}, {{HEX_INDEX_ONE, HEX_INDEX_TWO}}}},
    {"pwrite64", {PARAMS_NUMBER_THREE, {}, {{HEX_INDEX_ONE, HEX_INDEX_TWO}}}},
    {"mknodat", {PARAMS_NUMBER_FOUR, {STR_INDEX_ONE}, {}}},
    {"mkdirat", {PARAMS_NUMBER_THREE, {STR_INDEX_ONE}, {}}},
    {"fstatat", {PARAMS_NUMBER_FOUR, {STR_INDEX_ONE}, {}}},
    {"newfstatat", {PARAMS_NUMBER_FOUR, {STR_INDEX_ONE}, {}}},
    {"fstat", {PARAMS_NUMBER_TWO, {}, {}}},
    {"stat", {PARAMS_NUMBER_TWO, {STR_INDEX_ZERO}, {}}},
    {"readlink", {PARAMS_NUMBER_THREE, {STR_INDEX_ZERO, STR_INDEX_ONE}, {}}},
    {"readlinkat", {PARAMS_NUMBER_FOUR, {STR_INDEX_ONE, STR_INDEX_TWO}, {}}},
    {"opendir", {PARAMS_NUMBER_ONE, {STR_INDEX_ZERO}, {}}},
    {"access", {PARAMS_NUMBER_TWO, {STR_INDEX_ZERO}, {}}},
    {"popen", {PARAMS_NUMBER_TWO, {STR_INDEX_ZERO, STR_INDEX_ONE}, {}}},
    {"pclose", {PARAMS_NUMBER_ONE, {}, {}}},

    // 格式化输出
    {"sprintf", {PARAMS_NUMBER_TWO, {STR_INDEX_ZERO, STR_INDEX_ONE}, {}}},
    {"__sprintf_chk", {PARAMS_NUMBER_TWO, {STR_INDEX_ZERO, STR_INDEX_ONE}, {}}},
    {"snprintf", {PARAMS_NUMBER_THREE, {STR_INDEX_ZERO}, {}}},
    {"__snprintf_chk", {PARAMS_NUMBER_THREE, {STR_INDEX_ZERO}, {}}},
    {"vsprintf", {PARAMS_NUMBER_TWO, {STR_INDEX_ZERO}, {}}},
    {"__vsprintf_chk", {PARAMS_NUMBER_TWO, {STR_INDEX_ZERO}, {}}},
    {"vsnprintf", {PARAMS_NUMBER_THREE, {STR_INDEX_ZERO}, {}}},
    {"__vsnprintf_chk", {PARAMS_NUMBER_THREE, {STR_INDEX_ZERO}, {}}},
    {"fgets", {PARAMS_NUMBER_THREE, {STR_INDEX_ZERO}, {}}},
    {"__fgets_chk", {PARAMS_NUMBER_THREE, {STR_INDEX_ZERO}, {}}},
    {"sscanf", {PARAMS_NUMBER_TWO, {STR_INDEX_ZERO, STR_INDEX_ONE}, {}}},

    // 内存分配
    {"calloc", {PARAMS_NUMBER_TWO, {}, {}}},
    {"malloc", {PARAMS_NUMBER_ONE, {}, {}}},
    {"realloc", {PARAMS_NUMBER_TWO, {}, {{HEX_INDEX_ZERO, HEX_INDEX_SPECIAL_32}}}},
    {"free", {PARAMS_NUMBER_ONE, {}, {{HEX_INDEX_ZERO, HEX_INDEX_SPECIAL_32}}}},
    {"aligned_alloc", {PARAMS_NUMBER_TWO, {}, {}}},

    // 内存映射
    {"mmap", {PARAMS_NUMBER_SIX, {}, {}}},
    {"mmap64", {PARAMS_NUMBER_SIX, {}, {}}},
    {"mprotect", {PARAMS_NUMBER_THREE, {}, {}}},

    // 动态链接
    {"dlopen", {PARAMS_NUMBER_TWO, {STR_INDEX_ZERO}, {}}},
    {"dlsym", {PARAMS_NUMBER_TWO, {STR_INDEX_ONE}, {}}},
    {"dlclose", {PARAMS_NUMBER_ONE, {}, {}}},

    // 系统相关
    {"sysconf", {PARAMS_NUMBER_ONE, {}, {}}},
    {"__system_property_get", {PARAMS_NUMBER_TWO, {STR_INDEX_ZERO, STR_INDEX_ONE}, {}}},
    {"gettimeofday", {PARAMS_NUMBER_TWO, {}, {{HEX_INDEX_ZERO, HEX_INDEX_SPECIAL_32}}}},
    {"srand48", {PARAMS_NUMBER_ONE, {}, {}}},
    {"syscall", {PARAMS_NUMBER_ONE, {}, {}, FuncPrinter::syscall}},
    {"arc4random_buf", {PARAMS_NUMBER_TWO, {}, {{HEX_INDEX_ZERO, HEX_INDEX_ONE}}}}
};

const std::unordered_map<std::string, AfterJniFuncConfig> after_jni_func_configs = {
    {"FindClass", {PARAMS_NUMBER_TWO, {STR_INDEX_ONE}, {}, {}, {}, {}, {}}},
    {"GetMethodID", {PARAMS_NUMBER_FOUR, {STR_INDEX_TWO, STR_INDEX_THREE}, {}, {}, {}, {}, {}}},
    {"GetStaticMethodID", {PARAMS_NUMBER_FOUR, {STR_INDEX_TWO, STR_INDEX_THREE}, {}, {}, {}, {}, {}}},
    {"NewString", {PARAMS_NUMBER_TWO, {}, {}, {}, {STR_INDEX_ZERO}, {}, {}}},
    {"NewStringUTF", {PARAMS_NUMBER_TWO, {STR_INDEX_ONE}, {}, {}, {}, {}, {}}},
    {"GetStringLength", {PARAMS_NUMBER_TWO, {}, {}, {STR_INDEX_ONE}, {}, {}, {}}},
    {"GetStringUTFLength", {PARAMS_NUMBER_TWO, {}, {}, {STR_INDEX_ONE}, {}, {}, {}}},
    {"GetStringChars", {PARAMS_NUMBER_THREE, {}, {}, {STR_INDEX_ONE}, {}, {}, {}}},
    {"GetStringUTFChars", {PARAMS_NUMBER_THREE, {}, {}, {STR_INDEX_ONE}, {}, {}, {}}},
    {"ReleaseStringUTFChars", {PARAMS_NUMBER_THREE, {STR_INDEX_TWO}, {}, {STR_INDEX_ONE}, {}, {}, {}}},
    {"GetStringRegion", {PARAMS_NUMBER_FIVE, {}, {}, {STR_INDEX_ONE}, {}, {}, {}}},
    {"GetStringUTFRegion", {PARAMS_NUMBER_FIVE, {}, {}, {STR_INDEX_ONE}, {}, {}, {}}},
    {"GetStringCritical", {PARAMS_NUMBER_THREE, {}, {}, {STR_INDEX_ONE}, {}, {}, {}}},
    {"ReleaseStringCritical", {PARAMS_NUMBER_THREE, {}, {}, {STR_INDEX_ONE}, {}, {}, {}}},
    {"GetByteArrayRegion", {PARAMS_NUMBER_FIVE, {}, {}, {}, {}, {{HEX_INDEX_FOUR, HEX_INDEX_THREE}}, {}}},
    {"SetByteArrayRegion", {PARAMS_NUMBER_FIVE, {}, {}, {}, {}, {{HEX_INDEX_FOUR, HEX_INDEX_THREE}}, {}}},
    {"GetByteArrayElements", {PARAMS_NUMBER_THREE, {}, {}, {}, {}, {}, {{HEX_INDEX_ZERO, HEX_INDEX_SPECIAL_32}}}},
};

void FuncPrinter::params_join(FUNC_CONTEXT *func_context, uint count) {
    func_context->info[func_context->info_n++] = '(';
    for (int i = 0; i < count; i++) {
        Utils::auto_snprintf(func_context->info_n, func_context->info, "0x%llx", func_context->cpu_context.x[i]);
        if (i != count - 1) {
            func_context->info[func_context->info_n++] = ',';
            func_context->info[func_context->info_n++] = ' ';
        }
    }
    func_context->info[func_context->info_n++] = ')';
}

void FuncPrinter::read_string(int& buff_n, char *buff, char* str, size_t max_len) {
    if ((uint64_t)str <= 0x1000) {
        return;
    }

    // AArch64 合法 userspace 指针通常 > 4GB，
    // 过滤被误当作字符串地址的整型参数（如 AT_FDCWD=-100=0xffffff9c、fd、flags 等）
    if ((uint64_t)str < 0x100000000ULL) {
        return;
    }

    gsize bytes_read = 0;
    guint8 *copy = gum_memory_read(str, max_len, &bytes_read);
    if (copy == nullptr) return;

    for (size_t i = 0; i < bytes_read && copy[i] != '\0'; i++) {
        buff[buff_n++] = static_cast<char>(copy[i]);
    }
    gum_free(copy);
}


void FuncPrinter::hexdump(int& buff_n, char *buff, uint64_t address, size_t count) {
    if (address < 0x100000000ULL) {
        return;
    }

    constexpr size_t MAX_HEXDUMP_BYTES = 64 * 1024;
    size_t requested = count == 0 ? 4096 : std::min(count, MAX_HEXDUMP_BYTES);
    gsize bytes_read = 0;
    guint8 *byte_ptr = gum_memory_read(reinterpret_cast<gconstpointer>(address),
                                       requested, &bytes_read);
    if (byte_ptr == nullptr || bytes_read == 0) return;

    count = count == 0 ? strnlen(reinterpret_cast<const char *>(byte_ptr), bytes_read)
                       : bytes_read;
    if (count == 0) {
        gum_free(byte_ptr);
        return;
    }

    Utils::auto_snprintf(buff_n, buff,
                         "\nhexdump at address 0x%llx with length 0x%llx:\n",
                         address, count);

    size_t offset = 0;
    size_t total_lines = (count + 15) / 16;  // 向上取整
    size_t current_line = 0;

    while (offset < count) {
        current_line++;

        Utils::auto_snprintf(buff_n, buff, "%llx: ", address + offset);

        char ascii[20];
        int ascii_n = 0;
        ascii[ascii_n++] = '|';
        for (size_t i = 0; i < 16; ++i) {
            if (offset + i < count) {
                guint8 byte = byte_ptr[offset + i];

                Utils::auto_snprintf(buff_n, buff, "%02x ", byte);
                ascii[ascii_n++] = std::isprint(static_cast<unsigned char>(byte))
                                     ? static_cast<char>(byte) : '.';
            } else {
                buff[buff_n++] = ' ';
                buff[buff_n++] = ' ';
                buff[buff_n++] = ' ';
                ascii[ascii_n++] = ' ';
            }
        }
        ascii[ascii_n++] = '|';
        ascii[ascii_n] = '\0';

        Utils::auto_snprintf(buff_n, buff, "%s", ascii);

        if (current_line < total_lines) {
            buff[buff_n++] = '\n';
        }

        offset += 16;
    }
    gum_free(byte_ptr);
}

void FuncPrinter::syscall(FUNC_CONTEXT *func_context) {
    auto *self = TraceqCapture::get_instance();
    uint64_t syscall_nr = func_context->cpu_context.x[0];
    static thread_local char fallback_name[32];

    func_context->info_n = 0;
    func_context->name = resolve_syscall_name(self, syscall_nr, fallback_name, sizeof(fallback_name));
    shift_syscall_wrapper_args(&func_context->cpu_context);
    before(func_context);
}


void FuncPrinter::before(FUNC_CONTEXT *func_context) {
    auto it = func_configs.find(func_context->name);
    if (it != func_configs.end() && it->second.special_handler) {
        return it->second.special_handler(func_context);
    }

    Utils::auto_snprintf(func_context->info_n, func_context->info, "call func: %s", func_context->name);

    auto capture = TraceqCapture::get_instance();
    if (capture->options.mode == TRACEQ_MODE_DEBUG) {
        LOGE("call func: %s", func_context->name);
    }

#if PLATFORM_IOS
    int params_number = 0;
    std::vector<uint64_t> string_vector;
    std::vector<int> string_index_vector;
    std::vector<std::array<int, 2>> hexdump_vector;
    const char *class_name = nullptr;
    id obj = nil;

    std::string func_name_str = func_context->name;

    if (func_name_str == "objc_storeStrong") {
        params_number = 2;
        uint64_t isa = 0;
        get_obj_isa_address(&isa, func_context->cpu_context.x[0], sizeof(isa));
        obj = (id)isa;
        class_name = object_getClassName(obj);
        string_vector.push_back((uint64_t)class_name);
    } else if (func_name_str == "objc_msgSend") {
        params_number = 2;
        uint64_t selector_ptr = func_context->cpu_context.x[1];  // selector
        const char *selector_name = sel_getName((SEL)selector_ptr);
        id target = (id)func_context->cpu_context.x[0];

        if (target == nil) {
            Utils::auto_snprintf(func_context->info_n, func_context->info, "[nil_target %s]", selector_name);
        } else {
            const char* gotClassName = get_class_name(target);
            size_t len1 = strlen(gotClassName);
            size_t len2 = strlen(selector_name);
            auto class_selector_name = (char*)malloc(len1 + len2 + 4);
            snprintf(class_selector_name, len1 + len2 + 4, "[%s %s]", gotClassName, selector_name);

            selector_func_general_print(func_context->info_n, func_context->info, &func_context->cpu_context, class_selector_name);
            Utils::auto_snprintf(func_context->info_n, func_context->info, "%s", class_selector_name);
            free(class_selector_name);
        }
    } else if (func_name_str == "objc_retainAutoreleasedReturnValue" || func_name_str == "objc_retainAutoreleaseReturnValue" || func_name_str == "objc_autorelease" ||
        func_name_str == "objc_release" || func_name_str == "objc_retain" || func_name_str == "objc_autoreleaseReturnValue") {
        params_number = 1;
        if ((id)func_context->cpu_context.x[0] != nil) {
            class_name = get_class_name((id)func_context->cpu_context.x[0]);
            string_vector.push_back((uint64_t)class_name);
            if (strstr(class_name, "FMDeviceSafeDictionary") == nullptr) {
                obj = (id)func_context->cpu_context.x[0];
            }
        }
    } else if (func_name_str == "NSClassFromString") {
        params_number = 1;
        if ((id)func_context->cpu_context.x[0] != nil) {
            obj = (id)func_context->cpu_context.x[0];
            class_name = object_getClassName(obj);
        }
    } else if (func_name_str == "CC_SHA256") {
        params_number = 2;
        hexdump_vector.push_back(std::array<int, 2>{0, 1});
    } else if (func_name_str == "CC_MD5") {
        params_number = 2;
        hexdump_vector.push_back(std::array<int, 2>{0, 1});
    }

    if (params_number > 0 || obj != nil || !string_vector.empty() || !hexdump_vector.empty()) {
         params_join(func_context, params_number);

         if (class_name != nullptr && obj != nil) {
             print_ios_object(func_context->info_n, func_context->info, obj);
         }

         for (int reg_index: string_index_vector) {
             Utils::auto_snprintf(func_context->info_n, func_context->info, "\narg %d: ", reg_index);
             read_string(func_context->info_n, func_context->info, (char*)func_context->cpu_context.x[reg_index]);
         }

         for (uint64_t str_address: string_vector) {
             Utils::auto_snprintf(func_context->info_n, func_context->info, "\nclass : ");
             read_string(func_context->info_n, func_context->info, (char*)str_address, 1024);
         }

         for (std::array<int, 2> reg_pair: hexdump_vector) {
             hexdump(func_context->info_n, func_context->info, func_context->cpu_context.x[reg_pair[0]], reg_pair[1] == 32 ? 0 : func_context->cpu_context.x[reg_pair[1]]);
         }

         func_context->info[func_context->info_n++] = '\n';
         return;
    }
#endif

    if (it == func_configs.end()) {
        params_join(func_context, 0);
        func_context->info[func_context->info_n++] = '\n';
        return;
    }

    const auto& config = it->second;
    params_join(func_context, config.params_number);

    for (int idx : config.string_indices) {
        Utils::auto_snprintf(func_context->info_n, func_context->info, "\nargs%d: ", idx);
        read_string(func_context->info_n, func_context->info, (char*)func_context->cpu_context.x[idx]);
    }

    for (const auto& reg_pair : config.hexdump_indices) {
        if (reg_pair[0] >= 0 && reg_pair[1] >= 0) {
            hexdump(func_context->info_n, func_context->info, func_context->cpu_context.x[reg_pair[0]], reg_pair[1] == HEX_INDEX_SPECIAL_32 ? 0 : func_context->cpu_context.x[reg_pair[1]]);
        }
    }


    // if (config.special_handler) {
    //     config.special_handler(func_context);
    //     return;
    // }

    func_context->info[func_context->info_n++] = '\n';
}

#if PLATFORM_ANDROID

void FuncPrinter::jni_before(FUNC_CONTEXT *func_context) {
    auto instance = TraceqCapture::get_instance();
    Utils::auto_snprintf(func_context->info_n, func_context->info,
                         "call jni func: %s", func_context->name);
    auto it = after_jni_func_configs.find(func_context->name);
    params_join(func_context, it == after_jni_func_configs.end()
                              ? 0 : it->second.params_number);
    func_context->info[func_context->info_n++] = '\n';

    if (instance->options.mode == TRACEQ_MODE_DEBUG) {
        LOGE("call jni func: %s", func_context->name);
    }
}

void FuncPrinter::jni_after(FUNC_CONTEXT *func_context, GumCpuContext *curr_cpu_context) {
    auto instance = TraceqCapture::get_instance();

    auto it = after_jni_func_configs.find(func_context->name);
    if (it != after_jni_func_configs.end()) {
        const auto& config = it->second;

        for (int reg_index: config.jni_string_indices) {
            auto jstr = (jstring)(func_context->cpu_context.x[reg_index]);
            const char *cstr = instance->jni_env->GetStringUTFChars(jstr, nullptr);
            Utils::auto_snprintf(func_context->info_n, func_context->info, "\nargs%d: ", reg_index);
            read_string(func_context->info_n, func_context->info, (char*)cstr);
            instance->jni_env->ReleaseStringUTFChars(jstr, cstr);
        }

        for (int reg_index: config.curr_jni_string_indices) {
            auto jstr = (jstring)(curr_cpu_context->x[reg_index]);
            const char *cstr = instance->jni_env->GetStringUTFChars(jstr, nullptr);
            Utils::auto_snprintf(func_context->info_n, func_context->info, "\nargs%d: ", reg_index);
            read_string(func_context->info_n, func_context->info, (char*)cstr);
            instance->jni_env->ReleaseStringUTFChars(jstr, cstr);
        }

        for (int reg_index : config.string_indices) {
            Utils::auto_snprintf(func_context->info_n, func_context->info, "\nargs%d: ", reg_index);
            read_string(func_context->info_n, func_context->info, (char*)func_context->cpu_context.x[reg_index]);
        }

        for (int reg_index : config.curr_string_indices) {
            Utils::auto_snprintf(func_context->info_n, func_context->info, "\nargs%d: ", reg_index);
            read_string(func_context->info_n, func_context->info, (char*)curr_cpu_context->x[reg_index]);
        }

        for (std::array<int, 2> reg_pair: config.hexdump_indices) {
            hexdump(func_context->info_n, func_context->info, func_context->cpu_context.x[reg_pair[0]], reg_pair[1] == HEX_INDEX_SPECIAL_32 ? 0 : func_context->cpu_context.x[reg_pair[1]]);
        }

        for (std::array<int, 2> reg_pair: config.curr_hexdump_indices) {
            hexdump(func_context->info_n, func_context->info, curr_cpu_context->x[reg_pair[0]], reg_pair[1] == HEX_INDEX_SPECIAL_32 ? 0 : curr_cpu_context->x[reg_pair[1]]);
        }
    }

    if (strcmp(func_context->name, "FindClass") == 0 || strcmp(func_context->name, "DefineClass") == 0) {
        char jclass_name[1024] = {0};
        int jclass_name_n = 0;
        read_string(jclass_name_n, jclass_name, (char*)func_context->cpu_context.x[1],
                    sizeof(jclass_name) - 1);
        jclass_name[jclass_name_n] = '\0';
        if (jclass_name_n > 0) {
            instance->jni_classes[curr_cpu_context->x[0]] = jclass_name;
        }
    } else if (strcmp(func_context->name, "GetMethodID") == 0 || strcmp(func_context->name, "GetStaticMethodID") == 0) {
        char jmethod_name[4096] = {0};
        int jmethod_name_n = 0;

        read_string(jmethod_name_n, jmethod_name, (char*)func_context->cpu_context.x[2],
                    sizeof(jmethod_name) - 1);
        jmethod_name[jmethod_name_n] = '\0';
        if (jmethod_name_n > 0) {
            instance->jni_methods[curr_cpu_context->x[0]] = jmethod_name;
        }

        if (instance->jni_classes.count(func_context->cpu_context.x[1]) > 0) {
            auto jclass_name = instance->jni_classes[func_context->cpu_context.x[1]];

            Utils::auto_snprintf(func_context->info_n, func_context->info, "\njclass: %s", jclass_name.c_str());
            instance->jni_methods_classes[curr_cpu_context->x[0]] = jclass_name;
        }
    }

    if (call_jni_methods.count(func_context->name) > 0) {
        if (instance->jni_classes.count(func_context->cpu_context.x[1]) > 0) {
             Utils::auto_snprintf(func_context->info_n, func_context->info, "\njclass: %s", instance->jni_classes[func_context->cpu_context.x[1]].c_str());
        }

        if (instance->jni_methods.count(func_context->cpu_context.x[2]) > 0) {
            Utils::auto_snprintf(func_context->info_n, func_context->info, "\njmethod: %s", instance->jni_methods[func_context->cpu_context.x[2]].c_str());

            if (instance->jni_methods_classes.count(func_context->cpu_context.x[2]) > 0) {
                 Utils::auto_snprintf(func_context->info_n, func_context->info, "\njclass: %s", instance->jni_methods_classes[func_context->cpu_context.x[2]].c_str());
            }
        }
    }

    if (func_context->info_n > 0 && func_context->info[0] == '\n') {
        memmove(func_context->info, func_context->info + 1, --func_context->info_n);
    }
    if (func_context->info_n > 0 && func_context->info[func_context->info_n - 1] != '\n') {
        Utils::append_char(func_context->info, func_context->info_n, '\n');
    }
    Utils::append_string(func_context->info, func_context->info_n, "ret: 0x");
    Utils::append_uint64_hex(func_context->info, func_context->info_n, curr_cpu_context->x[0]);
    func_context->info[func_context->info_n++] = '\n';
}

#endif

void FuncPrinter::after(FUNC_CONTEXT *func_context, GumCpuContext *curr_cpu_context) {
    Utils::append_string(func_context->info, func_context->info_n, "ret: 0x");
    Utils::append_uint64_hex(func_context->info, func_context->info_n, curr_cpu_context->x[0]);
    func_context->info[func_context->info_n++] = '\n';
}

#if PLATFORM_IOS
#include <objc/runtime.h>
#include <objc/message.h>

void FuncPrinter::get_obj_isa_address(uint64_t *isa, uint64_t address, size_t size) {
    memcpy(isa, (void*)address, size);
}

void FuncPrinter::print_ios_dictionary(int& buff_n, char* buff, id obj, const char *class_name, int indent_level) {
    @autoreleasepool {
        NSDictionary *dict = (NSDictionary *)obj;
        NSUInteger count = [dict count];

        Utils::append_char(buff, buff_n, '\n');
        for (int i = 0; i < indent_level * 2; ++i) Utils::append_char(buff, buff_n, ' ');
        Utils::append_char(buff, buff_n, '{');

        if (count == 0) {
            Utils::append_string(buff, buff_n, "}");
            return;
        }

        BOOL first = YES;
        NSArray *keys = [dict allKeys];

        if ([keys count] > 0 && [[keys firstObject] isKindOfClass:[NSString class]]) {
            keys = [keys sortedArrayUsingSelector:@selector(compare:)];
        }

        for (id key in keys) {
            id value = [dict objectForKey:key];

            if (!first) {
                Utils::append_string(buff, buff_n, ",");
            }
            Utils::append_char(buff, buff_n, '\n');
            for (int i = 0; i < (indent_level + 1) * 2; ++i) Utils::append_char(buff, buff_n, ' ');

            if ([key isKindOfClass:[NSString class]]) {
                Utils::auto_snprintf(buff_n, buff, "\"%s\"", [key UTF8String]);
            } else if ([key isKindOfClass:[NSNumber class]]) {
                Utils::auto_snprintf(buff_n, buff, "%s", [[key stringValue] UTF8String]);
            } else {
                Utils::auto_snprintf(buff_n, buff, "%s", object_getClassName(key));
            }

            Utils::append_string(buff, buff_n, ": ");
            print_ios_object(buff_n, buff, value, indent_level + 1);

            first = NO;
        }

        Utils::append_char(buff, buff_n, '\n');
        for (int i = 0; i < indent_level * 2; ++i) Utils::append_char(buff, buff_n, ' ');
        Utils::append_char(buff, buff_n, '}');
    }
}

void FuncPrinter::print_ios_array(int& buff_n, char* buff, id obj, const char *class_name, int indent_level) {
    @autoreleasepool {
        NSArray *array = (NSArray *)obj;
        NSUInteger count = [array count];

        Utils::append_char(buff, buff_n, '\n');
        for (int i = 0; i < indent_level * 2; ++i) Utils::append_char(buff, buff_n, ' ');
        Utils::append_char(buff, buff_n, '[');

        if (count == 0) {
            Utils::append_string(buff, buff_n, "]");
            return;
        }

        for (NSUInteger i = 0; i < count; i++) {
            if (i > 0) {
                Utils::append_string(buff, buff_n, ",");
            }

            Utils::append_char(buff, buff_n, '\n');
            for (int j = 0; j < (indent_level + 1) * 2; ++j) Utils::append_char(buff, buff_n, ' ');

            id element = [array objectAtIndex:i];
            print_ios_object(buff_n, buff, element, indent_level + 1);
        }

        Utils::append_char(buff, buff_n, '\n');
        for (int i = 0; i < indent_level * 2; ++i) Utils::append_char(buff, buff_n, ' ');
        Utils::append_char(buff, buff_n, ']');
    }
}

void FuncPrinter::print_ios_string(int& buff_n, char* buff, id obj, const char *class_name, int indent_level) {
    @autoreleasepool {
        NSString *str = (NSString *)obj;
        NSUInteger length = [str length];

        if (indent_level == 0) {
            Utils::append_string(buff, buff_n, "\n");
        }

        if (length > 1024) {
            NSString *truncated = [str substringToIndex:1021];
            Utils::auto_snprintf(buff_n, buff, "\"%s...\"", [truncated UTF8String]);
        } else {
            NSString *escaped = [[str stringByReplacingOccurrencesOfString:@"\"" withString:@"\\\""]
                                stringByReplacingOccurrencesOfString:@"\n" withString:@"\\n"];
            Utils::auto_snprintf(buff_n, buff, "\"%s\"", [escaped UTF8String]);
        }
    }
}

void FuncPrinter::print_ios_data(int& buff_n, char* buff, id obj, const char *class_name, int indent_level) {
    @autoreleasepool {
        NSData *data = (NSData *)obj;
        NSUInteger length = [data length];
        if (length == 0) {
            Utils::append_string(buff, buff_n, "null");
        } else {
            auto bytes = (uint64_t)[data bytes];
            hexdump(buff_n, buff, bytes, (size_t)length);
        }
    }
}

void FuncPrinter::print_ios_number(int& buff_n, char* buff, id obj, const char *class_name, int indent_level) {
    @autoreleasepool {
        NSNumber *number = (NSNumber *)obj;

        if (indent_level == 0) {
            Utils::append_string(buff, buff_n, "\n");
        }

        Utils::append_string(buff, buff_n, [[number stringValue] UTF8String]);

        const char *type = [number objCType];
        if (strcmp(type, @encode(int)) == 0) {
            Utils::append_string(buff, buff_n, "(int)");
        } else if (strcmp(type, @encode(long)) == 0) {
            Utils::append_string(buff, buff_n, "(long)");
        } else if (strcmp(type, @encode(double)) == 0) {
            Utils::append_string(buff, buff_n, "(double)");
        } else if (strcmp(type, @encode(float)) == 0) {
            Utils::append_string(buff, buff_n, "(float)");
        } else if (strcmp(type, @encode(BOOL)) == 0) {
            Utils::append_string(buff, buff_n, "(bool)");
        }
    }
}

void FuncPrinter::print_ios_null(int& buff_n, char* buff, id obj, const char *class_name, int indent_level) {
    Utils::append_string(buff, buff_n, "\nnull");
}

void FuncPrinter::print_ios_object(int& buff_n, char* buff, id obj, int indent_level) {
    if (obj == nil) {
        Utils::append_string(buff, buff_n, "\nnull");
        return;
    }

    @autoreleasepool {
        const char *class_name = object_getClassName(obj);

        if ([obj isKindOfClass:[NSDictionary class]]) {
            print_ios_dictionary(buff_n, buff, obj, class_name, indent_level);
        } else if ([obj isKindOfClass:[NSArray class]]) {
            print_ios_array(buff_n, buff, obj, class_name, indent_level);
        } else if ([obj isKindOfClass:[NSString class]]) {
            print_ios_string(buff_n, buff, obj, class_name, indent_level);
        } else if ([obj isKindOfClass:[NSNumber class]]) {
            print_ios_number(buff_n, buff, obj, class_name, indent_level);
        } else if ([obj isKindOfClass:[NSData class]]) {
            print_ios_data(buff_n, buff, obj, class_name, indent_level);
        } else if (obj == [NSNull null]) {
            print_ios_null(buff_n, buff, obj, class_name, indent_level);
        } else {
            Utils::auto_snprintf(buff_n, buff, "\n%s", class_name);

            NSString *desc = [obj description];
            if (desc && ![desc isEqualToString:@""] && ![desc hasPrefix:@"<"] && [desc length] < 100) {
                Utils::auto_snprintf(buff_n, buff, "(\"%s\")", [desc UTF8String]);
            }
        }
    }
}

void FuncPrinter::selector_func_general_print(int& buff_n, char* buff, GumCpuContext *cpu_context, const char *class_selector_name) {
    // Placeholder or implementation if needed
}

const char * FuncPrinter::get_class_name(id target) {
    if (target == nil) {
        return nullptr;
    }

    Class targetClass = object_getClass(target);
    BOOL isMetaClass = class_isMetaClass(targetClass);
    NSString *className = nullptr;
    if (isMetaClass) {
        className = NSStringFromClass((Class)target);
    } else {
        className = NSStringFromClass([target class]);
    }

    return [className UTF8String];
}
#endif
