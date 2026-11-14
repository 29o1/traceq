//
// Created by lidongyooo on 2026/2/6.
//

#ifndef TRACEQ_CAPTURE_H
#define TRACEQ_CAPTURE_H

#include "Utils.h"
#include "CallbackContext.h"

struct REG_LIST {
    int num = 0;
    arm64_reg regs[31] = {};

    void add(arm64_reg reg) {
        if (reg == ARM64_REG_INVALID) return;
        for (int i = 0; i < num; i++) {
            if (regs[i] == reg) return;
        }
        if (num < 31) regs[num++] = reg;
    }
};


typedef enum {
    TRACEQ_MODE_STANDARD = 0,
    TRACEQ_MODE_DEBUG,
    TRACEQ_MODE_STABLE
} TraceqCaptureMode;

struct TraceqCaptureOptions {
    uint64_t mode;
};

#define BUFFER_SIZE (1024 * 1024 * 50)

struct FUNC_CONTEXT {
    uint64_t address = 0;
    const char* name = nullptr;
    char info[BUFFER_SIZE] = {};
    int info_n = 0;
    bool call = false;
    bool is_jni = false;
    GumCpuContext cpu_context{};
};

struct CALL_FRAME {
    uint64_t return_address;
    std::string name;
    bool is_jni;
    GumCpuContext cpu_context;
};

class TraceqCapture {
public:
    static TraceqCapture *get_instance();
    std::map<std::string, std::map<std::string, std::size_t>> modules;
    char trace_file_path[256];
    std::ofstream trace_file;
    int trace_thread_id;
    int trace_flush = 0;
    std::unordered_map<size_t, std::string> func_maps;
    FUNC_CONTEXT last_func_context = {};

    GumStalker* _stalker = nullptr;
    GumStalkerTransformer* _transformer = nullptr;

    static void transform_callback(GumStalkerIterator *iterator, GumStalkerOutput *output, gpointer user_data);
    const std::string* in_range_module(size_t address);
    const std::map<std::string, std::size_t>& get_module_by_name(const std::string &module_name);
    void follow();
    void unfollow();
    void reset_session();

    static void callout_callback(GumCpuContext *cpu_context, gpointer user_data);

    char buffer[BUFFER_SIZE] = {};
    int buffer_offset = 0;
    REG_LIST write_reg_list;
    std::vector<CALL_FRAME> call_stack;

    struct CachedModule {
        const std::string* name;
        size_t base;
        size_t end;
    } last_module_cache;

    TraceqCaptureOptions options;
    std::unordered_map<size_t, std::string> svc_func_maps;
    std::unordered_map<size_t, std::string> func_fds;

    uintptr_t atomic_addr = 0;
    int atomic_width = 0;
    uintptr_t atomic_counter = 10;

#if PLATFORM_ANDROID
    JNIEnv *get_run_time_env();


    JavaVM *java_vm = nullptr;
    JNIEnv *jni_env = nullptr;
    bool jni_env_init = false;
    std::unordered_map<size_t, std::string> jni_func_maps;
    std::unordered_map<size_t, std::string> jni_classes;
    std::unordered_map<size_t, std::string> jni_methods;
    std::unordered_map<size_t, std::string> jni_methods_classes;
#    endif



private:
    TraceqCapture();

    ~TraceqCapture();

    TraceqCapture(const TraceqCapture &) = delete;

    TraceqCapture &operator=(const TraceqCapture &) = delete;
};


#endif //TRACEQ_CAPTURE_H
