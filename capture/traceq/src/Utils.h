//
// Created by lidongyooo on 2026/2/6.
//

#ifndef TRACEQ_UTILS_H
#define TRACEQ_UTILS_H
#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <fstream>
#include <array>
#include <sstream>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include "platform.h"
#include <pthread.h>
#include <sys/stat.h>

#define LOG_TAG "traceq"

#if defined(TRACEQ_HOST_LAB)
// Host-only experiment build; production Android/iOS headers stay unchanged.
#include "frida-gum.h"
#include <Foundation/Foundation.h>
#include <cstdio>
#define LOGE(fmt, ...) fprintf(stderr, "[traceq] " fmt "\n", ##__VA_ARGS__)
#else
#if PLATFORM_IOS

#include "../libs/FridaGum-IOS-17.8.3.h"
#include <Foundation/Foundation.h>
#define LOGE(fmt, ...) NSLog(@"[ERROR] %s: " @fmt, LOG_TAG, ##__VA_ARGS__)

#else

#include "../libs/FridaGum-Android-17.8.3.h"
#include <jni.h>
#include <android/log.h>
#define LOGE(fmt, ...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, fmt, ##__VA_ARGS__)

#endif
#endif // TRACEQ_HOST_LAB

#define PAGE_SIZE 4096

#define PAGE_ALIGN_DOWN(addr) \
((uintptr_t)(addr) & ~(SYSTEM_PAGE_SIZE - 1))

#define PAGE_ALIGN_UP(addr) \
(((uintptr_t)(addr) + SYSTEM_PAGE_SIZE - 1) & ~(SYSTEM_PAGE_SIZE - 1))

extern const std::vector<std::string> svc_names;
extern const std::vector<std::string> jni_func_names;

class Utils {
public:
    // Operand WRITE may describe base writeback on a load, not a memory store.
    static bool memory_direction(const char* mnemonic, bool& reads, bool& writes) {
        const char* loads[] = {"ldr","ldrb","ldrh","ldrsb","ldrsh","ldrsw",
            "ldur","ldurb","ldurh","ldursb","ldursh","ldursw","ldp","ldnp","ldpsw",
            "ldar","ldarb","ldarh","ldxr","ldxrb","ldxrh","ldaxr","ldaxrb","ldaxrh","ldxp","ldaxp"};
        const char* stores[] = {"str","strb","strh","stur","sturb","sturh","stp","stnp",
            "stlr","stlrb","stlrh","stxr","stxrb","stxrh","stlxr","stlxrb","stlxrh","stxp","stlxp"};
        for (const char* m : loads) if (!strcmp(mnemonic,m)) { reads=true; writes=false; return true; }
        for (const char* m : stores) if (!strcmp(mnemonic,m)) { reads=false; writes=true; return true; }
        return false;
    }
    static std::vector<std::string> str_split(const std::string& s, char symbol);
    static int get_data_width(cs_insn *insn, cs_arm64 *arm64);
    static bool get_register_value(arm64_reg reg, _GumArm64CpuContext *ctx, __uint128_t &value);
    static const char *get_arm64_reg_name(arm64_reg reg);
    static void format_uint128_hex(__uint128_t value, int& counter, char* buff);
    static void auto_snprintf(int& counter, char* buff, const char* __restrict __format, ...);

    static inline void append_string(char* buff, int& counter, const char* str) {
        if (!str) return;
        while (*str) {
            buff[counter++] = *str++;
        }
    }

    static inline void append_char(char* buff, int& counter, char c) {
        buff[counter++] = c;
    }

    static void append_uint64_hex(char* buff, int& counter, uint64_t val);
    static void append_uint64_hex_fixed(char* buff, int& counter, uint64_t val);

    static inline uintptr_t apply_shift(__uint128_t value, arm64_shifter type, unsigned int amount) {
        uintptr_t val = (uintptr_t)value;
        if (amount == 0) return val;
        switch (type) {
            case ARM64_SFT_LSL:
                return val << amount;
            case ARM64_SFT_LSR:
                return val >> amount;
            case ARM64_SFT_ASR:
                return (uintptr_t)((intptr_t)val >> amount);
            case ARM64_SFT_ROR:
                return (val >> amount) | (val << (64 - amount));
            case ARM64_SFT_MSL:
                return (val << amount) | ((1ULL << amount) - 1);
            default:
                return val;
        }
    }

    static inline uintptr_t apply_extend_and_shift(__uint128_t value, arm64_extender ext,
                                                   arm64_shifter shift, unsigned int amount) {
        uint64_t extended = static_cast<uint64_t>(value);
        switch (ext) {
            case ARM64_EXT_UXTB: extended = static_cast<uint8_t>(extended); break;
            case ARM64_EXT_UXTH: extended = static_cast<uint16_t>(extended); break;
            case ARM64_EXT_UXTW: extended = static_cast<uint32_t>(extended); break;
            case ARM64_EXT_SXTB: extended = static_cast<uint64_t>(static_cast<int64_t>(static_cast<int8_t>(extended))); break;
            case ARM64_EXT_SXTH: extended = static_cast<uint64_t>(static_cast<int64_t>(static_cast<int16_t>(extended))); break;
            case ARM64_EXT_SXTW: extended = static_cast<uint64_t>(static_cast<int64_t>(static_cast<int32_t>(extended))); break;
            case ARM64_EXT_SXTX: extended = static_cast<uint64_t>(static_cast<int64_t>(extended)); break;
            case ARM64_EXT_UXTX:
            case ARM64_EXT_INVALID:
            default: break;
        }
        return apply_shift(extended, shift, amount);
    }
};


#endif //TRACEQ_UTILS_H
