//
// Created by lidongyooo on 2026/2/6.
//

#ifndef TRACEQ_CALLBACKCONTEXT_H
#define TRACEQ_CALLBACKCONTEXT_H
#include "Utils.h"

struct CALLBACK_CTX {
    std::string module_name;
    uint64_t module_base;
    unsigned int instruction_id;
    char mnemonic[32] = {};
    char op_str[160] = {};
    cs_arm64 arm64{};
};

class CallbackContext {
public:
    static CALLBACK_CTX* create(const cs_insn* instruction, const char* module_name,
                                uint64_t module_base);
    static void destroy(gpointer data);
};

#endif //TRACEQ_CALLBACKCONTEXT_H
