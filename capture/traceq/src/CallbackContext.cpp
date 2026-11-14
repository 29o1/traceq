//
// Created by lidongyooo on 2026/2/6.
//

#include "CallbackContext.h"

CALLBACK_CTX* CallbackContext::create(const cs_insn* instruction, const char* module_name,
                                      uint64_t module_base) {
    auto *ctx = new CALLBACK_CTX();
    ctx->module_name = module_name;
    ctx->module_base = module_base;
    ctx->instruction_id = instruction->id;
    memcpy(ctx->mnemonic, instruction->mnemonic, sizeof(ctx->mnemonic));
    memcpy(ctx->op_str, instruction->op_str, sizeof(ctx->op_str));
    if (instruction->detail) {
        memcpy(&ctx->arm64, &instruction->detail->arm64, sizeof(ctx->arm64));
    }
    return ctx;
}

void CallbackContext::destroy(gpointer data) {
    delete static_cast<CALLBACK_CTX *>(data);
}
