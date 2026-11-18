#pragma once
// Native fixture/expectation glue only. Classification calls the Rust product.
#include "frida-gum.h"
#include <cstring>
#include <initializer_list>
extern "C" bool traceq_lab_supported(const cs_insn* ins);
struct Plan { bool unsupported; };
static inline Plan* make_plan(const cs_insn* ins) {
    return new Plan{!traceq_lab_supported(ins)};
}
