#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Single active session. The native adapter returns normally on this thread;
// its own exact target prototype handles arguments, return values and sret.
typedef void (*TraceqInvoke)(void* context);

typedef struct TraceqInvokeReport {
    uint64_t version;
    uint64_t status;
    uint64_t thread_id;
    // target_ns is the native adapter interval, including its typed target call.
    uint64_t setup_ns;
    uint64_t follow_ns;
    uint64_t target_ns;
    uint64_t unfollow_ns;
    uint64_t finish_ns;
    uint64_t cleanup_ns;
    uint64_t total_ns;
    uint64_t instructions;
    uint64_t reads;
    uint64_t writes;
    uint64_t gaps;
    uint64_t commits;
    uint64_t code_base;
    uint64_t code_size;
} TraceqInvokeReport;

// Observation: 0 native, 1 reference, 2 banked, 3 fused. External execution is
// followed for reentry; only module_name instructions/data facts are recorded.
// Results belong to context; status reports capture completion.
int traceq_capture_invoke(const char* path, const char* module_name, TraceqInvoke invoke,
                         void* context, uint32_t observation, TraceqInvokeReport* report);

// Select the full loaded module containing module_address, useful when names
// or paths identify multiple instances. Use the address as a module anchor and
// supply the exact target call in the adapter. Keep the mapping and adapter
// alive until return. Zero address returns -1; no containing module returns -2.
int traceq_capture_invoke_at(const char* path, uint64_t module_address, TraceqInvoke invoke,
                            void* context, uint32_t observation, TraceqInvokeReport* report);

// Opt-in additional code spans. At most 63 extras, copied before following.
// Base and size must be nonzero, 4-byte aligned and nonwrapping. Adjacent or
// overlapping intervals coalesce. Keep mappings alive until return. Holes stay
// unobserved and outside calls retain their gap/unknown semantics.
// The report gives the union envelope; CodeRange metadata lists exact intervals.
// The trace uses observed code addresses and opcodes. Zero extras preserves
// invoke_at behavior. Invalid shape returns -1.
typedef struct TraceqCodeRange {
    uint64_t base;
    uint64_t size;
} TraceqCodeRange;

int traceq_capture_invoke_ranges_at(const char* path, uint64_t module_address,
                                   TraceqInvoke invoke, void* context, uint32_t observation,
                                   const TraceqCodeRange* extra, uint32_t extra_count,
                                   TraceqInvokeReport* report);

#ifdef __cplusplus
}
#endif
