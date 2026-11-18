#pragma once
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
// Single active session. The native adapter returns normally on this thread;
// its own exact target prototype handles arguments, return values and sret.
typedef void (*TraceqInvoke)(void* context);
typedef struct TraceqInvokeReport {
    uint64_t version,status,thread_id;
    // target_ns is the native adapter interval, including its typed target call.
    uint64_t setup_ns,follow_ns,target_ns,unfollow_ns,finish_ns,cleanup_ns,total_ns;
    uint64_t instructions,reads,writes,gaps,commits,code_base,code_size;
} TraceqInvokeReport;
// observation:0 native,1 reference,2 banked,3 fused. External execution is
// followed for reentry; only module_name instructions/data facts are recorded.
// Results belong to context; status reports capture completion, not target success.
int traceq_capture_invoke(const char* path,const char* module_name,TraceqInvoke invoke,
                         void* context,uint32_t observation,TraceqInvokeReport* report);
// Select the full loaded module containing module_address, useful when names
// or paths identify multiple instances. The address is an anchor, not a new
// entrypoint: invoke still calls the exact target prototype supplied by caller.
// Keep the target mapping/adapter alive for the call. Zero address returns -1;
// no containing module returns -2. Other errors and report layout are unchanged.
int traceq_capture_invoke_at(const char* path,uint64_t module_address,TraceqInvoke invoke,
                            void* context,uint32_t observation,TraceqInvokeReport* report);
// Opt-in additional code spans, copied before following. At most63 extras;
// base/size must be nonzero,4-byte aligned and nonwrapping. Adjacent/overlapping
// intervals coalesce. Keep mappings alive until return. No implicit widening:
// holes stay unobserved and outside calls retain their gap/unknown semantics.
// report.code_base/code_size are the union envelope; trace CodeRange metadata
// lists exact intervals. Observed code addresses/opcodes are recorded, with no relocation
// remapping. Zero extras preserves invoke_at behavior. Invalid shape returns-1.
typedef struct TraceqCodeRange { uint64_t base,size; } TraceqCodeRange;
int traceq_capture_invoke_ranges_at(const char* path,uint64_t module_address,
                                  TraceqInvoke invoke,void* context,uint32_t observation,
                                  const TraceqCodeRange* extra,uint32_t extra_count,
                                  TraceqInvokeReport* report);
#ifdef __cplusplus
}
#endif
