#pragma once
#include "AndroidCapture.h"
#include "GumPlatform.h"
#ifdef __cplusplus
extern "C" {
#endif
// Independent lab entry. mode:0 flat,1 buffered flat,2 chunks;
// observation:0 reference,1 banked,2 fused. Begin/end on one owning thread.
bool traceq_capture_begin(const char* path,uint64_t code,uint64_t code_size,
    uint64_t data,uint64_t data_size,uint32_t profile,uint32_t observation,
    uint32_t mode,bool external_followed);
bool traceq_capture_end(void);
void traceq_capture_transform(GumStalkerIterator*,GumStalkerOutput*,void*);
#ifdef __cplusplus
}
#endif
