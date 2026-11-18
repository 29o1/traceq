#pragma once

#include <stdbool.h>
#include <stdint.h>

typedef struct _GumStalkerIterator GumStalkerIterator;
typedef struct _GumStalkerOutput GumStalkerOutput;

#ifdef __cplusplus
extern "C" {
#endif
// Independent lab entry. The owner thread begins, follows, unfollows and ends.
// mode: 0 flat, 1 buffered flat, 2 chunks. observation: 0 reference, 1 banked, 2 fused.
bool traceq_capture_begin(const char* path, uint64_t code, uint64_t code_size,
                          uint64_t data, uint64_t data_size, uint32_t profile,
                          uint32_t observation, uint32_t mode, bool external_followed);
bool traceq_capture_end(void);
void traceq_capture_transform(GumStalkerIterator*, GumStalkerOutput*, void*);
#ifdef __cplusplus
}
#endif
