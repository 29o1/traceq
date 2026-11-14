#pragma once
#include "Utils.h"
#include "RecordBuffer.h"

// Opt-in experiment. Begin/end must surround exactly one controlled call on
// the current thread, after Gum initialization and before engine destruction.
// The code and data ranges must remain mapped and stable during the call.
bool traceq_writes_begin(const char* path, uintptr_t code, size_t code_size,
                          uintptr_t data, size_t data_size, bool execution_state = false,
                          bool external_followed = false);
// external_followed declares that the caller has not excluded external ranges
// from Stalker. It does not expand the recorded code range or promise memory effects.
bool traceq_writes_end();
bool traceq_writes_active();
void traceq_writes_instrument(GumStalkerIterator* it, const cs_insn* ins);
// Configure only while inactive. Legacy remains the default and readable.
bool traceq_writes_storage(TraceqStorageOptions options);

enum class TraceqObservation { Reference, Banked, Fused };
// All modes observe the same 65 register slots. Fused shares a snapshot only
// at an adjacent post/pre boundary inside one translated block.
bool traceq_writes_observation(TraceqObservation mode);
bool traceq_writes_transform_block(GumStalkerIterator* iterator);
struct TraceqCaptureSummary {
    uint64_t instructions,reads,writes,gaps,commits;
};
TraceqCaptureSummary traceq_writes_summary();

#ifdef TRACEQ_CAPTURE_PERF
// Diagnostic runs deliberately omit parts of collection; not usable as traces.
enum class TraceqProbe { Full, Engine, Callbacks, Observe, ThreadCheck, OwnerCheck };
void traceq_writes_probe(TraceqProbe mode);
void traceq_writes_thread_id_probe(bool enabled);
uint64_t traceq_writes_instruction_count();
struct TraceqObservationStats {
    uint64_t before_calls=0,after_calls=0,fused_calls=0,snapshots=0;
    uint64_t scalar_comparisons=0,vector_comparisons=0,reused_pre=0;
    uint64_t block_tail_flushes=0;
};
TraceqObservationStats traceq_writes_observation_stats();
struct TraceqStorageStats { uint64_t blocks,events,encoded_bytes,encode_ns,write_ns; };
TraceqStorageStats traceq_writes_storage_stats();
#endif
