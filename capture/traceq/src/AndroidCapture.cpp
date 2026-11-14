// Native call bridge for bounded Android capture. Follow/invoke/unfollow stay
// in this function and on the same native thread; no hook patches the target.
#include "TraceqCapture.h"
#include "WriteStream.h"
#include <ctime>
#include <cstring>
#include <limits>

struct TraceqObject24 { void* vtable;uint32_t capacity,length;void* data; };
static_assert(sizeof(TraceqObject24)==24,"AAPCS64 indirect-result object");
using Sret3=TraceqObject24(*)(const TraceqObject24*,uint32_t,uint64_t);
struct TraceqAndroidReport {
    uint64_t version,status,thread_id,target_ns,total_ns;
    uint64_t instructions,reads,writes,gaps,commits;
    uint64_t code_base,code_size,input_object,output_object;
};
static bool follow_external=false;
extern "C" __attribute__((visibility("default")))
int traceq_capture_external_flow(uint32_t enabled) {
    if(enabled>1 || traceq_writes_active())return -1;
    follow_external=enabled!=0;return 0;
}
static uint64_t now_ns() {
    timespec t{};clock_gettime(CLOCK_MONOTONIC,&t);
    return uint64_t(t.tv_sec)*1000000000+uint64_t(t.tv_nsec);
}
#ifdef TRACEQ_CAPTURE_PERF
// Stages: 0 full, 1 engine, 2 callouts, 3 observe, 4 encode/discard,
// 5 full/flush clocks, 6 thread-id checks, 7 thread-local owner checks,
// 8 full capture with the old per-instruction thread-id guard for interleaved A/B.
static uint32_t perf_stage=0;
struct TraceqPerfReport {
    uint64_t version,stage,setup_ns,follow_ns,target_ns,unfollow_ns,finish_ns,cleanup_ns;
    uint64_t before_calls,after_calls,fused_calls,snapshots,scalar_comparisons,vector_comparisons,reused_pre,block_tail_flushes;
    uint64_t blocks,events,encoded_bytes,encode_ns,write_ns;
} perf_report{};
extern "C" __attribute__((visibility("default")))
int traceq_capture_perf_config(uint32_t stage) {
    if(stage>8 || traceq_writes_active())return -1;
    perf_stage=stage;return 0;
}
extern "C" __attribute__((visibility("default")))
int traceq_capture_perf_report(void* report,uint32_t bytes) {
    if(!report || bytes!=sizeof perf_report)return -1;
    memcpy(report,&perf_report,sizeof perf_report);return 0;
}
#endif
static gboolean exclude_other(GumModule* module,gpointer opaque) {
    const auto* range=static_cast<const GumMemoryRange*>(opaque);
    auto* r=gum_module_get_range(module);
    if(!(range->base_address>=r->base_address && range->base_address-r->base_address<r->size))
        gum_stalker_exclude(TraceqCapture::get_instance()->_stalker,r);
    return TRUE;
}

extern "C" __attribute__((visibility("default")))
int traceq_capture_sret3(const char* path,const char* module_name,uint64_t offset,
                       const TraceqObject24* input,uint32_t argument,uint64_t timestamp,
                       TraceqObject24* output,uint32_t observation,TraceqAndroidReport* report) {
    if(!report || !module_name || !input || !output || observation>3 || (observation && !path))return -1;
#ifdef TRACEQ_CAPTURE_PERF
    const auto setup_started=now_ns();perf_report={};perf_report.version=1;perf_report.stage=perf_stage;
#endif
    memset(report,0,sizeof *report);report->version=1;
    gum_init();
    auto* module=gum_process_find_module_by_name(module_name);if(!module)return -2;
    auto range=*gum_module_get_range(module);g_object_unref(module);
    if(offset>=range.size || offset%4)return -3;
    auto fn=reinterpret_cast<Sret3>(range.base_address+offset);
    auto* g=TraceqCapture::get_instance();g->reset_session();
    report->code_base=range.base_address;report->code_size=range.size;
    report->thread_id=gum_process_get_current_thread_id();report->input_object=reinterpret_cast<uintptr_t>(input);
    if(observation) {
        g->_stalker=gum_stalker_new();g->trace_thread_id=0;g->options.mode=TRACEQ_MODE_STANDARD;
        gum_stalker_set_trust_threshold(g->_stalker,1);
        gum_stalker_set_ratio(g->_stalker,2);
        g->modules[module_name]["base"]=range.base_address;g->modules[module_name]["size"]=range.size;
        if(!follow_external)gum_process_enumerate_modules(exclude_other,&range);
        const auto mode=observation==3?TraceqObservation::Fused:
                        observation==2?TraceqObservation::Banked:TraceqObservation::Reference;
        TraceqStorageOptions storage{TraceqStorage::ChunkCpp,false};
#ifdef TRACEQ_CAPTURE_PERF
        traceq_writes_probe(perf_stage==7?TraceqProbe::OwnerCheck:perf_stage==6?TraceqProbe::ThreadCheck:perf_stage==1?TraceqProbe::Engine:perf_stage==2?TraceqProbe::Callbacks:
                             perf_stage==3?TraceqProbe::Observe:TraceqProbe::Full);
        traceq_writes_thread_id_probe(perf_stage==8);
        storage.discard=perf_stage==4;storage.time_flush=perf_stage==5;
#endif
        if(!traceq_writes_storage(storage) || !traceq_writes_observation(mode))return -4;
        // The module touches heap, stack and static data. This declares an
        // address scope, not a snapshot or a claim about unobserved writers.
        if(!traceq_writes_begin(path,range.base_address,range.size,0,UINT64_MAX,true,follow_external))return -5;
    }
    const uint64_t start=now_ns();if(observation)g->follow();const uint64_t entered=now_ns();
    TraceqObject24 result=fn(input,argument,timestamp);const uint64_t returned=now_ns();
    if(observation)g->unfollow();
#ifdef TRACEQ_CAPTURE_PERF
    const auto stopped=now_ns();
#endif
    const bool ok=!observation || traceq_writes_end();const uint64_t finished=now_ns();
    *output=result;report->output_object=reinterpret_cast<uintptr_t>(&result);
    report->target_ns=returned-entered;report->total_ns=finished-start;report->status=ok?1:0;
#ifdef TRACEQ_CAPTURE_PERF
    perf_report.setup_ns=start-setup_started;perf_report.follow_ns=entered-start;
    perf_report.target_ns=returned-entered;perf_report.unfollow_ns=stopped-returned;
    perf_report.finish_ns=finished-stopped;
#endif
    if(observation) {
        const auto counters=traceq_writes_summary();
        report->instructions=counters.instructions;report->reads=counters.reads;report->writes=counters.writes;
        report->gaps=counters.gaps;report->commits=counters.commits;
#ifdef TRACEQ_CAPTURE_PERF
        const auto obs=traceq_writes_observation_stats();const auto io=traceq_writes_storage_stats();
        perf_report.before_calls=obs.before_calls;perf_report.after_calls=obs.after_calls;perf_report.fused_calls=obs.fused_calls;
        perf_report.snapshots=obs.snapshots;perf_report.scalar_comparisons=obs.scalar_comparisons;perf_report.vector_comparisons=obs.vector_comparisons;
        perf_report.reused_pre=obs.reused_pre;perf_report.block_tail_flushes=obs.block_tail_flushes;
        perf_report.blocks=io.blocks;perf_report.events=io.events;perf_report.encoded_bytes=io.encoded_bytes;
        perf_report.encode_ns=io.encode_ns;perf_report.write_ns=io.write_ns;
#endif
        while(gum_stalker_garbage_collect(g->_stalker))g_usleep(1000);
        g->reset_session();
    }
#ifdef TRACEQ_CAPTURE_PERF
    perf_report.cleanup_ns=now_ns()-finished;
#endif
    return ok?0:-6;
}
