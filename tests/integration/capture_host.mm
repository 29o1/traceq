#include "TraceqCapture.h"
#include "WriteStream.h"
#include <dlfcn.h>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/resource.h>

using Target=uint64_t(*)(uint64_t,void*,uint64_t);
static uint64_t ns() {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}
static gboolean exclude_other(GumModule* module,gpointer opaque) {
    auto* g=static_cast<TraceqCapture*>(opaque);
    auto* r=gum_module_get_range(module);
    uint64_t start=g->modules.at("fixture").at("base");
    if (!(start>=r->base_address && start-r->base_address<r->size)) gum_stalker_exclude(g->_stalker,r);
    return TRUE;
}
int main(int argc,char** argv) {
    if (argc<8 || argc>10) {
        fprintf(stderr,"host library function native|text|writes|trace|trace-buffered|trace-chunks|trace-fast output seed count initial [--all-data] [--follow-external]\n");return 2;
    }
    bool all_data=false,follow_external=false;
    for(int i=8;i<argc;++i) {
        if(!strcmp(argv[i],"--all-data"))all_data=true;
        else if(!strcmp(argv[i],"--follow-external"))follow_external=true;
        else return 2;
    }
    void* lib=dlopen(argv[1],RTLD_NOW|RTLD_LOCAL);
    if (!lib) { fprintf(stderr,"%s\n",dlerror());return 2; }
    auto target=reinterpret_cast<Target>(dlsym(lib,argv[2]));
    std::string end_name=std::string(argv[2])+"_end";
    auto code=reinterpret_cast<uintptr_t>(target), end=reinterpret_cast<uintptr_t>(dlsym(lib,end_name.c_str()));
    if (!code || end<=code) return 2;
    uint64_t seed=strtoull(argv[5],nullptr,0),count=strtoull(argv[6],nullptr,0),initial=strtoull(argv[7],nullptr,0);
    if (count>1000000) return 2;
    alignas(16) uint8_t buffer[32]{};memcpy(buffer+16,&initial,8);
    const std::string mode=argv[3];
    const bool state_mode=mode=="trace" || mode=="trace-buffered" || mode=="trace-chunks" || mode=="trace-fast";
    TraceqCapture* g=nullptr;
    if (mode!="native") {
        gum_init_embedded();
        g=TraceqCapture::get_instance();g->reset_session();g->_stalker=gum_stalker_new();
        g->trace_thread_id=0;g->options.mode=TRACEQ_MODE_STANDARD;
        g->modules["fixture"]["base"]=code;g->modules["fixture"]["size"]=end-code;
        if(!follow_external)gum_process_enumerate_modules(exclude_other,g);
        if (mode=="text") g->trace_file.open(argv[4],std::ios::out|std::ios::trunc);
        else if (mode=="writes" || state_mode) {
            TraceqStorageOptions storage;
            if(mode=="trace-buffered")storage.storage=TraceqStorage::Buffered;
            if(mode=="trace-chunks" || mode=="trace-fast")storage.storage=TraceqStorage::ChunkCpp;
            if(!traceq_writes_storage(storage))return 3;
            if(!traceq_writes_observation(mode=="trace-fast"?TraceqObservation::Fused:TraceqObservation::Reference))return 3;
            if (!traceq_writes_begin(argv[4],code,end-code,all_data?0:reinterpret_cast<uintptr_t>(buffer),
                                      all_data?UINT64_MAX:sizeof buffer,state_mode,follow_external)) return 3;
        } else return 2;
    }
    const uint64_t begin=ns();
    if (g) g->follow();
    uint64_t result=target(seed,buffer,count);
    if (g) g->unfollow();
    bool ok=(mode!="writes" && !state_mode) || traceq_writes_end();
    double capture_ms=(ns()-begin)/1e6;
    if (g) {
        while (gum_stalker_garbage_collect(g->_stalker)) g_usleep(1000);
        g->reset_session();
    }
    rusage usage{};getrusage(RUSAGE_SELF,&usage);
    printf("{\"mode\":\"%s\",\"code_base\":\"0x%llx\",\"data_base\":\"0x%llx\","
           "\"result\":\"0x%llx\",\"capture_ms\":%.6f,\"rss_bytes\":%lld,\"buffer\":\"",mode.c_str(),
           (unsigned long long)code,(unsigned long long)(uintptr_t)buffer,(unsigned long long)result,capture_ms,(long long)usage.ru_maxrss);
    for (uint8_t b:buffer)printf("%02x",b);
    printf("\",\"ok\":%s}\n",ok?"true":"false");
    // Gum lifetime extends through the TraceqCapture singleton destructor.
    return ok?0:3;
}
