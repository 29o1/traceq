#include "Capture.h"
#include "frida-gum.h"
#include <dlfcn.h>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <sys/resource.h>
#include <utility>

using Target=uint64_t(*)(uint64_t,void*,uint64_t);
static uint64_t ns() {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}
static gboolean exclude_other(GumModule* module,gpointer opaque) {
    auto* g=static_cast<std::pair<uint64_t,GumStalker*>*>(opaque);
    auto* r=gum_module_get_range(module);
    uint64_t start=g->first;
    if (!(start>=r->base_address && start-r->base_address<r->size)) gum_stalker_exclude(g->second,r);
    return TRUE;
}
int main(int argc,char** argv) {
    if (argc<8 || argc>12) {
        fprintf(stderr,"host library function native|writes|trace|trace-buffered|trace-chunks|trace-fast output seed count initial [--all-data] [--follow-external] [--buffer-size N]\n");return 2;
    }
    bool all_data=false,follow_external=false;size_t buffer_size=32;
    for(int i=8;i<argc;++i) {
        if(!strcmp(argv[i],"--all-data"))all_data=true;
        else if(!strcmp(argv[i],"--follow-external"))follow_external=true;
        else if(!strcmp(argv[i],"--buffer-size") && i+1<argc) {
            buffer_size=strtoull(argv[++i],nullptr,0);if(buffer_size<32 || buffer_size>256)return 2;
        } else return 2;
    }
    void* lib=dlopen(argv[1],RTLD_NOW|RTLD_LOCAL);
    if (!lib) { fprintf(stderr,"%s\n",dlerror());return 2; }
    auto target=reinterpret_cast<Target>(dlsym(lib,argv[2]));
    std::string end_name=std::string(argv[2])+"_end";
    auto code=reinterpret_cast<uintptr_t>(target), end=reinterpret_cast<uintptr_t>(dlsym(lib,end_name.c_str()));
    if (!code || end<=code) return 2;
    uint64_t seed=strtoull(argv[5],nullptr,0),count=strtoull(argv[6],nullptr,0),initial=strtoull(argv[7],nullptr,0);
    if (count>1000000) return 2;
    alignas(16) uint8_t buffer[256]{};memcpy(buffer+16,&initial,8);
    const std::string mode=argv[3];
    const bool state_mode=mode=="trace" || mode=="trace-buffered" || mode=="trace-chunks" || mode=="trace-fast";
    GumStalker* stalker=nullptr;GumStalkerTransformer* transformer=nullptr;
    if (mode!="native") {
        gum_init_embedded();
        stalker=gum_stalker_new();transformer=gum_stalker_transformer_make_from_callback(traceq_capture_transform,nullptr,nullptr);
        std::pair<uint64_t,GumStalker*> selected{code,stalker};
        if(!follow_external)gum_process_enumerate_modules(exclude_other,&selected);
        if (mode=="writes" || state_mode) {
            uint32_t storage=mode=="trace-buffered"?1:(mode=="trace-chunks" || mode=="trace-fast")?2:0;
            if (!traceq_capture_begin(argv[4],code,end-code,all_data?0:reinterpret_cast<uintptr_t>(buffer),
                all_data?UINT64_MAX:buffer_size,state_mode?2:1,mode=="trace-fast"?2:0,storage,follow_external)) return 3;
        } else return 2;
    }
    const uint64_t begin=ns();
    if (stalker) gum_stalker_follow_me(stalker,transformer,nullptr);
    uint64_t result=target(seed,buffer,count);
    if (stalker) gum_stalker_unfollow_me(stalker);
    bool ok=(mode!="writes" && !state_mode) || traceq_capture_end();
    double capture_ms=(ns()-begin)/1e6;
    if (stalker) {
        gum_stalker_stop(stalker);
        while (gum_stalker_garbage_collect(stalker)) g_usleep(1000);
        g_object_unref(stalker);g_object_unref(transformer);
    }
    rusage usage{};getrusage(RUSAGE_SELF,&usage);
    printf("{\"mode\":\"%s\",\"code_base\":\"0x%llx\",\"data_base\":\"0x%llx\","
           "\"result\":\"0x%llx\",\"capture_ms\":%.6f,\"rss_bytes\":%lld,\"buffer\":\"",mode.c_str(),
           (unsigned long long)code,(unsigned long long)(uintptr_t)buffer,(unsigned long long)result,capture_ms,(long long)usage.ru_maxrss);
    for (size_t i=0;i<buffer_size;++i)printf("%02x",buffer[i]);
    printf("\",\"ok\":%s}\n",ok?"true":"false");
    // Gum remains initialized until the isolated process exits.
    return ok?0:3;
}
