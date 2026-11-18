#include "Capture.h"
#include "frida-gum.h"
#include <future>
#include <thread>
#include <string>
#include <cstdio>

static void target() {}
int main(int argc,char** argv) {
    if(argc!=2)return 2;
    gum_init_embedded();uint64_t data=0;
    auto begin=[&](const char* name) {
        std::string path=std::string(argv[1])+"-"+name+".gtsw";
        return traceq_capture_begin(path.c_str(),reinterpret_cast<uintptr_t>(&target),4,
                                  reinterpret_cast<uintptr_t>(&data),8,2,0,2,false);
    };
    if(!begin("main-first"))return 3;
    bool rejected_end=false,rejected_begin=false;
    std::thread intruder([&](){rejected_end=!traceq_capture_end();rejected_begin=!begin("nested");});intruder.join();
    if(!rejected_end || !rejected_begin || !traceq_capture_end())return 4;
    std::promise<bool> ready;auto started=ready.get_future();std::promise<void> release;auto proceed=release.get_future();
    bool worker_end=false;
    std::thread owner([&](){ready.set_value(begin("worker"));proceed.wait();worker_end=traceq_capture_end();});
    bool worker_begin=started.get();bool old_owner_rejected=!traceq_capture_end();release.set_value();owner.join();
    if(!worker_begin || !old_owner_rejected || !worker_end || !begin("main-next") || !traceq_capture_end())return 5;
    puts("{\"foreign_end_rejected\":true,\"nested_begin_rejected\":true,\"sequential_thread_handoff\":true,\"owner_reuse\":true}");
}
