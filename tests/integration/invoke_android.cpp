#include "AndroidCapture.h"
#include "fixtures/invoke_targets.h"
#include <dlfcn.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <stdexcept>
#include <unistd.h>
#include <sys/syscall.h>
using Invoke=decltype(&traceq_capture_invoke);
struct Context {
    decltype(&invoke_integer) integer;
    decltype(&invoke_floating) floating;
    decltype(&invoke_triple) triple;
    uint64_t seed=0,result=0,calls=0;
    double fp=0;InvokeTriple aggregate{};
    alignas(16) unsigned char storage[64];
    void* output(){return storage+16;}
    void reset(){result=calls=0;fp=0;aggregate={};memset(storage,0xa5,sizeof storage);}
};
static void integer(void* p){auto&c=*static_cast<Context*>(p);c.result=c.integer(c.seed,c.output(),1,2,3,4,5,6,7,8);++c.calls;}
static void floating(void* p){auto&c=*static_cast<Context*>(p);c.fp=c.floating(2.,3.f,4,1.,c.output());++c.calls;}
static void triple(void* p){auto&c=*static_cast<Context*>(p);c.aggregate=c.triple(c.seed,c.output());++c.calls;}
static void require(bool ok){if(!ok)throw std::runtime_error("invoke regression");}
int main(int argc,char**argv){try{
    if(argc!=4)return 2;
    void* library=dlopen(argv[1],RTLD_NOW|RTLD_LOCAL),*fixture=dlopen(argv[2],RTLD_NOW|RTLD_LOCAL);
    if(!library || !fixture){fprintf(stderr,"%s\n",dlerror());return 2;}
    auto invoke=reinterpret_cast<Invoke>(dlsym(library,"traceq_capture_invoke"));require(invoke);
    Context c{};c.integer=reinterpret_cast<decltype(c.integer)>(dlsym(fixture,"invoke_integer"));
    c.floating=reinterpret_cast<decltype(c.floating)>(dlsym(fixture,"invoke_floating"));c.triple=reinterpret_cast<decltype(c.triple)>(dlsym(fixture,"invoke_triple"));require(c.integer&&c.floating&&c.triple);
    const std::string file=argv[2],module=file.substr(file.find_last_of('/')+1),prefix=argv[3];
    TraceqInvokeReport report{};c.reset();
    require(invoke((prefix+"/missing/capture.gtsw").c_str(),module.c_str(),integer,&c,3,&report)==-5 && c.calls==0);
    require(invoke(nullptr,module.c_str(),integer,&c,3,&report)==-1);
    require(invoke(nullptr,module.c_str(),nullptr,&c,0,&report)==-1);
    require(invoke(nullptr,module.c_str(),integer,&c,4,&report)==-1);
    require(invoke(nullptr,"traceq-missing-module",integer,&c,0,&report)==-2);
    require(invoke(nullptr,module.c_str(),integer,&c,0,nullptr)==-1);
    struct Case{const char*name;TraceqInvoke call;} cases[]={{"integer",integer},{"floating",floating},{"triple",triple}};
    const uint64_t seeds[]={0,0x123456789abcdef0ull,UINT64_MAX};
    for(unsigned i=0;i<3;++i)for(auto test:cases)for(unsigned observation=0;observation<=3;++observation){
        c.reset();c.seed=seeds[i];std::string path=prefix+"/"+test.name+"-"+std::to_string(i)+"-"+std::to_string(observation)+".gtsw";
        require(invoke(path.c_str(),module.c_str(),test.call,&c,observation,&report)==0 && report.status==1 && report.version==1 && c.calls==1);
        require(report.thread_id==uint64_t(syscall(SYS_gettid)));
        require(report.setup_ns+report.follow_ns+report.target_ns+report.unfollow_ns+report.finish_ns+report.cleanup_ns==report.total_ns);
        require(observation?report.instructions>0:report.instructions==0);
        for(unsigned n=0;n<64;++n)if(n<16 || n>=24)require(c.storage[n]==0xa5);
        printf("{\"kind\":\"%s\",\"seed_index\":%u,\"seed\":\"0x%llx\",\"observation\":%u,\"data_base\":\"0x%llx\",\"result\":\"0x%llx\",\"fp\":%.17g,\"triple\":[\"0x%llx\",\"0x%llx\",\"0x%llx\"],\"buffer\":\"",test.name,i,(unsigned long long)c.seed,observation,(unsigned long long)(uintptr_t)c.output(),(unsigned long long)c.result,c.fp,(unsigned long long)c.aggregate.a,(unsigned long long)c.aggregate.b,(unsigned long long)c.aggregate.c);
        for(unsigned n=16;n<24;++n)printf("%02x",c.storage[n]);
        printf("\",\"instructions\":%llu,\"reads\":%llu,\"writes\":%llu,\"gaps\":%llu,\"commits\":%llu,\"total_ns\":%llu}\n",(unsigned long long)report.instructions,(unsigned long long)report.reads,(unsigned long long)report.writes,(unsigned long long)report.gaps,(unsigned long long)report.commits,(unsigned long long)report.total_ns);
        if(observation==3){auto calls=c.calls;require(invoke(path.c_str(),module.c_str(),test.call,&c,3,&report)==-5 && c.calls==calls);require(invoke(nullptr,module.c_str(),test.call,&c,0,&report)==0 && c.calls==calls+1);}
    }
    return 0;
}catch(const std::exception&e){fprintf(stderr,"%s\n",e.what());return 1;}}
