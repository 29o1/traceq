#include "AndroidCapture.h"
#include <dlfcn.h>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <string>
#include <unistd.h>
#include <sys/syscall.h>
using Named=decltype(&traceq_capture_invoke);
using At=int(*)(const char*,uint64_t,TraceqInvoke,void*,uint32_t,TraceqInvokeReport*);
using Target=uint64_t(*)(uint64_t,unsigned char*);
struct Context {Target target;uint64_t seed,result=0,calls=0;unsigned char bytes[64];void reset(){result=calls=0;memset(bytes,0xa5,64);}};
static void adapter(void*p){auto&c=*static_cast<Context*>(p);c.result=c.target(c.seed,c.bytes+16);++c.calls;}
static void require(bool ok,const char*why){if(!ok)throw std::runtime_error(why);}
int main(int argc,char**argv){try{
 if(argc!=5)return 2;
 void* collector=dlopen(argv[1],RTLD_NOW|RTLD_LOCAL);require(collector,"collector dlopen");
 auto named=reinterpret_cast<Named>(dlsym(collector,"traceq_capture_invoke"));auto at=reinterpret_cast<At>(dlsym(collector,"traceq_capture_invoke_at"));require(named,"named export");
 void*handles[2]={dlopen(argv[2],RTLD_NOW|RTLD_LOCAL),dlopen(argv[3],RTLD_NOW|RTLD_LOCAL)};require(handles[0]&&handles[1],"fixture dlopen");
 Target targets[2];Dl_info identities[2];for(unsigned i=0;i<2;++i){targets[i]=reinterpret_cast<Target>(dlsym(handles[i],"instance_target"));require(targets[i]&&dladdr(reinterpret_cast<void*>(targets[i]),&identities[i]),"target identity");}require(targets[0]!=targets[1]&&identities[0].dli_fbase!=identities[1].dli_fbase,"independent instances collapsed");
 const uint64_t seeds[]={0,0x123456789abcdef0ull,UINT64_MAX};std::string prefix=argv[4];TraceqInvokeReport report{};Context c{targets[0],0};c.reset();
 if(at){
  require(at(nullptr,0,adapter,&c,0,&report)==-1&&c.calls==0,"null anchor");
  require(at(nullptr,1,adapter,&c,0,&report)==-2&&c.calls==0,"unmapped anchor");
  require(at(nullptr,uint64_t(uintptr_t(targets[0])),nullptr,&c,0,&report)==-1,"null adapter");
  require(at(nullptr,uint64_t(uintptr_t(targets[0])),adapter,&c,4,&report)==-1,"bad mode");
  require(at(nullptr,uint64_t(uintptr_t(targets[0])),adapter,&c,3,&report)==-1,"missing capture path");
  require(at(nullptr,uint64_t(uintptr_t(targets[0])),adapter,&c,0,nullptr)==-1,"null report");
  require(at((prefix+"/missing/capture.gtsw").c_str(),uint64_t(uintptr_t(targets[0])),adapter,&c,3,&report)==-5&&c.calls==0,"missing output parent");
 }
 for(unsigned image=0;image<2;++image)for(unsigned seed=0;seed<3;++seed)for(unsigned selector=0;selector<(at?2u:1u);++selector)for(unsigned mode=0;mode<4;++mode){
  if(!selector&&mode==2)continue;
  c.target=targets[image];c.seed=seeds[seed];c.reset();const auto target=uint64_t(uintptr_t(c.target)),base=uint64_t(uintptr_t(identities[image].dli_fbase));
  std::string label=std::string(selector?"at":"name")+"-"+std::to_string(image)+"-"+std::to_string(seed)+"-"+std::to_string(mode);std::string path=prefix+"/"+label+".gtsw";
  int status=selector?at(path.c_str(),target,adapter,&c,mode,&report):named(path.c_str(),"libtraceq-instance.so",adapter,&c,mode,&report);
  require(status==0&&report.status==1&&report.version==1&&c.calls==1,"capture completion/call count");require(report.thread_id==uint64_t(syscall(SYS_gettid)),"thread changed");
  require(report.setup_ns+report.follow_ns+report.target_ns+report.unfollow_ns+report.finish_ns+report.cleanup_ns==report.total_ns,"phase sum");
  const bool contains=target>=report.code_base&&target-report.code_base<report.code_size;
  if(selector)require(contains&&report.code_base==base&&(!mode||report.instructions>0),"address selected wrong instance or empty capture");
  for(unsigned i=0;i<64;++i)if(i<16||i>=24)require(c.bytes[i]==0xa5,"output redzone changed");
  printf("{\"label\":\"%s\",\"selector\":\"%s\",\"image\":%u,\"seed_index\":%u,\"seed\":\"0x%llx\",\"observation\":%u,\"target\":\"0x%llx\",\"module_base\":\"0x%llx\",\"code_base\":\"0x%llx\",\"code_size\":%llu,\"target_inside_selected\":%s,\"output\":\"0x%llx\",\"result\":\"0x%llx\",\"bytes\":\"",label.c_str(),selector?"at":"name",image,seed,(unsigned long long)c.seed,mode,(unsigned long long)target,(unsigned long long)base,(unsigned long long)report.code_base,(unsigned long long)report.code_size,contains?"true":"false",(unsigned long long)(uintptr_t)(c.bytes+16),(unsigned long long)c.result);
  for(unsigned i=16;i<24;++i)printf("%02x",c.bytes[i]);
  printf("\",\"instructions\":%llu,\"reads\":%llu,\"writes\":%llu,\"gaps\":%llu,\"commits\":%llu,\"total_ns\":%llu}\n",(unsigned long long)report.instructions,(unsigned long long)report.reads,(unsigned long long)report.writes,(unsigned long long)report.gaps,(unsigned long long)report.commits,(unsigned long long)report.total_ns);fflush(stdout);
  if(selector&&mode==3){auto calls=c.calls;require(at(path.c_str(),target,adapter,&c,3,&report)==-5&&c.calls==calls,"existing capture overwritten");require(at(nullptr,target+1,adapter,&c,0,&report)==0&&c.calls==calls+1&&report.code_base==base,"unaligned interior anchor/recovery");}
 }
 return 0;
}catch(const std::exception&e){fprintf(stderr,"%s: %s\n",e.what(),dlerror());return 1;}}
