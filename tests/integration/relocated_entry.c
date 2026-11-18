/* Independent interception/adapter oracle. No collector implementation here. */
#include "AndroidCapture.h"
#include "frida-gum.h"
#include <dlfcn.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint64_t (*Target)(uint64_t,uint64_t*,uint64_t,uint64_t,uint64_t,uint64_t);
typedef struct { uint64_t fn,args[6],result,entry_sp; } Context;
_Static_assert(offsetof(Context,result)==56,"adapter result");
_Static_assert(offsetof(Context,entry_sp)==64,"adapter SP");
extern void relocated_adapter(void *);
typedef TraceqCodeRange ExtraRange;
typedef int (*Capture)(const char*,uint64_t,TraceqInvoke,void*,uint32_t,TraceqInvokeReport*);
typedef int (*CaptureExtra)(const char*,uint64_t,TraceqInvoke,void*,uint32_t,const ExtraRange*,uint32_t,TraceqInvokeReport*);
_Static_assert(_Generic(&traceq_capture_invoke_ranges_at,CaptureExtra:1,default:0),"range invoke ABI");
static void mark(void *p) { ++*(unsigned*)p; }
static Capture capture;
static CaptureExtra capture_extra;
static void *original;
static Target anchor;
static int expanded,rc;
static unsigned observation=3;
static Context observed;
static TraceqInvokeReport report;
static char path[1024];
static uint64_t collect(uint64_t seed,uint64_t*out,uint64_t a,uint64_t b,uint64_t c,uint64_t d) {
    observed=(Context){(uint64_t)original,{seed,(uint64_t)out,a,b,c,d},0,0};
    ExtraRange range={(uint64_t)original,128};
    memset(&report,0,sizeof(report));
    rc=expanded?capture_extra(path,(uint64_t)anchor,relocated_adapter,&observed,observation,&range,1,&report)
               :capture(path,(uint64_t)anchor,relocated_adapter,&observed,observation,&report);
    return observed.result;
}
static uint64_t replacement(uint64_t seed,uint64_t*out,uint64_t a,uint64_t b,uint64_t c,uint64_t d) { return collect(seed,out,a,b,c,d); }
static uint64_t replacement_carry(uint64_t seed,uint64_t*out,uint64_t count) { return collect(seed,out,count,0,0,0); }
static void reset(uint64_t *buf,uint64_t initial,int carry) {
    memset(buf,0xa5,64);if(carry)memset(buf+2,0,32);buf[4]=initial;if(!carry)buf[5]=UINT64_C(0xfedcba9876543210);
}
static int output_ok(const uint64_t *buf,uint64_t low,uint64_t high,uint64_t initial,int carry) {
    return buf[0]==UINT64_C(0xa5a5a5a5a5a5a5a5)&&buf[1]==buf[0]&&buf[2]==low&&
           buf[3]==high&&buf[4]==initial&&buf[5]==(carry?0:UINT64_C(0xfedcba9876543210))&&buf[6]==buf[0]&&buf[7]==buf[0];
}
static uint64_t call_target(unsigned variant,uint64_t seed,uint64_t*out,uint64_t count) {
    if(variant==2)return ((uint64_t(*)(uint64_t,uint64_t*,uint64_t))anchor)(seed,out,count);
    return anchor(seed,out,2,3,5,7);
}
int main(int argc,char **argv) {
    if(argc<5||argc>7)return 2;
    if(argc>5){observation=atoi(argv[5]);if(observation<1||observation>3)return 2;}
    void *sdk=dlopen(argv[1],RTLD_NOW|RTLD_LOCAL),*lib=dlopen(argv[2],RTLD_NOW|RTLD_LOCAL);
    if(!sdk||!lib){fprintf(stderr,"%s\n",dlerror());return 3;}
    capture=(Capture)dlsym(sdk,"traceq_capture_invoke_at");
    capture_extra=(CaptureExtra)dlsym(sdk,"traceq_capture_invoke_ranges_at");
    expanded=atoi(argv[4]);if(!capture|| (expanded&&!capture_extra))return 77;
    gum_init_embedded();GumInterceptor *hook=gum_interceptor_obtain();
    if(expanded) {
        Target valid=(Target)dlsym(lib,"relocated_spill");
        ExtraRange invalid[]={{0,4},{(uint64_t)valid,0},{(uint64_t)valid+1,4},{UINT64_MAX-3,8}};
        unsigned calls=0;TraceqInvokeReport rejected;
        for(unsigned i=0;i<sizeof(invalid)/sizeof(invalid[0]);i++)
            if(capture_extra(NULL,(uint64_t)valid,mark,&calls,0,&invalid[i],1,&rejected)!=-1||calls)return 8;
        if(capture_extra(NULL,(uint64_t)valid,mark,&calls,0,NULL,1,&rejected)!=-1||calls)return 8;
        if(capture_extra(NULL,(uint64_t)valid,mark,&calls,0,invalid,64,&rejected)!=-1||calls)return 8;
        if(capture_extra(NULL,(uint64_t)valid,mark,&calls,0,(const ExtraRange*)((char*)invalid+1),1,&rejected)!=-1||calls)return 8;
        if(capture_extra(NULL,(uint64_t)valid,mark,&calls,0,NULL,0,&rejected)||calls!=1||rejected.status!=1)return 8;
    }
    const char *names[]={"relocated_spill","relocated_literal","relocated_carry"};
    const uint64_t carry_seeds[]={0x12345678,0xffffffff,9},counts[]={4,8,0},initials[]={UINT64_C(0x8877665544332211),UINT64_C(0xffff00807f010203),7};
    const uint64_t seeds[]={0,77,UINT64_MAX};
    for(unsigned variant=0;variant<3;variant++)for(unsigned n=0;n<(argc>6?1:3);n++) {
        anchor=(Target)dlsym(lib,names[variant]);if(!anchor)return 4;
        uint64_t seed=variant==2?carry_seeds[n]:seeds[n],count=variant==2?counts[n]:2,initial=variant==2?initials[n]:7;
        __uint128_t wide=(__uint128_t)initial+(initial^seed);
        uint64_t want=variant==2?seed+count+(uint64_t)(wide>>64):seed+2+3+5+7+(variant?UINT64_C(0x1122334455667788):0);
        uint64_t low=variant==2?(uint64_t)wide:want,high=variant==2?want:(7^want);
        uint64_t buf[8];reset(buf,initial,variant==2);
        if(call_target(variant,seed,buf+2,count)!=want||!output_ok(buf,low,high,initial,variant==2))return 5;
        unsigned char prefix[128];memcpy(prefix,(void*)anchor,16);
        gum_interceptor_begin_transaction(hook);
        GumReplaceReturn replaced=gum_interceptor_replace_fast(hook,(void*)anchor,variant==2?(void*)replacement_carry:(void*)replacement,&original,NULL);
        gum_interceptor_end_transaction(hook);if(replaced!=GUM_REPLACE_OK)return 6;
        memcpy(prefix,(void*)original,128);
        snprintf(path,sizeof(path),"%s/%s-%u.gtsw",argv[3],names[variant],n);
        reset(buf,initial,variant==2);uint64_t actual=call_target(variant,seed,buf+2,count);
        int valid=rc==0&&report.status==1&&actual==want&&output_ok(buf,low,high,initial,variant==2);
        gum_interceptor_begin_transaction(hook);gum_interceptor_revert(hook,(void*)anchor);gum_interceptor_end_transaction(hook);
        reset(buf,initial,variant==2);valid&=call_target(variant,seed,buf+2,count)==want&&output_ok(buf,low,high,initial,variant==2);
        printf("{\"pass\":%s,\"case\":\"%s\",\"seed_index\":%u,\"seed\":\"0x%llx\",\"count\":%llu,\"initial\":\"0x%llx\",\"target\":\"%p\",\"trampoline\":\"%p\",\"entry_sp\":\"0x%llx\",\"output_address\":\"0x%llx\",\"result\":\"0x%llx\",\"instructions\":%llu,\"reads\":%llu,\"writes\":%llu,\"gaps\":%llu,\"commits\":%llu,\"total_ns\":%llu,\"prefix_hex\":\"",valid?"true":"false",names[variant],n,(unsigned long long)seed,(unsigned long long)count,(unsigned long long)initial,anchor,original,(unsigned long long)observed.entry_sp,(unsigned long long)observed.args[1],(unsigned long long)actual,(unsigned long long)report.instructions,(unsigned long long)report.reads,(unsigned long long)report.writes,(unsigned long long)report.gaps,(unsigned long long)report.commits,(unsigned long long)report.total_ns);
        for(unsigned i=0;i<128;i++)printf("%02x",prefix[i]);puts("\"}");
        if(!valid)return 7;
    }
    g_object_unref(hook);return 0;
}
