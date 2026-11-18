/* Both compiler helpers (MINIMAL) and user callouts (FULL) are allowed to
 * clobber FP state under the C ABI. The tracer must isolate those effects. */
#include "frida-gum.h"
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
static unsigned transforms,callouts;
static void corrupt_fp(void) {
    __asm__ volatile("mov x16,#0x400000\nmsr fpcr,x16\nmov x16,#0x10\nmsr fpsr,x16":::"x16","memory");
}
static void callout(GumCpuContext*cpu,gpointer data){(void)cpu;(void)data;++callouts;corrupt_fp();}
static void transform(GumStalkerIterator*it,GumStalkerOutput*out,gpointer data){
    (void)out;(void)data;const cs_insn*insn;++transforms;
    while(gum_stalker_iterator_next(it,&insn)) {
        if(insn->id==ARM64_INS_NOP)gum_stalker_iterator_put_callout(it,callout,NULL,NULL);
        gum_stalker_iterator_keep(it);
    }
    corrupt_fp();
}
typedef struct {GumStalker*stalker;GumAddress target;}Filter;
static gboolean exclude(GumModule*module,gpointer data){Filter*f=data;const GumMemoryRange*r=gum_module_get_range(module);if(f->target<r->base_address||f->target-r->base_address>=r->size)gum_stalker_exclude(f->stalker,r);return TRUE;}
int main(int argc,char**argv){
    if(argc!=2)return 2;void*lib=dlopen(argv[1],RTLD_NOW|RTLD_LOCAL);if(!lib)return 3;
    void(*target)(uint64_t*)=dlsym(lib,"fp_context_run");if(!target)return 4;
    uint64_t expected[8],actual[8],after[8];memset(expected,0xa5,sizeof expected);target(expected);
    if(expected[0]||expected[1]||expected[2]!=0x800000||expected[3]!=0x8000000)return 5;
    gum_init_embedded();GumStalker*stalker=gum_stalker_new();gum_stalker_set_trust_threshold(stalker,1);Filter filter={stalker,(GumAddress)target};gum_process_enumerate_modules(exclude,&filter);
    GumStalkerTransformer*tr=gum_stalker_transformer_make_from_callback(transform,NULL,NULL);
    memset(actual,0xa5,sizeof actual);gum_stalker_follow_me(stalker,tr,NULL);target(actual);gum_stalker_unfollow_me(stalker);
    while(gum_stalker_garbage_collect(stalker))g_usleep(1000);g_object_unref(tr);g_object_unref(stalker);
    memset(after,0xa5,sizeof after);target(after);int valid=!memcmp(expected,actual,sizeof expected)&&!memcmp(expected,after,sizeof expected)&&transforms>=2&&callouts>=1;
    printf("{\"pass\":%s,\"transforms\":%u,\"full_callouts\":%u,\"entry_fpcr\":%llu,\"entry_fpsr\":%llu,\"changed_fpcr\":%llu,\"changed_fpsr\":%llu,\"native_before_after\":%s}\n",valid?"true":"false",transforms,callouts,(unsigned long long)actual[0],(unsigned long long)actual[1],(unsigned long long)actual[2],(unsigned long long)actual[3],!memcmp(expected,after,sizeof expected)?"true":"false");return valid?0:6;
}
