/* Independent native oracle for a long callout block and target-stack isolation.
 * Only the fixture intentionally uses reserved bytes below its live SP. */
#include "frida-gum.h"
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
static unsigned callouts, transforms;
static GumAddress target_base;
static gsize target_size;
static void observe(GumCpuContext *cpu, gpointer unused) {
    (void)cpu; (void)unused; callouts++;
}
static void transform(GumStalkerIterator *it, GumStalkerOutput *out, gpointer unused) {
    (void)out; (void)unused; const cs_insn *insn; transforms++;
    while (gum_stalker_iterator_next(it, &insn)) {
        if (insn->address >= target_base && insn->address - target_base < target_size)
            gum_stalker_iterator_put_callout(it, observe, NULL, NULL);
        gum_stalker_iterator_keep(it);
    }
}
typedef struct { GumStalker *stalker; GumAddress target; } Filter;
static gboolean exclude(GumModule *module, gpointer data) {
    Filter *f=data; const GumMemoryRange *r=gum_module_get_range(module);
    if (f->target < r->base_address || f->target-r->base_address >= r->size)
        gum_stalker_exclude(f->stalker,r);
    else { target_base=r->base_address; target_size=r->size; }
    return TRUE;
}
int main(int argc,char **argv) {
    if (argc!=2) return 2;
    void *lib=dlopen(argv[1],RTLD_NOW|RTLD_LOCAL);
    uint64_t (*target)(uint64_t,uint8_t*)=lib?dlsym(lib,"dense_context_target"):NULL;
    if (!target) return 3;
    uint8_t expected[544],actual[544],after[544];
    memset(expected,0x5a,sizeof(expected));
    uint64_t raw=target(77,expected+16);
    if (raw!=4173) return 4;
    for (unsigned i=0;i<512;i++) if (expected[16+i]!=0xa5) return 5;
    gum_init_embedded(); GumStalker *stalker=gum_stalker_new();
    gum_stalker_set_trust_threshold(stalker,1);
    Filter f={stalker,(GumAddress)target}; gum_process_enumerate_modules(exclude,&f);
    GumStalkerTransformer *tr=gum_stalker_transformer_make_from_callback(transform,NULL,NULL);
    memset(actual,0x5a,sizeof(actual));
    gum_stalker_follow_me(stalker,tr,NULL);
    uint64_t observed=target(77,actual+16);
    gum_stalker_unfollow_me(stalker);
    gum_stalker_stop(stalker);
    while (gum_stalker_garbage_collect(stalker)) g_usleep(1000);
    g_object_unref(tr); g_object_unref(stalker);
    memset(after,0x5a,sizeof(after));
    uint64_t late=target(77,after+16);
    int pass=observed==raw && late==raw && !memcmp(expected,actual,sizeof(actual)) &&
             !memcmp(expected,after,sizeof(after)) && callouts>=4096;
    printf("{\"pass\":%s,\"callouts\":%u,\"transforms\":%u,"
           "\"result\":%llu,\"target_below_SP_bytes512_intact\":%s,"
           "\"native_before_after_and_guards\":%s}\n",pass?"true":"false",callouts,
           transforms,(unsigned long long)observed,!memcmp(expected+16,actual+16,512)?"true":"false",
           !memcmp(expected,after,sizeof(after))?"true":"false");
    return pass?0:6;
}
