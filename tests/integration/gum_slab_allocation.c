/* ARM64 slabs use absolute addresses. Exercise slab growth with code and data
 * deliberately placed far apart; reject the obsolete near-allocation request.
 * The linker wraps only this standalone test's allocator calls. */
#include "frida-gum.h"
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern gpointer __real_gum_memory_allocate(gpointer, gsize, gsize, GumPageProtection);
extern gpointer __real_gum_memory_allocate_near(const GumAddressSpec *, gsize, gsize,
                                                GumPageProtection);
static int armed;
static gsize dynamic_data_size;
static unsigned code_allocations, data_allocations, callouts, transforms;
static uintptr_t code_address, data_address, first_code;
static GumAddress target_base;
static gsize target_size;

gpointer __wrap_gum_memory_allocate(gpointer address, gsize size, gsize alignment,
                                    GumPageProtection prot)
{
    if (armed && address == NULL &&
        (size == 8u * 1024 * 1024 || size == dynamic_data_size)) {
        int code = size == 8u * 1024 * 1024;
        uintptr_t hint = code ? UINT64_C(0x1000000000) : UINT64_C(0x2000000000);
        gpointer result = __real_gum_memory_allocate((gpointer)hint, size, alignment, prot);
        if (code) { code_allocations++; code_address = (uintptr_t)result; }
        else { data_allocations++; data_address = (uintptr_t)result; }
        return result;
    }
    return __real_gum_memory_allocate(address, size, alignment, prot);
}

gpointer __wrap_gum_memory_allocate_near(const GumAddressSpec *spec, gsize size,
                                         gsize alignment, GumPageProtection prot)
{
    if (armed && (size == 8u * 1024 * 1024 || size == dynamic_data_size)) {
        dprintf(1, "{\"obsolete_near_request\":true,\"size\":%zu,"
                   "\"max_distance\":%zu,\"expected_rejection_exit\":77}\n",
                size, spec->max_distance);
        _exit(77); /* Baseline counterfactual; no App or native crash is needed. */
    }
    return __real_gum_memory_allocate_near(spec, size, alignment, prot);
}

static void observe(GumCpuContext *cpu, gpointer unused)
{
    (void)cpu; (void)unused; callouts++;
}
static void transform(GumStalkerIterator *it, GumStalkerOutput *out, gpointer unused)
{
    (void)unused;
    const cs_insn *insn;
    int first = 1;
    while (gum_stalker_iterator_next(it, &insn)) {
        if (first && insn->address >= target_base && insn->address - target_base < target_size) {
            transforms++;
            if (!first_code) first_code = (uintptr_t)gum_arm64_writer_cur(out->writer.arm64);
            gum_stalker_iterator_put_callout(it, observe, NULL, NULL);
        }
        first = 0;
        gum_stalker_iterator_keep(it);
    }
}
typedef struct { GumStalker *stalker; GumAddress target; } Filter;
static gboolean exclude(GumModule *module, gpointer data)
{
    Filter *f = data;
    const GumMemoryRange *r = gum_module_get_range(module);
    if (f->target < r->base_address || f->target - r->base_address >= r->size)
        gum_stalker_exclude(f->stalker, r);
    else { target_base = r->base_address; target_size = r->size; }
    return TRUE;
}
static uint64_t distance(uintptr_t a, uintptr_t b) { return a > b ? a - b : b - a; }

int main(int argc, char **argv)
{
    if (argc != 2) return 2;
    void *lib = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    uint64_t (*target)(uint64_t, uint64_t *) = lib ? dlsym(lib, "slab_allocation_target") : NULL;
    if (!target) return 3;
    _Alignas(16) unsigned char native[72], traced[72], after[72];
    memset(native, 0xa5, sizeof(native));
    *(uint64_t *)(native + 32) = 7;
    uint64_t expected = target(77, (uint64_t *)(native + 32));
    if (expected != 77 + 4096 || *(uint64_t *)(native + 32) != 7 + UINT64_C(4096) * 0x123)
        return 4;
    gum_init_embedded();
    GumStalker *stalker = gum_stalker_new();
    gum_stalker_set_trust_threshold(stalker, 1);
    Filter filter = {stalker, (GumAddress)target};
    gum_process_enumerate_modules(exclude, &filter);
    GumStalkerTransformer *tr = gum_stalker_transformer_make_from_callback(transform, NULL, NULL);
    gsize page = gum_query_page_size();
    dynamic_data_size = ((4u * 1024 * 1024 / 5 + page - 1) / page) * page;
    memset(traced, 0xa5, sizeof(traced));
    *(uint64_t *)(traced + 32) = 7;
    armed = 1;
    gum_stalker_follow_me(stalker, tr, NULL);
    uint64_t actual = target(77, (uint64_t *)(traced + 32));
    gum_stalker_unfollow_me(stalker);
    armed = 0;
    gum_stalker_stop(stalker);
    while (gum_stalker_garbage_collect(stalker)) g_usleep(1000);
    g_object_unref(tr); g_object_unref(stalker);
    memset(after, 0xa5, sizeof(after));
    *(uint64_t *)(after + 32) = 7;
    uint64_t late = target(77, (uint64_t *)(after + 32));
    int pass = actual == expected && late == expected && !memcmp(native, traced, 72) &&
        !memcmp(native, after, 72) && transforms >= 4096 && callouts >= 4096 &&
        code_allocations && data_allocations && code_address && data_address &&
        distance(code_address, first_code) > UINT64_C(0x80000000) &&
        distance(code_address, data_address) > UINT64_C(0x80000000);
    printf("{\"pass\":%s,\"transforms\":%u,\"callouts\":%u,\"code_allocations\":%u,"
           "\"data_allocations\":%u,\"code_distance\":%llu,\"data_distance\":%llu,"
           "\"native_before_after_and_guards\":%s}\n", pass ? "true" : "false", transforms,
           callouts, code_allocations, data_allocations,
           (unsigned long long)distance(code_address, first_code),
           (unsigned long long)distance(code_address, data_address),
           !memcmp(native, traced, 72) && !memcmp(native, after, 72) ? "true" : "false");
    return pass ? 0 : 5;
}
