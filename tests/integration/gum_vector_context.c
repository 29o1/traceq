/* A legal C callback may overwrite caller-saved SIMD state. Tracing must
 * preserve all target vectors, including the upper halves of V8..V15. */
#include "frida-gum.h"
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

static unsigned callbacks;

static void transform(GumStalkerIterator *it, GumStalkerOutput *output, gpointer data)
{
    const cs_insn *insn;
    (void)output;
    (void)data;
    ++callbacks;
    while (gum_stalker_iterator_next(it, &insn))
        gum_stalker_iterator_keep(it);
    __asm__ volatile(
        "movi v0.16b, #160\n"  "movi v1.16b, #161\n"
        "movi v2.16b, #162\n"  "movi v3.16b, #163\n"
        "movi v4.16b, #164\n"  "movi v5.16b, #165\n"
        "movi v6.16b, #166\n"  "movi v7.16b, #167\n"
        "movi v8.16b, #168\n"  "movi v9.16b, #169\n"
        "movi v10.16b, #170\n" "movi v11.16b, #171\n"
        "movi v12.16b, #172\n" "movi v13.16b, #173\n"
        "movi v14.16b, #174\n" "movi v15.16b, #175\n"
        "movi v16.16b, #176\n" "movi v17.16b, #177\n"
        "movi v18.16b, #178\n" "movi v19.16b, #179\n"
        "movi v20.16b, #180\n" "movi v21.16b, #181\n"
        "movi v22.16b, #182\n" "movi v23.16b, #183\n"
        "movi v24.16b, #184\n" "movi v25.16b, #185\n"
        "movi v26.16b, #186\n" "movi v27.16b, #187\n"
        "movi v28.16b, #188\n" "movi v29.16b, #189\n"
        "movi v30.16b, #190\n" "movi v31.16b, #191\n"
        ::: "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7",
            "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15",
            "v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23",
            "v24", "v25", "v26", "v27", "v28", "v29", "v30", "v31");
}

typedef struct { GumStalker *stalker; GumAddress target; } Filter;
static gboolean exclude_other_modules(GumModule *module, gpointer data)
{
    Filter *filter = data;
    const GumMemoryRange *range = gum_module_get_range(module);
    if (!(range->base_address <= filter->target &&
          filter->target < range->base_address + range->size))
        gum_stalker_exclude(filter->stalker, range);
    return TRUE;
}

int main(int argc, char **argv)
{
    if (argc != 2) return 2;
    void *library = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!library) return 3;
    void (*target)(const unsigned char *, unsigned char *) =
        dlsym(library, "vector_callback_target");
    if (!target) return 4;
    const unsigned seeds[] = {1, 7, 163};
    unsigned failures = 0;
    gum_init_embedded();
    for (unsigned seed_index = 0; seed_index != 3; ++seed_index) {
        unsigned char input[512], expected[512], output[576];
        for (unsigned i = 0; i != 512; ++i)
            expected[i] = input[i] = ((i / 16) * 7 + (i % 16) * 13 + seeds[seed_index]) & 255;
        memset(output, 0xa5, sizeof(output));
        target(input, output + 32);
        if (memcmp(expected, output + 32, 512)) return 5;
        GumStalker *stalker = gum_stalker_new();
        gum_stalker_set_trust_threshold(stalker, 1);
        Filter filter = {stalker, (GumAddress)target};
        gum_process_enumerate_modules(exclude_other_modules, &filter);
        GumStalkerTransformer *transformer =
            gum_stalker_transformer_make_from_callback(transform, NULL, NULL);
        callbacks = 0;
        memset(output, 0xa5, sizeof(output));
        gum_stalker_follow_me(stalker, transformer, NULL);
        target(input, output + 32);
        gum_stalker_unfollow_me(stalker);
        if (memcmp(input, expected, 512)) return 8;
        unsigned mismatch = 0;
        for (unsigned i = 0; i != 512; ++i)
            mismatch += expected[i] != output[32 + i];
        for (unsigned i = 0; i != 32; ++i)
            if (output[i] != 0xa5 || output[544 + i] != 0xa5) return 6;
        while (gum_stalker_garbage_collect(stalker)) g_usleep(1000);
        memset(output, 0xa5, sizeof(output));
        target(input, output + 32);
        if (memcmp(expected, output + 32, 512)) return 7;
        if (memcmp(input, expected, 512)) return 8;
        g_object_unref(transformer);
        g_object_unref(stalker);
        printf("{\"seed\":%u,\"callbacks\":%u,\"mismatched_bytes\":%u,"
               "\"guards\":true,\"raw_before_match\":true,\"raw_after_match\":true,\"input_unchanged\":true}\n",
               seeds[seed_index], callbacks, mismatch);
        failures += mismatch != 0 || callbacks < 2;
    }
    return failures ? 1 : 0;
}
