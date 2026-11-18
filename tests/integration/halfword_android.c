/* Owned native controls, based on the existing atomic observation lab. */
#define _GNU_SOURCE
#include "AndroidCapture.h"
#include <dlfcn.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

typedef void (*Fn)(uint64_t *, void *, uint64_t, uint64_t);
typedef int (*Capture)(const char *, uint64_t, TraceqInvoke, void *, uint32_t, TraceqInvokeReport *);
typedef struct { const char *name; unsigned cas, alias, address_compare, zero_source, discarded, loop; } Case;
static const Case cases[] = {
    {"half_casah",1}, {"half_casalh",1}, {"half_cash",1}, {"half_caslh",1},
    {"half_swplh"}, {"half_swpalh"}, {"half_swph"}, {"half_swpah"},
    {"half_cas_alias",1,1}, {"half_cas_base",1,0,1},
    {"half_swp_alias",0,1}, {"half_swp_base"},
    {"half_cas_zero",1,0,0,1}, {"half_swp_zero",0,0,0,1},
    {"half_cas_discard",1,0,0,0,1}, {"half_swp_discard",0,0,0,0,1},
    {"half_c_cas",1}, {"half_c_swap"},
    {"half_contended_cas",1,0,0,0,0,1}, {"half_contended_swap",0,0,0,0,0,1},
};
enum { N = 64, OUTPUT = 3 * N * 8 };
typedef struct {
    Fn fn; const Case *test; uint64_t compare, desired; unsigned calls;
    _Alignas(16) struct { uint8_t before[16]; _Atomic uint16_t value; uint8_t after[16]; } bank;
    _Alignas(16) uint8_t out[OUTPUT + 32];
    _Atomic int ready, stop;
} Context;
static void invoke(void *opaque) {
    Context *c = opaque;
    c->fn((uint64_t *)(c->out + 16), &c->bank.value, c->compare, c->test->loop ? N : c->desired);
    c->calls++;
}
static void *worker(void *opaque) {
    Context *c = opaque;
    unsigned value = 0;
    while (!atomic_load_explicit(&c->stop, memory_order_acquire)) {
        atomic_exchange_explicit(&c->bank.value, (uint16_t)(0x4000 + (value++ & 0x3fff)), memory_order_relaxed);
        atomic_store_explicit(&c->ready, 1, memory_order_release);
    }
    return NULL;
}
static uint64_t ticks(void) {
    char text[4096]; FILE *f = fopen("/proc/self/stat", "r");
    if (!f) return 0;
    char *ok = fgets(text, sizeof(text), f); fclose(f);
    char *last = ok ? strrchr(text, ')') : NULL, *save, *word;
    if (!last) return 0;
    word = strtok_r(last + 2, " ", &save);
    for (unsigned i = 0; word && i < 19; ++i) word = strtok_r(NULL, " ", &save);
    return word ? strtoull(word, NULL, 10) : 0;
}
static uint64_t now(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000000000 + t.tv_nsec;
}
int main(int argc, char **argv) {
    if (argc != 6 && argc != 7) return 2;
    void *sdk = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL), *library = dlopen(argv[2], RTLD_NOW | RTLD_LOCAL);
    Capture capture = sdk ? (Capture)dlsym(sdk, "traceq_capture_invoke_at") : NULL;
    if (!capture || !library) return 3;
    unsigned first = atoi(argv[4]), limit = atoi(argv[5]); uint64_t start = ticks();
    fprintf(stderr, "identity pid%d start%llu sdk%s fixture%s\n", getpid(), (unsigned long long)start, argv[1], argv[2]);
    for (unsigned i = first; i < sizeof(cases)/sizeof(cases[0]) && i < first + limit; ++i) {
        Fn fn = (Fn)dlsym(library, cases[i].name); if (!fn) return 4;
        for (unsigned pattern = 0; pattern < (cases[i].loop ? 1 : 3); ++pattern) {
            for (unsigned phase = 0; phase < 4; ++phase) {
                unsigned mode = phase == 1 ? 1 : phase == 2 ? 3 : 0;
                Context c = {.fn=fn, .test=&cases[i]};
                memset(&c.bank, 0xa5, sizeof(c.bank)); memset(c.out, 0xa5, sizeof(c.out));
                uint16_t initial = pattern == 0 ? 0 : pattern == 1 ? 0x8001 : 0xfffe;
                c.compare = pattern == 2 ? 0xdeadbeeffffffffeull : 0;
                c.desired = pattern == 2 ? 0xfeedface00001234ull : 1;
                if (!cases[i].cas) c.compare = c.desired;
                if (cases[i].address_compare) {
                    c.compare = (uintptr_t)&c.bank.value;
                    if (!pattern) initial = (uint16_t)c.compare;
                }
                uint16_t compared = cases[i].discarded ? 0 : (uint16_t)c.compare;
                uint16_t desired = cases[i].zero_source ? 0 : cases[i].cas && cases[i].alias ? compared : cases[i].cas ? (uint16_t)c.desired : (uint16_t)c.compare;
                if (cases[i].loop) c.compare = 0x8000;
                atomic_init(&c.bank.value, initial); atomic_init(&c.ready, 0); atomic_init(&c.stop, 0);
                pthread_t thread;
                if (cases[i].loop) {
                    if (pthread_create(&thread, NULL, worker, &c)) return 5;
                    while (!atomic_load_explicit(&c.ready, memory_order_acquire)) sched_yield();
                }
                TraceqInvokeReport r = {0}; int status = 0; char path[600];
                snprintf(path, sizeof(path), "%s/%u-%u-%u.gtsw", argv[3], i, pattern, mode);
                if (mode) status = capture(path, (uint64_t)fn, invoke, &c, mode, &r); else invoke(&c);
                if (cases[i].loop) { atomic_store_explicit(&c.stop, 1, memory_order_release); pthread_join(thread, NULL); }
                unsigned output = cases[i].loop ? OUTPUT : 8;
                uint64_t observed; memcpy(&observed, c.out + 16, 8);
                uint16_t final = atomic_load(&c.bank.value);
                if (status || (mode && r.status != 1) || c.calls != 1) return 6;
                if (!cases[i].loop && (observed != (cases[i].discarded ? 0 : initial) ||
                    final != (cases[i].cas && initial != compared ? initial : desired))) return 7;
                for (unsigned j=0;j<sizeof(c.out);++j) if ((j<16 || j>=16+output) && c.out[j]!=0xa5) return 8;
                for (unsigned j=0;j<sizeof(c.bank);++j) if ((j<16 || j>=18) && ((uint8_t *)&c.bank)[j]!=0xa5) return 9;
                unsigned pre_races = 0, post_races = 0, successes = 0;
                if (cases[i].loop) {
                    uint64_t *a=(uint64_t *)(c.out+16);
                    for (unsigned n=0;n<N;++n) {
                        if (a[3*n]>65535 || a[3*n+1]>65535 || a[3*n+2]>65535) return 10;
                        successes += a[3*n] == a[3*n+1];
                        pre_races += a[3*n] != a[3*n+1];
                        post_races += a[3*n+2] != (cases[i].cas && a[3*n]!=a[3*n+1] ? a[3*n] : 0x8000+n);
                    }
                    if (mode && (!pre_races || !post_races)) return 11;
                }
                if (mode) {
                    snprintf(path,sizeof(path),"%s/%u-%u-%u.bin",argv[3],i,pattern,mode);
                    FILE *f=fopen(path,"wb"); if (!f || fwrite(c.out+16,1,output,f)!=output || fclose(f)) return 12;
                    printf("{\"case\":%u,\"name\":\"%s\",\"pattern\":%u,\"mode\":%u,\"initial\":%u,\"compare\":%u,\"desired\":%u,\"final\":%u,\"old\":%llu,\"address\":\"0x%llx\",\"output\":\"0x%llx\",\"pc\":\"0x%llx\",\"instructions\":%llu,\"reads\":%llu,\"writes\":%llu,\"gaps\":%llu,\"commits\":%llu,\"total_ns\":%llu,\"pre_races\":%u,\"post_races\":%u,\"successes\":%u}\n",
                           i,cases[i].name,pattern,mode,initial,compared,desired,final,(unsigned long long)observed,
                           (unsigned long long)(uintptr_t)&c.bank.value,(unsigned long long)(uintptr_t)(c.out+16),
                           (unsigned long long)(uintptr_t)fn,(unsigned long long)r.instructions,(unsigned long long)r.reads,
                           (unsigned long long)r.writes,(unsigned long long)r.gaps,(unsigned long long)r.commits,
                           (unsigned long long)r.total_ns,pre_races,post_races,successes);
                    fflush(stdout);
                }
            }
        }
    }
    uint64_t previous = now();
    for (unsigned phase=0;phase<3;++phase) {
        if (phase && argc==7) sleep(11);
        uint16_t value=0; uint64_t old=9;
        Fn fn=(Fn)dlsym(library,"half_swplh");fn(&old,&value,7,0);
        if (old || value!=7 || ticks()!=start) return 13;
        uint64_t current=now();
        printf("{\"health\":%u,\"pid\":%d,\"start_ticks\":%llu,\"monotonic_ns\":%llu,\"elapsed_ns\":%llu,\"native_ok\":true}\n",
               phase,getpid(),(unsigned long long)start,(unsigned long long)current,(unsigned long long)(current-previous));
        fflush(stdout);previous=current;
    }
    return 0;
}
