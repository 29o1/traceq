// Owned native allocator regression. No App injection or process restart.
#include "AndroidCapture.h"
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

struct Context {
    void* (*allocate)(size_t);
    void (*release)(void*);
    void* (*copy)(void*, const void*, size_t);
    void* dest{};
    void* copied{};
    size_t size{96000};
    bool allocate_inside{};
    unsigned char source[6]{0x36, 0x32, 0x63, 0x31, 0x3b, 0x0a};
    unsigned char observed[6]{};
};

static void target(void* opaque) {
    auto& c = *static_cast<Context*>(opaque);
    if (c.allocate_inside) c.dest = c.allocate(c.size);
    if (!c.dest) return;
    c.copied = c.copy(c.dest, c.source, sizeof(c.source));
    for (size_t i = 0; i < sizeof(c.source); ++i)
        c.observed[i] = static_cast<volatile unsigned char*>(c.dest)[i];
}

static bool correct(const Context& c) {
    return c.dest && c.copied == c.dest && !memcmp(c.source, c.observed, sizeof(c.source));
}

static uint64_t start_ticks() {
    char buffer[4096];
    auto* file = fopen("/proc/self/stat", "r");
    if (!file) return 0;
    bool ok = fgets(buffer, sizeof(buffer), file) != nullptr;
    fclose(file);
    char* tail = ok ? strrchr(buffer, ')') : nullptr;
    if (!tail) return 0;
    char* state{};
    char* word = strtok_r(tail + 2, " ", &state);
    for (unsigned i = 0; word && i < 19; ++i) word = strtok_r(nullptr, " ", &state);
    return word ? strtoull(word, nullptr, 10) : 0;
}

static uint64_t monotonic_ns() {
    timespec t{};
    clock_gettime(CLOCK_MONOTONIC, &t);
    return uint64_t(t.tv_sec) * 1000000000 + uint64_t(t.tv_nsec);
}

int main(int argc, char** argv) {
    if (argc != 5) return 2;
    void* sdk = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    void* libc = dlopen("libc.so", RTLD_NOW | RTLD_LOCAL);
    if (!sdk || !libc) return 2;
    auto capture = reinterpret_cast<decltype(&traceq_capture_invoke)>(dlsym(sdk, "traceq_capture_invoke"));
    Context c{};
    c.allocate = reinterpret_cast<decltype(c.allocate)>(dlsym(libc, "malloc"));
    c.release = reinterpret_cast<decltype(c.release)>(dlsym(libc, "free"));
    c.copy = reinterpret_cast<decltype(c.copy)>(dlsym(libc, "memcpy"));
    if (!capture || !c.allocate || !c.release || !c.copy) return 2;
    c.allocate_inside = !strcmp(argv[3], "allocate");
    unsigned delay = strtoul(argv[4], nullptr, 10);
    if ((!c.allocate_inside && strcmp(argv[3], "copy")) || delay > 11) return 2;
    if (!c.allocate_inside) c.dest = c.allocate(c.size);
    uint64_t identity = start_ticks();
    printf("{\"stage\":\"before_capture\",\"pid\":%d,\"start_ticks\":%llu}\n",
           getpid(), (unsigned long long)identity);
    fflush(stdout);
    TraceqInvokeReport report{};
    int status = capture(argv[2], "libc.so", target, &c, 3, &report);
    bool ok = correct(c);
    rusage usage{};
    getrusage(RUSAGE_SELF, &usage);
    printf("{\"stage\":\"capture_returned\",\"pid\":%d,\"start_ticks\":%llu,"
           "\"status\":%d,\"capture_status\":%llu,\"correct\":%s,"
           "\"dest\":\"0x%llx\",\"copy_address\":\"0x%llx\",\"malloc_address\":\"0x%llx\","
           "\"instructions\":%llu,\"reads\":%llu,\"writes\":%llu,\"gaps\":%llu,\"commits\":%llu,"
           "\"code_size\":%llu,\"total_ns\":%llu,\"rss_kib\":%ld,\"buffer\":\"",
           getpid(), (unsigned long long)start_ticks(), status, (unsigned long long)report.status,
           ok ? "true" : "false", (unsigned long long)(uintptr_t)c.dest,
           (unsigned long long)(uintptr_t)c.copy, (unsigned long long)(uintptr_t)c.allocate,
           (unsigned long long)report.instructions, (unsigned long long)report.reads,
           (unsigned long long)report.writes, (unsigned long long)report.gaps,
           (unsigned long long)report.commits, (unsigned long long)report.code_size,
           (unsigned long long)report.total_ns, usage.ru_maxrss);
    for (unsigned char byte : c.observed) printf("%02x", byte);
    printf("\",\"monotonic_ns\":%llu}\n", (unsigned long long)monotonic_ns());
    fflush(stdout);
    if (c.dest) c.release(c.dest);
    if (status || report.status != 1 || !ok || !identity) return 1;
    // Two existing 11-second windows after invoke has unfollowed and reclaimed
    // its Gum code cache. Check another actual native allocation/copy each time.
    for (unsigned phase = 1; delay && phase <= 2; ++phase) {
        sleep(delay);
        c.allocate_inside = true;
        c.dest = c.copied = nullptr;
        target(&c);
        ok = correct(c) && start_ticks() == identity;
        printf("{\"stage\":\"delayed_native\",\"phase\":%u,\"pid\":%d,"
               "\"start_ticks\":%llu,\"correct\":%s,\"monotonic_ns\":%llu}\n",
               phase, getpid(), (unsigned long long)start_ticks(), ok ? "true" : "false",
               (unsigned long long)monotonic_ns());
        fflush(stdout);
        if (c.dest) c.release(c.dest);
        if (!ok) return 1;
    }
    return 0;
}
