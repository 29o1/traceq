#include <stdatomic.h>
#include <stdint.h>

__attribute__((noinline)) void half_c_cas(uint64_t *out, void *address, uint64_t compare, uint64_t desired) {
    uint16_t expected = (uint16_t)compare;
    atomic_compare_exchange_strong_explicit((_Atomic uint16_t *)address, &expected, (uint16_t)desired,
                                           memory_order_acquire, memory_order_acquire);
    *out = expected;
}

__attribute__((noinline)) void half_c_swap(uint64_t *out, void *address, uint64_t desired, uint64_t unused) {
    (void)unused;
    *out = atomic_exchange_explicit((_Atomic uint16_t *)address, (uint16_t)desired, memory_order_release);
}
