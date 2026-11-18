#include <stdint.h>
#include <string.h>
/* Optimized ordinary C: its first instructions perform the core algorithm. */
__attribute__((noinline)) uint64_t relocated_carry(uint64_t seed, void *output, uint64_t count) {
    uint64_t initial;
    memcpy(&initial,(unsigned char*)output+16,8);
    __uint128_t value=((__uint128_t)seed<<64)|initial;
    value+=((__uint128_t)count<<64)|(seed^initial);
    memcpy(output,&value,16);
    return (uint64_t)(value>>64);
}
