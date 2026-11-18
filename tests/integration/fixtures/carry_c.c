#include <stdint.h>
#include <string.h>
#define WIDE_CASE(NAME,EXPR) \
__attribute__((noinline)) uint64_t NAME(uint64_t seed,void* buffer,uint64_t count){ \
 uint64_t initial;memcpy(&initial,(unsigned char*)buffer+16,8); \
 __uint128_t a=((__uint128_t)seed<<64)|initial,b=((__uint128_t)count<<64)|(seed^initial),value=(EXPR); \
 memcpy(buffer,&value,16);return (uint64_t)(value>>64); } \
__attribute__((used,noinline)) uint64_t NAME##_end(void){return 1;}
WIDE_CASE(carry_add_c,a+b)
WIDE_CASE(carry_sub_c,a-b)
WIDE_CASE(carry_neg_c,0-a)
