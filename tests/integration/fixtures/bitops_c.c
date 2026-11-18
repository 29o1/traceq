#include <stdint.h>
static inline uint64_t reverse64(uint64_t x) {
    x=((x>>1)&UINT64_C(0x5555555555555555))|((x&UINT64_C(0x5555555555555555))<<1);
    x=((x>>2)&UINT64_C(0x3333333333333333))|((x&UINT64_C(0x3333333333333333))<<2);
    x=((x>>4)&UINT64_C(0x0f0f0f0f0f0f0f0f))|((x&UINT64_C(0x0f0f0f0f0f0f0f0f))<<4);
    return __builtin_bswap64(x);
}
__attribute__((noinline,used))
uint64_t bitops_c(uint64_t seed,void* data,uint64_t count) {
    uint64_t* p=(uint64_t*)data;uint64_t x=seed,other=p[2];
    p[0]=seed;p[1]=other;
    for(uint64_t i=0;i<count;++i) {
        uint64_t value=x^other^i;
        unsigned leading=value?__builtin_clzll(value):64;
        x=reverse64(value)^leading;
    }
    p[3]=x;return x;
}
__attribute__((noinline,used)) uint64_t bitops_c_end(void){return 0x4321;}
