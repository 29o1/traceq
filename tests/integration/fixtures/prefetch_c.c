#include <stdint.h>
__attribute__((noinline,used))
uint64_t prefetch_c(uint64_t seed,void* data,uint64_t count) {
    unsigned char* p=(unsigned char*)data;uint64_t acc=seed;
    __builtin_prefetch(p,1,0);
    for(uint64_t i=0;i<count;++i) {
        unsigned offset=(i*7)&31;
        __builtin_prefetch(p+offset,0,3);
        p[offset]^=(unsigned char)acc;
        acc=(acc>>1)^((uint64_t)p[offset]+i);
    }
    return acc;
}
__attribute__((noinline,used)) uint64_t prefetch_c_end(void){return 0x4321;}
