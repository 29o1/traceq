#include <stdint.h>

// Ordinary C: no inline assembly and no assumptions about register allocation.
__attribute__((noinline,used))
uint64_t multiply_c(uint64_t seed, void* data, uint64_t count) {
    uint64_t* p=(uint64_t*)data;
    uint64_t other=p[2], acc=seed;
    p[0]=seed;p[1]=other;
    for(uint64_t i=0;i<count;++i) {
        uint64_t u=(uint64_t)(uint32_t)acc*(uint32_t)other;
        int64_t s=(int64_t)(int32_t)(uint32_t)acc*(int32_t)(uint32_t)other;
        uint64_t high=(uint64_t)(((unsigned __int128)acc*other)>>64);
        acc=(u+(uint64_t)s+high)^i;
    }
    p[3]=acc;return acc;
}
__attribute__((noinline,used)) uint64_t multiply_c_end(void){return 0x4321;}

// A compiler-generated constant divisor commonly uses a widening multiply.
// The volatile loop variable keeps a bounded repeatable workload at O1 and O2.
__attribute__((noinline,used))
uint64_t multiply_indexed(uint64_t seed,void* data,uint64_t count) {
    unsigned char* p=(unsigned char*)data;
    for(unsigned i=0;i<20;++i)p[i]=(unsigned char)(seed+i);
    for(volatile uint32_t i=0;i<count;++i)p[i%20]^=(unsigned char)i;
    return p[0];
}
__attribute__((noinline,used)) uint64_t multiply_indexed_end(void){return 0x4321;}
