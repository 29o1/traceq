#include <stdint.h>
#include <string.h>
__attribute__((noinline)) uint64_t st2_c(uint64_t seed, void *buffer, uint64_t count) {
    unsigned char *out=buffer;
    uint64_t other;
    memcpy(&other,out+16,sizeof other);
    for (uint64_t i=0;i<count && i<16;++i) {
        out[i*2]=(unsigned char)(seed+i);
        out[i*2+1]=(unsigned char)(other+i*3);
    }
    return seed^other;
}
__attribute__((noinline,used)) uint64_t st2_c_end(void){return 0x4321;}
