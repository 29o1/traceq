#include <stdint.h>
#ifndef INSTANCE_TAG
#define INSTANCE_TAG 0x13579bdfu
#endif
__attribute__((visibility("default"),noinline))
uint64_t instance_target(uint64_t seed,unsigned char* output) {
    uint64_t value=seed^((uint64_t)INSTANCE_TAG);
    for(unsigned i=0;i<8;++i){value=(value*33+17)^i;output[i]=(unsigned char)(value>>(i&7));}
    return value;
}
