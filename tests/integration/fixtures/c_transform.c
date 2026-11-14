#include <stdint.h>

// Independent ordinary C workload. The tests specify byte-level behavior,
// without depending on compiler register allocation or instruction offsets.
__attribute__((noinline,used))
uint64_t c_transform(uint64_t seed, unsigned char* data, uint64_t count) {
    uint32_t state=(uint32_t)seed;
    for(uint64_t i=0;i<count && i<8;++i) {
        uint32_t input=data[16+i];
        state=(state^input)*33u+17u;
        data[i]=(unsigned char)(state>>3);
    }
    data[8]=(unsigned char)state;
    data[9]=(unsigned char)(state>>8);
    data[10]=(unsigned char)(state>>16);
    data[11]=(unsigned char)(state>>24);
    return state;
}

// Exported boundary marker, not called. Host validates that it follows the
// target. This TU contains no other function between these two symbols.
__attribute__((noinline,used)) uint64_t c_transform_end(void) {return 0x4321;}
