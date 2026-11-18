#include <stdint.h>
#include <string.h>
__attribute__((noinline)) uint64_t structure_c(uint64_t seed,void*buffer,uint64_t count){
 unsigned char*p=buffer;uint64_t initial;memcpy(&initial,p+16,8);
 for(unsigned i=0;i<64;++i)p[i]=(unsigned char)((seed+i*13)^(initial>>(i%8)*8));
 for(uint64_t i=0;i<count && i<64;++i)p[64+i]=p[i];
 return seed^initial;
}
__attribute__((used,noinline)) uint64_t structure_c_end(void){return 0x1234;}
