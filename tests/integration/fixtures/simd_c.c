#include <stdint.h>
#include <string.h>
__attribute__((noinline)) uint64_t simd_widen_c(uint64_t seed,void*buffer,uint64_t count){
 uint64_t initial;memcpy(&initial,(unsigned char*)buffer+16,8);uint16_t*out=buffer;const unsigned char*in=(unsigned char*)buffer+16;
 for(uint64_t i=0;i<count && i<8;++i)out[i]=(uint16_t)(in[i]<<3);
 return seed^initial;
}
__attribute__((used,noinline)) uint64_t simd_widen_c_end(void){return 1;}
__attribute__((noinline)) uint64_t simd_narrow_c(uint64_t seed,void*buffer,uint64_t count){
 uint64_t initial;memcpy(&initial,(unsigned char*)buffer+16,8);unsigned char*out=buffer;const uint16_t*in=(const uint16_t*)((unsigned char*)buffer+16);
 for(uint64_t i=0;i<count && i<8;++i)out[i]=(unsigned char)in[i];
 return seed^initial;
}
__attribute__((used,noinline)) uint64_t simd_narrow_c_end(void){return 2;}
__attribute__((noinline)) uint64_t simd_compare_c(uint64_t seed,void*buffer,uint64_t count){
 uint64_t initial;memcpy(&initial,(unsigned char*)buffer+16,8);unsigned char*out=buffer;const unsigned char*in=out+16;
 for(uint64_t i=0;i<count && i<8;++i)out[i]=in[i]==(unsigned char)seed?255:0;
 return seed^initial;
}
__attribute__((used,noinline)) uint64_t simd_compare_c_end(void){return 3;}
