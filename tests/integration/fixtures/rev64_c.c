#include <arm_neon.h>
#include <stdint.h>
#include <string.h>
// Zero count leaves the output untouched; nonzero count reverses one vector.
#define REV_CASE(NAME,T,V,LOAD,REVERSE,STORE) \
__attribute__((noinline)) uint64_t NAME(uint64_t seed,void* buffer,uint64_t count){ \
 uint64_t initial;memcpy(&initial,(unsigned char*)buffer+16,8); \
 if(count){V value=LOAD((const T*)((unsigned char*)buffer+16));STORE((T*)buffer,REVERSE(value));} \
 return seed^initial; } \
__attribute__((used,noinline)) uint64_t NAME##_end(void){return 1;}
REV_CASE(rev64_b8_c,uint8_t,uint8x8_t,vld1_u8,vrev64_u8,vst1_u8)
REV_CASE(rev64_b16_c,uint8_t,uint8x16_t,vld1q_u8,vrev64q_u8,vst1q_u8)
REV_CASE(rev64_h4_c,uint16_t,uint16x4_t,vld1_u16,vrev64_u16,vst1_u16)
REV_CASE(rev64_h8_c,uint16_t,uint16x8_t,vld1q_u16,vrev64q_u16,vst1q_u16)
REV_CASE(rev64_s2_c,uint32_t,uint32x2_t,vld1_u32,vrev64_u32,vst1_u32)
REV_CASE(rev64_s4_c,uint32_t,uint32x4_t,vld1q_u32,vrev64q_u32,vst1q_u32)
