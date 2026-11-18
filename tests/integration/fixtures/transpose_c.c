#include <arm_neon.h>
#include <stdint.h>
#include <string.h>
__attribute__((noinline)) uint64_t transpose_mix_c(uint64_t seed,void*output,uint64_t count){
 uint64_t initial;memcpy(&initial,(unsigned char*)output+16,8);uint64_t av[2]={seed,initial},bv[2]={initial,~seed};uint8x16_t a=vreinterpretq_u8_u64(vld1q_u64(av)),b=vreinterpretq_u8_u64(vld1q_u64(bv));
 for(uint64_t i=0;i<count;++i){
  uint8x16_t aa=vtrn1q_u8(a,b),bb=vreinterpretq_u8_u32(vtrn2q_u32(vreinterpretq_u32_u8(a),vreinterpretq_u32_u8(b)));
  uint16x4_t lo=vtrn1_u16(vreinterpret_u16_u8(vget_low_u8(a)),vreinterpret_u16_u8(vget_low_u8(b)));
  uint8x8_t hi=vtrn2_u8(vget_low_u8(a),vget_low_u8(b));
  a=veorq_u8(aa,vcombine_u8(vreinterpret_u8_u16(lo),vdup_n_u8(0)));b=veorq_u8(bb,vcombine_u8(hi,vdup_n_u8(0)));
 }
 vst1q_u8((unsigned char*)output,a);vst1q_u8((unsigned char*)output+16,b);return seed^initial;
}
__attribute__((used,noinline)) uint64_t transpose_mix_c_end(void){return 1;}
