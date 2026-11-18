#include <arm_neon.h>
#include <stdint.h>
#include <string.h>
__attribute__((noinline)) uint64_t polymul_mix_c(uint64_t seed,void*output,uint64_t count){
 uint64_t initial;memcpy(&initial,(unsigned char*)output+16,8);
 uint64_t av[2]={seed,initial},bv[2]={initial,~seed};
 poly64x2_t a=vreinterpretq_p64_u64(vld1q_u64(av)),b=vreinterpretq_p64_u64(vld1q_u64(bv));
 for(uint64_t i=0;i<count;++i){
  poly128_t lo=vmull_p64(vgetq_lane_p64(a,0),vgetq_lane_p64(b,0)),hi=vmull_high_p64(a,b);
  poly16x8_t lb=vmull_p8(vget_low_p8(vreinterpretq_p8_p64(a)),vget_low_p8(vreinterpretq_p8_p64(b)));
  poly16x8_t hb=vmull_high_p8(vreinterpretq_p8_p64(a),vreinterpretq_p8_p64(b));
  uint64x2_t lv,hv;memcpy(&lv,&lo,16);memcpy(&hv,&hi,16);
  a=vreinterpretq_p64_u64(veorq_u64(lv,vreinterpretq_u64_p16(lb)));
  b=vreinterpretq_p64_u64(veorq_u64(hv,vreinterpretq_u64_p16(hb)));
 }
 vst1q_u64((uint64_t*)output,vreinterpretq_u64_p64(a));vst1q_u64((uint64_t*)output+2,vreinterpretq_u64_p64(b));return seed^initial;
}
__attribute__((used,noinline)) uint64_t polymul_mix_c_end(void){return 1;}
