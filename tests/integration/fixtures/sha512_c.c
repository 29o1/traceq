#include <arm_neon.h>
#include <stdint.h>
#include <string.h>
// An ordinary C pipeline; the test computes its oracle through separate,
// untraced assembly functions, then checks every captured instruction state.
__attribute__((noinline)) uint64_t sha512_mix_c(uint64_t seed,void* output,uint64_t count){
 uint64_t initial;memcpy(&initial,(unsigned char*)output+16,8);
 const uint64_t av[2]={seed,seed^initial},bv[2]={initial,~seed},cv[2]={count,0xfedcba9876543210ull};
 uint64x2_t a=vld1q_u64(av),b=vld1q_u64(bv),c=vld1q_u64(cv);
 for(uint64_t i=0;i<count;++i){a=vsha512hq_u64(a,b,c);b=vsha512h2q_u64(b,c,a);c=vsha512su0q_u64(c,a);c=vsha512su1q_u64(c,a,b);}
 vst1q_u64((uint64_t*)output,a);vst1q_u64((uint64_t*)output+2,b);
 return seed^initial;
}
__attribute__((used,noinline)) uint64_t sha512_mix_c_end(void){return 1;}
