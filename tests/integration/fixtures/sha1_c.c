#include <arm_neon.h>
#include <stdint.h>
#include <string.h>
// The test checks this C pipeline through independent untraced assembly.
__attribute__((noinline)) uint64_t sha1_mix_c(uint64_t seed,void* output,uint64_t count){
 uint64_t initial;memcpy(&initial,(unsigned char*)output+16,8);
 const uint64_t av[2]={seed,initial},bv[2]={initial,~seed},wv[2]={count,0xfedcba9876543210ull};
 uint32x4_t a=vreinterpretq_u32_u64(vld1q_u64(av)),b=vreinterpretq_u32_u64(vld1q_u64(bv)),w=vreinterpretq_u32_u64(vld1q_u64(wv));uint32_t e=(uint32_t)(seed^initial);
 for(uint64_t i=0;i<count;++i){a=vsha1cq_u32(a,e,w);a=vsha1pq_u32(a,e,b);b=vsha1mq_u32(b,e,a);e=vsha1h_u32(e);w=vsha1su0q_u32(w,a,b);w=vsha1su1q_u32(w,a);}
 vst1q_u32((uint32_t*)output,a);vst1q_u32((uint32_t*)output+4,b);
 return seed^initial^(uint64_t)e;
}
__attribute__((used,noinline)) uint64_t sha1_mix_c_end(void){return 1;}
