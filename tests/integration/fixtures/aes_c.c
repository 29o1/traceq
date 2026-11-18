#include <arm_neon.h>
#include <stdint.h>
#include <string.h>
__attribute__((noinline)) uint64_t aes_mix_c(uint64_t seed,void* output,uint64_t count){
 uint64_t initial;memcpy(&initial,(unsigned char*)output+16,8);
 const uint64_t av[2]={seed,initial},bv[2]={initial,~seed};
 uint8x16_t a=vreinterpretq_u8_u64(vld1q_u64(av)),b=vreinterpretq_u8_u64(vld1q_u64(bv));
 for(uint64_t i=0;i<count;++i){a=vaeseq_u8(a,b);a=vaesmcq_u8(a);b=vaesdq_u8(b,a);b=vaesimcq_u8(b);}
 vst1q_u8((unsigned char*)output,a);vst1q_u8((unsigned char*)output+16,b);
 return seed^initial;
}
__attribute__((used,noinline)) uint64_t aes_mix_c_end(void){return 1;}
