#include <arm_neon.h>
#include <stdint.h>
#include <string.h>
// One padded SHA-256 block; the Python oracle hashes the original message.
static const uint32_t K[64]={
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
__attribute__((noinline)) uint64_t sha256_c(uint64_t seed,void* output,uint64_t count){
 uint64_t initial;memcpy(&initial,(unsigned char*)output+16,8);unsigned n=count&15;unsigned char block[64]={0};
 for(unsigned i=0;i<n;++i)block[i]=(unsigned char)((seed>>(8*(i&7)))^(initial>>(8*((i+3)&7)))^i);
 block[n]=0x80;block[63]=n*8;uint32_t words[16];for(unsigned i=0;i<16;++i)words[i]=((uint32_t)block[4*i]<<24)|((uint32_t)block[4*i+1]<<16)|((uint32_t)block[4*i+2]<<8)|block[4*i+3];
 const uint32_t iv[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
 uint32x4_t a=vld1q_u32(iv),b=vld1q_u32(iv+4),msg[4];for(unsigned i=0;i<4;++i)msg[i]=vld1q_u32(words+4*i);
 for(unsigned i=0;i<16;++i){unsigned slot=i&3;uint32x4_t wk=vaddq_u32(msg[slot],vld1q_u32(K+4*i)),old=a;a=vsha256hq_u32(a,b,wk);b=vsha256h2q_u32(b,old,wk);if(i<12)msg[slot]=vsha256su1q_u32(vsha256su0q_u32(msg[slot],msg[(slot+1)&3]),msg[(slot+2)&3],msg[(slot+3)&3]);}
 uint32_t state[8];vst1q_u32(state,vaddq_u32(a,vld1q_u32(iv)));vst1q_u32(state+4,vaddq_u32(b,vld1q_u32(iv+4)));
 for(unsigned i=0;i<8;++i){unsigned char*p=(unsigned char*)output+4*i;p[0]=state[i]>>24;p[1]=state[i]>>16;p[2]=state[i]>>8;p[3]=state[i];}
 return seed^initial;
}

__attribute__((used,noinline)) uint64_t sha256_c_end(void){return 1;}
