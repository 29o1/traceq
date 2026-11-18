#include "invoke_targets.h"
#include <string.h>
__attribute__((noinline)) uint64_t invoke_integer(uint64_t seed,void* output,uint64_t a,uint64_t b,uint64_t c,uint64_t d,uint64_t e,uint64_t f,uint64_t g,uint64_t h){
    uint64_t value=seed+a+3*b+5*c+7*d+11*e+13*f+17*g+19*h;
    memcpy(output,&value,8);return value^0x55667788;
}
__attribute__((noinline)) double invoke_floating(double a,float b,uint64_t x,double c,void* output){
    double value=a*b+x+c;memcpy(output,&value,8);return value+1;
}
__attribute__((noinline)) InvokeTriple invoke_triple(uint64_t seed,void* output){
    uint64_t value=seed^0x5a;memcpy(output,&value,8);
    InvokeTriple result={seed+1,seed+2,seed+3};return result;
}
