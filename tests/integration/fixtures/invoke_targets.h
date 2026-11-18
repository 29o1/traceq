#pragma once
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef struct InvokeTriple { uint64_t a,b,c; } InvokeTriple;
uint64_t invoke_integer(uint64_t,void*,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t);
double invoke_floating(double,float,uint64_t,double,void*);
InvokeTriple invoke_triple(uint64_t,void*);
#ifdef __cplusplus
}
#endif
