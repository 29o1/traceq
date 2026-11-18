#include "rust_classifier.h"
#include <cstdio>
#include <stdexcept>
static void require(bool x){if(!x)throw std::runtime_error("transpose observation boundary");}
int main(){try{
 for(auto id:{ARM64_INS_TRN1,ARM64_INS_TRN2})for(auto shape:{ARM64_VAS_8B,ARM64_VAS_16B,ARM64_VAS_4H,ARM64_VAS_8H,ARM64_VAS_2S,ARM64_VAS_4S,ARM64_VAS_2D}){
  cs_detail detail{};cs_insn ins{};ins.detail=&detail;ins.id=id;strcpy(ins.mnemonic,"transpose_boundary");auto&a=detail.arm64;a.op_count=3;
  for(unsigned i=0;i<a.op_count;++i){auto&o=a.operands[i];o.type=ARM64_OP_REG;o.vector_index=-1;o.reg=arm64_reg(ARM64_REG_V29+i);o.vas=shape;}
  auto good=a;auto supported=[&](){auto*q=make_plan(&ins);bool v=!q->unsupported;delete q;return v;};require(supported());
  for(unsigned i=0;i<good.op_count;++i){
   for(auto bad:{ARM64_REG_Z0,ARM64_REG_P0,ARM64_REG_X0,ARM64_REG_D0,ARM64_REG_Q0}){a=good;a.operands[i].reg=bad;require(!supported());}
   a=good;a.operands[i].type=ARM64_OP_MEM;require(!supported());a=good;a.operands[i].vector_index=0;require(!supported());
   a=good;a.operands[i].shift.type=ARM64_SFT_LSL;require(!supported());a=good;a.operands[i].ext=ARM64_EXT_UXTW;require(!supported());
   a=good;a.operands[i].vas=ARM64_VAS_1D;require(!supported());
  }
  a=good;++a.op_count;require(!supported());a=good;a.writeback=true;require(!supported());ins.detail=nullptr;require(!supported());
 }
 puts("PASS transpose shape/bank/count/shift/extension boundaries");return 0;
}catch(const std::exception&e){fprintf(stderr,"%s\n",e.what());return 1;}}
