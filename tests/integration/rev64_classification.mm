#include "rust_classifier.h"
#include <cstdio>
#include <stdexcept>
static void require(bool v){if(!v)throw std::runtime_error("REV64 support boundary");}
int main(){try{
 for(auto shape:{ARM64_VAS_8B,ARM64_VAS_16B,ARM64_VAS_4H,ARM64_VAS_8H,ARM64_VAS_2S,ARM64_VAS_4S}){
  cs_detail detail{};cs_insn ins{};ins.detail=&detail;ins.id=ARM64_INS_REV64;strcpy(ins.mnemonic,"rev64_boundary");auto&a=detail.arm64;a.op_count=2;
  for(unsigned i=0;i<2;++i){auto&o=a.operands[i];o.type=ARM64_OP_REG;o.reg=arm64_reg(ARM64_REG_V30+i);o.vas=shape;o.vector_index=-1;}
  auto good=a;auto supported=[&](){auto*p=make_plan(&ins);bool v=!p->unsupported;delete p;return v;};require(supported());
  for(unsigned i=0;i<2;++i){
   for(auto reg:{ARM64_REG_Z0,ARM64_REG_P0,ARM64_REG_X0,ARM64_REG_Q0,ARM64_REG_D0,ARM64_REG_S0}){a=good;a.operands[i].reg=reg;require(!supported());}
   for(auto bad:{ARM64_VAS_INVALID,ARM64_VAS_1D,ARM64_VAS_2D}){a=good;a.operands[i].vas=bad;require(!supported());}
   a=good;a.operands[i].vas=shape==ARM64_VAS_8B?ARM64_VAS_16B:ARM64_VAS_8B;require(!supported());
   a=good;a.operands[i].type=ARM64_OP_MEM;require(!supported());a=good;a.operands[i].vector_index=0;require(!supported());
   a=good;a.operands[i].shift.type=ARM64_SFT_LSL;require(!supported());a=good;a.operands[i].ext=ARM64_EXT_UXTW;require(!supported());
  }
  a=good;++a.op_count;require(!supported());a=good;a.writeback=true;require(!supported());ins.detail=nullptr;require(!supported());
 }
 puts("PASS REV64 register/count/arrangement/lane/shift/extension/writeback boundaries");return 0;
}catch(const std::exception&e){fprintf(stderr,"%s\n",e.what());return 1;}}
