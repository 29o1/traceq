#include "rust_classifier.h"
#include <cstdio>
#include <stdexcept>
static void require(bool v){if(!v)throw std::runtime_error("carry support boundary");}
int main(){try{
 for(auto id:{ARM64_INS_ADC,ARM64_INS_ADCS,ARM64_INS_SBC,ARM64_INS_SBCS,ARM64_INS_NGC,ARM64_INS_NGCS})for(bool word:{false,true}){
  cs_detail detail{};cs_insn ins{};ins.detail=&detail;ins.id=id;strcpy(ins.mnemonic,"carry_boundary");auto&a=detail.arm64;a.op_count=id==ARM64_INS_NGC||id==ARM64_INS_NGCS?2:3;
  for(unsigned i=0;i<a.op_count;++i){auto&o=a.operands[i];o.type=ARM64_OP_REG;o.reg=word?arm64_reg(ARM64_REG_W0+27+i):i==2?ARM64_REG_LR:i==1?ARM64_REG_FP:ARM64_REG_X28;o.vector_index=-1;}
  auto good=a;auto supported=[&](){auto*p=make_plan(&ins);bool v=!p->unsupported;delete p;return v;};require(supported());
  for(unsigned i=0;i<good.op_count;++i){a=good;a.operands[i].reg=word?ARM64_REG_WZR:ARM64_REG_XZR;require(supported());
   for(auto bad:{ARM64_REG_SP,ARM64_REG_WSP,ARM64_REG_Z0,ARM64_REG_P0,ARM64_REG_Q0,ARM64_REG_D0,ARM64_REG_S0}){a=good;a.operands[i].reg=bad;require(!supported());}
   a=good;a.operands[i].reg=word?ARM64_REG_X0:ARM64_REG_W0;require(!supported());a=good;a.operands[i].type=ARM64_OP_IMM;require(!supported());a=good;a.operands[i].vector_index=0;require(!supported());a=good;a.operands[i].vas=ARM64_VAS_4S;require(!supported());a=good;a.operands[i].shift.type=ARM64_SFT_LSL;require(!supported());a=good;a.operands[i].ext=ARM64_EXT_UXTW;require(!supported());
  }
  a=good;++a.op_count;require(!supported());a=good;a.writeback=true;require(!supported());ins.detail=nullptr;require(!supported());
 }
 puts("PASS scalarcarry bank/width/zero/count/shift/extension/writeback boundaries");return 0;
}catch(const std::exception&e){fprintf(stderr,"%s\n",e.what());return 1;}}
