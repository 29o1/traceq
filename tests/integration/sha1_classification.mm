#include "rust_classifier.h"
#include <cstdio>
#include <stdexcept>
static void require(bool x){if(!x)throw std::runtime_error("SHA1 observation boundary");}
int main(){try{
 for(auto id:{ARM64_INS_SHA1C,ARM64_INS_SHA1P,ARM64_INS_SHA1M,ARM64_INS_SHA1H,ARM64_INS_SHA1SU0,ARM64_INS_SHA1SU1}){
  cs_detail detail{};cs_insn ins{};ins.detail=&detail;ins.id=id;strcpy(ins.mnemonic,"sha1_boundary");auto&a=detail.arm64;
  bool hash=id==ARM64_INS_SHA1C||id==ARM64_INS_SHA1P||id==ARM64_INS_SHA1M,scalar=id==ARM64_INS_SHA1H;
  a.op_count=scalar||id==ARM64_INS_SHA1SU1?2:3;
  for(unsigned i=0;i<a.op_count;++i){auto&o=a.operands[i];o.type=ARM64_OP_REG;o.vector_index=-1;
   bool q=hash&&i==0,s=scalar||(hash&&i==1);o.reg=arm64_reg((q?ARM64_REG_Q0:s?ARM64_REG_S0:ARM64_REG_V0)+i);o.vas=q||s?ARM64_VAS_INVALID:ARM64_VAS_4S;}
  auto good=a;auto supported=[&](){auto*q=make_plan(&ins);bool v=!q->unsupported;delete q;return v;};require(supported());
  for(unsigned i=0;i<good.op_count;++i){
   for(auto bad:{ARM64_REG_Z0,ARM64_REG_P0,ARM64_REG_X0,ARM64_REG_D0}){a=good;a.operands[i].reg=bad;require(!supported());}
   a=good;a.operands[i].type=ARM64_OP_MEM;require(!supported());a=good;a.operands[i].vector_index=0;require(!supported());
   a=good;a.operands[i].shift.type=ARM64_SFT_LSL;require(!supported());a=good;a.operands[i].ext=ARM64_EXT_UXTW;require(!supported());a=good;a.operands[i].vas=ARM64_VAS_2S;require(!supported());
  }
  a=good;++a.op_count;require(!supported());a=good;a.writeback=true;require(!supported());ins.detail=nullptr;require(!supported());
 }
 puts("PASS SHA1 shape/bank/count/shift/extension boundaries");return 0;
}catch(const std::exception&e){fprintf(stderr,"%s\n",e.what());return 1;}}
