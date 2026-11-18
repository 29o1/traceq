#include "rust_classifier.h"
#include <cstdio>
#include <stdexcept>
static void require(bool value){if(!value)throw std::runtime_error("SIMD support boundary");}
int main(){try{
    for(auto id:{ARM64_INS_CMEQ,ARM64_INS_SHL,ARM64_INS_USHLL,ARM64_INS_USHLL2,ARM64_INS_UXTL,ARM64_INS_UXTL2,ARM64_INS_XTN,ARM64_INS_XTN2}) {
        cs_detail detail{};cs_insn ins{};ins.id=id;ins.detail=&detail;strcpy(ins.mnemonic,"simd_boundary");auto&a=detail.arm64;
        bool narrow=id==ARM64_INS_XTN || id==ARM64_INS_XTN2,high=id==ARM64_INS_USHLL2 || id==ARM64_INS_UXTL2;
        a.op_count=(id==ARM64_INS_UXTL || id==ARM64_INS_UXTL2 || narrow)?2:3;
        a.operands[0].type=a.operands[1].type=ARM64_OP_REG;a.operands[0].reg=ARM64_REG_V0;a.operands[1].reg=ARM64_REG_V1;a.operands[0].vector_index=a.operands[1].vector_index=-1;
        a.operands[0].vas=narrow?(id==ARM64_INS_XTN2?ARM64_VAS_16B:ARM64_VAS_8B):id==ARM64_INS_CMEQ || id==ARM64_INS_SHL?ARM64_VAS_16B:ARM64_VAS_8H;
        a.operands[1].vas=narrow?ARM64_VAS_8H:id==ARM64_INS_CMEQ || id==ARM64_INS_SHL || high?ARM64_VAS_16B:ARM64_VAS_8B;
        a.operands[2].type=ARM64_OP_IMM;a.operands[2].imm=id==ARM64_INS_CMEQ?0:1;
        auto supported=[&](){auto*p=make_plan(&ins);bool ok=!p->unsupported;delete p;return ok;};require(supported());
        auto original=a;
        for(auto reg:{ARM64_REG_Z0,ARM64_REG_P0,ARM64_REG_X0})for(unsigned operand:{0u,1u}) {a=original;a.operands[operand].reg=reg;require(!supported());}
        a=original;a.operands[1].type=ARM64_OP_MEM;require(!supported());
        a=original;a.operands[1].vector_index=0;require(!supported());
        if(a.op_count==3){a=original;a.operands[2].imm=id==ARM64_INS_CMEQ?1:8;require(!supported());}
        if(id==ARM64_INS_CMEQ) {
            a=original;a.op_count=4;a.operands[0].reg=ARM64_REG_D0;a.operands[1].reg=ARM64_REG_D1;
            a.operands[0].vas=a.operands[1].vas=ARM64_VAS_INVALID;a.operands[2].imm=0;a.operands[3]=a.operands[2];require(supported());
            a.operands[3].imm=1;require(!supported());a.operands[3].imm=0;a.operands[1].reg=ARM64_REG_Z0;require(!supported());
        }
    }
    puts("PASS SIMD represented-bank/shape/immediate boundaries; SVE not executed");return 0;
}catch(const std::exception&e){fprintf(stderr,"%s\n",e.what());return 1;}}
