// Exercise the register-bank support boundary without executing SVE.
#include "rust_classifier.h"
#include <cstdio>
#include <stdexcept>
#include <utility>
static void require(bool condition,const char* message){if(!condition)throw std::runtime_error(message);}
int main(){
    try {
        // Only register banks represented by the 65-slot snapshot are supported.
        // These classifier checks do not execute SVE on a machine lacking SVE.
        for(auto id:{ARM64_INS_CLZ,ARM64_INS_RBIT}) {
            cs_detail detail{};cs_insn ins{};ins.id=id;ins.detail=&detail;
            strcpy(ins.mnemonic,id==ARM64_INS_CLZ?"clz":"rbit");
            auto& a=detail.arm64;a.op_count=2;
            for(auto pair:{std::pair<arm64_reg,arm64_reg>{ARM64_REG_W0,ARM64_REG_WZR},
                           {ARM64_REG_XZR,ARM64_REG_FP},{ARM64_REG_V0,ARM64_REG_V31}}) {
                a.operands[0].type=a.operands[1].type=ARM64_OP_REG;
                a.operands[0].reg=pair.first;a.operands[1].reg=pair.second;
                auto* p=make_plan(&ins);bool supported=!p->unsupported;delete p;
                require(supported,"tracked bitop operands rejected");
            }
            for(auto reg:{ARM64_REG_Z0,ARM64_REG_P0}) {
                a.operands[0].reg=a.operands[1].reg=reg;
                auto* p=make_plan(&ins);bool unsupported=p->unsupported;delete p;
                require(unsupported,"untracked bitop operands accepted");
            }
            a.operands[0].reg=a.operands[1].reg=ARM64_REG_X0;
            a.operands[1].type=ARM64_OP_MEM;
            auto* p=make_plan(&ins);bool unsupported=p->unsupported;delete p;
            require(unsupported,"memory operand accepted as register-only bitop");
        }
        puts("PASS CLZ/RBIT operand-bank classification");return 0;
    }catch(const std::exception& e){fprintf(stderr,"%s\n",e.what());return 1;}
}
