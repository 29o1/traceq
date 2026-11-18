.text
.p2align 2
.global fp_context_run
.type fp_context_run,%function
fp_context_run:
 stp x29,x30,[sp,#-32]!
 mrs x9,fpcr
 mrs x10,fpsr
 stp x9,x10,[sp,#16]
 msr fpcr,xzr
 msr fpsr,xzr
 bl fp_callback_target
 ldp x9,x10,[sp,#16]
 msr fpcr,x9
 msr fpsr,x10
 ldp x29,x30,[sp],#32
 ret
.size fp_context_run,.-fp_context_run
.p2align 2
.global fp_callback_target
.type fp_callback_target,%function
fp_callback_target:
 mrs x3,fpcr
 mrs x4,fpsr
 stp x3,x4,[x0]
 mov x5,#0x800000
 mov x6,#0x8000000
 msr fpcr,x5
 msr fpsr,x6
 b 1f
1:
 nop
 mrs x7,fpcr
 mrs x8,fpsr
 stp x7,x8,[x0,#16]
 msr fpcr,x3
 msr fpsr,x4
 ret
.size fp_callback_target,.-fp_callback_target
.section .note.GNU-stack,"",%progbits
