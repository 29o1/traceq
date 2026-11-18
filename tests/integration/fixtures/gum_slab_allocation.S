.text
.p2align 2
.global slab_allocation_target
.type slab_allocation_target,%function
slab_allocation_target:
 .rept 4096
  add x0,x0,#1
  ldr x2,[x1]
  add x2,x2,#0x123
  str x2,[x1]
  b 1f
1:
 .endr
 ret
.size slab_allocation_target,.-slab_allocation_target
.section .note.GNU-stack,"",%progbits

.text
.p2align 2
.global dense_context_target
.type dense_context_target,%function
dense_context_target:
 stp x19,x20,[sp,#-16]!
 // Reserve accessible stack memory, then exercise it below the live target SP.
 sub sp,sp,#512
 mov x19,sp
 add sp,sp,#512
 mov x10,x19
 mov x11,#64
 mov x9,#0xa5a5
 movk x9,#0xa5a5,lsl #16
 movk x9,#0xa5a5,lsl #32
 movk x9,#0xa5a5,lsl #48
1:
 str x9,[x10],#8
 subs x11,x11,#1
 b.ne 1b
 // One long basic block with a callout at every original instruction.
 .rept 4096
 add x0,x0,#1
 .endr
 mov x10,x19
 mov x11,#64
2:
 ldr x9,[x10],#8
 str x9,[x1],#8
 subs x11,x11,#1
 b.ne 2b
 ldp x19,x20,[sp],#16
 ret
.size dense_context_target,.-dense_context_target
