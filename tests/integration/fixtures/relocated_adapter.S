.text
.p2align 2
.global relocated_adapter
.type relocated_adapter,%function
relocated_adapter:
 stp x19,x30,[sp,#-16]!
 mov x19,x0
 ldr x16,[x19]
 ldp x0,x1,[x19,#8]
 ldp x2,x3,[x19,#24]
 ldp x4,x5,[x19,#40]
 mov x9,sp
 str x9,[x19,#64]
 blr x16
 str x0,[x19,#56]
 ldp x19,x30,[sp],#16
 ret
.size relocated_adapter,.-relocated_adapter
.section .note.GNU-stack,"",%progbits
