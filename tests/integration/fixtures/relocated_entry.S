.text
.p2align 2
.global relocated_spill
.type relocated_spill,%function
relocated_spill:
 sub sp,sp,#64
 stp x0,x1,[sp]
 stp x2,x3,[sp,#16]
 stp x4,x5,[sp,#32]
 ldp x6,x7,[sp]
 add x6,x6,x2
 add x6,x6,x3
 add x6,x6,x4
 add x6,x6,x5
 str x6,[x1]
 ldr x8,[x1,#16]
 eor x8,x8,x6
 str x8,[x1,#8]
 mov x0,x6
 add sp,sp,#64
 ret
.size relocated_spill,.-relocated_spill
.p2align 2
.global relocated_literal
.type relocated_literal,%function
relocated_literal:
 sub sp,sp,#64
 adrp x9,.Lconstant
 ldr x10,[x9,:lo12:.Lconstant]
 stp x0,x1,[sp]
 ldp x6,x7,[sp]
 add x6,x6,x2
 add x6,x6,x3
 add x6,x6,x4
 add x6,x6,x5
 add x6,x6,x10
 str x6,[x1]
 ldr x8,[x1,#16]
 eor x8,x8,x6
 str x8,[x1,#8]
 mov x0,x6
 add sp,sp,#64
 ret
.size relocated_literal,.-relocated_literal
.section .rodata
.p2align 3
.Lconstant: .quad 0x1122334455667788
.section .note.GNU-stack,"",%progbits
