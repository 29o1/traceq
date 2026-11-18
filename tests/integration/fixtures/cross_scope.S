.text
.p2align 2
.globl _cross_target
_cross_target:
    stp x29, x30, [sp, #-32]!
    stp x19, x20, [sp, #16]
    mov x19, x1
    str x0, [x1]
    str x0, [x1, #8]
    adr x3, _cross_callback
    adrp x16, _cross_external@GOTPAGE
    ldr x16, [x16, _cross_external@GOTPAGEOFF]
    blr x16
    ldr x4, [x19]
    str x4, [x19, #16]
    str x0, [x19, #24]
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #32
    ret
_cross_callback:
    add x4, x0, #3
    str x4, [x1, #8]
    ret
.globl _cross_target_end
_cross_target_end:

.p2align 2
.globl _cross_tail
_cross_tail:
    mov x3, #0
    adrp x16, _cross_external@GOTPAGE
    ldr x16, [x16, _cross_external@GOTPAGEOFF]
    br x16
.globl _cross_tail_end
_cross_tail_end:

.p2align 2
.globl _cross_direct
_cross_direct:
    mov x3, #0
    b _cross_external
.globl _cross_direct_end
_cross_direct_end:
