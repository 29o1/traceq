.text
.p2align 2
.globl _fp_store_bits
_fp_store_bits:
    fmov d0, x0
    str d0, [x1]
    fmov s1, w0
    str s1, [x1, #8]
    str xzr, [x1, #16]
    ret
.globl _fp_store_bits_end
_fp_store_bits_end:

.p2align 2
.globl _store_writeback
_store_writeback:
    mov x8, x1
    stp x0, x2, [x8, #16]!
    str xzr, [x8], #8
    str w0, [x1, #4]
    eor x0, x0, x2
    ret
.globl _store_writeback_end
_store_writeback_end:

.p2align 2
.globl _unsupported_store
_unsupported_store:
    movi v0.16b, #3
    stlr x0, [x1]
    strb w0, [x1, #20]
    ret
.globl _unsupported_store_end
_unsupported_store_end:

.p2align 2
.globl _store_loop
_store_loop:
    mov x3, #0
1:  str x3, [x1]
    add x3, x3, #1
    cmp x3, x2
    b.lo 1b
    mov x0, x3
    ret
.globl _store_loop_end
_store_loop_end:

.p2align 2
.globl _signed_discard_read
_signed_discard_read:
    ldrsb x3, [x1, #16]
    ldr xzr, [x1, #16]
    str x3, [x1]
    mov x0, x3
    ret
.globl _signed_discard_read_end
_signed_discard_read_end:

.p2align 2
.globl _outside_call
_outside_call:
    mov x9, lr
    bl outside_helper
    mov lr, x9
    strb w0, [x1, #16]
    ret
.globl _outside_call_end
_outside_call_end:
.p2align 2
outside_helper:
    str x0, [x1]
    ret
