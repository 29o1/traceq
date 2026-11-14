.text
.p2align 2
.globl _arithmetic_branch
_arithmetic_branch:
    add x3, x0, #7
    eor x4, x3, x0
    subs x5, x4, #9
    b.lo 1f
    add x6, x5, #3
    b 2f
1:  add x6, x4, #11
2:  str x6, [x1]
    cmp x6, #16
    cset w7, hi
    str w7, [x1, #8]
    mov x0, x6
    ret
.globl _arithmetic_branch_end
_arithmetic_branch_end:

.p2align 2
.globl _memory_overlap
_memory_overlap:
    mov x3, #0x1122
    movk x3, #0x3344, lsl #16
    eor x3, x3, x0
    str x3, [x1]
    mov w4, #0xaabb
    strh w4, [x1, #2]
    strh w4, [x1, #2]
    ldrb w5, [x1, #3]
    ldr w6, [x1]
    rev w7, w6
    str w7, [x1, #8]
    add x0, x5, x6
    ret
.globl _memory_overlap_end
_memory_overlap_end:

.p2align 2
.globl _state_loop
_state_loop:
    ldr x3, [x1, #16]
    add x3, x3, #1
    str x3, [x1, #16]
    mov x4, #0
1:  add x0, x0, x3
    eor x0, x0, x4
    add x4, x4, #1
    cmp x4, x2
    b.lo 1b
    str x0, [x1]
    ret
.globl _state_loop_end
_state_loop_end:
