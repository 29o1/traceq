.text
.p2align 2
.globl _pair_writeback
_pair_writeback:
    stp x0, x2, [x1]
    mov x8, x1
    ldp x3, x4, [x8], #16
    str x3, [x8]
    str x4, [x8, #8]
    eor x0, x3, x4
    ret
.globl _pair_writeback_end
_pair_writeback_end:

.p2align 2
.globl _simd_bytes
_simd_bytes:
    movi v0.16b, #0x12
    dup v1.2d, x0
    eor v2.16b, v0.16b, v1.16b
    str q2, [x1]
    ldr q3, [x1]
    add v4.16b, v3.16b, v0.16b
    str q4, [x1, #16]
    umov x0, v4.d[0]
    ret
.globl _simd_bytes_end
_simd_bytes_end:

.p2align 2
.globl _indexed_bytes
_indexed_bytes:
    mov x4, #0
    mov x6, #0
1:  add x3, x0, x4
    strb w3, [x1, x4]
    ldrb w5, [x1, x4]
    add x6, x6, x5
    add x4, x4, #1
    cmp x4, x2
    b.lo 1b
    str x6, [x1, #24]
    mov x0, x6
    ret
.globl _indexed_bytes_end
_indexed_bytes_end:
