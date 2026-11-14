.text
.p2align 2
// Deterministic target context for all-register differential checks. x18 is
// platform-reserved and is left untouched. Save/restore the host ABI state.
.globl _traceq_controlled_call
_traceq_controlled_call:
    stp x29, x30, [sp, #-320]!
    stp x19, x20, [sp, #16]
    stp x21, x22, [sp, #32]
    stp x23, x24, [sp, #48]
    stp x25, x26, [sp, #64]
    stp x27, x28, [sp, #80]
    stp q8, q9, [sp, #96]
    stp q10, q11, [sp, #128]
    stp q12, q13, [sp, #160]
    stp q14, q15, [sp, #192]
    str x0, [sp, #224]
    stp x1, x2, [sp, #232]
    str x3, [sp, #248]
    mov x3, #3
    mov x4, #4
    mov x5, #5
    mov x6, #6
    mov x7, #7
    mov x8, #8
    mov x9, #9
    mov x10, #10
    mov x11, #11
    mov x12, #12
    mov x13, #13
    mov x14, #14
    mov x15, #15
    mov x17, #17
    mov x19, #19
    mov x20, #20
    mov x21, #21
    mov x22, #22
    mov x23, #23
    mov x24, #24
    mov x25, #25
    mov x26, #26
    mov x27, #27
    mov x28, #28
    mov x29, #29
    movi v0.16b, #0
    movi v1.16b, #1
    movi v2.16b, #2
    movi v3.16b, #3
    movi v4.16b, #4
    movi v5.16b, #5
    movi v6.16b, #6
    movi v7.16b, #7
    movi v8.16b, #8
    movi v9.16b, #9
    movi v10.16b, #10
    movi v11.16b, #11
    movi v12.16b, #12
    movi v13.16b, #13
    movi v14.16b, #14
    movi v15.16b, #15
    movi v16.16b, #16
    movi v17.16b, #17
    movi v18.16b, #18
    movi v19.16b, #19
    movi v20.16b, #20
    movi v21.16b, #21
    movi v22.16b, #22
    movi v23.16b, #23
    movi v24.16b, #24
    movi v25.16b, #25
    movi v26.16b, #26
    movi v27.16b, #27
    movi v28.16b, #28
    movi v29.16b, #29
    movi v30.16b, #30
    movi v31.16b, #31
    ldr x16, [sp, #224]
    ldp x0, x1, [sp, #232]
    ldr x2, [sp, #248]
    cmp xzr, xzr
    blr x16
    ldp q8, q9, [sp, #96]
    ldp q10, q11, [sp, #128]
    ldp q12, q13, [sp, #160]
    ldp q14, q15, [sp, #192]
    ldp x19, x20, [sp, #16]
    ldp x21, x22, [sp, #32]
    ldp x23, x24, [sp, #48]
    ldp x25, x26, [sp, #64]
    ldp x27, x28, [sp, #80]
    ldp x29, x30, [sp], #320
    ret

.p2align 2
.globl _boundary_flags
_boundary_flags:
    adds w3, w0, #1
    cset w4, cs
    mov x5, #-1
    mov w5, w3
    str x5, [x1]
    str w4, [x1, #8]
    fmov d0, x0
    fmov s0, w3
    str q0, [x1, #16]
    mov x10, x29
    mov x11, x30
    mov w29, w0
    mov w30, w2
    mov x29, x10
    mov x30, x11
    sub sp, sp, #16
    add sp, sp, #16
    subs x6, x0, #1
    csel x0, x5, x6, eq
    ret
.globl _boundary_flags_end
_boundary_flags_end:

.p2align 2
.globl _boundary_range_tail
_boundary_range_tail:
    add x0, x0, #3
.globl _boundary_range_tail_end
_boundary_range_tail_end:
    ret

.p2align 2
.globl _boundary_long
_boundary_long:
    .rept 4096
    add x0, x0, #1
    .endr
    str x0, [x1]
    ret
.globl _boundary_long_end
_boundary_long_end:

.p2align 2
.globl _boundary_exclusive
_boundary_exclusive:
1:  ldxr x3, [x1]
    add x3, x3, #1
    stxr w4, x3, [x1]
    cbnz w4, 1b
    ldr x0, [x1]
    ret
.globl _boundary_exclusive_end
_boundary_exclusive_end:

.p2align 2
.globl _boundary_simd_high
_boundary_simd_high:
    movi v0.16b, #0x55
    fmov v0.d[1], x0
    str q0, [x1]
    fmov d1, x0
    fmov s1, w0
    str q1, [x1, #16]
    ret
.globl _boundary_simd_high_end
_boundary_simd_high_end:

.p2align 2
.globl _android_control
_android_control:
    mov x9, lr
    adr x10, 1f
    br x10
    add x0, x0, #100
1:  bl 2f
    adr x10, 3f
    blr x10
    mov lr, x9
    ret
2:  add x0, x0, #7
    ret
3:  eor x0, x0, #0xff
    ret
.globl _android_control_end
_android_control_end:

.p2align 2
.globl _android_scalar
_android_scalar:
    adrp x8, _android_scalar@PAGE
    mvn x3, x0
    bfi x3, x0, #8, #8
    bfxil x3, x0, #16, #8
    ands x4, x3, #0xff
    ccmp x4, #0, #4, ne
    csetm x5, eq
    mrs x12, nzcv
    mov x6, #7
    udiv x7, x3, x6
    str x7, [x1]
    eor x0, x7, x5
    ret
.globl _android_scalar_end
_android_scalar_end:

.p2align 2
.globl _android_vectors
_android_vectors:
    movi v0.16b, #0x81
    movi v1.16b, #1
    ext v2.16b, v0.16b, v1.16b, #8
    ushl v3.16b, v2.16b, v1.16b
    zip1 v4.16b, v2.16b, v3.16b
    uzp1 v5.16b, v4.16b, v4.16b
    str q4, [x1]
    str q5, [x1, #16]
    umov x0, v5.d[0]
    ret
.globl _android_vectors_end
_android_vectors_end:

.p2align 2
.globl _android_acquire_pac
_android_acquire_pac:
    bti c
    paciasp
    ldar x3, [x1]
    add x3, x3, #1
    str x3, [x1]
    dmb ish
    autiasp
    xpaclri
    mov x0, x3
    ret
.globl _android_acquire_pac_end
_android_acquire_pac_end:
