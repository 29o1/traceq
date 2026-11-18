#ifdef __APPLE__
#define NAME(x) _##x
#else
#define NAME(x) x
#endif
.text
.p2align 2
// Identical setup gives an independent oracle for every operand and NZCV.
// x0=seed, x1=buffer, x2=count; the second operand is the 64-bit input at +16.
.macro MULTIPLY name, operation, dst, lhs, rhs, acc=
.p2align 2
.globl \name
\name:
    mov x8, x0
    ldr x9, [x1, #16]
    add x10, x8, x9
    str x8, [x1]
    str x9, [x1, #8]
    mov x11, #-1
    cmp x8, x9
.ifnb \acc
    \operation \dst, \lhs, \rhs, \acc
.else
    \operation \dst, \lhs, \rhs
.endif
    str x11, [x1, #24]
    mov x0, x11
    ret
.globl \name\()_end
\name\()_end:
.endm
MULTIPLY NAME(multiply_umull), umull, x11, w8, w9
MULTIPLY NAME(multiply_smull), smull, x11, w8, w9
MULTIPLY NAME(multiply_umaddl), umaddl, x11, w8, w9, x10
MULTIPLY NAME(multiply_smaddl), smaddl, x11, w8, w9, x10
MULTIPLY NAME(multiply_umsubl), umsubl, x11, w8, w9, x10
MULTIPLY NAME(multiply_smsubl), smsubl, x11, w8, w9, x10
MULTIPLY NAME(multiply_umnegl), umnegl, x11, w8, w9
MULTIPLY NAME(multiply_smnegl), smnegl, x11, w8, w9
MULTIPLY NAME(multiply_umulh), umulh, x11, x8, x9
MULTIPLY NAME(multiply_smulh), smulh, x11, x8, x9
MULTIPLY NAME(multiply_mul64), mul, x11, x8, x9
MULTIPLY NAME(multiply_mul32), mul, w11, w8, w9
MULTIPLY NAME(multiply_madd64), madd, x11, x8, x9, x10
MULTIPLY NAME(multiply_madd32), madd, w11, w8, w9, w10
MULTIPLY NAME(multiply_msub64), msub, x11, x8, x9, x10
MULTIPLY NAME(multiply_msub32), msub, w11, w8, w9, w10
MULTIPLY NAME(multiply_mneg64), mneg, x11, x8, x9
MULTIPLY NAME(multiply_mneg32), mneg, w11, w8, w9
MULTIPLY NAME(multiply_umull_zero), umull, x11, wzr, w9
MULTIPLY NAME(multiply_smaddl_zero), smaddl, x11, w8, w9, xzr

// Same mnemonic/ID as scalar UMULL, independently checked vector operands.
.p2align 2
.globl NAME(multiply_vector_gap)
NAME(multiply_vector_gap):
    movi v0.8b, #2
    movi v1.8b, #3
    str x0, [x1]
    umull v2.8h, v0.8b, v1.8b
    str q2, [x1, #16]
    ret
.globl NAME(multiply_vector_gap_end)
NAME(multiply_vector_gap_end):
