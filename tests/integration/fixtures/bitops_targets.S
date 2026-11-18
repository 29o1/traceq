#ifdef __APPLE__
#define NAME(x) _##x
#else
#define NAME(x) x
#endif
.text
.p2align 2
.macro SCALAR name, op, dst, src, alias=0
.p2align 2
.globl \name
\name:
    mov x8, #-1
.if \alias
    mov x8, x0
.endif
    mov x9, x0
    str x0, [x1]
    cmp x0, x2
    \op \dst, \src
    str x8, [x1, #8]
    ldr x10, [x1, #16]
    str x10, [x1, #24]
    mov x0, x8
    ret
.globl \name\()_end
\name\()_end:
.endm
SCALAR NAME(bitops_clz64), clz, x8, x9
SCALAR NAME(bitops_clz32), clz, w8, w9
SCALAR NAME(bitops_rbit64), rbit, x8, x9
SCALAR NAME(bitops_rbit32), rbit, w8, w9
SCALAR NAME(bitops_clz_zero64), clz, x8, xzr
SCALAR NAME(bitops_clz_zero32), clz, w8, wzr
SCALAR NAME(bitops_rbit_zero64), rbit, x8, xzr
SCALAR NAME(bitops_rbit_zero32), rbit, w8, wzr
SCALAR NAME(bitops_clz_discard64), clz, xzr, x9
SCALAR NAME(bitops_clz_discard32), clz, wzr, w9
SCALAR NAME(bitops_rbit_discard64), rbit, xzr, x9
SCALAR NAME(bitops_rbit_discard32), rbit, wzr, w9
SCALAR NAME(bitops_clz_alias64), clz, x8, x8, 1
SCALAR NAME(bitops_clz_alias32), clz, w8, w8, 1
SCALAR NAME(bitops_rbit_alias64), rbit, x8, x8, 1
SCALAR NAME(bitops_rbit_alias32), rbit, w8, w8, 1

.macro VECTOR name, op, dst, src, alias=0
.p2align 2
.globl \name
\name:
    movi v0.16b, #255
    ldr q1, [x1, #16]
.if \alias
    mov v0.16b, v1.16b
.endif
    str x0, [x1]
    cmp x0, x2
    \op \dst, \src
    str q0, [x1, #8]
    umov x0, v0.d[0]
    ret
.globl \name\()_end
\name\()_end:
.endm
VECTOR NAME(bitops_clz_8b), clz, v0.8b, v1.8b
VECTOR NAME(bitops_clz_16b), clz, v0.16b, v1.16b
VECTOR NAME(bitops_clz_4h), clz, v0.4h, v1.4h
VECTOR NAME(bitops_clz_8h), clz, v0.8h, v1.8h
VECTOR NAME(bitops_clz_2s), clz, v0.2s, v1.2s
VECTOR NAME(bitops_clz_4s), clz, v0.4s, v1.4s
VECTOR NAME(bitops_rbit_8b), rbit, v0.8b, v1.8b
VECTOR NAME(bitops_rbit_16b), rbit, v0.16b, v1.16b
VECTOR NAME(bitops_clz_vector_alias), clz, v0.16b, v0.16b, 1
VECTOR NAME(bitops_rbit_vector_alias), rbit, v0.16b, v0.16b, 1

.p2align 2
.globl NAME(bitops_gap)
NAME(bitops_gap):
    str x0, [x1]
    movi v0.16b, #1
    movi v1.16b, #2
    movi v2.16b, #3
    st3 {v0.8b, v1.8b, v2.8b}, [x1]
    ret
.globl NAME(bitops_gap_end)
NAME(bitops_gap_end):
.globl NAME(bitops_unknown)
NAME(bitops_unknown):
    ldr xzr, [x1, #16]
    ret
.globl NAME(bitops_unknown_end)
NAME(bitops_unknown_end):
