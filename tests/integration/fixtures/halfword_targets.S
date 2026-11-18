.arch armv8.1-a+lse
.text
.p2align 2
.macro one name, instruction, first, second, result
.global \name
.type \name, %function
\name:
    \instruction \first, \second, [x1]
    str \result, [x0]
    ret
.endm
one half_casah, casah, w2, w3, x2
one half_casalh, casalh, w2, w3, x2
one half_cash, cash, w2, w3, x2
one half_caslh, caslh, w2, w3, x2
one half_swplh, swplh, w2, w3, x3
one half_swpalh, swpalh, w2, w3, x3
one half_swph, swph, w2, w3, x3
one half_swpah, swpah, w2, w3, x3
one half_cas_alias, casah, w2, w2, x2
one half_cas_base, casah, w1, w3, x1
one half_swp_alias, swplh, w2, w2, x2
one half_swp_base, swplh, w2, w1, x1
one half_cas_zero, casah, w2, wzr, x2
one half_swp_zero, swplh, wzr, w3, x3
one half_cas_discard, casah, wzr, w3, xzr
one half_swp_discard, swplh, w2, wzr, xzr

.macro contended name, instruction, compare
.p2align 2
.global \name
.type \name, %function
\name:
1:
    ldrh w5, [x1]
    mov w6, w5
    .if \compare
    \instruction w6, w2, [x1]
    .else
    \instruction w2, w6, [x1]
    .endif
    ldrh w7, [x1]
    stp x6, x5, [x0]
    str x7, [x0, #16]
    add x0, x0, #24
    add w2, w2, #1
    subs x3, x3, #1
    b.ne 1b
    ret
.endm
contended half_contended_cas, casah, 1
contended half_contended_swap, swplh, 0
