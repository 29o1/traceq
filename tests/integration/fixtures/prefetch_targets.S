#ifdef __APPLE__
#define NAME(x) _##x
#else
#define NAME(x) x
#endif
.text
.macro PREFETCH name, index, instruction:vararg
.p2align 2
.globl \name
\name:
    str x0, [x1]
    mov x8, #\index
    cmp x0, x2
    \instruction
    ret
.globl \name\()_end
\name\()_end:
.endm
PREFETCH NAME(prefetch_base), 1, prfm pldl1keep, [x1]
PREFETCH NAME(prefetch_store), 1, prfm pstl1strm, [x1, #8]
PREFETCH NAME(prefetch_exec), 1, prfm plil2keep, [x1, #16]
PREFETCH NAME(prefetch_reg), 1, prfm pldl1keep, [x1, x8]
PREFETCH NAME(prefetch_shift), 1, prfm pldl1keep, [x1, x8, lsl #3]
PREFETCH NAME(prefetch_uxtw), 1, prfm pldl1keep, [x1, w8, uxtw #3]
PREFETCH NAME(prefetch_sxtw), -1, prfm pldl1keep, [x1, w8, sxtw #3]
PREFETCH NAME(prefetch_sxtx), -1, prfm pldl1keep, [x1, x8, sxtx #3]
PREFETCH NAME(prefetch_unscaled_pos), 1, prfum pldl1keep, [x1, #7]
PREFETCH NAME(prefetch_unscaled_neg), 1, prfum pldl1keep, [x1, #-7]
PREFETCH NAME(prefetch_unmapped), 0, prfm pldl1keep, [x8]
PREFETCH NAME(prefetch_unnamed), 1, prfm #31, [x1]
.p2align 2
.globl NAME(prefetch_forward)
NAME(prefetch_forward):
    str x0, [x1]
    cmp x0, x2
    prfm pldl1keep, 0f
    ret
.p2align 3
0:  .quad 0x0123456789abcdef
.globl NAME(prefetch_forward_end)
NAME(prefetch_forward_end):
.p2align 2
.globl NAME(prefetch_backward)
NAME(prefetch_backward):
    b 1f
.p2align 3
0:  .quad 0x0123456789abcdef
1:  str x0, [x1]
    cmp x0, x2
    prfm pstl1keep, 0b
    ret
.globl NAME(prefetch_backward_end)
NAME(prefetch_backward_end):
