#ifdef __APPLE__
#define NAME(x) _##x
#else
#define NAME(x) x
#endif
.text
.p2align 2

// x0=seed, x1=output buffer, x2=count. Pools are skipped by execution.
// Dirty destination slots expose missing W/S/D upper-bit clearing.
.macro LITERAL name, operation, dst, vector, backward, low, high
.p2align 2
.globl \name
\name:
.if \backward
    b 1f
    .p2align 4
0:  .quad \low, \high
1:
.endif
    str x0, [x1]
    mov x8, #-1
    movi v31.16b, #255
    cmp x0, x2
.if \backward
    \operation \dst, 0b
.else
    \operation \dst, 0f
.endif
.if \vector
    str q31, [x1, #16]
.else
    str x8, [x1, #8]
.endif
    mov x0, x8
    ret
.if !\backward
    .p2align 4
0:  .quad \low, \high
.endif
.globl \name\()_end
\name\()_end:
.endm

LITERAL NAME(literal_w_forward_zero), ldr, w8, 0, 0, 0, 0
LITERAL NAME(literal_x_forward_zero), ldr, x8, 0, 0, 0, 0
LITERAL NAME(literal_sw_forward_zero), ldrsw, x8, 0, 0, 0, 0
LITERAL NAME(literal_s_forward_zero), ldr, s31, 1, 0, 0, 0
LITERAL NAME(literal_d_forward_zero), ldr, d31, 1, 0, 0, 0
LITERAL NAME(literal_q_forward_zero), ldr, q31, 1, 0, 0, 0
LITERAL NAME(literal_w_backward_zero), ldr, w8, 0, 1, 0, 0
LITERAL NAME(literal_x_backward_zero), ldr, x8, 0, 1, 0, 0
LITERAL NAME(literal_sw_backward_zero), ldrsw, x8, 0, 1, 0, 0
LITERAL NAME(literal_s_backward_zero), ldr, s31, 1, 1, 0, 0
LITERAL NAME(literal_d_backward_zero), ldr, d31, 1, 1, 0, 0
LITERAL NAME(literal_q_backward_zero), ldr, q31, 1, 1, 0, 0
LITERAL NAME(literal_w_forward_bits), ldr, w8, 0, 0, 0x7ff8123480000001, 0xfedcba987fc12345
LITERAL NAME(literal_x_forward_bits), ldr, x8, 0, 0, 0x7ff8123480000001, 0xfedcba987fc12345
LITERAL NAME(literal_sw_forward_bits), ldrsw, x8, 0, 0, 0x7ff8123480000001, 0xfedcba987fc12345
LITERAL NAME(literal_s_forward_bits), ldr, s31, 1, 0, 0x7ff8123480000001, 0xfedcba987fc12345
LITERAL NAME(literal_d_forward_bits), ldr, d31, 1, 0, 0x7ff8123480000001, 0xfedcba987fc12345
LITERAL NAME(literal_q_forward_bits), ldr, q31, 1, 0, 0x7ff8123480000001, 0xfedcba987fc12345
LITERAL NAME(literal_w_backward_bits), ldr, w8, 0, 1, 0x7ff8123480000001, 0xfedcba987fc12345
LITERAL NAME(literal_x_backward_bits), ldr, x8, 0, 1, 0x7ff8123480000001, 0xfedcba987fc12345
LITERAL NAME(literal_sw_backward_bits), ldrsw, x8, 0, 1, 0x7ff8123480000001, 0xfedcba987fc12345
LITERAL NAME(literal_s_backward_bits), ldr, s31, 1, 1, 0x7ff8123480000001, 0xfedcba987fc12345
LITERAL NAME(literal_d_backward_bits), ldr, d31, 1, 1, 0x7ff8123480000001, 0xfedcba987fc12345
LITERAL NAME(literal_q_backward_bits), ldr, q31, 1, 1, 0x7ff8123480000001, 0xfedcba987fc12345
LITERAL NAME(literal_s_nan), ldr, s31, 1, 0, 0x7fc12345, 0
LITERAL NAME(literal_wzr_forward), ldr, wzr, 0, 0, 0x80000001, 0
LITERAL NAME(literal_xzr_forward), ldr, xzr, 0, 0, 0x7ff8123480000001, 0
LITERAL NAME(literal_swzr_forward), ldrsw, xzr, 0, 0, 0x80000001, 0
LITERAL NAME(literal_wzr_backward), ldr, wzr, 0, 1, 0, 0
LITERAL NAME(literal_xzr_backward), ldr, xzr, 0, 1, 0, 0
LITERAL NAME(literal_swzr_backward), ldrsw, xzr, 0, 1, 0, 0

.p2align 2
.globl NAME(literal_prefetch)
NAME(literal_prefetch):
    str x0, [x1]
    prfm pldl1keep, 0f
    ret
    .p2align 4
0:  .quad 0x12345678
.globl NAME(literal_prefetch_end)
NAME(literal_prefetch_end):

// Repeated literal loads isolate the cost of the previous coverage gap.
.p2align 2
.globl NAME(literal_loop)
NAME(literal_loop):
    mov x8, x0
0:  ldr q31, 1f
    eor x8, x8, x2
    sub x2, x2, #1
    cbnz x2, 0b
    str q31, [x1, #16]
    str x8, [x1]
    mov x0, x8
    ret
    .p2align 4
1:  .quad 0x7ff8123480000001, 0xfedcba987fc12345
.globl NAME(literal_loop_end)
NAME(literal_loop_end):
