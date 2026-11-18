#if defined(__APPLE__)
#define SYM(n) _##n
#else
#define SYM(n) n
#endif
.text
.macro BEGIN name
.p2align 2
.globl \name
.globl \name\()_end
\name:
    fmov d0, x0
    ldr d1, [x1, #16]
    mov v0.d[1], x2
    mov v1.d[1], x0
    cmp x0, x2
    mov x8, x1
.endm
.macro END name
    ret
\name\()_end:
.endm
BEGIN SYM(st2_8b_base)
    st2 {v0.8b, v1.8b}, [x8]
END SYM(st2_8b_base)
BEGIN SYM(st2_8b_imm)
    st2 {v0.8b, v1.8b}, [x8], #16
END SYM(st2_8b_imm)
BEGIN SYM(st2_8b_reg)
    mov x10, #7
    st2 {v0.8b, v1.8b}, [x8], x10
END SYM(st2_8b_reg)
BEGIN SYM(st2_16b_base)
    st2 {v0.16b, v1.16b}, [x8]
END SYM(st2_16b_base)
BEGIN SYM(st2_16b_imm)
    st2 {v0.16b, v1.16b}, [x8], #32
END SYM(st2_16b_imm)
BEGIN SYM(st2_16b_reg)
    mov x10, #7
    st2 {v0.16b, v1.16b}, [x8], x10
END SYM(st2_16b_reg)
BEGIN SYM(st2_4h_base)
    st2 {v0.4h, v1.4h}, [x8]
END SYM(st2_4h_base)
BEGIN SYM(st2_4h_imm)
    st2 {v0.4h, v1.4h}, [x8], #16
END SYM(st2_4h_imm)
BEGIN SYM(st2_4h_reg)
    mov x10, #7
    st2 {v0.4h, v1.4h}, [x8], x10
END SYM(st2_4h_reg)
BEGIN SYM(st2_8h_base)
    st2 {v0.8h, v1.8h}, [x8]
END SYM(st2_8h_base)
BEGIN SYM(st2_8h_imm)
    st2 {v0.8h, v1.8h}, [x8], #32
END SYM(st2_8h_imm)
BEGIN SYM(st2_8h_reg)
    mov x10, #7
    st2 {v0.8h, v1.8h}, [x8], x10
END SYM(st2_8h_reg)
BEGIN SYM(st2_2s_base)
    st2 {v0.2s, v1.2s}, [x8]
END SYM(st2_2s_base)
BEGIN SYM(st2_2s_imm)
    st2 {v0.2s, v1.2s}, [x8], #16
END SYM(st2_2s_imm)
BEGIN SYM(st2_2s_reg)
    mov x10, #7
    st2 {v0.2s, v1.2s}, [x8], x10
END SYM(st2_2s_reg)
BEGIN SYM(st2_4s_base)
    st2 {v0.4s, v1.4s}, [x8]
END SYM(st2_4s_base)
BEGIN SYM(st2_4s_imm)
    st2 {v0.4s, v1.4s}, [x8], #32
END SYM(st2_4s_imm)
BEGIN SYM(st2_4s_reg)
    mov x10, #7
    st2 {v0.4s, v1.4s}, [x8], x10
END SYM(st2_4s_reg)
BEGIN SYM(st2_2d_base)
    st2 {v0.2d, v1.2d}, [x8]
END SYM(st2_2d_base)
BEGIN SYM(st2_2d_imm)
    st2 {v0.2d, v1.2d}, [x8], #32
END SYM(st2_2d_imm)
BEGIN SYM(st2_2d_reg)
    mov x10, #7
    st2 {v0.2d, v1.2d}, [x8], x10
END SYM(st2_2d_reg)
BEGIN SYM(st2_b0_base)
    st2 {v0.b, v1.b}[0], [x8]
END SYM(st2_b0_base)
BEGIN SYM(st2_b0_imm)
    st2 {v0.b, v1.b}[0], [x8], #2
END SYM(st2_b0_imm)
BEGIN SYM(st2_b0_reg)
    mov x10, #7
    st2 {v0.b, v1.b}[0], [x8], x10
END SYM(st2_b0_reg)
BEGIN SYM(st2_b15_base)
    st2 {v0.b, v1.b}[15], [x8]
END SYM(st2_b15_base)
BEGIN SYM(st2_b15_imm)
    st2 {v0.b, v1.b}[15], [x8], #2
END SYM(st2_b15_imm)
BEGIN SYM(st2_b15_reg)
    mov x10, #7
    st2 {v0.b, v1.b}[15], [x8], x10
END SYM(st2_b15_reg)
BEGIN SYM(st2_h0_base)
    st2 {v0.h, v1.h}[0], [x8]
END SYM(st2_h0_base)
BEGIN SYM(st2_h0_imm)
    st2 {v0.h, v1.h}[0], [x8], #4
END SYM(st2_h0_imm)
BEGIN SYM(st2_h0_reg)
    mov x10, #7
    st2 {v0.h, v1.h}[0], [x8], x10
END SYM(st2_h0_reg)
BEGIN SYM(st2_h7_base)
    st2 {v0.h, v1.h}[7], [x8]
END SYM(st2_h7_base)
BEGIN SYM(st2_h7_imm)
    st2 {v0.h, v1.h}[7], [x8], #4
END SYM(st2_h7_imm)
BEGIN SYM(st2_h7_reg)
    mov x10, #7
    st2 {v0.h, v1.h}[7], [x8], x10
END SYM(st2_h7_reg)
BEGIN SYM(st2_s0_base)
    st2 {v0.s, v1.s}[0], [x8]
END SYM(st2_s0_base)
BEGIN SYM(st2_s0_imm)
    st2 {v0.s, v1.s}[0], [x8], #8
END SYM(st2_s0_imm)
BEGIN SYM(st2_s0_reg)
    mov x10, #7
    st2 {v0.s, v1.s}[0], [x8], x10
END SYM(st2_s0_reg)
BEGIN SYM(st2_s3_base)
    st2 {v0.s, v1.s}[3], [x8]
END SYM(st2_s3_base)
BEGIN SYM(st2_s3_imm)
    st2 {v0.s, v1.s}[3], [x8], #8
END SYM(st2_s3_imm)
BEGIN SYM(st2_s3_reg)
    mov x10, #7
    st2 {v0.s, v1.s}[3], [x8], x10
END SYM(st2_s3_reg)
BEGIN SYM(st2_d0_base)
    st2 {v0.d, v1.d}[0], [x8]
END SYM(st2_d0_base)
BEGIN SYM(st2_d0_imm)
    st2 {v0.d, v1.d}[0], [x8], #16
END SYM(st2_d0_imm)
BEGIN SYM(st2_d0_reg)
    mov x10, #7
    st2 {v0.d, v1.d}[0], [x8], x10
END SYM(st2_d0_reg)
BEGIN SYM(st2_d1_base)
    st2 {v0.d, v1.d}[1], [x8]
END SYM(st2_d1_base)
BEGIN SYM(st2_d1_imm)
    st2 {v0.d, v1.d}[1], [x8], #16
END SYM(st2_d1_imm)
BEGIN SYM(st2_d1_reg)
    mov x10, #7
    st2 {v0.d, v1.d}[1], [x8], x10
END SYM(st2_d1_reg)
BEGIN SYM(st2_wrap)
    mov v31.16b, v0.16b
    mov v0.16b, v1.16b
    st2 {v31.16b, v0.16b}, [x8]
END SYM(st2_wrap)
BEGIN SYM(st2_sp)
    sub sp, sp, #64
    st2 {v0.16b, v1.16b}, [sp]
    ldp q0, q1, [sp]
    stp q0, q1, [x1]
    add sp, sp, #64
END SYM(st2_sp)
BEGIN SYM(st2_unaligned)
    add x8, x8, #1
    st2 {v0.4h, v1.4h}, [x8]
END SYM(st2_unaligned)
BEGIN SYM(st2_alias)
    st2 {v0.4s, v1.4s}, [x8], x8
END SYM(st2_alias)
BEGIN SYM(st2_outside)
    sub sp, sp, #64
    str x0, [x1]
    st2 {v0.16b, v1.16b}, [sp]
    add sp, sp, #64
END SYM(st2_outside)
