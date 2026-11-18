.text
.p2align 2
.global vector_callback_target
.type vector_callback_target,%function
vector_callback_target:
 sub sp,sp,#128
 stp q8,q9,[sp,#0]
 stp q10,q11,[sp,#32]
 stp q12,q13,[sp,#64]
 stp q14,q15,[sp,#96]
 ldp q0,q1,[x0,#0]
 ldp q2,q3,[x0,#32]
 ldp q4,q5,[x0,#64]
 ldp q6,q7,[x0,#96]
 ldp q8,q9,[x0,#128]
 ldp q10,q11,[x0,#160]
 ldp q12,q13,[x0,#192]
 ldp q14,q15,[x0,#224]
 ldp q16,q17,[x0,#256]
 ldp q18,q19,[x0,#288]
 ldp q20,q21,[x0,#320]
 ldp q22,q23,[x0,#352]
 ldp q24,q25,[x0,#384]
 ldp q26,q27,[x0,#416]
 ldp q28,q29,[x0,#448]
 ldp q30,q31,[x0,#480]
 b 1f
 .p2align 4
1:
 nop
 stp q0,q1,[x1,#0]
 stp q2,q3,[x1,#32]
 stp q4,q5,[x1,#64]
 stp q6,q7,[x1,#96]
 stp q8,q9,[x1,#128]
 stp q10,q11,[x1,#160]
 stp q12,q13,[x1,#192]
 stp q14,q15,[x1,#224]
 stp q16,q17,[x1,#256]
 stp q18,q19,[x1,#288]
 stp q20,q21,[x1,#320]
 stp q22,q23,[x1,#352]
 stp q24,q25,[x1,#384]
 stp q26,q27,[x1,#416]
 stp q28,q29,[x1,#448]
 stp q30,q31,[x1,#480]
 ldp q8,q9,[sp,#0]
 ldp q10,q11,[sp,#32]
 ldp q12,q13,[sp,#64]
 ldp q14,q15,[sp,#96]
 add sp,sp,#128
 ret
.size vector_callback_target,.-vector_callback_target
.section .note.GNU-stack,"",%progbits
