//! Straight-line ARM64 code, preserving every target register and NZCV.
//! Context layout: pc/sp/nzcv at 0/8/16, x0..28 at24, fp/lr at256/264,
//! Q0..31 at272. One snapshot occupies784 bytes, a multiple of16.
pub const MAX_WORDS: usize = 80;
pub const CONTEXT_BYTES: usize = 784;

pub fn generate(head: u64, pc: u64, output: &mut [u32]) -> Option<usize> {
    if output.len() < MAX_WORDS || head == 0 || !head.is_multiple_of(8) {
        return None;
    }
    let mut n = 0;
    let mut put = |word| {
        output[n] = word;
        n += 1;
    };
    fn imm(put: &mut impl FnMut(u32), register: u32, value: u64) {
        for shift in 0..4 {
            put((if shift == 0 { 0xd2800000 } else { 0xf2800000 })
                | (shift << 21)
                | ((((value >> (shift * 16)) & 0xffff) as u32) << 5)
                | register);
        }
    }
    fn str_x(put: &mut impl FnMut(u32), register: u32, offset: u32) {
        put(0xf9000000 | ((offset / 8) << 10) | (16 << 5) | register);
    }
    put(0xd10083ff); // sub sp,sp,#32 (does not alter flags)
    put(0xa90047f0); // stp x16,x17,[sp]
    imm(&mut put, 17, head);
    put(0xf9400230); // ldr x16,[x17]: current snapshot destination
    for i in (0..28).step_by(2) {
        if i == 16 {
            continue;
        }
        put(0xa9000000 | (((24 + i * 8) / 8) << 15) | ((i + 1) << 10) | (16 << 5) | i);
    }
    str_x(&mut put, 28, 248);
    put(0xa9000000 | (32 << 15) | (30 << 10) | (16 << 5) | 29); // fp/lr
    for (saved, offset) in [(0, 152), (8, 160)] {
        // original x16/x17
        put(0xf9400000 | ((saved / 8) << 10) | (31 << 5) | 17);
        str_x(&mut put, 17, offset);
    }
    put(0x910083f1); // add x17,sp,#32: original target SP
    str_x(&mut put, 17, 8);
    put(0xd53b4211); // mrs x17,nzcv
    str_x(&mut put, 17, 16);
    imm(&mut put, 17, pc);
    str_x(&mut put, 17, 0);
    for i in (0..32).step_by(2) {
        put(0xad000000 | (((272 + i * 16) / 16) << 15) | ((i + 1) << 10) | (16 << 5) | i);
    }
    put(0x91000000 | ((CONTEXT_BYTES as u32) << 10) | (16 << 5) | 16); // next destination
    imm(&mut put, 17, head);
    put(0xf9000230); // str x16,[x17]
    put(0xa94047f0); // ldp x16,x17,[sp]
    put(0x910083ff); // add sp,sp,#32
    Some(n)
}
