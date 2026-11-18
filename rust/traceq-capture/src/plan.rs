//! Translation-time observation plans. Capstone operands are normalized before
//! the iterator advances. Callouts only keep execution fields.
pub(crate) mod address;

use crate::gum::*;
use address::Address;
use traceq_core::arm64_memory::{self, Width};
pub use traceq_core::wire::Header;

pub struct Plan {
    pub pc: u64,
    pub(crate) address: Address,
    pub sources: [u32; 4],
    pub width: u32,
    pub count: u32,
    pub structure_element: u32,
    pub structure_lane: i32,
    pub unsupported: bool,
    pub load: bool,
    pub post: bool,
    pub ordered_memory: bool,
    pub atomic_width: Option<Width>,
    pub word: u32,
    pub check_target: bool,
    pub target_register: u32,
    pub target_address: u64,
    pub transfer: u64,
}
impl Default for Plan {
    fn default() -> Self {
        Self {
            pc: 0,
            address: Address::Missing,
            sources: [0; 4],
            width: 0,
            count: 0,
            structure_element: 0,
            structure_lane: -1,
            unsupported: false,
            load: false,
            post: false,
            ordered_memory: false,
            atomic_width: None,
            word: 0,
            check_target: false,
            target_register: 0,
            target_address: 0,
            transfer: 0,
        }
    }
}
impl Plan {
    fn set_address(&mut self, operand: &Arm64Op) {
        self.address = Address::decode(operand);
    }

    pub(crate) fn effective_address(&self, cpu: &CpuContext) -> Option<u64> {
        self.address.evaluate(cpu)
    }

    #[cfg(test)]
    pub(crate) fn with_address(mut self, operand: &Arm64Op) -> Self {
        self.set_address(operand);
        self
    }
}
pub fn contains(base: u64, length: u64, address: u64, size: u64) -> bool {
    address >= base && size <= length && address - base <= length - size
}
pub fn reg_value(reg: u32, c: &CpuContext) -> Option<u128> {
    if reg == ARM64_REG_XZR || reg == ARM64_REG_WZR {
        return Some(0);
    }
    if reg == ARM64_REG_SP {
        return Some(c.sp as u128);
    }
    if reg == ARM64_REG_WSP {
        return Some(c.sp as u32 as u128);
    }
    if reg == ARM64_REG_FP {
        return Some(c.fp as u128);
    }
    if reg == ARM64_REG_LR {
        return Some(c.lr as u128);
    }
    if (ARM64_REG_X0..=ARM64_REG_X28).contains(&reg) {
        return Some(c.x[(reg - ARM64_REG_X0) as usize] as u128);
    }
    if (ARM64_REG_W0..=ARM64_REG_W30).contains(&reg) {
        let n = (reg - ARM64_REG_W0) as usize;
        return Some(
            (if n < 29 {
                c.x[n]
            } else if n == 29 {
                c.fp
            } else {
                c.lr
            }) as u32 as u128,
        );
    }
    for (first, last, width) in [
        (ARM64_REG_Q0, ARM64_REG_Q31, 16),
        (ARM64_REG_D0, ARM64_REG_D31, 8),
        (ARM64_REG_S0, ARM64_REG_S31, 4),
        (ARM64_REG_H0, ARM64_REG_H31, 2),
        (ARM64_REG_B0, ARM64_REG_B31, 1),
        (ARM64_REG_V0, ARM64_REG_V31, 16),
    ] {
        if (first..=last).contains(&reg) {
            let value = u128::from_le_bytes(c.vectors[(reg - first) as usize]);
            return Some(if width == 16 {
                value
            } else {
                value & ((1u128 << (width * 8)) - 1)
            });
        }
    }
    None
}
pub fn reg_width(reg: u32) -> u32 {
    if (ARM64_REG_Q0..=ARM64_REG_Q31).contains(&reg)
        || (ARM64_REG_V0..=ARM64_REG_V31).contains(&reg)
    {
        16
    } else if (ARM64_REG_D0..=ARM64_REG_D31).contains(&reg)
        || (ARM64_REG_X0..=ARM64_REG_X28).contains(&reg)
        || [ARM64_REG_FP, ARM64_REG_LR, ARM64_REG_XZR].contains(&reg)
    {
        8
    } else if (ARM64_REG_S0..=ARM64_REG_S31).contains(&reg)
        || (ARM64_REG_W0..=ARM64_REG_W30).contains(&reg)
        || reg == ARM64_REG_WZR
    {
        4
    } else if (ARM64_REG_H0..=ARM64_REG_H31).contains(&reg) {
        2
    } else if (ARM64_REG_B0..=ARM64_REG_B31).contains(&reg) {
        1
    } else {
        0
    }
}
fn gpr_width(reg: u32) -> u32 {
    if (ARM64_REG_W0..=ARM64_REG_W30).contains(&reg) || reg == ARM64_REG_WZR {
        4
    } else if (ARM64_REG_X0..=ARM64_REG_X28).contains(&reg)
        || [ARM64_REG_FP, ARM64_REG_LR, ARM64_REG_XZR].contains(&reg)
    {
        8
    } else {
        0
    }
}
fn plain(op: &Arm64Op) -> bool {
    op.shift.kind == ARM64_SFT_INVALID && op.ext == ARM64_EXT_INVALID
}
fn scalar_multiply(id: u32, a: &Arm64) -> bool {
    let (count, widening) = match id {
        ARM64_INS_SMADDL | ARM64_INS_UMADDL | ARM64_INS_SMSUBL | ARM64_INS_UMSUBL => (4, true),
        ARM64_INS_SMULL | ARM64_INS_UMULL | ARM64_INS_SMNEGL | ARM64_INS_UMNEGL => (3, true),
        ARM64_INS_SMULH | ARM64_INS_UMULH => (3, false),
        _ => return false,
    };
    a.op_count as usize == count
        && a.operands[..count].iter().enumerate().all(|(i, op)| {
            op.kind == ARM64_OP_REG
                && gpr_width(op.reg()) == if widening && (i == 1 || i == 2) { 4 } else { 8 }
                && plain(op)
        })
}
fn scalar_fp_width(op: &Arm64Op) -> u32 {
    if op.kind != ARM64_OP_REG || op.vas != ARM64_VAS_INVALID || op.vector_index != -1 || !plain(op)
    {
        0
    } else if (ARM64_REG_S0..=ARM64_REG_S31).contains(&op.reg()) {
        4
    } else if (ARM64_REG_D0..=ARM64_REG_D31).contains(&op.reg()) {
        8
    } else {
        0
    }
}
/// Register-only operations use actual post snapshots, never computed values.
/// Reject scaled/vector/half forms until their operand shapes are qualified.
fn scalar_computation(id: u32, a: &Arm64) -> bool {
    let expected_count = match id {
        ARM64_INS_SDIV | ARM64_INS_FADD | ARM64_INS_FMUL | ARM64_INS_FDIV | ARM64_INS_FCSEL => 3,
        ARM64_INS_FCMP | ARM64_INS_SCVTF => 2,
        _ => return false,
    };
    if a.writeback != 0 || a.op_count != expected_count {
        return false;
    }
    let ops = &a.operands;
    if id == ARM64_INS_SDIV {
        let width = gpr_width(ops[0].reg());
        return width != 0
            && ops[..3].iter().all(|op| {
                op.kind == ARM64_OP_REG
                    && gpr_width(op.reg()) == width
                    && op.vas == ARM64_VAS_INVALID
                    && op.vector_index == -1
                    && plain(op)
            });
    }
    let width = scalar_fp_width(&ops[0]);
    if width == 0 {
        return false;
    }
    match id {
        ARM64_INS_FADD | ARM64_INS_FMUL | ARM64_INS_FDIV => {
            ops[1..3].iter().all(|op| scalar_fp_width(op) == width)
        }
        ARM64_INS_FCSEL => {
            (ARM64_CC_EQ..=ARM64_CC_NV).contains(&a.cc)
                && a.update_flags == 0
                && a.post_index == 0
                && ops[1..3].iter().all(|op| scalar_fp_width(op) == width)
        }
        ARM64_INS_FCMP => {
            scalar_fp_width(&ops[1]) == width
                || ops[1].kind == ARM64_OP_FP
                    && ops[1].fp().to_bits() == 0
                    && ops[1].vas == ARM64_VAS_INVALID
                    && ops[1].vector_index == -1
                    && plain(&ops[1])
        }
        ARM64_INS_SCVTF => {
            scalar_fp_width(&ops[1]) == width
                || ops[1].kind == ARM64_OP_REG
                    && gpr_width(ops[1].reg()) != 0
                    && ops[1].vas == ARM64_VAS_INVALID
                    && ops[1].vector_index == -1
                    && plain(&ops[1])
        }
        _ => false,
    }
}
#[derive(Clone, Copy, Default, PartialEq, Eq)]
struct Shape {
    bits: u32,
    element: u32,
    scalar: bool,
}
fn shape(op: &Arm64Op) -> Shape {
    if op.kind != ARM64_OP_REG || op.vector_index != -1 || !plain(op) {
        return Shape::default();
    }
    if (ARM64_REG_D0..=ARM64_REG_D31).contains(&op.reg())
        && [ARM64_VAS_INVALID, ARM64_VAS_1D].contains(&op.vas)
    {
        return Shape {
            bits: 64,
            element: 64,
            scalar: true,
        };
    }
    if !(ARM64_REG_V0..=ARM64_REG_V31).contains(&op.reg()) {
        return Shape::default();
    }
    let (bits, element) = match op.vas {
        ARM64_VAS_8B => (64, 8),
        ARM64_VAS_16B => (128, 8),
        ARM64_VAS_4H => (64, 16),
        ARM64_VAS_8H => (128, 16),
        ARM64_VAS_2S => (64, 32),
        ARM64_VAS_4S => (128, 32),
        ARM64_VAS_2D => (128, 64),
        _ => return Shape::default(),
    };
    Shape {
        bits,
        element,
        scalar: false,
    }
}
fn simd_integer(id: u32, a: &Arm64) -> bool {
    let count = match id {
        ARM64_INS_CMEQ | ARM64_INS_SHL | ARM64_INS_USHLL | ARM64_INS_USHLL2 => 3,
        ARM64_INS_XTN | ARM64_INS_XTN2 | ARM64_INS_UXTL | ARM64_INS_UXTL2 => 2,
        _ => return false,
    };
    let zero = |op: &Arm64Op| op.kind == ARM64_OP_IMM && op.imm() == 0 && plain(op);
    let repeated =
        id == ARM64_INS_CMEQ && a.op_count == 4 && zero(&a.operands[2]) && zero(&a.operands[3]);
    if a.op_count != count && !repeated {
        return false;
    }
    let dest = shape(&a.operands[0]);
    let src = shape(&a.operands[1]);
    if dest.bits == 0 || src.bits == 0 || (repeated && !dest.scalar) {
        return false;
    }
    let immediate = |upper: u32| {
        let op = &a.operands[2];
        op.kind == ARM64_OP_IMM && op.imm() >= 0 && (op.imm() as u64) < upper as u64 && plain(op)
    };
    if id == ARM64_INS_CMEQ || id == ARM64_INS_SHL {
        if dest != src {
            return false;
        }
        return if id == ARM64_INS_SHL {
            immediate(src.element)
        } else {
            shape(&a.operands[2]) == src || immediate(1)
        };
    }
    if dest.scalar || src.scalar {
        return false;
    }
    if id == ARM64_INS_XTN || id == ARM64_INS_XTN2 {
        return src.bits == 128
            && src.element == 2 * dest.element
            && dest.bits == if id == ARM64_INS_XTN2 { 128 } else { 64 };
    }
    let upper = id == ARM64_INS_USHLL2 || id == ARM64_INS_UXTL2;
    dest.bits == 128
        && dest.element == 2 * src.element
        && src.bits == if upper { 128 } else { 64 }
        && (count == 2 || immediate(src.element))
}
fn vector_form(a: &Arm64, count: u8, forms: &[(u32, u32, u32)]) -> bool {
    if a.op_count != count || a.writeback != 0 {
        return false;
    }
    a.operands[..count as usize]
        .iter()
        .enumerate()
        .all(|(i, op)| {
            let (first, last, vas) = forms[i];
            op.kind == ARM64_OP_REG
                && (first..=last).contains(&op.reg())
                && op.vas == vas
                && op.vector_index == -1
                && plain(op)
        })
}
fn rounded_vector_arithmetic(id: u32, a: &Arm64) -> bool {
    if a.op_count != 3 || a.writeback != 0 {
        return false;
    }
    let dest = shape(&a.operands[0]);
    let src = shape(&a.operands[1]);
    if dest.bits == 0 || src.bits == 0 {
        return false;
    }
    if id == ARM64_INS_URSHR {
        let shift = &a.operands[2];
        return dest == src
            && shift.kind == ARM64_OP_IMM
            && plain(shift)
            && shift.imm() > 0
            && shift.imm() as u64 <= src.element as u64;
    }
    if dest.scalar || src.scalar {
        return false;
    }
    if [ARM64_INS_RADDHN, ARM64_INS_RADDHN2].contains(&id) {
        return src.bits == 128
            && src.element == 2 * dest.element
            && dest.bits == if id == ARM64_INS_RADDHN2 { 128 } else { 64 }
            && shape(&a.operands[2]) == src;
    }
    if ![ARM64_INS_UMULL, ARM64_INS_UMULL2].contains(&id)
        || dest.bits != 128
        || dest.element != 2 * src.element
        || src.bits != if id == ARM64_INS_UMULL2 { 128 } else { 64 }
    {
        return false;
    }
    let second = &a.operands[2];
    if second.vector_index < 0 {
        return shape(second) == src;
    }
    // Indexed H/S forms encode one element of the third vector, independently
    // of whether the first input uses its lower or upper half.
    second.kind == ARM64_OP_REG
        && (ARM64_REG_V0..=ARM64_REG_V31).contains(&second.reg())
        && (src.element != 16 || second.reg() < ARM64_REG_V0 + 16)
        && plain(second)
        && [16, 32].contains(&src.element)
        && second.vas
            == if src.element == 16 {
                ARM64_VAS_1H
            } else {
                ARM64_VAS_1S
            }
        && second.vector_index < (128 / src.element) as i32
}
fn special_register_only(id: u32, a: &Arm64) -> bool {
    let vector = |vas| (ARM64_REG_V0, ARM64_REG_V31, vas);
    let q = (ARM64_REG_Q0, ARM64_REG_Q31, ARM64_VAS_INVALID);
    let s = (ARM64_REG_S0, ARM64_REG_S31, ARM64_VAS_INVALID);
    match id {
        ARM64_INS_TRN1 | ARM64_INS_TRN2 => {
            let vas = a.operands[0].vas;
            [
                ARM64_VAS_8B,
                ARM64_VAS_16B,
                ARM64_VAS_4H,
                ARM64_VAS_8H,
                ARM64_VAS_2S,
                ARM64_VAS_4S,
                ARM64_VAS_2D,
            ]
            .contains(&vas)
                && vector_form(a, 3, &[vector(vas); 3])
        }
        ARM64_INS_PMULL | ARM64_INS_PMULL2 => {
            let high = id == ARM64_INS_PMULL2;
            let dest = a.operands[0].vas;
            let src = if dest == ARM64_VAS_8H {
                if high { ARM64_VAS_16B } else { ARM64_VAS_8B }
            } else if dest == ARM64_VAS_1Q {
                if high { ARM64_VAS_2D } else { ARM64_VAS_1D }
            } else {
                return false;
            };
            vector_form(a, 3, &[vector(dest), vector(src), vector(src)])
        }
        ARM64_INS_AESE | ARM64_INS_AESD | ARM64_INS_AESMC | ARM64_INS_AESIMC => {
            vector_form(a, 2, &[vector(ARM64_VAS_16B); 2])
        }
        ARM64_INS_SHA256H | ARM64_INS_SHA256H2 => vector_form(a, 3, &[q, q, vector(ARM64_VAS_4S)]),
        ARM64_INS_SHA256SU0 => vector_form(a, 2, &[vector(ARM64_VAS_4S); 2]),
        ARM64_INS_SHA256SU1 => vector_form(a, 3, &[vector(ARM64_VAS_4S); 3]),
        ARM64_INS_SHA512H | ARM64_INS_SHA512H2 => vector_form(a, 3, &[q, q, vector(ARM64_VAS_2D)]),
        ARM64_INS_SHA512SU0 => vector_form(a, 2, &[vector(ARM64_VAS_2D); 2]),
        ARM64_INS_SHA512SU1 => vector_form(a, 3, &[vector(ARM64_VAS_2D); 3]),
        ARM64_INS_SHA1C | ARM64_INS_SHA1P | ARM64_INS_SHA1M => {
            vector_form(a, 3, &[q, s, vector(ARM64_VAS_4S)])
        }
        ARM64_INS_SHA1H => vector_form(a, 2, &[s; 2]),
        ARM64_INS_SHA1SU1 => vector_form(a, 2, &[vector(ARM64_VAS_4S); 2]),
        ARM64_INS_SHA1SU0 => vector_form(a, 3, &[vector(ARM64_VAS_4S); 3]),
        ARM64_INS_REV64 => {
            let vas = a.operands[0].vas;
            [
                ARM64_VAS_8B,
                ARM64_VAS_16B,
                ARM64_VAS_4H,
                ARM64_VAS_8H,
                ARM64_VAS_2S,
                ARM64_VAS_4S,
            ]
            .contains(&vas)
                && vector_form(a, 2, &[vector(vas); 2])
        }
        ARM64_INS_ADC | ARM64_INS_ADCS | ARM64_INS_SBC | ARM64_INS_SBCS | ARM64_INS_NGC
        | ARM64_INS_NGCS => {
            let count = if id == ARM64_INS_NGC || id == ARM64_INS_NGCS {
                2
            } else {
                3
            };
            let width = gpr_width(a.operands[0].reg());
            width != 0
                && a.op_count == count
                && a.writeback == 0
                && a.operands[..count as usize].iter().all(|op| {
                    op.kind == ARM64_OP_REG
                        && gpr_width(op.reg()) == width
                        && op.vector_index == -1
                        && op.vas == ARM64_VAS_INVALID
                        && plain(op)
                })
        }
        _ => false,
    }
}
fn structure_shape(vas: u32) -> Option<(u32, u32)> {
    Some(match vas {
        ARM64_VAS_16B => (1, 16),
        ARM64_VAS_8B => (1, 8),
        ARM64_VAS_8H => (2, 16),
        ARM64_VAS_4H => (2, 8),
        ARM64_VAS_4S => (4, 16),
        ARM64_VAS_2S => (4, 8),
        ARM64_VAS_2D => (8, 16),
        ARM64_VAS_1B => (1, 1),
        ARM64_VAS_1H => (2, 2),
        ARM64_VAS_1S => (4, 4),
        ARM64_VAS_1D => (8, 8),
        _ => return None,
    })
}
fn simple_memory(op: &Arm64Op) -> bool {
    let mem = op.mem();
    mem.index == ARM64_REG_INVALID && mem.disp == 0 && plain(op)
}
fn valid_memory(op: &Arm64Op) -> bool {
    [ARM64_SFT_INVALID, ARM64_SFT_LSL].contains(&op.shift.kind)
        && op.shift.value < 64
        && [
            ARM64_EXT_INVALID,
            ARM64_EXT_UXTW,
            ARM64_EXT_SXTW,
            ARM64_EXT_UXTX,
            ARM64_EXT_SXTX,
        ]
        .contains(&op.ext)
}
fn ordered_gpr(op: &Arm64Op, width: u32, number: u8) -> bool {
    op.kind == ARM64_OP_REG
        && gpr_width(op.reg()) == width
        && if number == 31 {
            op.reg()
                == if width == 4 {
                    ARM64_REG_WZR
                } else {
                    ARM64_REG_XZR
                }
        } else {
            physical(op.reg()) == number as i32
        }
        && op.vas == ARM64_VAS_INVALID
        && op.vector_index == -1
        && plain(op)
}
fn ordered_address(op: &Arm64Op, base: u8) -> bool {
    if op.kind != ARM64_OP_MEM || op.vas != ARM64_VAS_INVALID || op.vector_index != -1 {
        return false;
    }
    let reg = op.mem().base;
    simple_memory(op)
        && if base == 31 {
            reg == ARM64_REG_SP
        } else {
            gpr_width(reg) == 8 && physical(reg) == base as i32
        }
}
fn base_plan(
    ins: &Insn,
    a: &Arm64,
    header: Header,
    in_code: &mut impl FnMut(u64, u64) -> bool,
) -> Plan {
    let mut p = Plan {
        pc: ins.address,
        ..Plan::default()
    };
    let m = ins.mnemonic();
    let n = a.op_count as usize;
    if [
        ARM64_INS_LDADD,
        ARM64_INS_LDADDA,
        ARM64_INS_LDADDAL,
        ARM64_INS_LDADDL,
        ARM64_INS_STLR,
    ]
    .contains(&ins.id)
    {
        p.unsupported = true;
        if a.writeback != 0 {
            return p;
        }
        let word = u32::from_le_bytes(ins.bytes[..4].try_into().unwrap());
        if ins.id == ARM64_INS_STLR {
            if n != 2 {
                return p;
            }
            let Some(d) = arm64_memory::store_release(word) else {
                return p;
            };
            if !ordered_gpr(&a.operands[0], d.width.bytes(), d.source)
                || !ordered_address(&a.operands[1], d.base)
            {
                return p;
            }
            p.sources[0] = a.operands[0].reg();
            p.set_address(&a.operands[1]);
            p.width = d.width.bytes();
        } else {
            if n != 3 || header.profile != 2 {
                return p;
            }
            let Some(d) = arm64_memory::atomic_add(word) else {
                return p;
            };
            let expected_id = match (d.acquire, d.release) {
                (false, false) => ARM64_INS_LDADD,
                (true, false) => ARM64_INS_LDADDA,
                (false, true) => ARM64_INS_LDADDL,
                (true, true) => ARM64_INS_LDADDAL,
            };
            if ins.id != expected_id
                || !ordered_gpr(&a.operands[0], d.width.bytes(), d.source)
                || !ordered_gpr(&a.operands[1], d.width.bytes(), d.result)
                || !ordered_address(&a.operands[2], d.base)
            {
                return p;
            }
            // count describes the address span, not the two observations of it.
            p.sources[0] = a.operands[0].reg();
            p.sources[1] = a.operands[1].reg();
            p.set_address(&a.operands[2]);
            p.width = d.width.bytes();
            p.atomic_width = Some(d.width);
        }
        p.count = 1;
        p.ordered_memory = true;
        p.unsupported = false;
        return p;
    }
    if ins.id == ARM64_INS_LD1 || ins.id == ARM64_INS_ST1 {
        p.unsupported = true;
        let count = a.operands[..n]
            .iter()
            .take_while(|op| op.kind == ARM64_OP_REG)
            .count();
        if !(1..=4).contains(&count)
            || (n != count + 1 && n != count + 2)
            || a.operands[count].kind != ARM64_OP_MEM
        {
            return p;
        }
        let first = &a.operands[0];
        let last = &a.operands[count - 1];
        let Some((element, width)) = structure_shape(last.vas) else {
            return p;
        };
        let lane = last.vector_index;
        if if lane >= 0 {
            count != 1 || width != element || lane as u32 >= 16 / element
        } else {
            width < 8
        } {
            return p;
        }
        if !(ARM64_REG_V0..=ARM64_REG_V31).contains(&first.reg()) {
            return p;
        }
        for i in 0..count {
            let op = &a.operands[i];
            if op.reg() != ARM64_REG_V0 + (first.reg() - ARM64_REG_V0 + i as u32) % 32
                || op.vas != last.vas
                || (op.vector_index != -1 && op.vector_index != lane)
            {
                return p;
            }
            p.sources[i] = op.reg();
        }
        let memory = &a.operands[count];
        p.set_address(memory);
        if !simple_memory(memory) {
            return p;
        }
        p.load = ins.id == ARM64_INS_LD1;
        p.count = count as u32;
        p.width = width;
        p.structure_lane = lane;
        if p.load && header.profile != 2 {
            p.count = 0
        }
        p.unsupported = false;
        return p;
    }
    if [ARM64_INS_ST2, ARM64_INS_ST4, ARM64_INS_LD4].contains(&ins.id) {
        p.unsupported = true;
        let count = if ins.id == ARM64_INS_ST2 { 2 } else { 4 };
        if (n != count + 1 && n != count + 2) || a.operands[count].kind != ARM64_OP_MEM {
            return p;
        }
        let first = &a.operands[0];
        let last = &a.operands[count - 1];
        if first.kind != ARM64_OP_REG || !(ARM64_REG_V0..=ARM64_REG_V31).contains(&first.reg()) {
            return p;
        }
        let Some((element, width)) = structure_shape(last.vas) else {
            return p;
        };
        let lane = last.vector_index;
        if if lane < 0 {
            width == element
        } else {
            width != element || lane as u32 >= 16 / element
        } {
            return p;
        }
        for (i, op) in a.operands[..count].iter().enumerate() {
            if op.kind != ARM64_OP_REG
                || op.reg() != ARM64_REG_V0 + (first.reg() - ARM64_REG_V0 + i as u32) % 32
                || op.vas != last.vas
                || (op.vector_index != -1 && op.vector_index != lane)
                || !plain(op)
            {
                return p;
            }
            p.sources[i] = op.reg();
        }
        let memory = &a.operands[count];
        p.set_address(memory);
        if !simple_memory(memory) {
            return p;
        }
        p.load = ins.id == ARM64_INS_LD4;
        p.width = width;
        p.count = if p.load && header.profile != 2 {
            0
        } else {
            count as u32
        };
        p.structure_element = element;
        p.structure_lane = lane;
        p.unsupported = false;
        return p;
    }
    let pair = m == "stp" || m == "stnp";
    if pair || ["str", "stur", "strb", "strh", "sturb", "sturh"].contains(&m) {
        let count = if pair { 2 } else { 1 };
        if n < count + 1 || a.operands[count].kind != ARM64_OP_MEM {
            p.unsupported = true;
            return p;
        }
        let memory = &a.operands[count];
        p.set_address(memory);
        for i in 0..count {
            if a.operands[i].kind != ARM64_OP_REG {
                p.unsupported = true;
                return p;
            }
            p.sources[i] = a.operands[i].reg();
        }
        p.width = reg_width(p.sources[0]);
        if ["strb", "sturb"].contains(&m) {
            p.width = 1
        }
        if ["strh", "sturh"].contains(&m) {
            p.width = 2
        }
        if p.width == 0 || (pair && reg_width(p.sources[1]) != p.width) || !valid_memory(memory) {
            p.unsupported = true;
            return p;
        }
        p.count = count as u32;
        return p;
    }
    const ALLOWED: &[&str] = &[
        "add", "adds", "sub", "subs", "eor", "and", "orr", "adr", "adrp", "ands", "bfi", "bfxil",
        "mvn", "ccmp", "csetm", "udiv", "ext", "ushl", "uzp1", "zip1", "mrs", "dmb", "bti",
        "paciasp", "autiasp", "xpaclri", "mul", "madd", "msub", "mneg", "neg", "negs", "bic",
        "eon", "orn", "ubfx", "sbfx", "ubfiz", "sbfiz", "uxtb", "uxth", "uxtw", "sxtb", "sxth",
        "sxtw", "extr", "cinc", "cinv", "cneg", "csinc", "csinv", "csneg", "mov", "movz", "movn",
        "movk", "cmp", "cmn", "tst", "cset", "csel", "rev", "rev16", "rev32", "lsl", "lsr", "asr",
        "ror", "movi", "dup", "umov", "fmov", "nop", "ret", "b", "cbz", "cbnz", "tbz", "tbnz",
        "ldr", "ldrb", "ldrh", "ldrsb", "ldrsh", "ldrsw", "ldur", "ldurb", "ldurh", "ldursb",
        "ldursh", "ldursw", "ldp", "ldnp", "ldar", "ldarb", "ldarh",
    ];
    p.unsupported = !(m.starts_with("b.") || ALLOWED.contains(&m));
    if [ARM64_INS_PRFM, ARM64_INS_PRFUM].contains(&ins.id) {
        p.unsupported = false
    }
    if [ARM64_INS_CLZ, ARM64_INS_RBIT].contains(&ins.id)
        && n == 2
        && a.operands[..2]
            .iter()
            .all(|op| op.kind == ARM64_OP_REG && reg_width(op.reg()) != 0)
    {
        p.unsupported = false
    }
    if scalar_multiply(ins.id, a)
        || scalar_computation(ins.id, a)
        || simd_integer(ins.id, a)
        || rounded_vector_arithmetic(ins.id, a)
        || special_register_only(ins.id, a)
    {
        p.unsupported = false
    }
    if m == "b" || m.starts_with("b.") || ["cbz", "cbnz", "tbz", "tbnz"].contains(&m) {
        if n == 0 {
            p.unsupported = true;
            return p;
        }
        let target = &a.operands[n - 1];
        if target.kind != ARM64_OP_IMM || !in_code(target.imm() as u64, 4) {
            p.unsupported = true
        }
    }
    p
}
/// # Safety
/// ins originates from the detail-enabled Gum ARM64 iterator and is live for
/// this call. All borrowed fields are copied before the function returns.
pub unsafe fn make(ins: &Insn, header: Header) -> Plan {
    unsafe {
        make_in_scope(ins, header, |address, size| {
            contains(header.code_base, header.code_size, address, size)
        })
    }
}
/// # Safety
/// Same iterator lifetime as make; in_code describes the exact declared union.
pub unsafe fn make_in_scope(
    ins: &Insn,
    header: Header,
    mut in_code: impl FnMut(u64, u64) -> bool,
) -> Plan {
    let Some(a) = (unsafe { ins.arm64() }).filter(|a| a.op_count <= 8) else {
        return Plan {
            pc: ins.address,
            word: if header.profile == 2 {
                u32::from_le_bytes(ins.bytes[..4].try_into().unwrap())
            } else {
                0
            },
            unsupported: true,
            ..Plan::default()
        };
    };
    let mut p = base_plan(ins, a, header, &mut in_code);
    if header.profile != 2 {
        return p;
    }
    p.word = u32::from_le_bytes(ins.bytes[..4].try_into().unwrap_or([0; 4]));
    let m = ins.mnemonic();
    let n = a.op_count as usize;
    const LOADS: &[&str] = &[
        "ldr", "ldrb", "ldrh", "ldrsb", "ldrsh", "ldrsw", "ldur", "ldurb", "ldurh", "ldursb",
        "ldursh", "ldursw", "ldp", "ldnp", "ldpsw", "ldar", "ldarb", "ldarh",
    ];
    if LOADS.contains(&m) {
        p.load = true
    }
    if p.load && ![ARM64_INS_LD1, ARM64_INS_LD4].contains(&ins.id) {
        let count = if ["ldp", "ldnp", "ldpsw"].contains(&m) {
            2
        } else {
            1
        };
        p.unsupported = true;
        if [ARM64_INS_LDR, ARM64_INS_LDRSW].contains(&ins.id)
            && n == 2
            && a.operands[0].kind == ARM64_OP_REG
            && a.operands[1].kind == ARM64_OP_IMM
            && a.writeback == 0
        {
            p.set_address(&a.operands[1]);
            p.sources[0] = a.operands[0].reg();
            p.width = if ins.id == ARM64_INS_LDRSW {
                4
            } else {
                reg_width(p.sources[0])
            };
            if [4, 8, 16].contains(&p.width) {
                p.count = 1;
                p.unsupported = false
            }
        } else if n > count && a.operands[count].kind == ARM64_OP_MEM {
            let memory = &a.operands[count];
            p.set_address(memory);
            let mut valid = true;
            for i in 0..count {
                valid &= a.operands[i].kind == ARM64_OP_REG;
                p.sources[i] = a.operands[i].reg();
                if a.writeback != 0 && p.sources[i] == memory.mem().base {
                    valid = false
                }
            }
            p.width = reg_width(p.sources[0]);
            if m.ends_with('b') {
                p.width = 1
            }
            if m.ends_with('h') {
                p.width = 2
            }
            if ["ldrsw", "ldursw", "ldpsw"].contains(&m) {
                p.width = 4
            }
            valid &= p.width > 0 && valid_memory(memory);
            if count == 2 && p.sources[0] == p.sources[1] {
                valid = false
            }
            if valid {
                p.count = count as u32;
                p.unsupported = false
            }
        }
    }
    let control = [
        ARM64_INS_B,
        ARM64_INS_BR,
        ARM64_INS_BL,
        ARM64_INS_BLR,
        ARM64_INS_RET,
        ARM64_INS_CBZ,
        ARM64_INS_CBNZ,
        ARM64_INS_TBZ,
        ARM64_INS_TBNZ,
    ]
    .contains(&ins.id);
    if [ARM64_INS_BR, ARM64_INS_BLR, ARM64_INS_BL, ARM64_INS_RET].contains(&ins.id) || m == "b" {
        if n == 1 && a.operands[0].kind == ARM64_OP_REG && ins.id != ARM64_INS_BL {
            p.check_target = true;
            p.target_register = a.operands[0].reg();
            p.unsupported = false;
        } else if n == 1
            && a.operands[0].kind == ARM64_OP_IMM
            && (ins.id == ARM64_INS_BL || m == "b")
        {
            p.check_target = true;
            p.target_address = a.operands[0].imm() as u64;
            p.unsupported = false;
        } else if ins.id == ARM64_INS_RET && n == 0 {
            p.check_target = true;
            p.target_register = ARM64_REG_LR;
            p.unsupported = false;
        }
        p.transfer = if ins.id == ARM64_INS_RET {
            3
        } else if [ARM64_INS_BL, ARM64_INS_BLR].contains(&ins.id) {
            1
        } else {
            2
        };
    }
    if a.writeback != 0 && p.count != 0 {
        let base = p.address.base().map_or(-1, physical);
        for i in 0..p.count as usize {
            if base >= 0 && physical(p.sources[i]) == base {
                p.unsupported = true
            }
        }
    }
    p.post = !p.unsupported && !control;
    p
}
fn physical(reg: u32) -> i32 {
    if (ARM64_REG_W0..=ARM64_REG_W30).contains(&reg) {
        (reg - ARM64_REG_W0) as i32
    } else if (ARM64_REG_X0..=ARM64_REG_X28).contains(&reg) {
        (reg - ARM64_REG_X0) as i32
    } else if reg == ARM64_REG_FP {
        29
    } else if reg == ARM64_REG_LR {
        30
    } else if [ARM64_REG_SP, ARM64_REG_WSP].contains(&reg) {
        31
    } else {
        -1
    }
}
pub(crate) fn store_values(cpu: &CpuContext, p: &Plan, values: &mut [u128; 4]) -> bool {
    for (slot, &source) in values.iter_mut().zip(&p.sources[..p.count as usize]) {
        let Some(value) = reg_value(source, cpu) else {
            return false;
        };
        *slot = value;
    }
    if p.structure_lane >= 0 {
        for value in &mut values[..p.count as usize] {
            *value >>= p.structure_lane as u32 * p.width * 8
        }
        return true;
    }
    if p.structure_element == 0 {
        return true;
    }
    let mut interleaved = [0u8; 64];
    let element = p.structure_element as usize;
    let width = p.width as usize;
    for lane in 0..width / element {
        for (reg, value) in values[..p.count as usize].iter().enumerate() {
            let bytes = value.to_le_bytes();
            interleaved[(lane * p.count as usize + reg) * element
                ..(lane * p.count as usize + reg + 1) * element]
                .copy_from_slice(&bytes[lane * element..(lane + 1) * element]);
        }
    }
    for (i, value) in values[..p.count as usize].iter_mut().enumerate() {
        let mut bytes = [0; 16];
        bytes[..width].copy_from_slice(&interleaved[i * width..(i + 1) * width]);
        *value = u128::from_le_bytes(bytes)
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    fn header() -> Header {
        Header {
            code_base: 0x1000,
            code_size: 0x1000,
            data_base: 0,
            data_size: u64::MAX,
            thread_id: 1,
            profile: 2,
        }
    }
    fn operand(reg: u32, vas: u32) -> Arm64Op {
        Arm64Op {
            vector_index: -1,
            kind: ARM64_OP_REG,
            value: OperandValue { reg },
            vas,
            ..Arm64Op::default()
        }
    }
    fn immediate(value: i64) -> Arm64Op {
        Arm64Op {
            kind: ARM64_OP_IMM,
            value: OperandValue { imm: value },
            ..Arm64Op::default()
        }
    }
    fn memory(base: u32) -> Arm64Op {
        Arm64Op {
            vector_index: -1,
            kind: ARM64_OP_MEM,
            value: OperandValue {
                mem: Mem {
                    base,
                    index: 0,
                    disp: 0,
                },
            },
            ..Arm64Op::default()
        }
    }
    fn instruction(
        id: u32,
        mnemonic: &str,
        ops: &[Arm64Op],
        writeback: bool,
    ) -> (Insn, Box<DetailArm64>) {
        let mut detail = Box::new(DetailArm64 {
            prefix: [0; 96],
            arm64: Arm64 {
                cc: 0,
                update_flags: 0,
                writeback: writeback as u8,
                post_index: 0,
                op_count: ops.len() as u8,
                operands: [Arm64Op::default(); 8],
            },
        });
        detail.arm64.operands[..ops.len()].copy_from_slice(ops);
        let mut ins = Insn {
            id,
            address: 0x1100,
            size: 4,
            bytes: [0; 24],
            mnemonic: [0; 32],
            op_str: [0; 160],
            detail: &*detail,
        };
        ins.mnemonic[..mnemonic.len()].copy_from_slice(mnemonic.as_bytes());
        (ins, detail)
    }
    fn classify(id: u32, m: &str, ops: &[Arm64Op], writeback: bool) -> Plan {
        let (ins, _detail) = instruction(id, m, ops, writeback);
        unsafe { make(&ins, header()) }
    }
    #[test]
    fn ordered_words_require_matching_operands_and_recoverable_old_value() {
        for (word, id, m, first, width) in [
            (0xb8200020u32, ARM64_INS_LDADD, "ldadd", ARM64_REG_W0, 4),
            (0xf8e00020, ARM64_INS_LDADDAL, "ldaddal", ARM64_REG_X0, 8),
        ] {
            let ops = [
                operand(first, 0),
                operand(first, 0),
                memory(ARM64_REG_X0 + 1),
            ];
            let (mut ins, mut detail) = instruction(id, m, &ops, false);
            ins.bytes[..4].copy_from_slice(&word.to_le_bytes());
            let p = unsafe { make(&ins, header()) };
            assert!(!p.unsupported && p.post && p.ordered_memory);
            assert_eq!(
                (p.count, p.width, p.sources[0], p.sources[1]),
                (1, width, first, first)
            );
            assert!(p.atomic_width.is_some());
            let mut legacy = header();
            legacy.profile = 1;
            assert!(unsafe { make(&ins, legacy) }.unsupported);
            detail.arm64.operands[1] = operand(first + 1, 0);
            assert!(unsafe { make(&ins, header()) }.unsupported);
            detail.arm64.operands[1] = ops[1];
            detail.arm64.operands[2] = memory(ARM64_REG_SP);
            assert!(unsafe { make(&ins, header()) }.unsupported);
            detail.arm64.operands[2] = ops[2];
            ins.bytes[..4].copy_from_slice(&(word | 31).to_le_bytes());
            assert!(unsafe { make(&ins, header()) }.unsupported);
            ins.bytes[..4].copy_from_slice(&word.to_le_bytes());
            detail.arm64.op_count = 2;
            assert!(unsafe { make(&ins, header()) }.unsupported);
        }
        let ops = [operand(ARM64_REG_WZR, 0), memory(ARM64_REG_X0 + 8)];
        let (mut ins, mut detail) = instruction(ARM64_INS_STLR, "stlr", &ops, false);
        ins.bytes[..4].copy_from_slice(&0x889ffd1fu32.to_le_bytes());
        let p = unsafe { make(&ins, header()) };
        assert!(!p.unsupported && p.post && p.ordered_memory && p.atomic_width.is_none());
        assert_eq!((p.count, p.width, p.sources[0]), (1, 4, ARM64_REG_WZR));
        detail.arm64.writeback = 1;
        assert!(unsafe { make(&ins, header()) }.unsupported);
    }
    #[test]
    fn signed_division_shapes_are_register_only_and_same_width() {
        for first in [ARM64_REG_W0, ARM64_REG_X0] {
            let ops = [
                operand(first, 0),
                operand(first + 1, 0),
                operand(first + 2, 0),
            ];
            let p = classify(ARM64_INS_SDIV, "sdiv", &ops, false);
            assert!(!p.unsupported && p.post && p.count == 0 && !p.load);
            for index in 0..3 {
                for invalid in [
                    operand(ARM64_REG_SP, 0),
                    operand(ARM64_REG_S0, 0),
                    operand(
                        if first == ARM64_REG_W0 {
                            ARM64_REG_X0
                        } else {
                            ARM64_REG_W0
                        },
                        0,
                    ),
                    immediate(0),
                ] {
                    let mut bad = ops;
                    bad[index] = invalid;
                    assert!(classify(ARM64_INS_SDIV, "sdiv", &bad, false).unsupported);
                }
                let mut bad = ops;
                bad[index].vector_index = 0;
                assert!(classify(ARM64_INS_SDIV, "sdiv", &bad, false).unsupported);
                bad[index] = ops[index];
                bad[index].shift.kind = ARM64_SFT_LSL;
                assert!(classify(ARM64_INS_SDIV, "sdiv", &bad, false).unsupported);
            }
            assert!(classify(ARM64_INS_SDIV, "sdiv", &ops[..2], false).unsupported);
            assert!(classify(ARM64_INS_SDIV, "sdiv", &ops, true).unsupported);
        }
        let zero = [operand(ARM64_REG_XZR, 0); 3];
        assert!(classify(ARM64_INS_SDIV, "sdiv", &zero, false).post);
    }
    #[test]
    fn scalar_fp_select_requires_same_width_and_valid_condition_metadata() {
        for first in [ARM64_REG_S0, ARM64_REG_D0] {
            for registers in [[0, 1, 2], [1, 1, 31], [31, 31, 0]] {
                let ops = registers.map(|r| operand(first + r, 0));
                let (ins, mut detail) = instruction(ARM64_INS_FCSEL, "fcsel", &ops, false);
                for cc in ARM64_CC_EQ..=ARM64_CC_NV {
                    detail.arm64.cc = cc;
                    let p = unsafe { make(&ins, header()) };
                    assert!(!p.unsupported && p.post && !p.load && p.count == 0);
                }
                for cc in [0, ARM64_CC_NV + 1, u32::MAX] {
                    detail.arm64.cc = cc;
                    assert!(unsafe { make(&ins, header()) }.unsupported);
                }
                detail.arm64.cc = ARM64_CC_EQ;
                for (i, original) in ops.iter().copied().enumerate() {
                    let mut vector = original;
                    vector.vas = ARM64_VAS_4S;
                    let mut lane = original;
                    lane.vector_index = 0;
                    let mut shifted = original;
                    shifted.shift.kind = ARM64_SFT_LSL;
                    let mut extended = original;
                    extended.ext = ARM64_EXT_UXTW;
                    for bad in [
                        operand(ARM64_REG_H0, 0),
                        operand(ARM64_REG_X0, 0),
                        operand(
                            if first == ARM64_REG_S0 {
                                ARM64_REG_D0
                            } else {
                                ARM64_REG_S0
                            },
                            0,
                        ),
                        immediate(0),
                        vector,
                        lane,
                        shifted,
                        extended,
                    ] {
                        detail.arm64.operands[i] = bad;
                        assert!(unsafe { make(&ins, header()) }.unsupported);
                    }
                    detail.arm64.operands[i] = original;
                }
                for count in [0, 2, 4, 8] {
                    detail.arm64.op_count = count;
                    assert!(unsafe { make(&ins, header()) }.unsupported);
                }
                detail.arm64.op_count = 3;
                detail.arm64.update_flags = 1;
                assert!(unsafe { make(&ins, header()) }.unsupported);
                detail.arm64.update_flags = 0;
                detail.arm64.post_index = 1;
                assert!(unsafe { make(&ins, header()) }.unsupported);
                detail.arm64.post_index = 0;
                detail.arm64.writeback = 1;
                assert!(unsafe { make(&ins, header()) }.unsupported);
            }
        }
    }
    #[test]
    fn scalar_fp_shapes_reject_vector_half_scaled_and_nonzero_comparison() {
        for first in [ARM64_REG_S0, ARM64_REG_D0] {
            let same = [
                operand(first, 0),
                operand(first + 1, 0),
                operand(first + 31, 0),
            ];
            for (id, m) in [
                (ARM64_INS_FADD, "fadd"),
                (ARM64_INS_FMUL, "fmul"),
                (ARM64_INS_FDIV, "fdiv"),
            ] {
                let p = classify(id, m, &same, false);
                assert!(!p.unsupported && p.post && p.count == 0 && !p.load);
                assert!(classify(id, m, &same[..2], false).unsupported);
                assert!(classify(id, m, &same, true).unsupported);
                for index in 0..3 {
                    for invalid in [
                        operand(ARM64_REG_H0, 0),
                        operand(ARM64_REG_V0, ARM64_VAS_4S),
                        operand(ARM64_REG_X0, 0),
                        operand(
                            if first == ARM64_REG_S0 {
                                ARM64_REG_D0
                            } else {
                                ARM64_REG_S0
                            },
                            0,
                        ),
                    ] {
                        let mut bad = same;
                        bad[index] = invalid;
                        assert!(classify(id, m, &bad, false).unsupported);
                    }
                    let mut bad = same;
                    bad[index].ext = ARM64_EXT_UXTW;
                    assert!(classify(id, m, &bad, false).unsupported);
                }
            }
            let zero = Arm64Op {
                vector_index: -1,
                kind: ARM64_OP_FP,
                value: OperandValue { fp: 0.0 },
                ..Arm64Op::default()
            };
            for second in [same[1], zero] {
                assert!(classify(ARM64_INS_FCMP, "fcmp", &[same[0], second], false).post);
            }
            for bits in [(-0.0f64).to_bits(), 1.0f64.to_bits(), f64::NAN.to_bits()] {
                let bad = Arm64Op {
                    value: OperandValue {
                        fp: f64::from_bits(bits),
                    },
                    ..zero
                };
                assert!(classify(ARM64_INS_FCMP, "fcmp", &[same[0], bad], false).unsupported);
            }
            assert!(classify(ARM64_INS_FCMP, "fcmp", &[same[0], immediate(0)], false).unsupported);
            for source in [
                same[1],
                operand(ARM64_REG_W0, 0),
                operand(ARM64_REG_X0, 0),
                operand(ARM64_REG_WZR, 0),
            ] {
                assert!(classify(ARM64_INS_SCVTF, "scvtf", &[same[0], source], false).post);
                assert!(
                    classify(
                        ARM64_INS_SCVTF,
                        "scvtf",
                        &[same[0], source, immediate(1)],
                        false
                    )
                    .unsupported
                );
            }
            assert!(
                classify(
                    ARM64_INS_SCVTF,
                    "scvtf",
                    &[same[0], operand(ARM64_REG_H0, 0)],
                    false
                )
                .unsupported
            );
        }
    }
    #[test]
    fn scalar_alias_width_and_forbidden_writeback() {
        let ops = [
            operand(ARM64_REG_FP, 0),
            operand(ARM64_REG_W0, 0),
            operand(ARM64_REG_W0 + 1, 0),
        ];
        assert!(!classify(ARM64_INS_SMULL, "smull", &ops, false).unsupported);
        let mut wrong = ops;
        wrong[1] = operand(ARM64_REG_X0, 0);
        assert!(classify(ARM64_INS_SMULL, "smull", &wrong, false).unsupported);
        let p = classify(
            ARM64_INS_LDR,
            "ldr",
            &[operand(ARM64_REG_W0, 0), memory(ARM64_REG_X0)],
            true,
        );
        assert!(p.unsupported, "W0 and X0 alias the writeback base");
    }
    #[test]
    fn carry_shape_and_simd_scalar_zero_alias() {
        let ops = [
            operand(ARM64_REG_X0, 0),
            operand(ARM64_REG_X0 + 1, 0),
            operand(ARM64_REG_XZR, 0),
        ];
        assert!(!classify(ARM64_INS_ADCS, "adcs", &ops, false).unsupported);
        let mut wrong = ops;
        wrong[2] = operand(ARM64_REG_WZR, 0);
        assert!(classify(ARM64_INS_ADCS, "adcs", &wrong, false).unsupported);
        let ops = [
            operand(ARM64_REG_D0, 0),
            operand(ARM64_REG_D0 + 1, 0),
            immediate(0),
            immediate(0),
        ];
        assert!(!classify(ARM64_INS_CMEQ, "cmeq", &ops, false).unsupported);
        let mut vector = ops;
        vector[0] = operand(ARM64_REG_V0, ARM64_VAS_2D);
        vector[1] = operand(ARM64_REG_V0 + 1, ARM64_VAS_2D);
        assert!(classify(ARM64_INS_CMEQ, "cmeq", &vector, false).unsupported);
    }
    #[test]
    fn literal_load_bits_and_zero_destination_are_preserved() {
        let p = classify(
            ARM64_INS_LDR,
            "ldr",
            &[operand(ARM64_REG_Q0, 0), immediate(0x1550)],
            false,
        );
        assert!(!p.unsupported && p.load && p.post);
        assert_eq!((p.count, p.width), (1, 16));
        assert!(matches!(p.address, Address::Literal(0x1550)));
        let p = classify(
            ARM64_INS_LDRSW,
            "ldrsw",
            &[operand(ARM64_REG_XZR, 0), immediate(0x1550)],
            false,
        );
        assert_eq!((p.count, p.width, p.sources[0]), (1, 4, ARM64_REG_XZR));
    }
    #[test]
    fn conditional_target_inside_envelope_hole_stays_unknown() {
        let (ins, _detail) = instruction(ARM64_INS_B, "b.eq", &[immediate(0x1800)], false);
        let ordinary = unsafe { make(&ins, header()) };
        assert!(!ordinary.unsupported);
        let scoped = unsafe {
            make_in_scope(&ins, header(), |pc, size| {
                contains(0x1000, 0x100, pc, size) || contains(0x1f00, 0x100, pc, size)
            })
        };
        assert!(scoped.unsupported);
    }
    #[test]
    fn scope_transfers_and_unknown_word() {
        let p = classify(ARM64_INS_BL, "bl", &[immediate(0x3000)], false);
        assert!(!p.unsupported && p.check_target && !p.post);
        assert_eq!((p.target_address, p.transfer), (0x3000, 1));
        let p = classify(ARM64_INS_RET, "ret", &[], false);
        assert_eq!((p.target_register, p.transfer), (ARM64_REG_LR, 3));
        let p = classify(ARM64_INS_B, "b.eq", &[immediate(0x3000)], false);
        assert!(p.unsupported);
        let (ins, _detail) = instruction(0, "unknown", &[], false);
        let mut ins = ins;
        ins.detail = core::ptr::null();
        ins.bytes[..4].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        let p = unsafe { make(&ins, header()) };
        assert!(p.unsupported);
        assert_eq!(p.word, 0x1234_5678);
    }
    #[test]
    fn interleaved_structure_and_lane_values() {
        let p = classify(
            ARM64_INS_ST2,
            "st2",
            &[
                operand(ARM64_REG_V0, ARM64_VAS_4H),
                operand(ARM64_REG_V0 + 1, ARM64_VAS_4H),
                memory(ARM64_REG_X0),
            ],
            false,
        );
        assert!(!p.unsupported && p.post);
        assert_eq!((p.count, p.width, p.structure_element), (2, 8, 2));
        let mut cpu = CpuContext {
            pc: 0,
            sp: 0,
            nzcv: 0,
            x: [0; 29],
            fp: 0,
            lr: 0,
            vectors: [[0; 16]; 32],
        };
        cpu.vectors[0] = [
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        cpu.vectors[1] = [
            0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let mut values = [0; 4];
        assert!(store_values(&cpu, &p, &mut values));
        assert_eq!(values[0] as u64, 0x2322_1312_2120_1110);
        assert_eq!(values[1] as u64, 0x2726_1716_2524_1514);
        let mut lane = operand(ARM64_REG_V0, ARM64_VAS_1H);
        lane.vector_index = 7;
        let p = classify(ARM64_INS_ST1, "st1", &[lane, memory(ARM64_REG_X0)], false);
        assert!(!p.unsupported);
        cpu.vectors[0][14] = 0xaa;
        cpu.vectors[0][15] = 0xbb;
        let mut values = [0; 4];
        assert!(store_values(&cpu, &p, &mut values));
        assert_eq!(values[0], 0xbbaa);
        lane.vector_index = 8;
        assert!(classify(ARM64_INS_ST1, "st1", &[lane, memory(ARM64_REG_X0)], false).unsupported);
    }
    #[test]
    fn rounded_arithmetic_shape_and_shift_edges() {
        for (vas, element) in [
            (ARM64_VAS_8B, 8),
            (ARM64_VAS_16B, 8),
            (ARM64_VAS_4H, 16),
            (ARM64_VAS_8H, 16),
            (ARM64_VAS_2S, 32),
            (ARM64_VAS_4S, 32),
            (ARM64_VAS_2D, 64),
            (ARM64_VAS_INVALID, 64),
        ] {
            let reg = if vas == ARM64_VAS_INVALID {
                ARM64_REG_D0
            } else {
                ARM64_REG_V0
            };
            for shift in [0, 1, element, element + 1] {
                let p = classify(
                    ARM64_INS_URSHR,
                    "urshr",
                    &[operand(reg, vas), operand(reg + 1, vas), immediate(shift)],
                    false,
                );
                assert_eq!(!p.unsupported, shift > 0 && shift <= element);
            }
        }
        for (low, high, wide, lane_vas) in [
            (ARM64_VAS_8B, ARM64_VAS_16B, ARM64_VAS_8H, ARM64_VAS_1B),
            (ARM64_VAS_4H, ARM64_VAS_8H, ARM64_VAS_4S, ARM64_VAS_1H),
            (ARM64_VAS_2S, ARM64_VAS_4S, ARM64_VAS_2D, ARM64_VAS_1S),
        ] {
            for (id, src) in [(ARM64_INS_UMULL, low), (ARM64_INS_UMULL2, high)] {
                let mut ops = [
                    operand(ARM64_REG_V0, wide),
                    operand(ARM64_REG_V0 + 1, src),
                    operand(ARM64_REG_V0 + 2, src),
                ];
                let p = classify(id, "umull", &ops, false);
                assert!(!p.unsupported && p.post && p.count == 0);
                assert!(classify(id, "umull", &ops, true).unsupported);
                ops[0].vas = src;
                assert!(classify(id, "umull", &ops, false).unsupported);
                ops[0].vas = wide;
                ops[2].vas = lane_vas;
                ops[2].vector_index = 0;
                assert_eq!(
                    !classify(id, "umull", &ops, false).unsupported,
                    lane_vas != ARM64_VAS_1B
                );
                if lane_vas != ARM64_VAS_1B {
                    let lanes = 128 / shape(&ops[1]).element;
                    ops[2].vector_index = lanes as i32 - 1;
                    assert!(!classify(id, "umull", &ops, false).unsupported);
                    ops[2].vector_index += 1;
                    assert!(classify(id, "umull", &ops, false).unsupported);
                    ops[2].vector_index = 0;
                    ops[2].value = OperandValue {
                        reg: ARM64_REG_V0 + 31,
                    };
                    assert_eq!(
                        !classify(id, "umull", &ops, false).unsupported,
                        lane_vas == ARM64_VAS_1S
                    );
                }
            }
            for (id, dest) in [(ARM64_INS_RADDHN, low), (ARM64_INS_RADDHN2, high)] {
                let mut ops = [
                    operand(ARM64_REG_V0, dest),
                    operand(ARM64_REG_V0 + 1, wide),
                    operand(ARM64_REG_V0 + 2, wide),
                ];
                assert!(!classify(id, "raddhn", &ops, false).unsupported);
                ops[2].vas = dest;
                assert!(classify(id, "raddhn", &ops, false).unsupported);
            }
        }
        let ops = [
            operand(ARM64_REG_V0, ARM64_VAS_8H),
            operand(ARM64_REG_V0 + 1, ARM64_VAS_8B),
            operand(ARM64_REG_V0 + 2, ARM64_VAS_8B),
        ];
        assert!(classify(ARM64_INS_SMULL, "smull", &ops, false).unsupported);
    }
    #[test]
    fn four_way_memory_chunks_use_actual_registers_in_memory_order() {
        let mut cpu = CpuContext {
            pc: 0,
            sp: 0,
            nzcv: 0,
            x: [0; 29],
            fp: 0,
            lr: 0,
            vectors: [[0; 16]; 32],
        };
        for (i, reg) in [30, 31, 0, 1].into_iter().enumerate() {
            for j in 0..16 {
                cpu.vectors[reg][j] = (i * 32 + j) as u8;
            }
        }
        for (vas, element, width) in [
            (ARM64_VAS_8B, 1, 8),
            (ARM64_VAS_16B, 1, 16),
            (ARM64_VAS_4H, 2, 8),
            (ARM64_VAS_8H, 2, 16),
            (ARM64_VAS_2S, 4, 8),
            (ARM64_VAS_4S, 4, 16),
            (ARM64_VAS_2D, 8, 16),
        ] {
            for (id, name) in [(ARM64_INS_ST4, "st4"), (ARM64_INS_LD4, "ld4")] {
                let ops = [
                    operand(ARM64_REG_V0 + 30, vas),
                    operand(ARM64_REG_V0 + 31, vas),
                    operand(ARM64_REG_V0, vas),
                    operand(ARM64_REG_V0 + 1, vas),
                    memory(ARM64_REG_X0),
                ];
                let p = classify(id, name, &ops, false);
                assert!(!p.unsupported && p.post);
                assert_eq!(
                    (p.count, p.width, p.structure_element, p.load),
                    (4, width, element, id == ARM64_INS_LD4)
                );
                let mut values = [0; 4];
                assert!(store_values(&cpu, &p, &mut values));
                let bytes: Vec<_> = values
                    .iter()
                    .flat_map(|v| v.to_le_bytes().into_iter().take(width as usize))
                    .collect();
                let mut expected = Vec::new();
                for lane in 0..width / element {
                    for reg in [30, 31, 0, 1] {
                        for j in 0..element {
                            expected.push(cpu.vectors[reg][(lane * element + j) as usize]);
                        }
                    }
                }
                assert_eq!(bytes, expected);
            }
        }
        for (vas, element) in [
            (ARM64_VAS_1B, 1),
            (ARM64_VAS_1H, 2),
            (ARM64_VAS_1S, 4),
            (ARM64_VAS_1D, 8),
        ] {
            let lane = 16 / element - 1;
            let mut ops = [
                operand(ARM64_REG_V0 + 30, vas),
                operand(ARM64_REG_V0 + 31, vas),
                operand(ARM64_REG_V0, vas),
                operand(ARM64_REG_V0 + 1, vas),
                memory(ARM64_REG_X0),
            ];
            for op in &mut ops[..4] {
                op.vector_index = lane;
            }
            let p = classify(ARM64_INS_ST4, "st4", &ops, false);
            assert!(!p.unsupported);
            let mut values = [0; 4];
            assert!(store_values(&cpu, &p, &mut values));
            for (i, reg) in [30, 31, 0, 1].into_iter().enumerate() {
                let mut want = [0; 16];
                want[..element as usize].copy_from_slice(
                    &cpu.vectors[reg][(lane * element) as usize..((lane + 1) * element) as usize],
                );
                assert_eq!(
                    values[i] & ((1u128 << (element * 8)) - 1),
                    u128::from_le_bytes(want)
                );
            }
            ops[3].vector_index = lane + 1;
            assert!(classify(ARM64_INS_ST4, "st4", &ops, false).unsupported);
            ops[3].vector_index = lane;
            ops[2] = operand(ARM64_REG_V0 + 2, vas);
            assert!(classify(ARM64_INS_ST4, "st4", &ops, false).unsupported);
        }
    }
    #[test]
    fn vector_crypto_shapes_reject_unsupported_arrangements() {
        let v = |r, vas| operand(ARM64_REG_V0 + r, vas);
        for (id, m) in [(ARM64_INS_AESE, "aese"), (ARM64_INS_AESIMC, "aesimc")] {
            assert!(
                !classify(id, m, &[v(0, ARM64_VAS_16B), v(1, ARM64_VAS_16B)], false).unsupported
            );
            assert!(classify(id, m, &[v(0, ARM64_VAS_8B), v(1, ARM64_VAS_8B)], false).unsupported);
        }
        assert!(
            !classify(
                ARM64_INS_PMULL2,
                "pmull2",
                &[v(0, ARM64_VAS_1Q), v(1, ARM64_VAS_2D), v(2, ARM64_VAS_2D)],
                false
            )
            .unsupported
        );
        assert!(
            classify(
                ARM64_INS_PMULL2,
                "pmull2",
                &[v(0, ARM64_VAS_1Q), v(1, ARM64_VAS_1D), v(2, ARM64_VAS_1D)],
                false
            )
            .unsupported
        );
        assert!(
            !classify(
                ARM64_INS_SHA1H,
                "sha1h",
                &[operand(ARM64_REG_S0, 0), operand(ARM64_REG_S0 + 1, 0)],
                false
            )
            .unsupported
        );
        assert!(
            !classify(
                ARM64_INS_TRN2,
                "trn2",
                &[v(0, ARM64_VAS_4S), v(1, ARM64_VAS_4S), v(2, ARM64_VAS_4S)],
                false
            )
            .unsupported
        );
        assert!(
            classify(
                ARM64_INS_TRN2,
                "trn2",
                &[v(0, ARM64_VAS_4S), v(1, ARM64_VAS_2S), v(2, ARM64_VAS_4S)],
                false
            )
            .unsupported
        );
    }
    #[test]
    fn integer_vector_shift_bounds_and_upper_half() {
        let v = |r, vas| operand(ARM64_REG_V0 + r, vas);
        assert!(
            !classify(
                ARM64_INS_SHL,
                "shl",
                &[v(0, ARM64_VAS_4S), v(1, ARM64_VAS_4S), immediate(31)],
                false
            )
            .unsupported
        );
        assert!(
            classify(
                ARM64_INS_SHL,
                "shl",
                &[v(0, ARM64_VAS_4S), v(1, ARM64_VAS_4S), immediate(32)],
                false
            )
            .unsupported
        );
        assert!(
            !classify(
                ARM64_INS_UXTL2,
                "uxtl2",
                &[v(0, ARM64_VAS_4S), v(1, ARM64_VAS_8H)],
                false
            )
            .unsupported
        );
        assert!(
            classify(
                ARM64_INS_UXTL2,
                "uxtl2",
                &[v(0, ARM64_VAS_4S), v(1, ARM64_VAS_4H)],
                false
            )
            .unsupported
        );
    }
}
