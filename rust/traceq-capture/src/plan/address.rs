//! Effective addresses retained after Capstone metadata goes out of scope.
use super::reg_value;
use crate::gum::{
    ARM64_EXT_SXTW, ARM64_EXT_UXTW, ARM64_OP_IMM, ARM64_OP_MEM, ARM64_REG_INVALID, Arm64Op,
    CpuContext,
};

#[derive(Clone, Copy)]
pub(crate) enum Extension {
    Native,
    UnsignedWord,
    SignedWord,
}

#[derive(Clone, Copy, Default)]
pub(crate) enum Address {
    #[default]
    Missing,
    Literal(u64),
    Indexed {
        base: u32,
        index: u32,
        displacement: i32,
        shift: u32,
        extension: Extension,
    },
}

impl Address {
    pub(super) fn decode(op: &Arm64Op) -> Self {
        match op.kind {
            ARM64_OP_IMM => Self::Literal(op.imm() as u64),
            ARM64_OP_MEM => {
                let mem = op.mem();
                Self::Indexed {
                    base: mem.base,
                    index: mem.index,
                    displacement: mem.disp,
                    shift: op.shift.value,
                    extension: match op.ext {
                        ARM64_EXT_UXTW => Extension::UnsignedWord,
                        ARM64_EXT_SXTW => Extension::SignedWord,
                        _ => Extension::Native,
                    },
                }
            }
            _ => Self::Missing,
        }
    }

    pub(super) fn base(self) -> Option<u32> {
        match self {
            Self::Indexed { base, .. } => Some(base),
            _ => None,
        }
    }

    pub(super) fn evaluate(self, cpu: &CpuContext) -> Option<u64> {
        match self {
            Self::Missing => None,
            Self::Literal(address) => Some(address),
            Self::Indexed {
                base,
                index,
                displacement,
                shift,
                extension,
            } => {
                let base = reg_value(base, cpu)? as u64;
                let index = if index == ARM64_REG_INVALID {
                    0
                } else {
                    reg_value(index, cpu)? as u64
                };
                let index = match extension {
                    Extension::Native => index,
                    Extension::UnsignedWord => index as u32 as u64,
                    Extension::SignedWord => index as i32 as i64 as u64,
                };
                Some(
                    base.wrapping_add(index.wrapping_shl(shift))
                        .wrapping_add(displacement as u64),
                )
            }
        }
    }
}
