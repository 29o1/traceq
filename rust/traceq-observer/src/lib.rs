//! ARM64 CPU-context layout shared with the pinned Gum ABI.

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CpuContext {
    pub pc: u64,
    pub sp: u64,
    pub nzcv: u64,
    pub x: [u64; 29],
    pub fp: u64,
    pub lr: u64,
    pub vectors: [[u8; 16]; 32],
}
