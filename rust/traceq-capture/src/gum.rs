//! The minimal FFI surface for the pinned Gum devkit. This module does not own
//! Gum objects. The invoke owner keeps modules mapped, stops Stalker, drains its
//! garbage collector, and then releases transformer/stalker references.
#![allow(dead_code)]
use core::ffi::{c_char, c_int, c_void};
pub use traceq_observer::CpuContext;
#[path = "gum_constants.rs"]
mod constants;
pub use constants::*;

pub enum Stalker {}
pub enum Transformer {}
pub enum Iterator {}
pub enum Output {}
pub enum Module {}
pub type Destroy = Option<unsafe extern "C" fn(*mut c_void)>;
pub type Callout = unsafe extern "C" fn(*mut CpuContext, *mut c_void);
pub type Transform = unsafe extern "C" fn(*mut Iterator, *mut Output, *mut c_void);
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct MemoryRange {
    pub base_address: u64,
    pub size: usize,
}
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct Mem {
    pub base: u32,
    pub index: u32,
    pub disp: i32,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub union OperandValue {
    pub reg: u32,
    pub imm: i64,
    pub fp: f64,
    pub mem: Mem,
    pub storage: [u64; 2],
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Shift {
    pub kind: u32,
    pub value: u32,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Arm64Op {
    pub vector_index: i32,
    pub vas: u32,
    pub shift: Shift,
    pub ext: u32,
    pub kind: u32,
    pub svcr: u32,
    pub value: OperandValue,
    pub access: u8,
}
impl Default for Arm64Op {
    fn default() -> Self {
        Self {
            vector_index: 0,
            vas: 0,
            shift: Shift::default(),
            ext: 0,
            kind: 0,
            svcr: 0,
            value: OperandValue { storage: [0; 2] },
            access: 0,
        }
    }
}
impl Arm64Op {
    // The instruction's operand tag determines the active C union member. The
    // integer members have no invalid bit patterns; callers check kind first.
    pub fn reg(&self) -> u32 {
        unsafe { self.value.reg }
    }
    pub fn imm(&self) -> i64 {
        unsafe { self.value.imm }
    }
    pub fn fp(&self) -> f64 {
        unsafe { self.value.fp }
    }
    pub fn mem(&self) -> Mem {
        unsafe { self.value.mem }
    }
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Arm64 {
    pub cc: u32,
    pub update_flags: u8,
    pub writeback: u8,
    pub post_index: u8,
    pub op_count: u8,
    pub operands: [Arm64Op; 8],
}
/// Only the ARM64 prefix is used. The C union can be larger for other CPUs.
/// No value of this prefix type is passed by value or allocated for Gum.
#[repr(C)]
pub struct DetailArm64 {
    pub prefix: [u8; 96],
    pub arm64: Arm64,
}
#[repr(C)]
pub struct Insn {
    pub id: u32,
    pub address: u64,
    pub size: u16,
    pub bytes: [u8; 24],
    pub mnemonic: [u8; 32],
    pub op_str: [u8; 160],
    pub detail: *const DetailArm64,
}
impl Insn {
    pub fn mnemonic(&self) -> &str {
        ascii(&self.mnemonic)
    }
    pub fn operands_text(&self) -> &str {
        ascii(&self.op_str)
    }
    /// # Safety
    /// The instruction must originate from the detail-enabled Gum iterator;
    /// its detail storage must remain live for the current transform call.
    pub unsafe fn arm64(&self) -> Option<&Arm64> {
        if self.detail.is_null() {
            None
        } else {
            Some(unsafe { &(*self.detail).arm64 })
        }
    }
}
fn ascii(bytes: &[u8]) -> &str {
    let n = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    core::str::from_utf8(&bytes[..n]).unwrap_or("")
}
unsafe extern "C" {
    pub fn gum_init();
    pub fn gum_process_get_current_thread_id() -> u64;
    pub fn gum_process_find_module_by_name(name: *const c_char) -> *mut Module;
    pub fn gum_process_find_module_by_address(address: u64) -> *mut Module;
    pub fn gum_process_enumerate_modules(
        callback: Option<unsafe extern "C" fn(*mut Module, *mut c_void) -> c_int>,
        data: *mut c_void,
    );
    pub fn gum_module_get_name(module: *mut Module) -> *const c_char;
    pub fn gum_module_get_range(module: *mut Module) -> *const MemoryRange;
    #[cfg_attr(
        any(target_os = "android", target_os = "ios"),
        link_name = "_frida_g_object_unref"
    )]
    pub fn g_object_unref(object: *mut c_void);
    #[cfg_attr(
        any(target_os = "android", target_os = "ios"),
        link_name = "_frida_g_usleep"
    )]
    pub fn g_usleep(microseconds: usize);
    pub fn gum_stalker_new() -> *mut Stalker;
    pub fn gum_stalker_set_trust_threshold(stalker: *mut Stalker, threshold: c_int);
    pub fn gum_stalker_stop(stalker: *mut Stalker);
    pub fn gum_stalker_garbage_collect(stalker: *mut Stalker) -> c_int;
    pub fn gum_stalker_follow_me(
        stalker: *mut Stalker,
        transformer: *mut Transformer,
        sink: *mut c_void,
    );
    pub fn gum_stalker_unfollow_me(stalker: *mut Stalker);
    pub fn gum_stalker_follow(
        stalker: *mut Stalker,
        thread: usize,
        transformer: *mut Transformer,
        sink: *mut c_void,
    );
    pub fn gum_stalker_unfollow(stalker: *mut Stalker, thread: usize);
    pub fn gum_stalker_exclude(stalker: *mut Stalker, range: *const MemoryRange);
    pub fn gum_stalker_transformer_make_from_callback(
        callback: Option<Transform>,
        data: *mut c_void,
        destroy: Destroy,
    ) -> *mut Transformer;
    pub fn gum_stalker_iterator_next(
        iterator: *mut Iterator,
        instruction: *mut *const Insn,
    ) -> c_int;
    pub fn gum_stalker_iterator_keep(iterator: *mut Iterator);
    pub fn gum_stalker_iterator_get_memory_access(iterator: *mut Iterator) -> c_int;
    pub fn gum_stalker_iterator_put_callout(
        iterator: *mut Iterator,
        callback: Callout,
        data: *mut c_void,
        destroy: Destroy,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{align_of, offset_of, size_of};
    #[test]
    fn pinned_arm64_layout() {
        assert_eq!(
            (
                size_of::<CpuContext>(),
                align_of::<CpuContext>(),
                offset_of!(CpuContext, vectors)
            ),
            (784, 8, 272)
        );
        assert_eq!(
            (
                size_of::<Arm64Op>(),
                align_of::<Arm64Op>(),
                offset_of!(Arm64Op, value),
                offset_of!(Arm64Op, access)
            ),
            (56, 8, 32, 48)
        );
        assert_eq!((size_of::<Arm64>(), offset_of!(Arm64, operands)), (456, 8));
        assert_eq!(offset_of!(DetailArm64, arm64), 96);
        assert_eq!(
            (
                size_of::<Insn>(),
                offset_of!(Insn, mnemonic),
                offset_of!(Insn, op_str),
                offset_of!(Insn, detail)
            ),
            (248, 42, 74, 240)
        );
    }
}
