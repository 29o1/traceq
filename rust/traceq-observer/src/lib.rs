//! Experimental full-context observer and ARM64 snapshot code generation.
//! This FFI is pinned to the independently checked Gum 17.8.3 ARM64 layout.
#![deny(unsafe_op_in_unsafe_fn)]

pub mod snapshot;
use core::{
    mem::{align_of, offset_of, size_of},
    ptr,
};

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
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Event {
    pub kind: u64,
    pub seq: u64,
    pub pc: u64,
    pub address: u64,
    pub size: u64,
    pub low: u64,
    pub high: u64,
    pub detail: u64,
}
#[repr(C)]
pub struct StateView {
    pub values: *mut u128,
    pub known: *mut u8,
    pub gpr_bank: *mut u64,
    pub complete: *mut u8,
}
unsafe extern "C" {
    fn memcmp(a: *const core::ffi::c_void, b: *const core::ffi::c_void, n: usize) -> i32;
}

/// Sizes and offsets are compared to the actual C header before any capture.
#[unsafe(no_mangle)]
pub extern "C" fn traceq_observer_layout(field: u32) -> usize {
    match field {
        0 => size_of::<CpuContext>(),
        1 => align_of::<CpuContext>(),
        2 => offset_of!(CpuContext, vectors),
        3 => offset_of!(CpuContext, x),
        4 => offset_of!(CpuContext, sp),
        5 => offset_of!(CpuContext, nzcv),
        6 => offset_of!(CpuContext, fp),
        7 => offset_of!(CpuContext, lr),
        8 => size_of::<Event>(),
        9 => size_of::<StateView>(),
        _ => usize::MAX,
    }
}

/// # Safety
/// View, state and output refer to live, aligned, disjoint objects. StateView
/// has 65 u128 values, 65 validity bytes (0/1), 29 bank words, one complete byte.
/// CPU uses the checked C layout, including Gum's potentially unaligned proxy
/// stack context; output holds capacity aligned Events. No pointer is
/// retained. Only the owning capture thread may call this function on the state.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn traceq_observer_delta(
    view: *mut StateView,
    cpu: *const CpuContext,
    kind: u64,
    seq: u64,
    pc: u64,
    output: *mut Event,
    capacity: usize,
) -> usize {
    if view.is_null()
        || cpu.is_null()
        || output.is_null()
        || capacity < 65
        || !matches!(kind, 5 | 6)
        || !(view as usize).is_multiple_of(align_of::<StateView>())
        || !(output as usize).is_multiple_of(align_of::<Event>())
    {
        return usize::MAX;
    }
    // The C owner establishes object bounds and lifetime; null/alignment checks
    // cannot prove arbitrary foreign pointers are valid.
    let view = unsafe { &mut *view };
    if view.values.is_null()
        || view.known.is_null()
        || view.gpr_bank.is_null()
        || view.complete.is_null()
        || !(view.values as usize).is_multiple_of(align_of::<u128>())
        || !(view.gpr_bank as usize).is_multiple_of(align_of::<u64>())
    {
        return usize::MAX;
    }
    if !(cpu as usize).is_multiple_of(align_of::<CpuContext>()) {
        // Gum supports target SP misalignment. Keep the copy off the normal
        // path while avoiding an unaligned Rust reference to its context.
        return unsafe { delta_unaligned(view, cpu, kind, seq, pc, output, capacity) };
    }
    let cpu = unsafe { &*cpu };
    let complete = unsafe { *view.complete != 0 };
    let mut used = 0;
    let mut observe = |slot: usize, value: u128| {
        // Every index is bounded by the fixed 65-slot loops below.
        unsafe {
            if *view.known.add(slot) == 0 || *view.values.add(slot) != value {
                ptr::write(
                    output.add(used),
                    Event {
                        kind,
                        seq,
                        pc,
                        address: slot as u64,
                        size: if slot < 33 { 8 } else { 16 },
                        low: value as u64,
                        high: (value >> 64) as u64,
                        detail: 1,
                    },
                );
                used += 1;
                *view.values.add(slot) = value;
                *view.known.add(slot) = 1;
            }
        }
    };
    if !complete || unsafe { memcmp(view.gpr_bank.cast(), cpu.x.as_ptr().cast(), 29 * 8) != 0 } {
        for (i, value) in cpu.x.iter().copied().enumerate() {
            observe(i, value as u128);
        }
        unsafe {
            ptr::copy_nonoverlapping(cpu.x.as_ptr(), view.gpr_bank, 29);
        }
    }
    for (slot, value) in [(29, cpu.fp), (30, cpu.lr), (31, cpu.sp), (32, cpu.nzcv)] {
        observe(slot, value as u128);
    }
    if !complete
        || unsafe {
            memcmp(
                view.values.add(33).cast(),
                cpu.vectors.as_ptr().cast(),
                32 * 16,
            ) != 0
        }
    {
        for (i, value) in cpu.vectors.iter().enumerate() {
            observe(i + 33, u128::from_le_bytes(*value));
        }
    }
    unsafe {
        *view.complete = 1;
    }
    used
}

#[cold]
#[inline(never)]
unsafe fn delta_unaligned(
    view: *mut StateView,
    cpu: *const CpuContext,
    kind: u64,
    seq: u64,
    pc: u64,
    output: *mut Event,
    capacity: usize,
) -> usize {
    let aligned = unsafe { ptr::read_unaligned(cpu) };
    unsafe { traceq_observer_delta(view, &aligned, kind, seq, pc, output, capacity) }
}

/// # Safety
/// output refers to capacity writable u32 words. The buffer is used only during
/// this call. head points to a live owning-thread cursor with sufficient mapped
/// snapshot capacity at execution time; this function emits code, it does not
/// validate executable memory, Gum placement or runtime buffer ownership.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn traceq_observer_snapshot_words(
    head: u64,
    pc: u64,
    output: *mut u32,
    capacity: usize,
) -> usize {
    if output.is_null()
        || !(output as usize).is_multiple_of(align_of::<u32>())
        || capacity < snapshot::MAX_WORDS
    {
        return 0;
    }
    let words = unsafe { core::slice::from_raw_parts_mut(output, capacity) };
    snapshot::generate(head, pc, words).unwrap_or(0)
}
