//! Gum callback ownership: the pre callout owns its Plan, while a fused
//! Boundary owns only its current Plan. Previous/post pointers are borrowed
//! until Gum destroys the compiled block. The invoke owner drains Gum's GC
//! before releasing the session and transformer.
use crate::{
    gum::*,
    plan::{self, Plan},
    runtime,
};
use core::{ffi::c_void, ptr};

unsafe extern "C" fn before(cpu: *mut CpuContext, data: *mut c_void) {
    crate::ffi_guard(|| unsafe { runtime::before(cpu, data.cast()) });
}
unsafe extern "C" fn after(cpu: *mut CpuContext, data: *mut c_void) {
    crate::ffi_guard(|| unsafe { runtime::after(cpu, data.cast()) });
}
unsafe extern "C" fn free_plan(data: *mut c_void) {
    if !data.is_null() {
        drop(unsafe { Box::from_raw(data.cast::<Plan>()) })
    }
}
struct Boundary {
    previous: *mut Plan,
    current: *mut Plan,
}
unsafe extern "C" fn shared(cpu: *mut CpuContext, data: *mut c_void) {
    crate::ffi_guard(|| {
        let boundary = unsafe { &*data.cast::<Boundary>() };
        unsafe { runtime::shared_boundary(cpu, boundary.previous, boundary.current) };
    });
}
unsafe extern "C" fn free_boundary(data: *mut c_void) {
    if data.is_null() {
        return;
    }
    let boundary = unsafe { Box::from_raw(data.cast::<Boundary>()) };
    if !boundary.current.is_null() {
        drop(unsafe { Box::from_raw(boundary.current) })
    }
}
unsafe fn post(iterator: *mut Iterator, p: *mut Plan) {
    unsafe { gum_stalker_iterator_put_callout(iterator, after, p.cast(), None) }
}
unsafe fn instrument_one(iterator: *mut Iterator, ins: &Insn, header: traceq_core::wire::Header) {
    if !runtime::code_contains(ins.address, 4) {
        unsafe { gum_stalker_iterator_keep(iterator) };
        return;
    }
    if unsafe { gum_stalker_iterator_get_memory_access(iterator) } == 1 {
        runtime::exclusive();
        unsafe { gum_stalker_iterator_keep(iterator) };
        return;
    }
    let p = Box::into_raw(Box::new(unsafe {
        plan::make_in_scope(ins, header, runtime::code_contains)
    }));
    if header.profile == 2 {
        runtime::emit_site(ins)
    }
    unsafe {
        gum_stalker_iterator_put_callout(iterator, before, p.cast(), Some(free_plan));
        gum_stalker_iterator_keep(iterator);
        if if header.profile == 2 {
            (*p).post
        } else {
            (*p).count != 0 && !(*p).unsupported
        } {
            post(iterator, p)
        }
    }
}
unsafe fn fused(iterator: *mut Iterator, header: traceq_core::wire::Header) {
    let mut instruction = ptr::null();
    let mut deferred: *mut Plan = ptr::null_mut();
    while unsafe { gum_stalker_iterator_next(iterator, &mut instruction) } != 0 {
        let ins = unsafe { &*instruction };
        if !runtime::code_contains(ins.address, 4) {
            if !deferred.is_null() {
                unsafe { post(iterator, deferred) };
                deferred = ptr::null_mut()
            }
            unsafe { gum_stalker_iterator_keep(iterator) };
            continue;
        }
        let p = Box::into_raw(Box::new(unsafe {
            plan::make_in_scope(ins, header, runtime::code_contains)
        }));
        runtime::emit_site(ins);
        if !deferred.is_null()
            && unsafe { (*deferred).pc.wrapping_add(4) == (*p).pc && !(*p).unsupported }
        {
            let boundary = Box::into_raw(Box::new(Boundary {
                previous: deferred,
                current: p,
            }));
            unsafe {
                gum_stalker_iterator_put_callout(
                    iterator,
                    shared,
                    boundary.cast(),
                    Some(free_boundary),
                )
            };
            deferred = ptr::null_mut();
        } else {
            if !deferred.is_null() {
                unsafe { post(iterator, deferred) };
                deferred = ptr::null_mut()
            }
            unsafe {
                gum_stalker_iterator_put_callout(iterator, before, p.cast(), Some(free_plan))
            };
        }
        unsafe { gum_stalker_iterator_keep(iterator) };
        if unsafe { (*p).post } {
            deferred = p
        }
    }
    if !deferred.is_null() {
        unsafe { post(iterator, deferred) }
    }
}
/// # Safety
/// Gum invokes this only while its iterator/output and the owning capture
/// session are live. Runtime verifies owner identity for each executed callout.
pub unsafe extern "C" fn transform(
    iterator: *mut Iterator,
    _output: *mut Output,
    _data: *mut c_void,
) {
    crate::ffi_guard(|| {
        let Some((header, observation)) = runtime::config() else {
            let mut ins = ptr::null();
            while unsafe { gum_stalker_iterator_next(iterator, &mut ins) } != 0 {
                unsafe { gum_stalker_iterator_keep(iterator) }
            }
            return;
        };
        if header.profile == 2
            && observation == 2
            && unsafe { gum_stalker_iterator_get_memory_access(iterator) } != 1
        {
            unsafe { fused(iterator, header) };
            return;
        }
        let mut ins = ptr::null();
        while unsafe { gum_stalker_iterator_next(iterator, &mut ins) } != 0 {
            unsafe { instrument_one(iterator, &*ins, header) }
        }
    });
}
