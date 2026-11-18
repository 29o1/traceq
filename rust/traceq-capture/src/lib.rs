//! Rust capture SDK. Gum and system FFI are kept at the native boundary.
//! Every exported entry and Gum callback contains Rust unwinding. Expected
//! failures use status values; no caller can recover invalid foreign pointers.
#![deny(unsafe_op_in_unsafe_fn)]
pub mod code_scope;
pub use code_scope::CodeRange;
use code_scope::{CodeScope, MAX_CODE_RANGES};
pub mod gum;
pub mod instrument;
pub mod plan;
pub mod runtime;
pub mod storage;
use std::ffi::{CStr, c_char, c_void};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use storage::Mode;
use traceq_core::wire::Header;

#[inline]
pub fn ffi_guard(f: impl FnOnce()) {
    if std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).is_err() {
        runtime::fail();
    }
}
fn guarded<T: Copy>(failure: T, f: impl FnOnce() -> T) -> T {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(v) => v,
        Err(_) => {
            runtime::fail();
            failure
        }
    }
}
#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct InvokeReport {
    pub version: u64,
    pub status: u64,
    pub thread_id: u64,
    pub setup_ns: u64,
    pub follow_ns: u64,
    pub target_ns: u64,
    pub unfollow_ns: u64,
    pub finish_ns: u64,
    pub cleanup_ns: u64,
    pub total_ns: u64,
    pub instructions: u64,
    pub reads: u64,
    pub writes: u64,
    pub gaps: u64,
    pub commits: u64,
    pub code_base: u64,
    pub code_size: u64,
}
type Invoke = unsafe extern "C" fn(*mut c_void);
static INVOKING: AtomicBool = AtomicBool::new(false);
struct InvokeLease;
impl Drop for InvokeLease {
    fn drop(&mut self) {
        INVOKING.store(false, Ordering::Release);
    }
}
struct Engine {
    stalker: *mut gum::Stalker,
    transformer: *mut gum::Transformer,
    following: bool,
}
impl Engine {
    unsafe fn new() -> Option<Self> {
        unsafe {
            let transformer = gum::gum_stalker_transformer_make_from_callback(
                Some(instrument::transform),
                ptr::null_mut(),
                None,
            );
            if transformer.is_null() {
                return None;
            }
            let stalker = gum::gum_stalker_new();
            if stalker.is_null() {
                gum::g_object_unref(transformer.cast());
                return None;
            }
            Some(Self {
                stalker,
                transformer,
                following: false,
            })
        }
    }
    unsafe fn follow(&mut self) {
        self.following = true;
        unsafe {
            gum::gum_stalker_follow_me(self.stalker, self.transformer, ptr::null_mut());
        }
    }
    unsafe fn unfollow(&mut self) {
        if self.following {
            unsafe {
                gum::gum_stalker_unfollow_me(self.stalker);
            }
            self.following = false;
        }
    }
}
impl Drop for Engine {
    fn drop(&mut self) {
        unsafe {
            self.unfollow();
            if runtime::owns() {
                let _ = runtime::end();
            }
            // Gum owns Plan/Boundary userdata until its code cache has been reclaimed.
            gum::gum_stalker_stop(self.stalker);
            while gum::gum_stalker_garbage_collect(self.stalker) != 0 {
                gum::g_usleep(1000);
            }
            gum::g_object_unref(self.stalker.cast());
            gum::g_object_unref(self.transformer.cast());
        }
    }
}

unsafe fn select_scope(
    module: *const c_char,
    address: u64,
    extra: &[CodeRange],
) -> Result<CodeScope, i32> {
    let selected = unsafe {
        if !module.is_null() {
            gum::gum_process_find_module_by_name(module)
        } else {
            gum::gum_process_find_module_by_address(address)
        }
    };
    if selected.is_null() {
        return Err(-2);
    }
    let range = unsafe { *gum::gum_module_get_range(selected) };
    unsafe {
        gum::g_object_unref(selected.cast());
    }
    if address != 0 && !plan::contains(range.base_address, range.size as u64, address, 1) {
        return Err(-2);
    }
    CodeScope::new(
        CodeRange {
            base: range.base_address,
            size: range.size as u64,
        },
        extra,
    )
    .ok_or(-1)
}

#[allow(clippy::too_many_arguments)]
unsafe fn invoke_impl(
    path: *const c_char,
    module: *const c_char,
    address: u64,
    invoke: Option<Invoke>,
    context: *mut c_void,
    observation: u32,
    report: *mut InvokeReport,
    extra: &[CodeRange],
) -> i32 {
    let started = std::time::Instant::now();
    let Some(invoke) = invoke else {
        return -1;
    };
    if report.is_null()
        || !(report as usize).is_multiple_of(std::mem::align_of::<InvokeReport>())
        || (module.is_null() && address == 0)
        || observation > 3
        || (observation != 0 && path.is_null())
    {
        return -1;
    }
    if INVOKING
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
        .is_err()
    {
        return -7;
    }
    let _lease = InvokeLease;
    if runtime::active() {
        return -7;
    }
    unsafe {
        gum::gum_init();
    }
    let scope = unsafe { select_scope(module, address, extra) };
    unsafe {
        report.write(InvokeReport {
            version: 1,
            ..Default::default()
        });
    }
    let scope = match scope {
        Ok(scope) => scope,
        Err(status) => return status,
    };
    let (code_base, code_size) = scope.envelope();
    let thread_id = unsafe { gum::gum_process_get_current_thread_id() };
    unsafe {
        (*report).code_base = code_base;
        (*report).code_size = code_size;
        (*report).thread_id = thread_id;
    }
    let mut engine = if observation != 0 {
        let Some(e) = (unsafe { Engine::new() }) else {
            return -4;
        };
        Some(e)
    } else {
        None
    };
    if let Some(e) = engine.as_ref() {
        unsafe {
            gum::gum_stalker_set_trust_threshold(e.stalker, 1);
            // Gum 17.26 uses its upstream 64KiB worst-case block margin.
        }
        let path = unsafe { CStr::from_ptr(path) };
        let path = Path::new(std::ffi::OsStr::from_bytes(path.to_bytes()));
        let h = Header {
            code_base,
            code_size,
            data_base: 0,
            data_size: u64::MAX,
            thread_id,
            profile: 2,
        };
        if !runtime::begin_scoped(path, h, observation - 1, Mode::Chunked, true, scope) {
            return -5;
        }
    }
    let setup = started.elapsed();
    if let Some(e) = engine.as_mut() {
        unsafe {
            e.follow();
        }
    }
    let entered = started.elapsed();
    unsafe {
        invoke(context);
    }
    let returned = started.elapsed();
    if let Some(e) = engine.as_mut() {
        unsafe {
            e.unfollow();
        }
    }
    let stopped = started.elapsed();
    // The caller may refer to the report through its opaque callback context.
    // Do not hold a Rust mutable borrow of that memory through the callback.
    let report = unsafe { &mut *report };
    let mut ok = true;
    if observation != 0 {
        let Some((completed, n)) = runtime::end() else {
            return -6;
        };
        ok = completed;
        report.instructions = n.instructions;
        report.reads = n.reads;
        report.writes = n.writes;
        report.gaps = n.gaps;
        report.commits = n.commits;
    }
    let finished = started.elapsed();
    drop(engine);
    let cleaned = started.elapsed();
    report.status = ok as u64;
    report.setup_ns = setup.as_nanos() as u64;
    report.follow_ns = (entered - setup).as_nanos() as u64;
    report.target_ns = (returned - entered).as_nanos() as u64;
    report.unfollow_ns = (stopped - returned).as_nanos() as u64;
    report.finish_ns = (finished - stopped).as_nanos() as u64;
    report.cleanup_ns = (cleaned - finished).as_nanos() as u64;
    report.total_ns = cleaned.as_nanos() as u64;
    if ok { 0 } else { -6 }
}
/// # Safety
/// Strings, callback/context and aligned report remain valid for this entire call.
/// The adapter returns normally on this thread and keeps target mappings alive.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn traceq_capture_invoke(
    path: *const c_char,
    module: *const c_char,
    invoke: Option<Invoke>,
    context: *mut c_void,
    observation: u32,
    report: *mut InvokeReport,
) -> i32 {
    guarded(-6, || unsafe {
        invoke_impl(path, module, 0, invoke, context, observation, report, &[])
    })
}
/// # Safety
/// Same lifetime and pointer requirements as traceq_capture_invoke.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn traceq_capture_invoke_at(
    path: *const c_char,
    address: u64,
    invoke: Option<Invoke>,
    context: *mut c_void,
    observation: u32,
    report: *mut InvokeReport,
) -> i32 {
    guarded(-6, || unsafe {
        invoke_impl(
            path,
            ptr::null(),
            address,
            invoke,
            context,
            observation,
            report,
            &[],
        )
    })
}

/// Opt-in exact code observation intervals in addition to the anchor module.
/// # Safety
/// Same pointer/lifetime requirements as invoke_at. extra points at extra_count
/// readable CodeRange entries; keep every selected code mapping alive until return.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn traceq_capture_invoke_ranges_at(
    path: *const c_char,
    address: u64,
    invoke: Option<Invoke>,
    context: *mut c_void,
    observation: u32,
    extra: *const CodeRange,
    extra_count: u32,
    report: *mut InvokeReport,
) -> i32 {
    guarded(-6, || {
        if extra_count as usize >= MAX_CODE_RANGES
            || (extra_count != 0
                && (extra.is_null()
                    || !(extra as usize).is_multiple_of(std::mem::align_of::<CodeRange>())))
        {
            return -1;
        }
        let ranges = if extra_count == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(extra, extra_count as usize) }
        };
        unsafe {
            invoke_impl(
                path,
                ptr::null(),
                address,
                invoke,
                context,
                observation,
                report,
                ranges,
            )
        }
    })
}

// C ABI used by the independent native lab; it shares the product runtime.
/// # Safety
/// Path is a live NUL-terminated string. Code/data mappings remain live until end.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn traceq_capture_begin(
    path: *const c_char,
    code: u64,
    code_size: u64,
    data: u64,
    data_size: u64,
    profile: u32,
    observation: u32,
    mode: u32,
    external: bool,
) -> bool {
    guarded(false, || {
        if path.is_null() {
            return false;
        }
        let mode = match mode {
            0 => Mode::Flat,
            1 => Mode::Buffered,
            2 => Mode::Chunked,
            _ => return false,
        };
        let path = unsafe { CStr::from_ptr(path) };
        let path = Path::new(std::ffi::OsStr::from_bytes(path.to_bytes()));
        runtime::begin(
            path,
            Header {
                code_base: code,
                code_size,
                data_base: data,
                data_size,
                thread_id: unsafe { gum::gum_process_get_current_thread_id() },
                profile: profile as u64,
            },
            observation,
            mode,
            external,
        )
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn traceq_capture_end() -> bool {
    guarded(false, || runtime::end().is_some_and(|(ok, _)| ok))
}
/// # Safety
/// Gum supplies the live iterator/output and invokes on the capture owner.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn traceq_capture_transform(
    iterator: *mut gum::Iterator,
    output: *mut gum::Output,
    data: *mut c_void,
) {
    unsafe {
        instrument::transform(iterator, output, data);
    }
}
