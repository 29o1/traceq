//! Independent native-lab adapter; this archive is never linked into the SDK.
use traceq_capture::{gum::Insn,plan};
use traceq_capture::plan::Header;
/// The caller supplies live Capstone storage matching capture_ffi_layout.c.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn traceq_lab_supported(ins:*const Insn)->bool {
    if ins.is_null(){return false}
    std::panic::catch_unwind(|| {
        let h=Header{code_base:0,code_size:u64::MAX,data_base:0,data_size:u64::MAX,thread_id:1,profile:1};
        !unsafe{plan::make(&*ins,h)}.unsupported
    }).unwrap_or(false)
}
