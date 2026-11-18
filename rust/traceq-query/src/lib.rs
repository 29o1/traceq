//! Product selected-state query boundary. No native Rust object is serialized
//! or exposed to C++; the shared core validates the entire capture before any
//! selected state is returned. The CLI owns argument and presentation policy.
#![deny(unsafe_op_in_unsafe_fn)]
mod agent;
pub mod cli;
pub use agent::native_main as agent_main;
mod context;
mod instructions;
mod memory;
use std::{
    ffi::{CStr, c_char},
    fs::File,
    io::BufReader,
    mem::{align_of, size_of},
    os::unix::ffi::OsStrExt,
    path::Path,
    ptr,
};
use traceq_core::{Result, replay, wire::Input};

#[repr(C)]
pub struct StateResult {
    pub abi_version: u64,
    pub header: [u64; 6],
    pub counts: [u64; 8],
    pub flags: u64,
    pub range_count: u64,
    pub ranges: [[u64; 2]; 64],
    pub pre: [[u64; 2]; 65],
    pub post: [[u64; 2]; 65],
    pub pre_known: [u64; 2],
    pub post_known: [u64; 2],
}
fn selected_state(path: &Path, at: u64) -> Result<StateResult> {
    let input = Input::new(BufReader::with_capacity(64 * 1024, File::open(path)?))?;
    let mut selected = None;
    let info = replay::read_selected(
        input,
        |seq| seq == at,
        |group, _| {
            selected = Some(group.clone());
        },
    )?;
    // Explicit ranges are bounded and validated by the core before callbacks.
    let mut result = StateResult {
        abi_version: 1,
        header: [
            info.header.code_base,
            info.header.code_size,
            info.header.data_base,
            info.header.data_size,
            info.header.thread_id,
            info.header.profile,
        ],
        counts: [
            info.instructions,
            info.reads,
            info.writes,
            info.gaps,
            info.commits,
            info.unknown_reads,
            info.exits,
            info.reentries,
        ],
        flags: u64::from(info.chunked)
            | (u64::from(info.boundary_capture) << 1)
            | (u64::from(info.external_followed) << 2)
            | (u64::from(info.unpositioned_gap) << 3),
        range_count: info.ranges.len() as u64,
        ranges: [[0; 2]; 64],
        pre: [[0; 2]; 65],
        post: [[0; 2]; 65],
        pre_known: [0; 2],
        post_known: [0; 2],
    };
    for (row, &(base, size)) in result.ranges.iter_mut().zip(&info.ranges) {
        *row = [base, size];
    }
    if let Some(group) = selected {
        result.flags |= 16 | (u64::from(group.committed) << 5);
        result.pre_known = group.pre.known;
        result.post_known = group.post.known;
        for (out, value) in result.pre.iter_mut().zip(group.pre.bits) {
            *out = [value as u64, (value >> 64) as u64];
        }
        for (out, value) in result.post.iter_mut().zip(group.post.bits) {
            *out = [value as u64, (value >> 64) as u64];
        }
    }
    Ok(result)
}

#[unsafe(no_mangle)]
pub extern "C" fn traceq_state_result_size() -> usize {
    size_of::<StateResult>()
}
/// # Safety
/// path is a live NUL-terminated filename. output points to a writable aligned
/// StateResult, and error points to error_capacity writable bytes (or is null
/// when capacity is0). All objects are disjoint and live throughout this call.
/// No pointer is retained. On failure output is unchanged; no provisional state
/// escapes when a later record, END or trailing-byte check fails.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn traceq_query_state(
    path: *const c_char,
    at: u64,
    output: *mut StateResult,
    output_size: usize,
    error: *mut u8,
    error_capacity: usize,
) -> i32 {
    if path.is_null()
        || output.is_null()
        || output_size != size_of::<StateResult>()
        || !(output as usize).is_multiple_of(align_of::<StateResult>())
        || (error.is_null() && error_capacity != 0)
    {
        return 2;
    }
    let filename = unsafe { CStr::from_ptr(path) };
    let path = Path::new(std::ffi::OsStr::from_bytes(filename.to_bytes()));
    match selected_state(path, at) {
        Ok(result) => {
            unsafe {
                ptr::write(output, result);
                if error_capacity > 0 {
                    *error = 0;
                }
            }
            0
        }
        Err(failure) => {
            let message = failure.message.as_bytes();
            let n = message.len().min(error_capacity.saturating_sub(1));
            if error_capacity > 0 {
                unsafe {
                    ptr::copy_nonoverlapping(message.as_ptr(), error, n);
                    *error.add(n) = 0;
                }
            }
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs::OpenOptions,
        io::Write,
        time::{SystemTime, UNIX_EPOCH},
    };
    pub(super) fn independent_fixture() -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "traceq-state-ffi-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        file.write_all(b"GTSW001\0").unwrap();
        for word in [0x1000u64, 4, 0x2000, 16, 7, 2, 64] {
            file.write_all(&word.to_le_bytes()).unwrap();
        }
        let text = b"add x0, x0, #1";
        let mut bytes = [0u8; 24];
        bytes[..text.len()].copy_from_slice(text);
        let records = [
            [
                8,
                0,
                0x1000,
                0x91000400,
                text.len() as u64,
                u64::from_le_bytes(bytes[..8].try_into().unwrap()),
                u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
                0,
            ],
            [1, 0, 0x1000, 0x91000400, 0, 0, 0, 1],
            [5, 0, 0x1000, 0, 8, 7, 0, 1],
            [5, 0, 0x1000, 64, 16, 0x123, 0xfedc, 1],
            [6, 0, 0x1000, 0, 8, 8, 0, 1],
            [9, 0, 0x1000, 0, 0, 0, 0, 1],
            [4, 1, 0, 0, 0, 0, 1, 2],
        ];
        for record in records {
            for word in record {
                file.write_all(&word.to_le_bytes()).unwrap();
            }
        }
        path
    }
    #[test]
    fn ffi_layout_values_and_no_provisional_state() {
        assert_eq!(size_of::<StateResult>(), 3272);
        assert_eq!(std::mem::offset_of!(StateResult, pre), 1160);
        let path = independent_fixture();
        let filename = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        // StateResult contains only integers, so every bit pattern is valid.
        let mut result: StateResult = unsafe { std::mem::zeroed() };
        let mut error = [0u8; 256];
        let status = unsafe {
            traceq_query_state(
                filename.as_ptr(),
                0,
                &mut result,
                size_of::<StateResult>(),
                error.as_mut_ptr(),
                error.len(),
            )
        };
        assert_eq!(status, 0);
        assert_eq!(result.abi_version, 1);
        assert_eq!(result.counts, [1, 0, 0, 0, 1, 0, 0, 0]);
        assert_eq!(result.flags, 16 | 32);
        assert_eq!(result.pre[0], [7, 0]);
        assert_eq!(result.post[0], [8, 0]);
        assert_eq!(result.post[64], [0x123, 0xfedc]);
        assert_eq!(result.pre_known, [1, 1]);
        assert_eq!(result.post_known, [1, 1]);
        result.abi_version = 999;
        let bad_size = unsafe {
            traceq_query_state(
                filename.as_ptr(),
                0,
                &mut result,
                size_of::<StateResult>() - 1,
                error.as_mut_ptr(),
                error.len(),
            )
        };
        assert_eq!(bad_size, 2);
        assert_eq!(result.abi_version, 999);
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(&[0x55])
            .unwrap();
        let failure = unsafe {
            traceq_query_state(
                filename.as_ptr(),
                0,
                &mut result,
                size_of::<StateResult>(),
                error.as_mut_ptr(),
                error.len(),
            )
        };
        assert_eq!(failure, 1);
        assert_eq!(result.abi_version, 999);
        assert!(
            std::str::from_utf8(&error)
                .unwrap()
                .contains("trailing bytes")
        );
        std::fs::remove_file(path).unwrap();
    }
}
