//! Bounded instruction pages from validated evidence-only replay. Row callbacks
//! are provisional; site text is transferred after END/suffix validation.
use std::{
    collections::BTreeSet,
    ffi::{CStr, c_char, c_void},
    fs::File,
    io::BufReader,
    mem::{align_of, size_of},
    os::unix::ffi::OsStrExt,
    path::Path,
    ptr,
};
use traceq_core::{Error, Result, replay, wire::Input};

#[repr(C)]
pub struct Request {
    pub abi_version: u64,
    pub from: u64,
    pub to: u64,
    pub offset: u64,
    pub limit: u64,
    pub gaps_only: u64,
}
#[repr(C)]
pub struct Summary {
    pub abi_version: u64,
    pub header: [u64; 6],
    pub counts: [u64; 8],
    pub flags: u64,
    pub range_count: u64,
    pub ranges: [[u64; 2]; 64],
    pub total: u64,
    pub shown: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct Row {
    pub seq: u64,
    pub pc: u64,
    pub word: u64,
    pub flags: u64,
}
#[repr(C)]
pub struct Sink {
    pub user: *mut c_void,
    pub row: Option<extern "C" fn(*mut c_void, *const Row) -> i32>,
    pub site: Option<extern "C" fn(*mut c_void, u64, *const u8, usize) -> i32>,
}
#[unsafe(no_mangle)]
pub extern "C" fn traceq_instructions_layout(field: u32) -> usize {
    match field {
        0 => size_of::<Request>(),
        1 => size_of::<Summary>(),
        2 => size_of::<Row>(),
        3 => size_of::<Sink>(),
        _ => usize::MAX,
    }
}
fn query(path: &Path, request: &Request, sink: &Sink) -> Result<Summary> {
    let input = Input::new(BufReader::with_capacity(64 * 1024, File::open(path)?))?;
    let (mut total, mut shown, mut failed) = (0u64, 0u64, false);
    let mut sites = BTreeSet::new();
    let info = replay::read_evidence(input, |g, _| {
        if g.seq < request.from || g.seq > request.to || (request.gaps_only != 0 && !g.gap) {
            return;
        }
        let n = total;
        total += 1;
        if n < request.offset || shown >= request.limit {
            return;
        }
        shown += 1;
        if !failed {
            let row = Row {
                seq: g.seq,
                pc: g.pc,
                word: g.word,
                flags: u64::from(g.committed) | (u64::from(g.gap) << 1),
            };
            failed = (sink.row.unwrap())(sink.user, &row) != 0;
            sites.insert(g.pc);
        }
    })?;
    if failed {
        return Err(Error::trace("instruction row callback failed"));
    }
    for pc in sites {
        let text = &info.sites[&pc].text;
        if (sink.site.unwrap())(sink.user, pc, text.as_ptr(), text.len()) != 0 {
            return Err(Error::trace("instruction site callback failed"));
        }
    }
    let mut ranges = [[0; 2]; 64];
    for (out, &(base, size)) in ranges.iter_mut().zip(&info.ranges) {
        *out = [base, size];
    }
    Ok(Summary {
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
        ranges,
        total,
        shown,
    })
}
fn aligned<T>(p: *const T) -> bool {
    !p.is_null() && (p as usize).is_multiple_of(align_of::<T>())
}
/// # Safety
/// Live, disjoint checked request/output/sink objects, NUL-terminated path and
/// writable error_capacity bytes (or null/zero). Callbacks must not unwind or
/// retain borrowed pointers. Rows are staged until this returns0; summary is
/// untouched on failure. No pointer is retained after this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn traceq_query_instructions(
    path: *const c_char,
    request: *const Request,
    request_size: usize,
    output: *mut Summary,
    sink: *const Sink,
    error: *mut u8,
    error_capacity: usize,
) -> i32 {
    if path.is_null()
        || !aligned(request)
        || request_size != size_of::<Request>()
        || !aligned(output)
        || !aligned(sink)
        || (error.is_null() && error_capacity != 0)
    {
        return 2;
    }
    let request = unsafe { &*request };
    let sink = unsafe { &*sink };
    if request.abi_version != 1
        || request.from > request.to
        || !(1..=4096).contains(&request.limit)
        || request.gaps_only > 1
        || sink.row.is_none()
        || sink.site.is_none()
    {
        return 2;
    }
    let filename = unsafe { CStr::from_ptr(path) };
    let path = Path::new(std::ffi::OsStr::from_bytes(filename.to_bytes()));
    match query(path, request, sink) {
        Ok(summary) => {
            unsafe {
                ptr::write(output, summary);
                if error_capacity > 0 {
                    *error = 0;
                }
            };
            0
        }
        Err(failure) => {
            if error_capacity > 0 {
                let n = failure.message.len().min(error_capacity - 1);
                unsafe {
                    ptr::copy_nonoverlapping(failure.message.as_ptr(), error, n);
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
    use std::{ffi::CString, fs::OpenOptions, io::Write};
    #[derive(Default)]
    struct Observed {
        rows: Vec<Row>,
        texts: Vec<Vec<u8>>,
        reject: bool,
    }
    extern "C" fn row(user: *mut c_void, row: *const Row) -> i32 {
        let seen = unsafe { &mut *user.cast::<Observed>() };
        if seen.reject {
            return 1;
        }
        seen.rows.push(unsafe { *row });
        0
    }
    extern "C" fn site(user: *mut c_void, _pc: u64, bytes: *const u8, len: usize) -> i32 {
        unsafe { &mut *user.cast::<Observed>() }
            .texts
            .push(unsafe { std::slice::from_raw_parts(bytes, len) }.to_vec());
        0
    }
    #[test]
    fn final_metadata_layout_page_and_no_summary_after_failure() {
        assert_eq!(
            (
                size_of::<Request>(),
                size_of::<Summary>(),
                size_of::<Row>(),
                size_of::<Sink>()
            ),
            (48, 1176, 32, 24)
        );
        assert_eq!(std::mem::offset_of!(Summary, total), 1160);
        let path = crate::tests::independent_fixture();
        let mut raw = std::fs::read(&path).unwrap();
        raw.truncate(raw.len() - 64);
        let suffix = b" ; final";
        for record in [
            [1, 1, 0x1000, 0x91000400, 0, 0, 0, 0],
            [
                8,
                14,
                0x1000,
                0x91000400,
                8,
                u64::from_le_bytes(*suffix),
                0,
                0,
            ],
            [4, 2, 0, 0, 0, 0, 1, 2],
        ] {
            for word in record {
                raw.extend(word.to_le_bytes());
            }
        }
        std::fs::write(&path, raw).unwrap();
        let filename = CString::new(path.as_os_str().as_bytes()).unwrap();
        let request = Request {
            abi_version: 1,
            from: 0,
            to: u64::MAX,
            offset: 0,
            limit: 1,
            gaps_only: 0,
        };
        let mut seen = Observed::default();
        let sink = Sink {
            user: (&mut seen as *mut Observed).cast(),
            row: Some(row),
            site: Some(site),
        };
        let mut summary = std::mem::MaybeUninit::<Summary>::uninit();
        let mut error = [0u8; 256];
        let result = unsafe {
            traceq_query_instructions(
                filename.as_ptr(),
                &request,
                size_of::<Request>(),
                summary.as_mut_ptr(),
                &sink,
                error.as_mut_ptr(),
                error.len(),
            )
        };
        assert_eq!(result, 0);
        let summary = unsafe { summary.assume_init() };
        assert_eq!((summary.total, summary.shown), (2, 1));
        assert_eq!(
            seen.rows,
            [Row {
                seq: 0,
                pc: 0x1000,
                word: 0x91000400,
                flags: 1
            }]
        );
        assert_eq!(seen.texts, [b"add x0, x0, #1 ; final".to_vec()]);
        // A callback rejection cannot publish even after successful parsing.
        seen.reject = true;
        let mut summary = vec![0xabu64; size_of::<Summary>() / 8];
        let result = unsafe {
            traceq_query_instructions(
                filename.as_ptr(),
                &request,
                size_of::<Request>(),
                summary.as_mut_ptr().cast(),
                &sink,
                error.as_mut_ptr(),
                error.len(),
            )
        };
        assert_eq!(result, 1);
        assert!(summary.iter().all(|word| *word == 0xab));
        seen.reject = false;
        seen.texts.clear();
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"x")
            .unwrap();
        let result = unsafe {
            traceq_query_instructions(
                filename.as_ptr(),
                &request,
                size_of::<Request>(),
                summary.as_mut_ptr().cast(),
                &sink,
                error.as_mut_ptr(),
                error.len(),
            )
        };
        assert_eq!(result, 1);
        assert!(seen.texts.is_empty());
        assert!(summary.iter().all(|word| *word == 0xab));
        std::fs::remove_file(path).unwrap();
    }
}
