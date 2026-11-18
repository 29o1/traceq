//! Bounded context ABI. Row callbacks are provisional: the CLI stages them and
//! publishes only after the complete stream, END and suffix have validated.
use std::{
    cell::Cell,
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
    pub window_count: u64,
    pub offset: u64,
    pub limit: u64,
    pub windows: [[u64; 2]; 64],
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
#[repr(C)]
pub struct Row {
    pub seq: u64,
    pub pc: u64,
    pub word: u64,
    pub flags: u64,
    pub target: u64,
    pub transfer: u64,
    pub expected_return: u64,
    pub exit_seq: u64,
    pub gap_count: u64,
    pub gap_reason_mask: u64,
    pub pre: [[u64; 2]; 65],
    pub post: [[u64; 2]; 65],
    pub pre_known: [u64; 2],
    pub post_known: [u64; 2],
    pub pre_observed: [u64; 2],
    pub post_observed: [u64; 2],
    pub access_count: u64,
    pub accesses: [[u64; 8]; 4],
}
#[repr(C)]
pub struct Sink {
    pub user: *mut c_void,
    pub row: Option<extern "C" fn(*mut c_void, *const Row) -> i32>,
    pub site: Option<extern "C" fn(*mut c_void, u64, *const u8, usize) -> i32>,
    pub module: Option<extern "C" fn(*mut c_void, u64, u64, *const u8, usize) -> i32>,
}

#[unsafe(no_mangle)]
pub extern "C" fn traceq_context_layout(field: u32) -> usize {
    match field {
        0 => size_of::<Request>(),
        1 => size_of::<Summary>(),
        2 => size_of::<Row>(),
        3 => size_of::<Sink>(),
        _ => usize::MAX,
    }
}
fn row(g: &replay::Group) -> Row {
    let mut r = Row {
        seq: g.seq,
        pc: g.pc,
        word: g.word,
        flags: u64::from(g.committed) | (u64::from(g.gap) << 1) | (u64::from(g.reentered) << 2),
        target: g.exit.target,
        transfer: g.exit.transfer,
        expected_return: g.exit.expected_return,
        exit_seq: g.exit_seq,
        gap_count: g.gap_count,
        gap_reason_mask: g.gap_reason_mask,
        pre: g.pre.bits.map(|v| [v as u64, (v >> 64) as u64]),
        post: g.post.bits.map(|v| [v as u64, (v >> 64) as u64]),
        pre_known: g.pre.known,
        post_known: g.post.known,
        pre_observed: g.pre_observed,
        post_observed: g.post_observed,
        access_count: g.accesses.len() as u64,
        accesses: [[0; 8]; 4],
    };
    for (dst, event) in r.accesses.iter_mut().zip(&g.accesses) {
        *dst = event.words();
    }
    r
}
fn query(path: &Path, request: &Request, sink: &Sink) -> Result<Summary> {
    let windows = &request.windows[..request.window_count as usize];
    let mut window = 0;
    let total = Cell::new(0u64);
    let shown = Cell::new(0u64);
    let mut failed = false;
    let mut sites = BTreeSet::new();
    let input = Input::new(BufReader::with_capacity(64 * 1024, File::open(path)?))?;
    let info = replay::read_selected(
        input,
        |seq| {
            while window < windows.len() && seq > windows[window][1] {
                window += 1;
            }
            if window == windows.len() || seq < windows[window][0] {
                return false;
            }
            let n = total.get();
            total.set(n + 1);
            let capture = n >= request.offset && shown.get() < request.limit;
            if capture {
                shown.set(shown.get() + 1);
            }
            capture
        },
        |group, _| {
            if !failed {
                let result = row(group);
                failed = (sink.row.unwrap())(sink.user, &result) != 0;
                sites.insert(group.pc);
            }
        },
    )?;
    if failed {
        return Err(Error::trace("context row callback failed"));
    }
    // Metadata can be extended after a selected row. Transfer the final text
    // only after validation, preserving the established context presentation.
    for pc in sites {
        let text = &info.sites[&pc].text;
        if (sink.site.unwrap())(sink.user, pc, text.as_ptr(), text.len()) != 0 {
            return Err(Error::trace("context site callback failed"));
        }
    }
    for base in &info.module_order {
        let module = &info.modules[base];
        if (sink.module.unwrap())(
            sink.user,
            *base,
            module.size,
            module.name.as_ptr(),
            module.name.len(),
        ) != 0
        {
            return Err(Error::trace("context module callback failed"));
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
        total: total.get(),
        shown: shown.get(),
    })
}
fn aligned<T>(p: *const T) -> bool {
    !p.is_null() && (p as usize).is_multiple_of(align_of::<T>())
}
/// # Safety
/// All pointers refer to live, disjoint objects of their checked C ABI types;
/// filename is NUL-terminated, error holds error_capacity bytes (or null/zero).
/// The caller checks traceq_context_layout before allocating output and Sink.
/// Callbacks must not unwind or retain borrowed row/text pointers. They stage
/// provisional results; no row is evidence of success until this returns0.
/// Output is unchanged on failure. No pointer is retained after the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn traceq_query_context(
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
        || !(1..=64).contains(&request.window_count)
        || !(1..=4096).contains(&request.limit)
        || sink.row.is_none()
        || sink.site.is_none()
        || sink.module.is_none()
    {
        return 2;
    }
    let windows = &request.windows[..request.window_count as usize];
    if windows.iter().any(|r| r[0] > r[1]) || windows.windows(2).any(|r| r[0][1] >= r[1][0]) {
        return 2;
    }
    let filename = unsafe { CStr::from_ptr(path) };
    let path = Path::new(std::ffi::OsStr::from_bytes(filename.to_bytes()));
    match query(path, request, sink) {
        Ok(result) => {
            unsafe {
                ptr::write(output, result);
                if error_capacity != 0 {
                    *error = 0;
                }
            }
            0
        }
        Err(failure) => {
            if error_capacity != 0 {
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
    use std::io::Write;
    #[derive(Default)]
    struct Observed {
        rows: Vec<[u64; 5]>,
        site: Vec<u8>,
        reject: bool,
    }
    extern "C" fn collect(user: *mut c_void, row: *const Row) -> i32 {
        let observed = unsafe { &mut *user.cast::<Observed>() };
        if observed.reject {
            return 1;
        }
        let row = unsafe { &*row };
        observed.rows.push([
            row.seq,
            row.pre[0][0],
            row.post[0][0],
            row.post[64][1],
            row.pre_known[1],
        ]);
        0
    }
    extern "C" fn site(user: *mut c_void, _: u64, text: *const u8, len: usize) -> i32 {
        let observed = unsafe { &mut *user.cast::<Observed>() };
        observed.site = unsafe { std::slice::from_raw_parts(text, len) }.to_vec();
        0
    }
    extern "C" fn module(_: *mut c_void, _: u64, _: u64, _: *const u8, _: usize) -> i32 {
        0
    }
    #[test]
    fn layout_full_width_and_failure_never_publish_summary() {
        assert_eq!(
            (
                size_of::<Request>(),
                size_of::<Summary>(),
                size_of::<Row>(),
                std::mem::offset_of!(Row, pre)
            ),
            (1056, 1176, 2488, 80)
        );
        let path = crate::tests::independent_fixture();
        let filename = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        let mut request = Request {
            abi_version: 1,
            window_count: 1,
            offset: 0,
            limit: 1,
            windows: [[0; 2]; 64],
        };
        let mut observed = Observed::default();
        let sink = Sink {
            user: (&mut observed as *mut Observed).cast(),
            row: Some(collect),
            site: Some(site),
            module: Some(module),
        };
        let mut summary: Summary = unsafe { std::mem::zeroed() };
        let mut diagnostic = [0u8; 256];
        let invoke = |request: &Request, summary: &mut Summary| unsafe {
            traceq_query_context(
                filename.as_ptr(),
                request,
                size_of::<Request>(),
                summary,
                &sink,
                diagnostic.as_mut_ptr(),
                diagnostic.len(),
            )
        };
        let mut invoke = invoke;
        assert_eq!(invoke(&request, &mut summary), 0);
        assert_eq!(observed.rows, [[0, 7, 8, 0xfedc, 1]]);
        assert_eq!(observed.site, b"add x0, x0, #1");
        assert_eq!((summary.total, summary.shown), (1, 1));
        summary.abi_version = 999;
        observed.reject = true;
        assert_eq!(invoke(&request, &mut summary), 1);
        assert_eq!(summary.abi_version, 999);
        observed.reject = false;
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(&[0x55])
            .unwrap();
        assert_eq!(invoke(&request, &mut summary), 1);
        assert_eq!(summary.abi_version, 999);
        request.offset = 999;
        assert_eq!(invoke(&request, &mut summary), 1);
        assert_eq!(summary.abi_version, 999);
        request.window_count = 65;
        assert_eq!(invoke(&request, &mut summary), 2);
        assert_eq!(summary.abi_version, 999);
        std::fs::remove_file(path).unwrap();
    }
}
