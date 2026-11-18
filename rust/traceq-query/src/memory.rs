//! Product byte-state ABI. No cells or summary are published before END and
//! the entire suffix validate. Native layouts are not trace wire formats.
use std::{
    ffi::{CStr, c_char},
    fs::File,
    io::BufReader,
    mem::{align_of, size_of},
    os::unix::ffi::OsStrExt,
    path::Path,
    ptr,
};
use traceq_core::{memory, wire::Input};

#[repr(C)]
pub struct Request {
    pub abi_version: u64,
    pub base: u64,
    pub length: u64,
    pub at: u64,
    pub phase: u64,
}
#[repr(C)]
pub struct Summary {
    pub abi_version: u64,
    pub header: [u64; 6],
    pub counts: [u64; 8],
    pub flags: u64,
    pub range_count: u64,
    pub ranges: [[u64; 2]; 64],
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct Cell {
    pub known: u64,
    pub value: u64,
    pub seq: u64,
    pub pc: u64,
}

#[repr(C)]
pub struct BatchRequest {
    pub abi_version: u64,
    pub base: u64,
    pub length: u64,
    pub offset: u64,
    pub limit: u64,
    pub count: u64,
    pub checkpoints: [[u64; 2]; 64],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CheckpointStatus {
    pub at: u64,
    pub phase: u64,
    pub pc: u64,
    pub flags: u64,
    pub gap_count: u64,
    pub gap_reasons: u64,
}

fn observed_cell(observation: Option<memory::Observation>) -> Cell {
    match observation {
        Some(o) => Cell {
            known: 1,
            value: u64::from(o.value),
            seq: o.seq,
            pc: o.pc,
        },
        None => Cell {
            known: 0,
            value: 0,
            seq: 0,
            pc: 0,
        },
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn traceq_memory_batch_layout(field: u32) -> usize {
    match field {
        0 => size_of::<BatchRequest>(),
        1 => size_of::<Summary>(),
        2 => size_of::<Cell>(),
        3 => size_of::<CheckpointStatus>(),
        _ => usize::MAX,
    }
}

/// # Safety
/// All pointers are live, disjoint, aligned native objects with the declared
/// sizes. path is NUL terminated. statuses has status_count entries; cells has
/// cell_count entries (and may be null only when cell_count is zero). The error
/// buffer may be null only with zero capacity. No pointer is retained; failure
/// leaves summary/statuses/cells untouched, including errors after all targets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn traceq_query_memory_batch(
    path: *const c_char,
    request: *const BatchRequest,
    request_size: usize,
    summary: *mut Summary,
    summary_size: usize,
    statuses: *mut CheckpointStatus,
    status_count: usize,
    cells: *mut Cell,
    cell_count: usize,
    error: *mut u8,
    error_capacity: usize,
) -> i32 {
    if path.is_null()
        || request.is_null()
        || summary.is_null()
        || statuses.is_null()
        || (cells.is_null() && cell_count != 0)
        || request_size != size_of::<BatchRequest>()
        || summary_size != size_of::<Summary>()
        || !(request as usize).is_multiple_of(align_of::<BatchRequest>())
        || !(summary as usize).is_multiple_of(align_of::<Summary>())
        || !(statuses as usize).is_multiple_of(align_of::<CheckpointStatus>())
        || !(cells as usize).is_multiple_of(align_of::<Cell>())
        || (error.is_null() && error_capacity != 0)
    {
        return 2;
    }
    let request = unsafe { &*request };
    if request.abi_version != 1
        || !(1..=4096).contains(&request.length)
        || !(1..=4096).contains(&request.limit)
        || !(1..=64).contains(&request.count)
        || request.base.checked_add(request.length).is_none()
        || status_count != request.count as usize
    {
        return 2;
    }
    let shown = request
        .limit
        .min(request.length.saturating_sub(request.offset));
    if shown * request.count > 4096 || cell_count != (shown * request.count) as usize {
        return 2;
    }
    let mut checkpoints = Vec::with_capacity(status_count);
    for &[at, phase] in request.checkpoints.iter().take(status_count) {
        if phase > 1 {
            return 2;
        }
        checkpoints.push(memory::Checkpoint {
            at,
            phase: if phase == 0 {
                memory::Phase::Pre
            } else {
                memory::Phase::Post
            },
        });
    }
    let filename = unsafe { CStr::from_ptr(path) };
    let path = Path::new(std::ffi::OsStr::from_bytes(filename.to_bytes()));
    let result = File::open(path)
        .map_err(traceq_core::Error::from)
        .and_then(|file| {
            memory::snapshots(
                Input::new(BufReader::with_capacity(64 * 1024, file))?,
                request.base,
                request.length as usize,
                &checkpoints,
                request.offset,
                request.limit as usize,
            )
        });
    match result {
        Ok(batch) => {
            let result = capture_summary(&batch.info, false, batch.range_valid);
            for (index, point) in batch.points.iter().enumerate() {
                let status = CheckpointStatus {
                    at: point.checkpoint.at,
                    phase: u64::from(point.checkpoint.phase == memory::Phase::Post),
                    pc: point.pc,
                    flags: u64::from(point.selected_event)
                        | (u64::from(point.committed) << 1)
                        | (u64::from(point.gap) << 2),
                    gap_count: point.gap_count,
                    gap_reasons: point.gap_reasons,
                };
                for (byte, observation) in point.cells.iter().enumerate() {
                    unsafe {
                        ptr::write(
                            cells.add(index * shown as usize + byte),
                            observed_cell(*observation),
                        );
                    }
                }
                unsafe {
                    ptr::write(statuses.add(index), status);
                }
            }
            unsafe {
                ptr::write(summary, result);
                if error_capacity > 0 {
                    *error = 0;
                }
            }
            0
        }
        Err(failure) => {
            let bytes = failure.message.as_bytes();
            let n = bytes.len().min(error_capacity.saturating_sub(1));
            if error_capacity > 0 {
                unsafe {
                    ptr::copy_nonoverlapping(bytes.as_ptr(), error, n);
                    *error.add(n) = 0;
                }
            }
            1
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn traceq_memory_layout(field: u32) -> usize {
    match field {
        0 => size_of::<Request>(),
        1 => size_of::<Summary>(),
        2 => size_of::<Cell>(),
        _ => usize::MAX,
    }
}

fn capture_summary(
    info: &traceq_core::replay::Info,
    selected_event: bool,
    range_valid: bool,
) -> Summary {
    let mut result = Summary {
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
            | (u64::from(info.unpositioned_gap) << 3)
            | (u64::from(selected_event) << 4)
            | (u64::from(range_valid) << 5),
        range_count: info.ranges.len() as u64,
        ranges: [[0; 2]; 64],
    };
    for (row, &(base, size)) in result.ranges.iter_mut().zip(&info.ranges) {
        *row = [base, size];
    }
    result
}

/// # Safety
/// path is a live NUL-terminated filename. Request, summary, cell buffer and
/// diagnostic buffer are disjoint, aligned and live for the call. Writable
/// buffers have the declared sizes. No pointer is retained; failure leaves
/// summary/cells untouched. error may be null only when capacity is zero.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn traceq_query_memory(
    path: *const c_char,
    request: *const Request,
    request_size: usize,
    summary: *mut Summary,
    summary_size: usize,
    cells: *mut Cell,
    cell_count: usize,
    error: *mut u8,
    error_capacity: usize,
) -> i32 {
    if path.is_null()
        || request.is_null()
        || summary.is_null()
        || cells.is_null()
        || request_size != size_of::<Request>()
        || summary_size != size_of::<Summary>()
        || !(request as usize).is_multiple_of(align_of::<Request>())
        || !(summary as usize).is_multiple_of(align_of::<Summary>())
        || !(cells as usize).is_multiple_of(align_of::<Cell>())
        || (error.is_null() && error_capacity != 0)
    {
        return 2;
    }
    let request = unsafe { &*request };
    if request.abi_version != 1
        || !(1..=4096).contains(&request.length)
        || request.phase > 1
        || request.base.checked_add(request.length).is_none()
        || cell_count != request.length as usize
    {
        return 2;
    }
    let filename = unsafe { CStr::from_ptr(path) };
    let path = Path::new(std::ffi::OsStr::from_bytes(filename.to_bytes()));
    let result = File::open(path)
        .map_err(traceq_core::Error::from)
        .and_then(|file| {
            let input = Input::new(BufReader::with_capacity(64 * 1024, file))?;
            memory::snapshot(
                input,
                request.base,
                request.length as usize,
                request.at,
                if request.phase == 0 {
                    memory::Phase::Pre
                } else {
                    memory::Phase::Post
                },
            )
        });
    match result {
        Ok(snapshot) => {
            let result = capture_summary(
                &snapshot.info,
                snapshot.selected_event,
                snapshot.range_valid,
            );
            // Core returned Ok. Publish each bounded cell and then its summary.
            for (index, observation) in snapshot.cells.iter().enumerate() {
                let cell = match observation {
                    Some(o) => Cell {
                        known: 1,
                        value: u64::from(o.value),
                        seq: o.seq,
                        pc: o.pc,
                    },
                    None => Cell {
                        known: 0,
                        value: 0,
                        seq: 0,
                        pc: 0,
                    },
                };
                unsafe {
                    ptr::write(cells.add(index), cell);
                }
            }
            unsafe {
                ptr::write(summary, result);
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
    use std::{ffi::CString, fs::OpenOptions, io::Write};

    #[test]
    fn batch_layout_wide_pages_and_no_publication_for_bad_requests_or_suffix() {
        assert_eq!(size_of::<BatchRequest>(), 1072);
        assert_eq!(std::mem::offset_of!(BatchRequest, checkpoints), 48);
        assert_eq!(size_of::<CheckpointStatus>(), 48);
        assert_eq!(std::mem::offset_of!(CheckpointStatus, gap_reasons), 40);
        let path = crate::tests::independent_fixture();
        let mut raw = std::fs::read(&path).unwrap();
        let access = [
            7u64,
            0,
            0x1000,
            0x2000,
            16,
            0x0807060504030201,
            0x100f0e0d0c0b0a09,
            1,
        ];
        raw.splice(
            64 + 5 * 64..64 + 5 * 64,
            access.into_iter().flat_map(u64::to_le_bytes),
        );
        raw[64 + 7 * 64 + 5 * 8..64 + 7 * 64 + 6 * 8].copy_from_slice(&1u64.to_le_bytes());
        std::fs::write(&path, raw).unwrap();
        let filename = CString::new(path.as_os_str().as_bytes()).unwrap();
        let mut request = BatchRequest {
            abi_version: 1,
            base: 0x2000,
            length: 16,
            offset: 7,
            limit: 3,
            count: 3,
            checkpoints: [[0; 2]; 64],
        };
        request.checkpoints[0] = [0, 1];
        request.checkpoints[1] = [0, 0];
        request.checkpoints[2] = [0, 1];
        let sentinel = Cell {
            known: 9,
            value: 8,
            seq: 7,
            pc: 6,
        };
        let status_sentinel = CheckpointStatus {
            at: 9,
            phase: 8,
            pc: 7,
            flags: 6,
            gap_count: 5,
            gap_reasons: 4,
        };
        let mut cells = [sentinel; 9];
        let mut statuses = [status_sentinel; 3];
        let mut summary = vec![0xabu64; size_of::<Summary>() / 8];
        let mut error = [0u8; 256];
        let invoke = |request: &BatchRequest,
                      cells: *mut Cell,
                      cell_count,
                      statuses: &mut [CheckpointStatus; 3],
                      summary: &mut Vec<u64>,
                      error: &mut [u8; 256]| unsafe {
            traceq_query_memory_batch(
                filename.as_ptr(),
                request,
                size_of::<BatchRequest>(),
                summary.as_mut_ptr().cast(),
                size_of::<Summary>(),
                statuses.as_mut_ptr(),
                3,
                cells,
                cell_count,
                error.as_mut_ptr(),
                error.len(),
            )
        };
        assert_eq!(
            invoke(
                &request,
                cells.as_mut_ptr(),
                9,
                &mut statuses,
                &mut summary,
                &mut error
            ),
            0
        );
        assert_eq!(
            statuses[0],
            CheckpointStatus {
                at: 0,
                phase: 1,
                pc: 0x1000,
                flags: 3,
                gap_count: 0,
                gap_reasons: 0
            }
        );
        assert_eq!(statuses[1].phase, 0);
        assert_eq!(statuses[2], statuses[0]);
        for i in [0, 1, 2, 6, 7, 8] {
            assert_eq!(
                cells[i],
                Cell {
                    known: 1,
                    value: 8 + (i % 3) as u64,
                    seq: 0,
                    pc: 0x1000
                }
            );
        }
        assert!(cells[3..6].iter().all(|c| c.known == 0));
        for (count, limit, phase) in [(0, 3, 1), (3, 3, 2), (64, 4096, 1)] {
            request.count = count;
            request.limit = limit;
            request.checkpoints[0][1] = phase;
            cells.fill(sentinel);
            statuses.fill(status_sentinel);
            summary.fill(0xab);
            assert_eq!(
                invoke(
                    &request,
                    cells.as_mut_ptr(),
                    9,
                    &mut statuses,
                    &mut summary,
                    &mut error
                ),
                2
            );
            assert_eq!(cells, [sentinel; 9]);
            assert_eq!(statuses, [status_sentinel; 3]);
            assert!(summary.iter().all(|v| *v == 0xab));
        }
        request.count = 3;
        request.limit = 3;
        request.checkpoints[0][1] = 1;
        request.offset = u64::MAX;
        assert_eq!(
            invoke(
                &request,
                ptr::null_mut(),
                0,
                &mut statuses,
                &mut summary,
                &mut error
            ),
            0
        );
        assert_eq!(statuses[0].flags, 3);
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"x")
            .unwrap();
        for offset in [7, u64::MAX] {
            request.offset = offset;
            cells.fill(sentinel);
            statuses.fill(status_sentinel);
            summary.fill(0xab);
            assert_eq!(
                invoke(
                    &request,
                    if offset == 7 {
                        cells.as_mut_ptr()
                    } else {
                        ptr::null_mut()
                    },
                    if offset == 7 { 9 } else { 0 },
                    &mut statuses,
                    &mut summary,
                    &mut error
                ),
                1
            );
            assert_eq!(cells, [sentinel; 9]);
            assert_eq!(statuses, [status_sentinel; 3]);
            assert!(summary.iter().all(|v| *v == 0xab));
        }
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn layout_and_no_partial_publication_after_bad_tail() {
        assert_eq!(
            (
                size_of::<Request>(),
                size_of::<Summary>(),
                size_of::<Cell>()
            ),
            (40, 1160, 32)
        );
        assert_eq!(std::mem::offset_of!(Summary, ranges), 136);
        assert_eq!(std::mem::offset_of!(Cell, pc), 24);
        let path = crate::tests::independent_fixture();
        let filename = CString::new(path.as_os_str().as_bytes()).unwrap();
        let request = Request {
            abi_version: 1,
            base: 0x2000,
            length: 16,
            at: 0,
            phase: 1,
        };
        let sentinel = Cell {
            known: 9,
            value: 8,
            seq: 7,
            pc: 6,
        };
        let mut cells = [sentinel; 16];
        let mut summary = std::mem::MaybeUninit::<Summary>::uninit();
        let mut error = [0u8; 256];
        let invoke = |cells: &mut [Cell; 16],
                      summary: &mut std::mem::MaybeUninit<Summary>,
                      error: &mut [u8; 256]| unsafe {
            traceq_query_memory(
                filename.as_ptr(),
                &request,
                size_of::<Request>(),
                summary.as_mut_ptr(),
                size_of::<Summary>(),
                cells.as_mut_ptr(),
                cells.len(),
                error.as_mut_ptr(),
                error.len(),
            )
        };
        assert_eq!(invoke(&mut cells, &mut summary, &mut error), 0);
        assert!(cells.iter().all(|c| c.known == 0));
        let summary = unsafe { summary.assume_init() };
        assert_eq!(summary.flags & 48, 48);
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"x")
            .unwrap();
        let mut summary_bytes = vec![0xabu64; size_of::<Summary>() / 8];
        let mut cells = [sentinel; 16];
        let status = unsafe {
            traceq_query_memory(
                filename.as_ptr(),
                &request,
                size_of::<Request>(),
                summary_bytes.as_mut_ptr().cast(),
                size_of::<Summary>(),
                cells.as_mut_ptr(),
                cells.len(),
                error.as_mut_ptr(),
                error.len(),
            )
        };
        assert_eq!(status, 1);
        assert!(summary_bytes.iter().all(|b| *b == 0xab));
        assert_eq!(cells, [sentinel; 16]);
        assert!(error[0] != 0);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn full_sixteen_byte_observation_crosses_abi_and_bad_request_does_not_publish() {
        let path = crate::tests::independent_fixture();
        let mut raw = std::fs::read(&path).unwrap();
        let access = [
            7u64,
            0,
            0x1000,
            0x2000,
            16,
            0x0807060504030201,
            0x100f0e0d0c0b0a09,
            1,
        ];
        let access: Vec<u8> = access.into_iter().flat_map(u64::to_le_bytes).collect();
        raw.splice(64 + 5 * 64..64 + 5 * 64, access);
        raw[64 + 7 * 64 + 5 * 8..64 + 7 * 64 + 6 * 8].copy_from_slice(&1u64.to_le_bytes());
        std::fs::write(&path, raw).unwrap();
        let filename = CString::new(path.as_os_str().as_bytes()).unwrap();
        let request = Request {
            abi_version: 1,
            base: 0x2000,
            length: 16,
            at: 0,
            phase: 1,
        };
        let sentinel = Cell {
            known: 9,
            value: 8,
            seq: 7,
            pc: 6,
        };
        let mut cells = [sentinel; 16];
        let mut summary = std::mem::MaybeUninit::<Summary>::uninit();
        let status = unsafe {
            traceq_query_memory(
                filename.as_ptr(),
                &request,
                size_of::<Request>(),
                summary.as_mut_ptr(),
                size_of::<Summary>(),
                cells.as_mut_ptr(),
                16,
                ptr::null_mut(),
                0,
            )
        };
        assert_eq!(status, 0);
        for (index, cell) in cells.iter().enumerate() {
            assert_eq!(
                *cell,
                Cell {
                    known: 1,
                    value: index as u64 + 1,
                    seq: 0,
                    pc: 0x1000
                }
            );
        }
        let mut cells = [sentinel; 16];
        let mut summary_bytes = vec![0xabu64; size_of::<Summary>() / 8];
        for (length, phase, count) in [(0, 1, 16), (16, 2, 16), (16, 1, 15)] {
            let bad = Request {
                abi_version: 1,
                base: 0x2000,
                length,
                at: 0,
                phase,
            };
            let status = unsafe {
                traceq_query_memory(
                    filename.as_ptr(),
                    &bad,
                    size_of::<Request>(),
                    summary_bytes.as_mut_ptr().cast(),
                    size_of::<Summary>(),
                    cells.as_mut_ptr(),
                    count,
                    ptr::null_mut(),
                    0,
                )
            };
            assert_eq!(status, 2);
            assert_eq!(cells, [sentinel; 16]);
            assert!(summary_bytes.iter().all(|b| *b == 0xab));
        }
        std::fs::remove_file(path).unwrap();
    }
}
