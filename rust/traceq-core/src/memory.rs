//! Bounded byte snapshots from actual memory observations. Unknown evidence
//! never supplies a value, and callbacks cannot publish before full validation.
use crate::{Error, Result, replay, wire::Input};
use std::io::Read;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Pre,
    Post,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Observation {
    pub value: u8,
    pub seq: u64,
    pub pc: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    pub at: u64,
    pub phase: Phase,
}

pub struct CheckpointSnapshot {
    pub checkpoint: Checkpoint,
    pub cells: Vec<Option<Observation>>,
    pub selected_event: bool,
    pub pc: u64,
    pub committed: bool,
    pub gap: bool,
    pub gap_count: u64,
    pub gap_reasons: u64,
}

pub struct BatchSnapshot {
    pub info: replay::Info,
    pub points: Vec<CheckpointSnapshot>,
    pub range_valid: bool,
}

fn observe(cells: &mut [Option<Observation>], base: u64, g: &replay::EvidenceGroup<'_>) {
    if g.gap {
        cells.fill(None);
    }
    let end = base + cells.len() as u64;
    for access in g.accesses {
        let first = base.max(access.address);
        let last = end.min(access.address + access.size);
        for address in first..last {
            let lane = (address - access.address) as u32;
            let value = if lane < 8 {
                access.low >> (lane * 8)
            } else {
                access.high >> ((lane - 8) * 8)
            };
            cells[(address - base) as usize] = (access.detail == 1).then_some(Observation {
                value: value as u8,
                seq: g.seq,
                pc: g.pc,
            });
        }
    }
}

fn capture(
    point: &mut CheckpointSnapshot,
    cells: &[Option<Observation>],
    g: &replay::EvidenceGroup<'_>,
) {
    point.selected_event = true;
    point.pc = g.pc;
    point.committed = g.committed;
    point.gap = g.gap;
    point.gap_count = g.gap_count;
    point.gap_reasons = g.gap_reason_mask;
    if point.checkpoint.phase == Phase::Pre || g.committed {
        point.cells.copy_from_slice(cells);
    }
    // An unobserved post snapshot is unknown, but does not erase the running
    // history used by later checkpoints. Only actual gaps/observations do that.
}

/// One full validation pass, one running byte state, bounded selected pages.
/// Request order and duplicates are retained; execution order is internal.
pub fn snapshots<R: Read>(
    input: Input<R>,
    base: u64,
    len: usize,
    checkpoints: &[Checkpoint],
    offset: u64,
    limit: usize,
) -> Result<BatchSnapshot> {
    if !(1..=4096).contains(&len)
        || base.checked_add(len as u64).is_none()
        || !(1..=64).contains(&checkpoints.len())
        || !(1..=4096).contains(&limit)
    {
        return Err(Error::trace("invalid memory checkpoint bounds"));
    }
    let first = offset.min(len as u64) as usize;
    let shown = limit.min(len - first);
    if shown * checkpoints.len() > 4096 {
        return Err(Error::trace(
            "memory checkpoint page exceeds 4096 byte cells",
        ));
    }
    let mut range_valid = input.header.contains_data(base, len as u64);
    let mut points: Vec<_> = checkpoints
        .iter()
        .map(|&checkpoint| CheckpointSnapshot {
            checkpoint,
            cells: vec![None; shown],
            selected_event: false,
            pc: 0,
            committed: false,
            gap: false,
            gap_count: 0,
            gap_reasons: 0,
        })
        .collect();
    let mut order: Vec<_> = (0..checkpoints.len()).collect();
    order.sort_by_key(|&i| (checkpoints[i].at, checkpoints[i].phase == Phase::Post, i));
    let last = checkpoints[*order.last().unwrap()].at;
    let mut next = 0;
    let mut cells = vec![None; shown];
    let page_base = base + first as u64;
    let info = replay::read_evidence(input, |g, _| {
        while next < order.len()
            && checkpoints[order[next]].at == g.seq
            && checkpoints[order[next]].phase == Phase::Pre
        {
            capture(&mut points[order[next]], &cells, &g);
            next += 1;
        }
        if range_valid && shown != 0 && g.seq <= last {
            observe(&mut cells, page_base, &g);
        }
        while next < order.len() && checkpoints[order[next]].at == g.seq {
            capture(&mut points[order[next]], &cells, &g);
            next += 1;
        }
    })?;
    if info.unpositioned_gap {
        for point in &mut points {
            point.cells.fill(None);
        }
    }
    if info.instructions == 0 {
        range_valid = true;
    }
    Ok(BatchSnapshot {
        info,
        points,
        range_valid,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn bytes(records: &[[u64; 8]]) -> Vec<u8> {
        let mut bytes = b"GTSW001\0".to_vec();
        for word in [0x1000u64, 4, 0x2000, 32, 7, 2, 64] {
            bytes.extend(word.to_le_bytes());
        }
        // One independent, literal site; execution order can revisit it.
        let mut text = [0u8; 24];
        text[..3].copy_from_slice(b"nop");
        let site = [
            8,
            0,
            0x1000,
            0xd503201f,
            3,
            u64::from_le_bytes(text[..8].try_into().unwrap()),
            0,
            0,
        ];
        for record in std::iter::once(&site).chain(records.iter()) {
            for word in record {
                bytes.extend(word.to_le_bytes());
            }
        }
        bytes
    }
    fn run(records: &[[u64; 8]], at: u64, phase: Phase) -> CheckpointSnapshot {
        snapshots(
            Input::new(Cursor::new(bytes(records))).unwrap(),
            0x2001,
            16,
            &[Checkpoint { at, phase }],
            0,
            16,
        )
        .unwrap()
        .points
        .pop()
        .unwrap()
    }
    fn observations() -> Vec<[u64; 8]> {
        vec![
            [1, 0, 0x1000, 0xd503201f, 0, 0, 0, 1],
            [
                7,
                0,
                0x1000,
                0x2000,
                16,
                0x0807060504030201,
                0x100f0e0d0c0b0a09,
                1,
            ],
            [9, 0, 0x1000, 0, 0, 0, 0, 1],
            [1, 1, 0x1000, 0xd503201f, 0, 0, 0, 1],
            [2, 1, 0x1000, 0x2007, 2, 0xbbaa, 0, 1],
            [7, 1, 0x1000, 0x2001, 1, 0, 0, 0],
            [9, 1, 0x1000, 0, 0, 0, 0, 1],
            [1, 2, 0x1000, 0xd503201f, 0, 0, 0, 0],
            [3, 2, 0x1000, 0, 0, 0, 0, 1],
            [1, 3, 0x1000, 0xd503201f, 0, 0, 0, 1],
            [7, 3, 0x1000, 0x200f, 1, 0xcc, 0, 1],
            [9, 3, 0x1000, 0, 0, 0, 0, 1],
            [4, 4, 0, 1, 1, 3, 3, 2],
        ]
    }
    #[test]
    fn lanes_pre_post_unknown_reads_gaps_and_sources() {
        let records = observations();
        let pre = run(&records, 0, Phase::Pre);
        assert!(pre.cells.iter().all(Option::is_none));
        let first = run(&records, 0, Phase::Post);
        let expected: Vec<_> = (2..=16).map(Some).chain([None]).collect();
        assert_eq!(
            first
                .cells
                .iter()
                .map(|c| c.map(|o| o.value))
                .collect::<Vec<_>>(),
            expected
        );
        assert_eq!(
            first.cells[8],
            Some(Observation {
                value: 10,
                seq: 0,
                pc: 0x1000
            })
        );
        let second = run(&records, 1, Phase::Post);
        assert_eq!(second.cells[0], None);
        assert_eq!(second.cells[6].unwrap().value, 0xaa);
        assert_eq!(
            second.cells[7],
            Some(Observation {
                value: 0xbb,
                seq: 1,
                pc: 0x1000
            })
        );
        assert_eq!(run(&records, 2, Phase::Pre).cells, second.cells);
        assert!(
            run(&records, 2, Phase::Post)
                .cells
                .iter()
                .all(Option::is_none)
        );
        let after = run(&records, 3, Phase::Post);
        assert_eq!(after.cells.iter().flatten().count(), 1);
        assert_eq!(after.cells[14].unwrap().value, 0xcc);
        // A later positioned gap does not invalidate an earlier cutoff.
        assert_eq!(run(&records, 0, Phase::Post).cells, first.cells);
    }
    #[test]
    fn global_gap_and_unobserved_completion_never_supply_bytes() {
        let mut records = observations();
        records.insert(records.len() - 1, [3, 4, 0, 0, 0, 0, 0, 4]);
        records.last_mut().unwrap()[4] = 2;
        assert!(
            run(&records, 0, Phase::Post)
                .cells
                .iter()
                .all(Option::is_none)
        );
        let records = [
            [1, 0, 0x1000, 0xd503201f, 0, 0, 0, 1],
            [2, 0, 0x1000, 0x2001, 1, 0xab, 0, 1],
            [9, 0, 0x1000, 0, 0, 0, 0, 1],
            [1, 1, 0x1000, 0xd503201f, 0, 0, 0, 0],
            [4, 2, 0, 1, 0, 0, 1, 2],
        ];
        assert!(run(&records, 1, Phase::Pre).cells[0].is_some());
        assert!(
            run(&records, 1, Phase::Post)
                .cells
                .iter()
                .all(Option::is_none)
        );
    }
    #[test]
    fn suffix_and_unselected_register_damage_still_fail() {
        let records = observations();
        let mut raw = bytes(&records);
        raw.push(0);
        assert!(
            snapshots(
                Input::new(Cursor::new(raw)).unwrap(),
                0x2001,
                1,
                &[Checkpoint {
                    at: 0,
                    phase: Phase::Post
                }],
                0,
                1,
            )
            .is_err()
        );
        let mut records = observations();
        records.insert(11, [5, 3, 0x1000, 65, 8, 7, 0, 1]);
        assert!(
            snapshots(
                Input::new(Cursor::new(bytes(&records))).unwrap(),
                0x2001,
                1,
                &[Checkpoint {
                    at: 0,
                    phase: Phase::Post
                }],
                0,
                1,
            )
            .is_err()
        );
    }

    #[test]
    fn checkpoint_pages_keep_request_order_and_consume_one_stream() {
        use std::{cell::Cell, rc::Rc};
        struct Counted {
            cursor: Cursor<Vec<u8>>,
            count: Rc<Cell<usize>>,
        }
        impl Read for Counted {
            fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
                let n = self.cursor.read(out)?;
                self.count.set(self.count.get() + n);
                Ok(n)
            }
        }
        let records = observations();
        let checkpoints: Vec<_> = [
            (3, Phase::Post),
            (0, Phase::Pre),
            (0, Phase::Post),
            (2, Phase::Pre),
            (2, Phase::Post),
            (3, Phase::Pre),
            (0, Phase::Post),
        ]
        .into_iter()
        .map(|(at, phase)| Checkpoint { at, phase })
        .collect();
        let raw = bytes(&records);
        let length = raw.len();
        let count = Rc::new(Cell::new(0));
        let input = Input::new(Counted {
            cursor: Cursor::new(raw),
            count: count.clone(),
        })
        .unwrap();
        let batch = snapshots(input, 0x2001, 16, &checkpoints, 1, 3).unwrap();
        assert_eq!(count.get(), length);
        for (point, checkpoint) in batch.points.iter().zip(checkpoints) {
            assert_eq!(point.checkpoint, checkpoint);
            assert!(point.selected_event);
            assert_eq!(
                point.cells,
                run(&records, checkpoint.at, checkpoint.phase).cells[1..4]
            );
        }
        assert_eq!(
            batch.points[2]
                .cells
                .iter()
                .flatten()
                .map(|o| o.value)
                .collect::<Vec<_>>(),
            vec![3, 4, 5]
        );
        assert_eq!(batch.points[4].gap_count, 1);
        assert_eq!(batch.points[4].gap_reasons, 2);
    }

    #[test]
    fn unobserved_post_does_not_erase_later_pre_and_global_gap_erases_all() {
        let mut records = vec![
            [1, 0, 0x1000, 0xd503201f, 0, 0, 0, 1],
            [2, 0, 0x1000, 0x2001, 1, 0xab, 0, 1],
            [9, 0, 0x1000, 0, 0, 0, 0, 1],
            [1, 1, 0x1000, 0xd503201f, 0, 0, 0, 0],
            [1, 2, 0x1000, 0xd503201f, 0, 0, 0, 0],
            [4, 3, 0, 1, 0, 0, 1, 2],
        ];
        let points = [
            Checkpoint {
                at: 1,
                phase: Phase::Post,
            },
            Checkpoint {
                at: 2,
                phase: Phase::Pre,
            },
        ];
        let run = |records: &[[u64; 8]], offset| {
            snapshots(
                Input::new(Cursor::new(bytes(records))).unwrap(),
                0x2001,
                16,
                &points,
                offset,
                16,
            )
        };
        let batch = run(&records, 0).unwrap();
        assert!(batch.points[0].cells.iter().all(Option::is_none));
        assert_eq!(batch.points[1].cells[0].unwrap().value, 0xab);
        assert!(!batch.points[0].committed);
        let empty = run(&records, u64::MAX).unwrap();
        assert!(
            empty
                .points
                .iter()
                .all(|p| p.selected_event && p.cells.is_empty())
        );
        records.insert(records.len() - 1, [3, 3, 0, 0, 0, 0, 0, 4]);
        records.last_mut().unwrap()[4] = 1;
        let global = run(&records, 0).unwrap();
        assert!(global.info.unpositioned_gap);
        assert!(
            global
                .points
                .iter()
                .all(|p| p.cells.iter().all(Option::is_none))
        );
        let mut raw = bytes(&records);
        raw.push(0);
        assert!(
            snapshots(
                Input::new(Cursor::new(raw)).unwrap(),
                0x2001,
                16,
                &points,
                u64::MAX,
                16
            )
            .is_err()
        );
        records.insert(records.len() - 2, [5, 2, 0x1000, 65, 8, 9, 0, 1]);
        assert!(run(&records, u64::MAX).is_err());
    }
}
