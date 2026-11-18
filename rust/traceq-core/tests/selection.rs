use std::io::Cursor;
use traceq_core::{
    replay::{self, Group},
    wire::{self, Event, Input, Kind},
};
// Spell out the eight wire fields so these fixtures do not share replay logic.
#[allow(clippy::too_many_arguments)]
fn event(
    kind: Kind,
    seq: u64,
    pc: u64,
    address: u64,
    size: u64,
    low: u64,
    high: u64,
    detail: u64,
) -> Event {
    Event {
        kind,
        seq,
        pc,
        address,
        size,
        low,
        high,
        detail,
    }
}
fn fixture() -> Vec<Event> {
    let mut rows = Vec::new();
    for n in 0..4 {
        rows.push(event(
            Kind::Site,
            0,
            0x1000 + n * 4,
            0xd503201f,
            3,
            u64::from_le_bytes(*b"nop\0\0\0\0\0"),
            0,
            0,
        ));
    }
    rows.extend([
        event(Kind::Exec, 0, 0x1000, 0xd503201f, 0, 0, 0, 1),
        event(Kind::RegPre, 0, 0x1000, 0, 8, 0xffffffffffff0000, 0, 1),
        event(
            Kind::RegPre,
            0,
            0x1000,
            64,
            16,
            0x12345,
            0xfedcba9876543210,
            1,
        ),
        event(Kind::RegPost, 0, 0x1000, 0, 8, 17, 0, 1),
        event(Kind::Write, 0, 0x1000, 0x2000, 1, 17, 0, 1),
        event(Kind::Commit, 0, 0x1000, 0, 0, 0, 0, 1),
        event(Kind::Exec, 1, 0x1004, 0xd503201f, 0, 0, 0, 0),
        event(Kind::RegPre, 1, 0x1004, 0, 8, 18, 0, 1),
        event(Kind::Gap, 1, 0x1004, 0, 0, 0, 0, 1),
        event(Kind::Exec, 2, 0x1008, 0xd503201f, 0, 0, 0, 1),
        event(Kind::RegPre, 2, 0x1008, 64, 16, 25, 1 << 63, 1),
        event(Kind::RegPost, 2, 0x1008, 31, 8, 0xa003, 0, 1),
        event(Kind::Commit, 2, 0x1008, 0, 0, 0, 0, 1),
        event(Kind::Exec, 3, 0x100c, 0xd503201f, 0, 0, 0, 0),
        event(Kind::End, 4, 0, 1, 1, 0, 2, 2),
    ]);
    rows
}
fn bytes(rows: &[Event], chunked: bool) -> Vec<u8> {
    let mut out = if chunked {
        wire::CHUNK_MAGIC.to_vec()
    } else {
        wire::FLAT_MAGIC.to_vec()
    };
    for word in [0x1000u64, 16, 0x2000, 64, 7, 2, 64] {
        out.extend_from_slice(&word.to_le_bytes());
    }
    if chunked {
        let encoded = wire::encode_block(rows).unwrap();
        out.extend_from_slice(wire::BLOCK_MAGIC);
        out.extend_from_slice(&(rows.len() as u32).to_le_bytes());
        out.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
        out.extend_from_slice(&encoded);
    } else {
        for row in rows {
            for word in row.words() {
                out.extend_from_slice(&word.to_le_bytes());
            }
        }
    }
    out
}
fn full(data: &[u8]) -> Vec<Group> {
    let mut groups = Vec::new();
    replay::read(Input::new(Cursor::new(data)).unwrap(), |g, _| {
        groups.push(g.clone())
    })
    .unwrap();
    groups
}
#[test]
fn selected_carry_gap_high_bits_and_reused_access_storage() {
    for chunked in [false, true] {
        let data = bytes(&fixture(), chunked);
        let groups = full(&data);
        assert_eq!(groups.len(), 4);
        assert_eq!(groups[0].pre.bits[0], 0xffffffffffff0000);
        assert_eq!(groups[0].post.bits[0], 17);
        assert_eq!(groups[0].post.bits[64], 0xfedcba98765432100000000000012345);
        assert_eq!(groups[1].pre.bits[0], 18);
        assert!(groups[1].gap);
        assert!(groups[1].accesses.is_empty());
        assert_eq!(groups[1].post.known, [0, 0]);
        assert!(!groups[2].pre.is_known(0));
        assert_eq!(groups[2].pre.bits[64], (1u128 << 127) | 25);
        assert_eq!(groups[2].post.bits[31], 0xa003);
        assert_eq!(groups[3].pre.known, [1 << 31, 1]);
        assert_eq!(groups[3].post.known, [0, 0]);
        assert!(groups[3].accesses.is_empty());
        for selection in [vec![], vec![0], vec![1], vec![2], vec![3], vec![0, 2, 3]] {
            let mut observed = Vec::new();
            let info = replay::read_selected(
                Input::new(Cursor::new(&data)).unwrap(),
                |seq| selection.contains(&seq),
                |g, _| observed.push(g.clone()),
            )
            .unwrap();
            assert_eq!(
                (info.instructions, info.writes, info.gaps, info.commits),
                (4, 1, 1, 2)
            );
            assert_eq!(observed.len(), selection.len());
            for (&index, actual) in selection.iter().zip(observed) {
                assert_eq!(
                    replay::fingerprint(7, &actual),
                    replay::fingerprint(7, &groups[index as usize])
                );
                assert_eq!(actual.pre, groups[index as usize].pre);
                assert_eq!(actual.post, groups[index as usize].post);
            }
        }
    }
}
#[test]
fn unselected_and_suffix_records_still_block_success() {
    for chunked in [false, true] {
        let original = fixture();
        let mut missing_commit = original.clone();
        missing_commit.retain(|e| !(e.kind == Kind::Commit && e.seq == 0));
        let mut late_invalid = original.clone();
        late_invalid.insert(
            late_invalid.len() - 1,
            event(Kind::RegPre, 3, 0x100c, 65, 8, 9, 0, 1),
        );
        let mut bad_end = original.clone();
        bad_end.last_mut().unwrap().high = 99;
        for rows in [missing_commit, late_invalid, bad_end] {
            let data = bytes(&rows, chunked);
            for selected in [false, true] {
                let result = replay::read_selected(
                    Input::new(Cursor::new(&data)).unwrap(),
                    |seq| selected && seq == 0,
                    |_, _| {},
                );
                assert!(result.is_err());
            }
        }
        let mut trailing = bytes(&original, chunked);
        trailing.push(0x55);
        assert!(
            replay::read_selected(
                Input::new(Cursor::new(trailing)).unwrap(),
                |_| false,
                |_, _| {}
            )
            .is_err()
        );
    }
}

#[test]
fn fixed_site_words_repeated_and_colliding_pcs_still_validate() {
    let rows = vec![
        event(
            Kind::Site,
            0,
            0x1000,
            0xd503201f,
            3,
            u64::from_le_bytes(*b"nop\0\0\0\0\0"),
            0,
            0,
        ),
        event(
            Kind::Site,
            0,
            0x1100,
            0x91000400,
            3,
            u64::from_le_bytes(*b"add\0\0\0\0\0"),
            0,
            0,
        ),
        event(Kind::Exec, 0, 0x1000, 0xd503201f, 0, 0, 0, 0),
        event(Kind::Exec, 1, 0x1100, 0x91000400, 0, 0, 0, 0),
        event(Kind::Exec, 2, 0x1000, 0xd503201f, 0, 0, 0, 0),
        event(Kind::End, 3, 0, 0, 0, 0, 0, 2),
    ];
    for chunked in [false, true] {
        let encode = |rows: &[Event]| {
            let mut raw = bytes(rows, chunked);
            raw[16..24].copy_from_slice(&0x400u64.to_le_bytes());
            raw
        };
        let mut seen = Vec::new();
        replay::read_evidence(Input::new(Cursor::new(encode(&rows))).unwrap(), |g, _| {
            seen.push((g.pc, g.word))
        })
        .unwrap();
        assert_eq!(
            seen,
            [
                (0x1000, 0xd503201f),
                (0x1100, 0x91000400),
                (0x1000, 0xd503201f)
            ]
        );
        let mut hit_wrong_word = rows.clone();
        hit_wrong_word[3].pc = 0x1000;
        let mut collision_unknown = rows.clone();
        collision_unknown[3].pc = 0x1200;
        collision_unknown[3].address = 0xd503201f;
        let mut changed_site = rows.clone();
        changed_site.insert(
            3,
            event(
                Kind::Site,
                3,
                0x1000,
                0x91000400,
                3,
                u64::from_le_bytes(*b"add\0\0\0\0\0"),
                0,
                0,
            ),
        );
        for invalid in [hit_wrong_word, collision_unknown, changed_site] {
            let raw = encode(&invalid);
            assert!(
                replay::read_evidence(Input::new(Cursor::new(&raw)).unwrap(), |_, _| {}).is_err()
            );
            assert!(
                replay::read_selected(
                    Input::new(Cursor::new(&raw)).unwrap(),
                    |seq| seq == 0,
                    |_, _| {}
                )
                .is_err()
            );
        }
    }
}

#[test]
fn observations_expose_only_recorded_slots_and_validate_the_suffix() {
    for chunked in [false, true] {
        let data = bytes(&fixture(), chunked);
        let mut observed = Vec::new();
        let info = replay::read_observations(Input::new(Cursor::new(&data)).unwrap(), |g, _| {
            observed.push((
                g.seq,
                g.pre.get(0),
                g.pre.get(64),
                g.post.get(0),
                g.post.get(31),
            ));
            assert_eq!(g.pre.get(65), None);
        })
        .unwrap();
        assert_eq!(
            (info.instructions, info.writes, info.gaps, info.commits),
            (4, 1, 1, 2)
        );
        assert_eq!(
            observed,
            [
                (
                    0,
                    Some(0xffffffffffff0000),
                    Some(0xfedcba98765432100000000000012345),
                    Some(17),
                    None
                ),
                (1, Some(18), None, None, None),
                (2, None, Some((1u128 << 127) | 25), None, Some(0xa003)),
                (3, None, None, None, None),
            ]
        );
        let mut post_gap = fixture();
        post_gap.insert(8, event(Kind::Gap, 0, 0x1000, 0, 0, 0, 0, 1));
        post_gap.last_mut().unwrap().size = 2;
        replay::read_observations(
            Input::new(Cursor::new(bytes(&post_gap, chunked))).unwrap(),
            |g, _| {
                if g.seq == 0 {
                    assert_eq!(g.post.get(0), None);
                }
            },
        )
        .unwrap();
        let mut trailing = data;
        trailing.push(0x55);
        assert!(
            replay::read_observations(Input::new(Cursor::new(&trailing)).unwrap(), |_, _| {})
                .is_err()
        );
        let mut invalid = fixture();
        invalid.insert(
            invalid.len() - 1,
            event(Kind::RegPre, 3, 0x100c, 65, 8, 9, 0, 1),
        );
        assert!(
            replay::read_observations(
                Input::new(Cursor::new(bytes(&invalid, chunked))).unwrap(),
                |_, _| {}
            )
            .is_err()
        );
    }
}
