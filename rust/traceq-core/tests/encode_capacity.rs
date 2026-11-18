use traceq_core::wire::{
    Event, Kind, MAX_RECORD_BYTES, MAX_RECORDS, decode_block, encode_block_into,
};
#[test]
fn independent_wire_and_capacity() {
    let event = Event {
        kind: Kind::Exec,
        seq: 1,
        pc: 4,
        address: 0,
        size: 0,
        low: 0,
        high: 0,
        detail: 1,
    };
    let mut bytes = vec![0xa5; MAX_RECORD_BYTES];
    let n = encode_block_into(&[event], &mut bytes).unwrap();
    // Width nibbles: delta seq=2, delta pc=8, final detail=1.
    assert_eq!(&bytes[..n], &[1, 0x11, 0, 0, 1, 2, 8, 1]);
    assert_eq!(decode_block(&bytes[..n], 1).unwrap(), vec![event]);
    let old = bytes.clone();
    assert!(encode_block_into(&[event], &mut bytes[..MAX_RECORD_BYTES - 1]).is_err());
    assert_eq!(bytes, old);
    assert!(encode_block_into(&[], &mut bytes).is_err());
    let events = vec![
        Event {
            kind: Kind::Write,
            seq: u64::MAX,
            pc: u64::MAX,
            address: u64::MAX,
            size: 16,
            low: u64::MAX,
            high: u64::MAX,
            detail: u64::MAX
        };
        MAX_RECORDS
    ];
    let mut full = vec![0; MAX_RECORDS * MAX_RECORD_BYTES];
    let n = encode_block_into(&events, &mut full).unwrap();
    assert_eq!(decode_block(&full[..n], MAX_RECORDS).unwrap(), events);
    let overflow = vec![event; MAX_RECORDS + 1];
    assert!(encode_block_into(&overflow, &mut full).is_err());
}

#[test]
fn decoder_checks_each_packed_field_and_exact_block_tail() {
    for field in 0..7 {
        for width in 0..=8u32 {
            // Literal GTSC record: one write, one populated width nibble.
            // Even delta bytes avoid signed zigzag when this is a seq or PC.
            let mut raw = vec![2];
            raw.extend_from_slice(&(width << (field * 4)).to_le_bytes());
            raw.extend_from_slice(
                &[0x42, 0x37, 0x13, 0x99, 0x22, 0x11, 0xcc, 0xaa][..width as usize],
            );
            let mut bytes = [0; 8];
            bytes[..width as usize].copy_from_slice(&raw[5..]);
            let mut expected = [0; 8];
            expected[0] = 2;
            expected[field + 1] = if field < 2 {
                u64::from_le_bytes(bytes) >> 1
            } else {
                u64::from_le_bytes(bytes)
            };
            let mut aligned = vec![0xff];
            aligned.extend_from_slice(&raw);
            assert_eq!(decode_block(&aligned[1..], 1).unwrap()[0].words(), expected);
            for tail in 0..raw.len() {
                assert!(
                    decode_block(&raw[..tail], 1).is_err(),
                    "field {field}, width {width}, tail {tail}"
                );
            }
            raw.push(0);
            assert!(decode_block(&raw, 1).is_err());
        }
        for invalid_width in 9..=15u32 {
            let mut raw = vec![2];
            raw.extend_from_slice(&(invalid_width << (field * 4)).to_le_bytes());
            raw.resize(5 + invalid_width as usize, 0);
            assert!(decode_block(&raw, 1).is_err());
        }
    }
    assert!(decode_block(&[2, 0, 0, 0, 0x80], 1).is_err());
}

#[test]
fn decoder_preserves_fields_across_common_packed_layouts() {
    let bytes = [
        &[9, 0, 0, 0, 1, 0xfd][..],
        &[1, 0x11, 4, 0, 1, 2, 9, 0x65, 0x43, 0x21, 1, 200],
        &[6, 0, 0x11, 4, 1, 32, 8, 3, 2, 1, 0x80, 254],
    ]
    .concat();
    let words: Vec<_> = decode_block(&bytes, 3)
        .unwrap()
        .into_iter()
        .map(Event::words)
        .collect();
    assert_eq!(
        words,
        [
            [9, 0, 0, 0, 0, 0, 0, 0xfd],
            [1, 1, u64::MAX - 4, 0x0121_4365, 0, 0, 0, 200],
            [6, 1, u64::MAX - 4, 32, 8, 0x8001_0203, 0, 254],
        ]
    );
    for end in 0..bytes.len() {
        assert!(decode_block(&bytes[..end], 3).is_err(), "prefix {end}");
    }
}
