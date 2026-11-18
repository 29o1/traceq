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
