use traceq_observer_lab::{CpuContext, Event, StateView, traceq_observer_delta};
const ZERO: Event = Event {
    kind: 0,
    seq: 0,
    pc: 0,
    address: 0,
    size: 0,
    low: 0,
    high: 0,
    detail: 0,
};
fn set(c: &mut CpuContext, i: usize, value: u128) {
    match i {
        0..=28 => c.x[i] = value as u64,
        29 => c.fp = value as u64,
        30 => c.lr = value as u64,
        31 => c.sp = value as u64,
        32 => c.nzcv = value as u64,
        _ => c.vectors[i - 33] = value.to_le_bytes(),
    }
}
#[test]
fn full65_sparse_updates_and_gap_rebuild() {
    let mut c = CpuContext {
        pc: 0,
        sp: 0,
        nzcv: 0,
        x: [0; 29],
        fp: 0,
        lr: 0,
        vectors: [[0; 16]; 32],
    };
    let mut expected = [0u128; 65];
    for (i, v) in expected.iter_mut().enumerate() {
        *v = (0x8000000000000000u128 + i as u128)
            | if i >= 33 {
                (0xfedcba9876543210u128 + i as u128) << 64
            } else {
                0
            };
        set(&mut c, i, *v);
    }
    let mut values = [0u128; 65];
    let mut known = [0u8; 65];
    let mut bank = [0u64; 29];
    let mut complete = 0u8;
    let mut view = StateView {
        values: values.as_mut_ptr(),
        known: known.as_mut_ptr(),
        gpr_bank: bank.as_mut_ptr(),
        complete: &mut complete,
    };
    let mut events = [ZERO; 65];
    let observe = |v: &mut StateView, e: &mut [Event; 65], c: &CpuContext| unsafe {
        traceq_observer_delta(v, c, 5, 77, 0x1000, e.as_mut_ptr(), 65)
    };
    assert_eq!(observe(&mut view, &mut events, &c), 65);
    assert_eq!(values, expected);
    assert_eq!(known, [1; 65]);
    assert_eq!(complete, 1);
    for (i, e) in events.iter().enumerate() {
        assert_eq!(e.address, i as u64);
        assert_eq!(e.low, expected[i] as u64);
        assert_eq!(e.high, (expected[i] >> 64) as u64);
        assert_eq!(e.size, if i < 33 { 8 } else { 16 });
        assert_eq!(e.kind, 5);
        assert_eq!(e.seq, 77);
    }
    assert_eq!(observe(&mut view, &mut events, &c), 0);
    for i in 0..65 {
        expected[i] ^= if i < 33 { 0x5500 } else { 1u128 << 127 };
        set(&mut c, i, expected[i]);
        assert_eq!(observe(&mut view, &mut events, &c), 1);
        assert_eq!(events[0].address, i as u64);
        assert_eq!(values, expected);
    }
    known.fill(0);
    complete = 0;
    assert_eq!(observe(&mut view, &mut events, &c), 65);
    assert_eq!(known, [1; 65]);
    assert_eq!(values, expected);
    assert_eq!(complete, 1);
    let before = values;
    assert_eq!(
        unsafe { traceq_observer_delta(&mut view, &c, 0, 0, 0, events.as_mut_ptr(), 65) },
        usize::MAX
    );
    assert_eq!(values, before);
    assert_eq!(
        unsafe { traceq_observer_delta(&mut view, &c, 5, 0, 0, events.as_mut_ptr(), 64) },
        usize::MAX
    );
    assert_eq!(values, before);
    // A valid foreign context can live at an odd proxy-stack address. Every
    // high vector bit and validity slot must survive the cold copy path.
    let mut storage = vec![0u8; std::mem::size_of::<CpuContext>() + 1];
    unsafe {
        std::ptr::copy_nonoverlapping(
            (&c as *const CpuContext).cast::<u8>(),
            storage.as_mut_ptr().add(1),
            std::mem::size_of::<CpuContext>(),
        );
    }
    known.fill(0);
    complete = 0;
    let count = unsafe {
        traceq_observer_delta(
            &mut view,
            storage.as_ptr().add(1).cast(),
            5,
            77,
            0x1000,
            events.as_mut_ptr(),
            65,
        )
    };
    assert_eq!(count, 65);
    assert_eq!(values, expected);
    assert_eq!(known, [1; 65]);
    assert_eq!(complete, 1);
}
