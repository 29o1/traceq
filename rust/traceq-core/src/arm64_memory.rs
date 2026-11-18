//! Narrow product-shared descriptions of qualified A64 memory operations.
//! The native instruction executes unchanged; these describe its observations.
//! LDADD semantics: Arm DDI0602 (2024), LDADD family, operation and encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Width {
    H16,
    W32,
    W64,
}
impl Width {
    pub fn bytes(self) -> u32 {
        match self {
            Self::H16 => 2,
            Self::W32 => 4,
            Self::W64 => 8,
        }
    }
    pub fn mask(self, bits: u64) -> u64 {
        match self {
            Self::H16 => bits as u16 as u64,
            Self::W32 => bits as u32 as u64,
            Self::W64 => bits,
        }
    }
    /// Completed atomic old bits plus the saved pre-instruction addend.
    pub fn add(self, old: u64, addend: u64) -> u64 {
        self.mask(old.wrapping_add(addend))
    }
}
/// Only confirmed architectural writes are returned. A failed CAS may perform
/// an implementation-dependent old-value writeback; it needs an explicit gap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AtomicOp {
    Add(Width),
    SwapHalfword,
    CompareSwapHalfword,
}
impl AtomicOp {
    pub fn width(self) -> Width {
        match self {
            Self::Add(width) => width,
            Self::SwapHalfword | Self::CompareSwapHalfword => Width::H16,
        }
    }
    pub fn confirmed_write(self, old: u64, source: u64, compare: u64) -> Option<u64> {
        match self {
            Self::Add(width) => Some(width.add(old, source)),
            Self::SwapHalfword => Some(Width::H16.mask(source)),
            Self::CompareSwapHalfword => {
                (Width::H16.mask(old) == Width::H16.mask(compare)).then(|| Width::H16.mask(source))
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HalfwordAtomic {
    pub operation: AtomicOp,
    pub source: u8,
    pub result: u8,
    pub base: u8,
    pub acquire: bool,
    pub release: bool,
}
/// Arm DDI0602 halfword CASH/SWPH families. Returned old bits are required;
/// discarded results, adjacent operations and other widths stay unsupported.
pub fn halfword_atomic(word: u32) -> Option<HalfwordAtomic> {
    let first = ((word >> 16) & 31) as u8;
    let second = (word & 31) as u8;
    let (operation, source, result, acquire, release) = if word & 0xffa0_7c00 == 0x48a0_7c00 {
        (
            AtomicOp::CompareSwapHalfword,
            second,
            first,
            word & (1 << 22) != 0,
            word & (1 << 15) != 0,
        )
    } else if word & 0xff20_fc00 == 0x7820_8000 {
        (
            AtomicOp::SwapHalfword,
            first,
            second,
            word & (1 << 23) != 0,
            word & (1 << 22) != 0,
        )
    } else {
        return None;
    };
    (result != 31).then_some(HalfwordAtomic {
        operation,
        source,
        result,
        base: ((word >> 5) & 31) as u8,
        acquire,
        release,
    })
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AtomicAdd {
    pub width: Width,
    pub source: u8,
    pub result: u8,
    pub base: u8,
    pub acquire: bool,
    pub release: bool,
}
pub fn atomic_add(word: u32) -> Option<AtomicAdd> {
    if word & 0x3f20_fc00 != 0x3820_0000 || word >> 30 < 2 || word & 31 == 31 {
        // No byte/halfword, other LSE operation or discarded old result.
        return None;
    }
    Some(AtomicAdd {
        width: if word >> 30 == 2 {
            Width::W32
        } else {
            Width::W64
        },
        source: ((word >> 16) & 31) as u8,
        result: (word & 31) as u8,
        base: ((word >> 5) & 31) as u8,
        acquire: word & (1 << 23) != 0,
        release: word & (1 << 22) != 0,
    })
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoreRelease {
    pub width: Width,
    pub source: u8,
    pub base: u8,
}
pub fn store_release(word: u32) -> Option<StoreRelease> {
    if word & 0x3fff_fc00 != 0x089f_fc00 || word >> 30 < 2 {
        return None;
    }
    Some(StoreRelease {
        width: if word >> 30 == 2 {
            Width::W32
        } else {
            Width::W64
        },
        source: (word & 31) as u8,
        base: ((word >> 5) & 31) as u8,
    })
}
pub const ATOMIC_WRITE_SOURCE: &str =
    "atomic add result from returned old bits and saved addend; post callback confirmed";
pub const ATOMIC_SWAP_WRITE_SOURCE: &str =
    "atomic swap saved source bits; returned old bits and post callback confirmed";
pub const ATOMIC_CAS_WRITE_SOURCE: &str = "atomic compare-and-swap saved replacement; returned old bits matched saved compare; post callback confirmed";
pub fn atomic_write_source(word: u32) -> Option<&'static str> {
    if atomic_add(word).is_some() {
        Some(ATOMIC_WRITE_SOURCE)
    } else {
        halfword_atomic(word).map(|decoded| match decoded.operation {
            AtomicOp::SwapHalfword => ATOMIC_SWAP_WRITE_SOURCE,
            AtomicOp::CompareSwapHalfword => ATOMIC_CAS_WRITE_SOURCE,
            AtomicOp::Add(_) => ATOMIC_WRITE_SOURCE,
        })
    }
}

/// Exact system encodings; the low five bits name an X register (31 is XZR).
pub fn dc_zva_register(word: u32) -> Option<u8> {
    (word & !31 == 0xd50b_7420).then_some((word & 31) as u8)
}
pub fn dczid_register(word: u32) -> Option<u8> {
    (word & !31 == 0xd53b_00e0).then_some((word & 31) as u8)
}
pub const DC_ZVA_WRITE_SOURCE: &str =
    "DC ZVA architectural zero fill; observed DCZID_EL0 and post callback confirmed";

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn zero_by_address_encodings_do_not_accept_other_system_operations() {
        for register in 0..32 {
            assert_eq!(
                dc_zva_register(0xd50b_7420 | register),
                Some(register as u8)
            );
            assert_eq!(dczid_register(0xd53b_00e0 | register), Some(register as u8));
        }
        for bit in 5..32 {
            assert_eq!(dc_zva_register(0xd50b_7423 ^ (1 << bit)), None);
            assert_eq!(dczid_register(0xd53b_00e5 ^ (1 << bit)), None);
        }
    }
    #[test]
    fn halfword_ordering_fields_and_failure_uncertainty() {
        for acquire in [false, true] {
            for release in [false, true] {
                let cas = 0x48a0_7c41 | ((acquire as u32) << 22) | ((release as u32) << 15);
                let swap = 0x7820_8020 | ((acquire as u32) << 23) | ((release as u32) << 22);
                let c = halfword_atomic(cas).unwrap();
                assert_eq!(
                    (c.operation, c.source, c.result, c.base),
                    (AtomicOp::CompareSwapHalfword, 1, 0, 2)
                );
                let s = halfword_atomic(swap).unwrap();
                assert_eq!(
                    (s.operation, s.source, s.result, s.base),
                    (AtomicOp::SwapHalfword, 0, 0, 1)
                );
                for d in [c, s] {
                    assert_eq!((d.acquire, d.release), (acquire, release));
                }
            }
        }
        for word in [
            0x08e0_7c41,
            0x88e0_7c41,
            0x48ff_7c41,
            0x3860_8020,
            0xb860_8020,
            0x7860_803f,
            0x7860_0020,
            0x48e0_7841,
        ] {
            assert_eq!(halfword_atomic(word), None, "{word:x}");
        }
        assert_eq!(
            AtomicOp::CompareSwapHalfword.confirmed_write(0x8001, 0xfeed_1234, 0xbeef_8001),
            Some(0x1234)
        );
        assert_eq!(AtomicOp::CompareSwapHalfword.confirmed_write(7, 9, 0), None);
        assert_eq!(
            AtomicOp::SwapHalfword.confirmed_write(0x8001, 0xfeed_1234, 0),
            Some(0x1234)
        );
        assert_eq!(halfword_atomic(0x48e0_7c5f).unwrap().source, 31);
    }
    #[test]
    fn real_words_and_order_variants() {
        for (word, acquire, release) in [
            (0xb8200020, false, false),
            (0xb8a00020, true, false),
            (0xb8600020, false, true),
            (0xb8e00020, true, true),
        ] {
            let d = atomic_add(word).unwrap();
            assert_eq!((d.width, d.source, d.result, d.base), (Width::W32, 0, 0, 1));
            assert_eq!((d.acquire, d.release), (acquire, release));
            assert_eq!(atomic_add(word | 0x4000_0000).unwrap().width, Width::W64);
        }
        let d = store_release(0x889ffd1f).unwrap();
        assert_eq!((d.width, d.source, d.base), (Width::W32, 31, 8));
        assert_eq!(store_release(0xc89ffd1f).unwrap().width, Width::W64);
    }
    #[test]
    fn reject_nearby_operations_and_wrap_at_native_width() {
        for word in [
            0x38200020, 0x78200020, 0xb820003f, 0xb8208020, 0xb8201020, 0xb8bfc020, 0x91000400,
        ] {
            assert_eq!(atomic_add(word), None, "{word:x}");
        }
        for word in [0x089ffd1f, 0x489ffd1f, 0x88dffd1f, 0x889f7d1f, 0xd503201f] {
            assert_eq!(store_release(word), None, "{word:x}");
        }
        assert_eq!(Width::W32.add(u32::MAX as u64, 1), 0);
        assert_eq!(Width::W64.add(u64::MAX, 1), 0);
        assert_eq!(Width::W32.add(1, u64::MAX), 0);
    }
}
