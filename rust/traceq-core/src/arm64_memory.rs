//! Narrow product-shared descriptions of the qualified A64 ordered accesses.
//! The native instruction executes unchanged; these describe its observations.
//! LDADD semantics: Arm DDI0602 (2024), LDADD family, operation and encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Width {
    W32,
    W64,
}
impl Width {
    pub fn bytes(self) -> u32 {
        match self {
            Self::W32 => 4,
            Self::W64 => 8,
        }
    }
    pub fn mask(self, bits: u64) -> u64 {
        match self {
            Self::W32 => bits as u32 as u64,
            Self::W64 => bits,
        }
    }
    /// Completed atomic old bits plus the saved pre-instruction addend.
    pub fn add(self, old: u64, addend: u64) -> u64 {
        self.mask(old.wrapping_add(addend))
    }
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

#[cfg(test)]
mod tests {
    use super::*;
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
