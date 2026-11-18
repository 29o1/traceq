//! One bit per possible ARM64 instruction in the declared scope. Allocate at
//! setup, before following; translation never grows a target-heap collection.
use crate::code_scope::{CodeScope, MAX_CODE_RANGES};

pub(crate) struct Sites {
    offsets: [usize; MAX_CODE_RANGES],
    words: Vec<u64>,
}

impl Sites {
    pub fn new(scope: &CodeScope) -> Option<Self> {
        let mut offsets = [0; MAX_CODE_RANGES];
        let mut count = 0usize;
        for (index, range) in scope.ranges().iter().enumerate() {
            offsets[index] = count;
            let words = usize::try_from((range.size / 4).div_ceil(64)).ok()?;
            count = count.checked_add(words)?;
        }
        let mut words = Vec::new();
        words.try_reserve_exact(count).ok()?;
        words.resize(count, 0);
        Some(Self { offsets, words })
    }

    /// None means an invalid instruction address. The caller must fail the
    /// capture, retaining native execution instead of emitting incomplete sites.
    pub fn insert(&mut self, scope: &CodeScope, pc: u64) -> Option<bool> {
        if pc & 3 != 0 {
            return None;
        }
        let ranges = scope.ranges();
        let index = ranges
            .partition_point(|range| range.base <= pc)
            .checked_sub(1)?;
        let range = ranges[index];
        let offset = pc - range.base;
        if range.size < 4 || offset > range.size - 4 {
            return None;
        }
        let bit = usize::try_from(offset / 4).ok()?;
        let word = self.words.get_mut(self.offsets[index] + bit / 64)?;
        let mask = 1 << (bit % 64);
        let new = *word & mask == 0;
        *word |= mask;
        Some(new)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::code_scope::CodeRange;

    #[test]
    fn unique_instruction_bits_cross_words_and_disjoint_ranges() {
        let scope = CodeScope::new(
            CodeRange {
                base: 0x1000,
                size: 260,
            },
            &[CodeRange {
                base: 0x8000,
                size: 4,
            }],
        )
        .unwrap();
        let mut sites = Sites::new(&scope).unwrap();
        for pc in [0x1000, 0x10fc, 0x1100, 0x8000] {
            assert_eq!(sites.insert(&scope, pc), Some(true));
            assert_eq!(sites.insert(&scope, pc), Some(false));
        }
        for pc in [0xffc, 0x1001, 0x1104, 0x4000, 0x8004] {
            assert_eq!(sites.insert(&scope, pc), None);
        }
    }

    #[test]
    fn legacy_unaligned_envelope_keeps_distinct_aligned_instructions() {
        let scope = CodeScope::single(0x1001, 264);
        let mut sites = Sites::new(&scope).unwrap();
        assert_eq!(sites.insert(&scope, 0x1000), None);
        for pc in (0x1004..=0x1104).step_by(4) {
            assert_eq!(sites.insert(&scope, pc), Some(true));
        }
        assert_eq!(sites.insert(&scope, 0x1104), Some(false));
        assert_eq!(sites.insert(&scope, 0x1108), None);
    }
}
