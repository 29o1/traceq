//! Fixed-capacity executable observation intervals. The wire header is their
//! envelope; explicit CodeRange records describe the actual union and its holes.
use crate::plan;

pub const MAX_CODE_RANGES: usize = 64;
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CodeRange {
    pub base: u64,
    pub size: u64,
}
impl CodeRange {
    fn end(self) -> Option<u64> {
        self.base.checked_add(self.size)
    }
    fn valid(self) -> bool {
        self.base != 0
            && self.base & 3 == 0
            && self.size != 0
            && self.size & 3 == 0
            && self.end().is_some()
    }
}
pub struct CodeScope {
    ranges: [CodeRange; MAX_CODE_RANGES],
    len: usize,
    cached: usize,
}
impl CodeScope {
    pub fn single(base: u64, size: u64) -> Self {
        let mut ranges = [CodeRange::default(); MAX_CODE_RANGES];
        ranges[0] = CodeRange { base, size };
        Self {
            ranges,
            len: 1,
            cached: 0,
        }
    }
    pub fn new(primary: CodeRange, extra: &[CodeRange]) -> Option<Self> {
        if extra.len() >= MAX_CODE_RANGES || primary.size == 0 || primary.end().is_none() {
            return None;
        }
        // Legacy module captures keep their original header contract.
        if extra.is_empty() {
            return Some(Self::single(primary.base, primary.size));
        }
        if !primary.valid() || extra.iter().any(|r| !r.valid()) {
            return None;
        }
        let mut scope = Self::single(primary.base, primary.size);
        scope.ranges[1..=extra.len()].copy_from_slice(extra);
        let count = extra.len() + 1;
        scope.ranges[..count].sort_unstable_by_key(|r| r.base);
        let mut len = 0;
        for index in 0..count {
            let next = scope.ranges[index];
            if len != 0 && next.base <= scope.ranges[len - 1].end()? {
                let previous = &mut scope.ranges[len - 1];
                previous.size = previous.end()?.max(next.end()?) - previous.base;
            } else {
                scope.ranges[len] = next;
                len += 1;
            }
        }
        scope.len = len;
        Some(scope)
    }
    pub fn ranges(&self) -> &[CodeRange] {
        &self.ranges[..self.len]
    }
    pub fn envelope(&self) -> (u64, u64) {
        let first = self.ranges[0].base;
        let last = self.ranges[self.len - 1];
        (first, last.base + last.size - first)
    }
    #[inline]
    pub fn contains(&mut self, address: u64, size: u64) -> bool {
        let r = self.ranges[self.cached];
        if plan::contains(r.base, r.size, address, size) {
            return true;
        }
        let next = self.ranges().partition_point(|r| r.base <= address);
        if next == 0 {
            return false;
        }
        self.cached = next - 1;
        let r = self.ranges[self.cached];
        plan::contains(r.base, r.size, address, size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn explicit_union_excludes_holes_and_keeps_instruction_tails() {
        let mut scope = CodeScope::new(
            CodeRange {
                base: 0x3000,
                size: 16,
            },
            &[CodeRange {
                base: 0x1000,
                size: 32,
            }],
        )
        .unwrap();
        assert_eq!(scope.envelope(), (0x1000, 0x2010));
        for _ in 0..3 {
            for pc in [0x1000, 0x101c, 0x3000, 0x300c] {
                assert!(scope.contains(pc, 4));
            }
            for pc in [0xffc, 0x101d, 0x1020, 0x2000, 0x2ffc, 0x300d, 0x3010] {
                assert!(!scope.contains(pc, 4));
            }
        }
    }
    #[test]
    fn overlaps_and_adjacency_merge_without_broadening_holes() {
        let scope = CodeScope::new(
            CodeRange {
                base: 0x1000,
                size: 16,
            },
            &[
                CodeRange {
                    base: 0x1008,
                    size: 16,
                },
                CodeRange {
                    base: 0x1018,
                    size: 8,
                },
                CodeRange {
                    base: 0x3000,
                    size: 4,
                },
            ],
        )
        .unwrap();
        assert_eq!(
            scope.ranges(),
            &[
                CodeRange {
                    base: 0x1000,
                    size: 32
                },
                CodeRange {
                    base: 0x3000,
                    size: 4
                }
            ]
        );
    }
    #[test]
    fn extra_shapes_overflow_and_capacity_are_bounded() {
        let primary = CodeRange {
            base: 0x1000,
            size: 4,
        };
        for range in [
            CodeRange { base: 0, size: 4 },
            CodeRange {
                base: 0x2001,
                size: 4,
            },
            CodeRange {
                base: 0x2000,
                size: 0,
            },
            CodeRange {
                base: 0x2000,
                size: 2,
            },
            CodeRange {
                base: u64::MAX - 3,
                size: 4,
            },
        ] {
            assert!(CodeScope::new(primary, &[range]).is_none());
        }
        let extra: Vec<_> = (1..64)
            .map(|i| CodeRange {
                base: 0x1000 + i * 16,
                size: 4,
            })
            .collect();
        assert_eq!(CodeScope::new(primary, &extra).unwrap().ranges().len(), 64);
        assert!(CodeScope::new(primary, &[primary; 64]).is_none());
    }
}
