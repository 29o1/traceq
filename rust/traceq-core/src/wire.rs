//! Explicit little-endian transport, bounded to one packed block. No Rust
//! native layout is serialized. Sequence/PC arithmetic is modulo 2^64.
use crate::{Error, Result};
use std::io::Read;

pub const FLAT_MAGIC: &[u8; 8] = b"GTSW001\0";
pub const CHUNK_MAGIC: &[u8; 8] = b"GTSC001\0";
pub const BLOCK_MAGIC: &[u8; 8] = b"GTBL001\0";
pub const MAX_RECORDS: usize = 1024;
pub const MAX_RECORD_BYTES: usize = 61;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    Exec = 1,
    Write,
    Gap,
    End,
    RegPre,
    RegPost,
    Read,
    Site,
    Commit,
    Module,
    ScopeExit,
    ScopeReenter,
    Features,
    CodeRange,
}
impl TryFrom<u64> for Kind {
    type Error = Error;
    fn try_from(n: u64) -> Result<Self> {
        Ok(match n {
            1 => Self::Exec,
            2 => Self::Write,
            3 => Self::Gap,
            4 => Self::End,
            5 => Self::RegPre,
            6 => Self::RegPost,
            7 => Self::Read,
            8 => Self::Site,
            9 => Self::Commit,
            10 => Self::Module,
            11 => Self::ScopeExit,
            12 => Self::ScopeReenter,
            13 => Self::Features,
            14 => Self::CodeRange,
            _ => return Err(Error::unsupported(format!("unknown event kind {n}"))),
        })
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Event {
    pub kind: Kind,
    pub seq: u64,
    pub pc: u64,
    pub address: u64,
    pub size: u64,
    pub low: u64,
    pub high: u64,
    pub detail: u64,
}
impl Event {
    pub fn from_words(w: [u64; 8]) -> Result<Self> {
        Ok(Self {
            kind: w[0].try_into()?,
            seq: w[1],
            pc: w[2],
            address: w[3],
            size: w[4],
            low: w[5],
            high: w[6],
            detail: w[7],
        })
    }
    pub fn words(self) -> [u64; 8] {
        [
            self.kind as u64,
            self.seq,
            self.pc,
            self.address,
            self.size,
            self.low,
            self.high,
            self.detail,
        ]
    }
    pub fn bytes24(self) -> [u8; 24] {
        let mut b = [0; 24];
        for (dst, word) in b
            .chunks_exact_mut(8)
            .zip([self.low, self.high, self.detail])
        {
            dst.copy_from_slice(&word.to_le_bytes());
        }
        b
    }
}
#[derive(Clone, Copy, Debug)]
pub struct Header {
    pub code_base: u64,
    pub code_size: u64,
    pub data_base: u64,
    pub data_size: u64,
    pub thread_id: u64,
    pub profile: u64,
}

impl Header {
    #[inline]
    pub fn contains_data(self, base: u64, len: u64) -> bool {
        base >= self.data_base
            && len <= self.data_size
            && base - self.data_base <= self.data_size - len
    }
}

fn u64le(b: &[u8]) -> u64 {
    u64::from_le_bytes(b[..8].try_into().expect("fixed field"))
}
fn unzigzag(v: u64) -> u64 {
    (v >> 1) ^ 0u64.wrapping_sub(v & 1)
}
fn zigzag(v: u64) -> u64 {
    (v << 1) ^ 0u64.wrapping_sub(v >> 63)
}

pub fn decode_block(bytes: &[u8], count: usize) -> Result<Vec<Event>> {
    let mut out = Vec::new();
    decode_block_into(bytes, count, &mut out)?;
    Ok(out)
}
fn decode_block_into(bytes: &[u8], count: usize, out: &mut Vec<Event>) -> Result<()> {
    if count == 0 || count > MAX_RECORDS || bytes.len() > count * MAX_RECORD_BYTES {
        return Err(Error::trace("invalid block bounds"));
    }
    out.clear();
    out.reserve(count);
    // Packed width nibbles, from sequence delta through detail. These common
    // layouts can use fixed reads, independent of the event kind.
    const DETAIL_BYTE: u32 = 0x0100_0000; // [0, 0, 0, 0, 0, 0, 1]
    const STEP_AND_ADDRESS: u32 = 0x0100_0411; // [1, 1, 4, 0, 0, 0, 1]
    const RANGE_AND_LOW: u32 = 0x0104_1100; // [0, 0, 1, 1, 4, 0, 1]
    let (mut pos, mut seq, mut pc) = (0, 0u64, 0u64);
    for _ in 0..count {
        if bytes.len() - pos < 5 {
            return Err(Error::trace("truncated block record"));
        }
        let kind = bytes[pos] as u64;
        let widths = u32::from_le_bytes(bytes[pos + 1..pos + 5].try_into().expect("fixed field"));
        if widths >> 28 != 0 {
            return Err(Error::trace("reserved width bits"));
        }
        pos += 5;
        let mut w = [0u64; 8];
        w[0] = kind;
        match (widths, &bytes[pos..]) {
            (DETAIL_BYTE, [detail, ..]) => {
                w[7] = u64::from(*detail);
                pos += 1;
            }
            (STEP_AND_ADDRESS, [seq, pc, a, b, c, d, detail, ..]) => {
                w[1] = u64::from(*seq);
                w[2] = u64::from(*pc);
                w[3] = u64::from(u32::from_le_bytes([*a, *b, *c, *d]));
                w[7] = u64::from(*detail);
                pos += 7;
            }
            (RANGE_AND_LOW, [address, size, a, b, c, d, detail, ..]) => {
                w[3] = u64::from(*address);
                w[4] = u64::from(*size);
                w[5] = u64::from(u32::from_le_bytes([*a, *b, *c, *d]));
                w[7] = u64::from(*detail);
                pos += 7;
            }
            _ => {
                for j in 0..7 {
                    let width = ((widths >> (4 * j)) & 15) as usize;
                    if width > 8 || width > bytes.len() - pos {
                        return Err(Error::trace("invalid field width"));
                    }
                    if width != 0 {
                        if bytes.len() - pos >= 8 {
                            // Mask bytes belonging to later fields in the block.
                            w[j + 1] = u64le(&bytes[pos..]) & (u64::MAX >> ((8 - width) * 8));
                        } else {
                            // The block tail has no readable padding.
                            for (shift, byte) in bytes[pos..pos + width].iter().enumerate() {
                                w[j + 1] |= u64::from(*byte) << (shift * 8);
                            }
                        }
                    }
                    pos += width;
                }
            }
        }
        seq = seq.wrapping_add(unzigzag(w[1]));
        pc = pc.wrapping_add(unzigzag(w[2]));
        w[1] = seq;
        w[2] = pc;
        out.push(Event::from_words(w)?);
    }
    if pos != bytes.len() {
        return Err(Error::trace("trailing packed data"));
    }
    Ok(())
}
pub fn encode_block(events: &[Event]) -> Result<Vec<u8>> {
    let mut out = vec![0; events.len().min(MAX_RECORDS) * MAX_RECORD_BYTES];
    let size = encode_block_into(events, &mut out)?;
    out.truncate(size);
    Ok(out)
}

/// Encode into caller-owned reusable storage. Capacity is checked before writing;
/// no allocation or partial block is exposed on a capacity error.
pub fn encode_block_into(events: &[Event], out: &mut [u8]) -> Result<usize> {
    if events.is_empty() || events.len() > MAX_RECORDS {
        return Err(Error::trace("invalid block count"));
    }
    if out.len() < events.len() * MAX_RECORD_BYTES {
        return Err(Error::trace("insufficient encoding capacity"));
    }
    let mut used = 0;
    let (mut seq, mut pc) = (0u64, 0u64);
    for e in events {
        let fields = [
            zigzag(e.seq.wrapping_sub(seq)),
            zigzag(e.pc.wrapping_sub(pc)),
            e.address,
            e.size,
            e.low,
            e.high,
            e.detail,
        ];
        seq = e.seq;
        pc = e.pc;
        out[used] = e.kind as u8;
        let at = used + 1;
        used += 5;
        let mut widths = 0u32;
        for (j, v) in fields.into_iter().enumerate() {
            let n = ((64 - v.leading_zeros()) as usize).div_ceil(8);
            widths |= (n as u32) << (4 * j);
            // Capacity reserves the worst-case 5+7*8 bytes for each record.
            // Full stores may overlap bytes not yet emitted; subsequent fields
            // replace them. Only `used` bytes are submitted. This avoids seven
            // variable-size libc memcpy calls per event on Android ARM64.
            out[used..used + 8].copy_from_slice(&v.to_le_bytes());
            used += n;
        }
        out[at..at + 4].copy_from_slice(&widths.to_le_bytes());
    }
    Ok(used)
}

pub struct Input<R: Read> {
    reader: R,
    pub header: Header,
    pub chunked: bool,
    bytes: Vec<u8>,
    events: Vec<Event>,
    index: usize,
}
impl<R: Read> Input<R> {
    pub fn new(mut reader: R) -> Result<Self> {
        let mut b = [0; 64];
        reader.read_exact(&mut b)?;
        let chunked = &b[..8] == CHUNK_MAGIC;
        if !chunked && &b[..8] != FLAT_MAGIC {
            return Err(Error::unsupported(
                "unsupported transport; expected GTSW001 or GTSC001",
            ));
        }
        let h = Header {
            code_base: u64le(&b[8..]),
            code_size: u64le(&b[16..]),
            data_base: u64le(&b[24..]),
            data_size: u64le(&b[32..]),
            thread_id: u64le(&b[40..]),
            profile: u64le(&b[48..]),
        };
        if h.profile != 2 {
            return Err(Error::unsupported("only execution profile 2 is supported"));
        }
        if u64le(&b[56..]) != 64
            || h.code_size == 0
            || h.data_size == 0
            || h.code_base.checked_add(h.code_size).is_none()
            || h.data_base.checked_add(h.data_size).is_none()
        {
            return Err(Error::trace("invalid execution-state header"));
        }
        Ok(Self {
            reader,
            header: h,
            chunked,
            bytes: Vec::new(),
            events: Vec::new(),
            index: 0,
        })
    }
    pub fn next_event(&mut self) -> Result<Event> {
        if !self.chunked {
            let mut b = [0; 64];
            self.reader.read_exact(&mut b)?;
            let mut w = [0; 8];
            for (j, v) in w.iter_mut().enumerate() {
                *v = u64le(&b[j * 8..]);
            }
            return Event::from_words(w);
        }
        if self.index == self.events.len() {
            let mut b = [0; 16];
            self.reader.read_exact(&mut b)?;
            if &b[..8] != BLOCK_MAGIC {
                return Err(Error::trace("invalid block magic"));
            }
            let count = u32::from_le_bytes(b[8..12].try_into().expect("fixed field")) as usize;
            let size = u32::from_le_bytes(b[12..16].try_into().expect("fixed field")) as usize;
            if count == 0 || count > MAX_RECORDS || size > count * MAX_RECORD_BYTES {
                return Err(Error::trace("invalid block bounds"));
            }
            self.bytes.resize(size, 0);
            self.reader.read_exact(&mut self.bytes)?;
            decode_block_into(&self.bytes, count, &mut self.events)?;
            self.index = 0;
        }
        let e = self.events[self.index];
        self.index += 1;
        Ok(e)
    }
    pub fn finish(&mut self) -> Result<()> {
        if self.chunked && self.index != self.events.len() {
            return Err(Error::trace("records after END"));
        }
        let mut b = [0; 1];
        if self.reader.read(&mut b)? != 0 {
            return Err(Error::trace("trailing bytes"));
        }
        Ok(())
    }
}
