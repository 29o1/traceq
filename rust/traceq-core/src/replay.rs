//! Validated evidence reconstruction, independent of a capture engine. Callbacks
//! are provisional until `read` returns Ok: a damaged suffix invalidates a query.
use crate::{
    Error, Result,
    wire::{Event, Header, Input, Kind},
};
use std::{collections::HashMap, io::Read};

pub const REGISTER_COUNT: usize = 65;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Registers {
    pub bits: [u128; REGISTER_COUNT],
    pub known: [u64; 2],
}
impl Default for Registers {
    fn default() -> Self {
        Self {
            bits: [0; REGISTER_COUNT],
            known: [0; 2],
        }
    }
}
impl Registers {
    #[inline]
    pub fn is_known(&self, slot: usize) -> bool {
        self.known[slot / 64] & (1 << (slot % 64)) != 0
    }
    #[inline]
    pub fn all_known(&self) -> bool {
        self.known == [u64::MAX, 1]
    }
    #[inline]
    fn set(&mut self, slot: usize, value: u128) {
        self.bits[slot] = value;
        self.known[slot / 64] |= 1 << (slot % 64);
    }
}
#[derive(Default, Clone, Debug)]
pub struct Exit {
    pub target: u64,
    pub transfer: u64,
    pub expected_return: u64,
}
#[derive(Default, Clone, Debug)]
pub struct Group {
    pub seq: u64,
    pub pc: u64,
    pub word: u64,
    pub pre: Registers,
    pub post: Registers,
    pub pre_observed: [u64; 2],
    pub post_observed: [u64; 2],
    pub accesses: Vec<Event>,
    pub committed: bool,
    pub gap: bool,
    pub exit: Exit,
    pub reentered: bool,
    pub exit_seq: u64,
    pub gap_count: u64,
    pub gap_reason_mask: u64,
}
/// Validated instruction evidence without register snapshots. The private
/// replay can omit snapshot copies without exposing stale register bits.
pub struct EvidenceGroup<'a> {
    pub seq: u64,
    pub pc: u64,
    pub word: u64,
    pub accesses: &'a [Event],
    pub committed: bool,
    pub gap: bool,
    pub exit: &'a Exit,
    pub reentered: bool,
    pub exit_seq: u64,
    pub gap_count: u64,
    pub gap_reason_mask: u64,
}
/// Explicit values recorded at one event. Inherited register values are not
/// exposed by this view, so callers cannot confuse an observation with carry.
pub struct RegisterObservations<'a> {
    bits: &'a [u128; REGISTER_COUNT],
    pub observed: [u64; 2],
}
impl RegisterObservations<'_> {
    pub fn get(&self, slot: usize) -> Option<u128> {
        (slot < REGISTER_COUNT && self.observed[slot / 64] & (1 << (slot % 64)) != 0)
            .then(|| self.bits[slot])
    }
}
pub struct ObservationGroup<'a> {
    pub seq: u64,
    pub pc: u64,
    pub pre: RegisterObservations<'a>,
    pub post: RegisterObservations<'a>,
    pub accesses: &'a [Event],
    pub committed: bool,
}
pub struct Site {
    pub word: u32,
    pub text: Vec<u8>,
}
pub struct Module {
    pub size: u64,
    pub name: Vec<u8>,
}
pub struct Info {
    pub header: Header,
    pub chunked: bool,
    pub instructions: u64,
    pub reads: u64,
    pub writes: u64,
    pub gaps: u64,
    pub commits: u64,
    pub unknown_reads: u64,
    pub exits: u64,
    pub reentries: u64,
    pub unpositioned_gap: bool,
    pub boundary_capture: bool,
    pub external_followed: bool,
    pub ranges: Vec<(u64, u64)>,
    pub sites: HashMap<u64, Site>,
    pub modules: HashMap<u64, Module>,
    // Keep source insertion order when crossing into the existing query
    // presentation layer, including captures with overlapping module ranges.
    pub module_order: Vec<u64>,
    pub gap_reasons: [u64; 7],
    pub unsupported_mnemonics: HashMap<Vec<u8>, u64>,
}
impl Info {
    fn new(header: Header, chunked: bool) -> Self {
        Self {
            header,
            chunked,
            instructions: 0,
            reads: 0,
            writes: 0,
            gaps: 0,
            commits: 0,
            unknown_reads: 0,
            exits: 0,
            reentries: 0,
            unpositioned_gap: false,
            boundary_capture: false,
            external_followed: false,
            ranges: Vec::new(),
            sites: HashMap::new(),
            modules: HashMap::new(),
            module_order: Vec::new(),
            gap_reasons: [0; 7],
            unsupported_mnemonics: HashMap::new(),
        }
    }
    #[inline]
    fn in_code(&self, address: u64) -> bool {
        if self.ranges.is_empty() {
            address >= self.header.code_base
                && address - self.header.code_base < self.header.code_size
        } else {
            self.ranges
                .iter()
                .any(|&(base, size)| address >= base && address - base <= size - 4)
        }
    }
}
// These small helpers are also used by replay monomorphizations in the query
// crate. Export their bodies so validation does not add a call per predicate.
#[inline]
fn require(ok: bool, why: &'static str) -> Result<()> {
    if ok { Ok(()) } else { Err(Error::trace(why)) }
}
#[derive(Default)]
struct Active {
    group: Group,
    live: bool,
    capture: bool,
    registers: bool,
    observations: bool,
    expect_post: bool,
    post_started: bool,
    post_records: bool,
}
impl Active {
    #[inline]
    fn begin(
        &mut self,
        e: Event,
        carry: &Registers,
        capture: bool,
        registers: bool,
        observations: bool,
    ) {
        self.registers = capture && registers;
        self.observations = capture && observations;
        let g = &mut self.group;
        g.seq = e.seq;
        g.pc = e.pc;
        g.word = e.address;
        g.pre.known = carry.known;
        if self.registers {
            g.pre.bits.copy_from_slice(&carry.bits);
        }
        g.post.known = [0; 2];
        g.pre_observed = [0; 2];
        g.post_observed = [0; 2];
        g.accesses.clear();
        g.committed = false;
        g.gap = false;
        g.exit = Exit::default();
        g.reentered = false;
        g.exit_seq = 0;
        g.gap_count = 0;
        g.gap_reason_mask = 0;
        self.live = true;
        self.capture = capture;
        self.expect_post = e.detail == 1;
        self.post_started = false;
        self.post_records = false;
    }
    #[inline]
    fn start_post(&mut self) {
        if !self.post_started {
            self.group.post.known = self.group.pre.known;
            if self.registers {
                self.group.post.bits.copy_from_slice(&self.group.pre.bits);
            }
            self.post_started = true;
        }
    }
}
#[derive(Default)]
struct Boundary {
    open: bool,
    seq: u64,
    has_gap: bool,
}

// Fixed-code profile: a site's word cannot change after declaration. A small
// direct-mapped cache avoids repeated dictionary hashing on executed PCs.
// Collisions/misses use the full site map; every metadata record still validates.
struct SiteWords {
    pcs: [u64; 64],
    words: [u64; 64],
    valid: u64,
}
impl SiteWords {
    fn new() -> Self {
        Self {
            pcs: [0; 64],
            words: [0; 64],
            valid: 0,
        }
    }
    #[inline]
    fn matches(&mut self, info: &Info, pc: u64, word: u64) -> bool {
        let index = ((pc >> 2) & 63) as usize;
        if self.valid & (1u64 << index) != 0 && self.pcs[index] == pc {
            return self.words[index] == word;
        }
        if info
            .sites
            .get(&pc)
            .is_none_or(|site| site.word as u64 != word)
        {
            return false;
        }
        self.pcs[index] = pc;
        self.words[index] = word;
        self.valid |= 1u64 << index;
        true
    }
}

fn flush<F: FnMut(&Group, &Info)>(
    a: &mut Active,
    boundary: &mut Boundary,
    info: &Info,
    callback: &mut F,
) -> Result<()> {
    if !a.live {
        return Ok(());
    }
    let g = &mut a.group;
    require(
        !boundary.open || boundary.seq >= g.seq,
        "missing scope reentry record",
    )?;
    if g.exit.transfer != 0 {
        require(
            g.exit.transfer == 3 || g.gap,
            "scope exit without coverage gap",
        )?;
        require(g.pre.all_known(), "incomplete scope exit state")?;
        boundary.has_gap = g.gap;
    }
    require(
        (!a.post_records && g.accesses.is_empty()) || g.committed,
        "unconfirmed post-instruction records",
    )?;
    require(
        !a.expect_post || g.committed || g.gap,
        "missing required completion observation",
    )?;
    if a.capture {
        if !a.post_started && a.registers {
            g.post = Registers::default();
        }
        callback(g, info);
    }
    a.live = false;
    Ok(())
}

pub fn read<R: Read, F: FnMut(&Group, &Info)>(input: Input<R>, callback: F) -> Result<Info> {
    read_selected(input, |_| true, callback)
}

/// Validate every record and the complete END/suffix, retaining the same
/// register carry and structural/access checks. Materialize and call back only
/// for selected groups. Callbacks remain provisional until this returns Ok.
/// The selection predicate is called once per instruction in sequence order.
pub fn read_selected<R: Read, P: FnMut(u64) -> bool, F: FnMut(&Group, &Info)>(
    input: Input<R>,
    selected: P,
    callback: F,
) -> Result<Info> {
    read_impl::<true, false, _, _, _>(input, selected, callback)
}

/// Validate the complete stream while exposing only explicitly recorded
/// register values and accesses. No full pre/post register arrays are copied.
/// Callbacks remain provisional until the complete END and suffix validate.
pub fn read_observations<R: Read, F: FnMut(ObservationGroup<'_>, &Info)>(
    input: Input<R>,
    mut callback: F,
) -> Result<Info> {
    read_impl::<false, true, _, _, _>(
        input,
        |_| true,
        |g, info| {
            callback(
                ObservationGroup {
                    seq: g.seq,
                    pc: g.pc,
                    pre: RegisterObservations {
                        bits: &g.pre.bits,
                        observed: std::array::from_fn(|i| g.pre_observed[i] & g.pre.known[i]),
                    },
                    post: RegisterObservations {
                        bits: &g.post.bits,
                        observed: std::array::from_fn(|i| g.post_observed[i] & g.post.known[i]),
                    },
                    accesses: &g.accesses,
                    committed: g.committed,
                },
                info,
            );
        },
    )
}

/// Observe every instruction's accesses and coverage facts while validating
/// all65 register observations, boundaries, completion, END and suffix. No
/// inherited register snapshots are copied or exposed. Callbacks remain
/// provisional until Ok, exactly as for read_selected.
pub fn read_evidence<R: Read, F: FnMut(EvidenceGroup<'_>, &Info)>(
    input: Input<R>,
    mut callback: F,
) -> Result<Info> {
    read_impl::<false, false, _, _, _>(
        input,
        |_| true,
        |g, info| {
            callback(
                EvidenceGroup {
                    seq: g.seq,
                    pc: g.pc,
                    word: g.word,
                    accesses: &g.accesses,
                    committed: g.committed,
                    gap: g.gap,
                    exit: &g.exit,
                    reentered: g.reentered,
                    exit_seq: g.exit_seq,
                    gap_count: g.gap_count,
                    gap_reason_mask: g.gap_reason_mask,
                },
                info,
            );
        },
    )
}

fn read_impl<
    const REGISTERS: bool,
    const OBSERVATIONS: bool,
    R: Read,
    P: FnMut(u64) -> bool,
    F: FnMut(&Group, &Info),
>(
    mut input: Input<R>,
    mut selected: P,
    mut callback: F,
) -> Result<Info> {
    let mut info = Info::new(input.header, input.chunked);
    let mut active = Active::default();
    let mut carry = Registers::default();
    let mut boundary = Boundary::default();
    let mut site_words = SiteWords::new();
    loop {
        let e = input.next_event()?;
        match e.kind {
            Kind::Features => {
                let explicit = e.address == 3;
                if e.address != 1 && !explicit {
                    return Err(Error::unsupported("unsupported stream features"));
                }
                require(
                    !active.live
                        && !info.boundary_capture
                        && e.seq == 0
                        && e.pc == 0
                        && e.low <= 1
                        && e.high == 0
                        && e.detail == 0
                        && if explicit {
                            info.sites.is_empty()
                                && !info.unpositioned_gap
                                && info.modules.is_empty()
                                && (2..=64).contains(&e.size)
                        } else {
                            e.size == 0
                        },
                    "invalid stream features",
                )?;
                info.boundary_capture = true;
                info.external_followed = e.low == 1;
                if explicit {
                    for index in 0..e.size {
                        let range = input.next_event()?;
                        let h = &info.header;
                        require(
                            range.kind == Kind::CodeRange
                                && range.seq == index
                                && range.pc != 0
                                && range.address != 0
                                && range.pc & 3 == 0
                                && range.address & 3 == 0
                                && range.size == 0
                                && range.low == 0
                                && range.high == 0
                                && range.detail == 0
                                && range.pc >= h.code_base
                                && range.address <= h.code_size
                                && range.pc - h.code_base <= h.code_size - range.address,
                            "invalid code range metadata",
                        )?;
                        if let Some(&(base, size)) = info.ranges.last() {
                            require(
                                range.pc > base + size,
                                "overlapping or adjacent explicit ranges",
                            )?;
                        }
                        require(
                            index != 0 || range.pc == h.code_base,
                            "invalid first code range",
                        )?;
                        require(
                            index + 1 != e.size
                                || range.pc + range.address == h.code_base + h.code_size,
                            "invalid code range envelope",
                        )?;
                        info.ranges.push((range.pc, range.address));
                    }
                }
                continue;
            }
            Kind::Module => {
                require(
                    info.boundary_capture
                        && !active.live
                        && e.address != 0
                        && e.pc.checked_add(e.address).is_some()
                        && (1..=24).contains(&e.size)
                        && e.seq <= 4096 - e.size,
                    "invalid module metadata",
                )?;
                if !info.modules.contains_key(&e.pc) {
                    info.module_order.push(e.pc);
                }
                let module = info.modules.entry(e.pc).or_insert(Module {
                    size: e.address,
                    name: Vec::new(),
                });
                require(
                    e.seq == module.name.len() as u64 && (e.seq == 0 || module.size == e.address),
                    "inconsistent module metadata",
                )?;
                module
                    .name
                    .extend_from_slice(&e.bytes24()[..e.size as usize]);
                continue;
            }
            Kind::Site => {
                require(
                    info.in_code(e.pc)
                        && (1..=24).contains(&e.size)
                        && e.seq <= 256 - e.size
                        && e.address <= u32::MAX as u64,
                    "invalid site metadata",
                )?;
                let site = info.sites.entry(e.pc).or_insert(Site {
                    word: e.address as u32,
                    text: Vec::new(),
                });
                require(
                    site.word as u64 == e.address,
                    "changed code inside fixed-code profile",
                )?;
                require(e.seq == site.text.len() as u64, "noncontiguous site text")?;
                site.text.extend_from_slice(&e.bytes24()[..e.size as usize]);
                continue;
            }
            Kind::Exec => {
                flush(&mut active, &mut boundary, &info, &mut callback)?;
                require(
                    e.seq == info.instructions
                        && info.in_code(e.pc)
                        && (e.pc - info.header.code_base).is_multiple_of(4)
                        && e.address <= u32::MAX as u64
                        && e.detail <= 1
                        && e.size == 0
                        && e.low == 0
                        && e.high == 0
                        && site_words.matches(&info, e.pc, e.address),
                    "invalid instruction event",
                )?;
                active.begin(e, &carry, selected(e.seq), REGISTERS, OBSERVATIONS);
                info.instructions += 1;
                continue;
            }
            Kind::End => {
                flush(&mut active, &mut boundary, &info, &mut callback)?;
                require(
                    e.seq == info.instructions
                        && e.address == info.writes
                        && e.size == info.gaps
                        && e.low == info.reads
                        && e.high == info.commits
                        && e.detail == 2
                        && e.pc == 0,
                    "invalid completion counters",
                )?;
                input.finish()?;
                return Ok(info);
            }
            Kind::Gap if e.detail == 4 && e.seq == info.instructions && e.pc == 0 => {
                info.unpositioned_gap = true;
                info.gaps += 1;
                info.gap_reasons[4] += 1;
                continue;
            }
            _ => {}
        }
        require(active.live, "event outside its instruction")?;
        let a = &mut active;
        require(
            e.seq == a.group.seq && e.pc == a.group.pc,
            "event outside its instruction",
        )?;
        match e.kind {
            Kind::ScopeExit => {
                let g = &mut a.group;
                require(
                    info.boundary_capture
                        && !boundary.open
                        && g.exit.transfer == 0
                        && !g.committed
                        && !g.gap
                        && !a.expect_post
                        && !info.in_code(e.address)
                        && (1..=3).contains(&e.size)
                        && e.low == if e.size == 1 { e.pc.wrapping_add(4) } else { 0 }
                        && e.high == 0
                        && e.detail == 1,
                    "invalid scope exit",
                )?;
                g.exit = Exit {
                    target: e.address,
                    transfer: e.size,
                    expected_return: e.low,
                };
                boundary.open = true;
                boundary.seq = g.seq;
                info.exits += 1;
            }
            Kind::ScopeReenter => {
                let g = &mut a.group;
                require(
                    info.boundary_capture
                        && boundary.open
                        && boundary.has_gap
                        && !g.reentered
                        && e.address == boundary.seq
                        && g.seq == boundary.seq + 1
                        && !g.gap
                        && !g.committed
                        && !a.post_records
                        && e.size == 0
                        && e.low == 0
                        && e.high == 0
                        && e.detail == 1,
                    "invalid scope reentry",
                )?;
                require(g.pre.all_known(), "incomplete scope reentry state")?;
                g.reentered = true;
                g.exit_seq = boundary.seq;
                boundary.open = false;
                info.reentries += 1;
            }
            Kind::Gap => {
                let g = &mut a.group;
                require(
                    (1..=6).contains(&e.detail) && !g.committed,
                    "invalid gap record",
                )?;
                info.gaps += 1;
                info.gap_reasons[e.detail as usize] += 1;
                if e.detail == 1 {
                    let text = &info.sites[&e.pc].text;
                    let mnemonic = text
                        .split(|b| *b == b' ')
                        .next()
                        .unwrap_or_default()
                        .to_vec();
                    *info.unsupported_mnemonics.entry(mnemonic).or_default() += 1;
                }
                g.gap = true;
                a.post_started = true;
                g.post.known = [0; 2];
                if a.registers {
                    g.post.bits.fill(0);
                }
                carry = Registers::default();
                g.gap_count += 1;
                g.gap_reason_mask |= 1 << e.detail;
            }
            Kind::RegPre | Kind::RegPost => {
                let g = &a.group;
                require(
                    e.address < REGISTER_COUNT as u64
                        && e.size == if e.address < 33 { 8 } else { 16 }
                        && e.detail == 1
                        && (e.size != 8 || e.high == 0)
                        && !g.committed,
                    "invalid register observation",
                )?;
                let slot = e.address as usize;
                let value = e.low as u128 | ((e.high as u128) << 64);
                if e.kind == Kind::RegPre {
                    require(
                        !a.post_records && !g.gap && g.accesses.is_empty(),
                        "late pre-state observation",
                    )?;
                    carry.set(slot, value);
                    a.group.pre.known[slot / 64] |= 1 << (slot % 64);
                    if a.registers || a.observations {
                        a.group.pre.bits[slot] = value;
                    }
                    a.group.pre_observed[slot / 64] |= 1 << (slot % 64);
                } else {
                    require(a.expect_post, "unexpected post-state observation")?;
                    a.start_post();
                    a.post_records = true;
                    carry.set(slot, value);
                    a.group.post.known[slot / 64] |= 1 << (slot % 64);
                    if a.registers || a.observations {
                        a.group.post.bits[slot] = value;
                    }
                    a.group.post_observed[slot / 64] |= 1 << (slot % 64);
                }
            }
            Kind::Read | Kind::Write => {
                let g = &mut a.group;
                let h = &info.header;
                require(
                    a.expect_post
                        && !g.committed
                        && g.accesses.len() < 4
                        && (1..=16).contains(&e.size)
                        && e.address >= h.data_base
                        && e.size <= h.data_size
                        && e.address - h.data_base <= h.data_size - e.size
                        && e.detail <= 1
                        && (e.kind != Kind::Write || e.detail == 1),
                    "invalid memory event",
                )?;
                g.accesses.push(e);
                if e.kind == Kind::Read {
                    info.reads += 1;
                    if e.detail == 0 {
                        info.unknown_reads += 1;
                    }
                } else {
                    info.writes += 1;
                }
            }
            Kind::Commit => {
                require(
                    a.expect_post
                        && !a.group.committed
                        && e.address == 0
                        && e.size == 0
                        && e.low == 0
                        && e.high == 0
                        && e.detail == 1,
                    "invalid instruction commit",
                )?;
                a.start_post();
                a.group.committed = true;
                info.commits += 1;
            }
            _ => return Err(Error::trace("unexpected execution-state record")),
        }
    }
}

pub fn mix(hash: u64, value: u64) -> u64 {
    (hash ^ value).wrapping_mul(1099511628211)
}
/// Cross-language validation fingerprint, including every known payload bit,
/// explicit observation masks, actual accesses and boundary facts.
pub fn fingerprint(mut hash: u64, g: &Group) -> u64 {
    for v in [
        g.seq,
        g.pc,
        g.word,
        g.committed as u64,
        g.gap as u64,
        g.exit.target,
        g.exit.transfer,
        g.exit.expected_return,
        g.reentered as u64,
        g.exit_seq,
        g.gap_count,
        g.gap_reason_mask,
        g.accesses.len() as u64,
    ] {
        hash = mix(hash, v);
    }
    for e in &g.accesses {
        for v in e.words() {
            hash = mix(hash, v);
        }
    }
    for state in [&g.pre, &g.post] {
        for i in 0..REGISTER_COUNT {
            let known = state.is_known(i);
            hash = mix(hash, known as u64);
            if known {
                hash = mix(hash, state.bits[i] as u64);
                hash = mix(hash, (state.bits[i] >> 64) as u64);
            }
        }
    }
    for v in g.pre_observed.into_iter().chain(g.post_observed) {
        hash = mix(hash, v);
    }
    hash
}
