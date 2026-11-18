//! Exact recorded-value searches.
//! Selected hits are bounded; every transport frame is checked before output.
use super::*;
use std::collections::{HashMap, VecDeque};

#[derive(Clone, Default)]
struct Hit {
    key: usize,
    order: u64,
    ev: u64,
    pc: u64,
    address: u64,
    access: usize,
    size: usize,
    slot: Option<usize>,
    post: bool,
    write: Option<bool>,
    byte_offset: usize,
    access_size: u64,
    last_access: usize,
    last_ev: u64,
    last_pc: u64,
}
#[derive(Default)]
struct Page {
    total: u64,
    hits: VecDeque<Hit>,
}
impl Page {
    fn add(&mut self, hit: Hit, options: &Options) {
        let index = self.total;
        self.total += 1;
        if options.last != 0 {
            if self.hits.len() as u64 == options.last {
                self.hits.pop_front();
            }
            self.hits.push_back(hit);
        } else if index >= options.offset && (self.hits.len() as u64) < options.limit {
            self.hits.push_back(hit);
        }
    }
    fn truncated(&self, options: &Options) -> bool {
        (self.hits.len() as u64)
            < if options.last != 0 {
                self.total
            } else {
                self.total.saturating_sub(options.offset)
            }
    }
}
struct Options {
    path: String,
    from: u64,
    to: u64,
    limit: u64,
    offset: u64,
    last: u64,
    context: u64,
    read: bool,
    write: bool,
    across_events: bool,
    json: bool,
}
impl Default for Options {
    fn default() -> Self {
        Self {
            path: String::new(),
            from: 0,
            to: u64::MAX,
            limit: 20,
            offset: 0,
            last: 0,
            context: 0,
            read: false,
            write: false,
            across_events: false,
            json: false,
        }
    }
}
const NUMERIC_HELP: &str = "traceq find-value V FILE [--read|--write] [--from E --to E] [--limit N --offset M | --last N] [--context N] [--json]\ntraceq find-value FILE --value V [--value V ...] [same options]\n  Profile 2 GTSW/GTSC: exact unsigned numeric values, up to 128 bits.\n  Search known recorded register pre/post observations and memory accesses.\n  Register phases describe snapshots; --read/--write select memory only.\n  Inherited register state is not repeated. No subword or byte-substring matching.\n  Up to 64 distinct values; limit/offset/last apply per value, at most 4096 output hits.\n  One full validated scan; --context 1..200 adds a scan around the first shown hit.\n  Context for a register hit selects that register's full-width view.\n";
const BYTES_HELP: &str = "traceq find-value FILE --bytes HEX [--bytes HEX ...] [--across-events] [--read|--write] [--from E --to E] [--limit N --offset M | --last N] [--context N] [--json]\n  Profile 2 GTSW/GTSC: exact patterns in known recorded memory bytes.\n  Up to64 distinct patterns of1..64 bytes; contiguous hexadecimal digits.\n  Contiguous accesses may join within one instruction/direction without gaps.\n  Unknown accesses and event/direction/address changes break byte spans.\n  --across-events joins adjacent increasing addresses across events in a64-byte window.\n  With --read/--write, known disjoint opposite accesses may be skipped; overlaps break.\n  All unknown accesses, gaps and selected address/direction changes break runs.\n  An unpositioned gap suppresses joins across events or skipped accesses.\n  Historical recorded runs only; no current-memory or last-writer claim.\n  Reordered stores can leave complete content with no sequence hit.\n  Locate/disambiguate a shorter prefix; use mem-access --range B,L to choose the last required observation E, then mem-state --range B,L --checkpoint E:post before later gaps.\n  Run hits use first ev/access_index and last_ev/last_access_index, ordered by completion byte.\n  Pagination applies per pattern, at most4096 output hits.\n  One full validated scan; --context 1..200 adds a scan around the first shown hit.\n  In run mode --context selects bounded windows at both endpoints of the first hit.\n  Numeric --value matching stays exact; do not mix --bytes and numeric values.\n";

fn core_error(error: traceq_core::Error) -> CliError {
    CliError(error.message, 1)
}
fn pattern(text: &str) -> Result<Vec<u8>, CliError> {
    let text = text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))
        .unwrap_or(text);
    let invalid = || {
        CliError(
            "--bytes requires 1..64 bytes of contiguous hexadecimal digits".into(),
            2,
        )
    };
    if text.is_empty()
        || text.len() > 128
        || !text.len().is_multiple_of(2)
        || !text.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(invalid());
    }
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).map_err(|_| invalid())?, 16)
                .map_err(|_| invalid())
        })
        .collect()
}
fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub(super) fn run(args: &[String]) -> Result<Response, CliError> {
    let byte_mode = args.iter().any(|s| s == "--bytes");
    let mut options = Options {
        json: args.iter().any(|s| s == "--json"),
        ..Options::default()
    };
    let (mut values, mut patterns, mut positional) = (vec![], vec![], vec![]);
    let (mut has_values, mut has_limit, mut has_offset, mut has_last) =
        (false, false, false, false);
    let mut i = 1;
    while i < args.len() {
        let arg = &args[i];
        i += 1;
        match arg.as_str() {
            "--help" | "-h" => {
                return Ok(Response::text(if byte_mode {
                    BYTES_HELP
                } else {
                    NUMERIC_HELP
                }));
            }
            "--json" => {}
            "--bytes" => {
                let bytes = pattern(next(args, &mut i, arg)?)?;
                if !patterns.contains(&bytes) {
                    patterns.push(bytes);
                }
            }
            "--value" => {
                if byte_mode {
                    return Err(CliError(
                        "require FILE --bytes HEX... without numeric values".into(),
                        2,
                    ));
                }
                has_values = true;
                values.push(number128(next(args, &mut i, arg)?)?);
            }
            "--read" => options.read = true,
            "--write" => options.write = true,
            "--across-events" => options.across_events = true,
            "--from" => options.from = parse_u64(next(args, &mut i, arg)?, false)?,
            "--to" => options.to = parse_u64(next(args, &mut i, arg)?, false)?,
            "--limit" => {
                has_limit = true;
                options.limit = parse_page_number("find-value", next(args, &mut i, arg)?)?;
            }
            "--offset" => {
                has_offset = true;
                options.offset = parse_u64(next(args, &mut i, arg)?, true)?;
            }
            "--last" => {
                has_last = true;
                options.last = parse_page_number("find-value", next(args, &mut i, arg)?)?;
            }
            "--context" => {
                options.context = parse_u64(next(args, &mut i, arg)?, true)?;
                if options.context == 0 || options.context > 200 {
                    return Err(CliError("--context must be 1..200".into(), 2));
                }
            }
            _ if !arg.is_empty() && !arg.starts_with('-') => {
                if byte_mode && !positional.is_empty() {
                    return Err(CliError(format!("unsupported argument: {arg}"), 2));
                }
                positional.push(arg.clone());
            }
            _ => return Err(CliError(format!("unsupported argument: {arg}"), 2)),
        }
    }
    if options.across_events && !byte_mode {
        return Err(CliError("--across-events requires --bytes".into(), 2));
    }
    if byte_mode {
        if positional.len() != 1 || patterns.is_empty() {
            return Err(CliError("require FILE --bytes HEX...".into(), 2));
        }
        options.path = positional.remove(0);
    } else if has_values && positional.len() == 1 {
        options.path = positional.remove(0);
    } else if !has_values && positional.len() == 2 {
        values.push(number128(&positional[0])?);
        options.path = positional.remove(1);
    } else {
        return Err(CliError("require V FILE or FILE --value V...".into(), 2));
    }
    if options.read && options.write
        || options.from > options.to
        || options.limit == 0
        || options.limit > 4096
        || has_last && (options.last == 0 || options.last > 4096 || has_limit || has_offset)
    {
        return Err(CliError(
            "invalid filter, event window or pagination".into(),
            2,
        ));
    }
    let mut unique = vec![];
    for value in values {
        if !unique.contains(&value) {
            unique.push(value);
        }
    }
    let values = unique;
    let count = if byte_mode {
        patterns.len()
    } else {
        values.len()
    };
    if count == 0
        || count > 64
        || count as u64
            * if options.last != 0 {
                options.last
            } else {
                options.limit
            }
            > 4096
    {
        return Err(CliError(
            if byte_mode {
                "require 1..64 byte patterns and at most 4096 output hits across patterns"
            } else {
                "require 1..64 values and at most 4096 output hits across values"
            }
            .into(),
            2,
        ));
    }
    if byte_mode {
        find_bytes(options, patterns)
    } else {
        find_numbers(options, values)
    }
}

fn find_numbers(options: Options, values: Vec<u128>) -> Result<Response, CliError> {
    let index: HashMap<_, _> = values.iter().enumerate().map(|(i, v)| (*v, i)).collect();
    let registers = !options.read && !options.write;
    let mut all: Vec<Page> = (0..values.len()).map(|_| Page::default()).collect();
    let mut memory: Vec<Page> = (0..values.len()).map(|_| Page::default()).collect();
    let (mut order, mut unknown_reads) = (0, 0u64);
    let mut match_value = |value: u128, mut hit: Hit| {
        let Some(&key) = index.get(&value) else {
            return;
        };
        hit.key = key;
        hit.order = order;
        order += 1;
        if registers && hit.write.is_some() {
            memory[key].add(hit.clone(), &options);
        }
        all[key].add(hit, &options);
    };
    let info = replay::read_observations(input(&options.path).map_err(core_error)?, |g, _| {
        if g.seq < options.from || g.seq > options.to {
            return;
        }
        if registers {
            for post in [false, true] {
                if post && !g.committed {
                    continue;
                }
                let state = if post { &g.post } else { &g.pre };
                for (bank, &bits) in state.observed.iter().enumerate() {
                    let mut bits = bits;
                    while bits != 0 {
                        let slot = bank * 64 + bits.trailing_zeros() as usize;
                        bits &= bits - 1;
                        if let Some(value) = state.get(slot) {
                            match_value(
                                value,
                                Hit {
                                    ev: g.seq,
                                    pc: g.pc,
                                    slot: Some(slot),
                                    size: if slot < 33 { 8 } else { 16 },
                                    post,
                                    ..Hit::default()
                                },
                            );
                        }
                    }
                }
            }
        }
        for (access, a) in g.accesses.iter().enumerate() {
            let write = a.kind == Kind::Write;
            if options.read && write || options.write && !write {
                continue;
            }
            if a.detail == 0 {
                unknown_reads += 1;
                continue;
            }
            match_value(
                a.low as u128 | ((a.high as u128) << 64),
                Hit {
                    ev: g.seq,
                    pc: g.pc,
                    address: a.address,
                    size: a.size as usize,
                    write: Some(write),
                    access,
                    ..Hit::default()
                },
            );
        }
    })
    .map_err(core_error)?;
    let pages = if registers && info.unpositioned_gap {
        memory
    } else {
        all
    };
    finish(
        options,
        &info,
        pages,
        &values,
        &[],
        unknown_reads,
        registers,
    )
}

struct Span {
    base: u64,
    write: bool,
    bytes: Vec<u8>,
    starts: Vec<usize>,
    accesses: Vec<usize>,
}
impl Span {
    fn new() -> Self {
        Self {
            base: 0,
            write: false,
            bytes: Vec::with_capacity(64),
            starts: Vec::with_capacity(4),
            accesses: Vec::with_capacity(4),
        }
    }
    fn flush(
        &mut self,
        g: &replay::EvidenceGroup<'_>,
        patterns: &[Vec<u8>],
        candidates: &[Vec<usize>; 256],
        pages: &mut [Page],
        options: &Options,
        order: &mut u64,
    ) {
        for pos in 0..self.bytes.len() {
            for &key in &candidates[self.bytes[pos] as usize] {
                let pattern = &patterns[key];
                if !self.bytes[pos..].starts_with(pattern) {
                    continue;
                }
                let first = self.starts.partition_point(|&at| at <= pos) - 1;
                let last = self.starts.partition_point(|&at| at < pos + pattern.len()) - 1;
                let access = self.accesses[first];
                pages[key].add(
                    Hit {
                        key,
                        order: *order,
                        ev: g.seq,
                        pc: g.pc,
                        address: self.base + pos as u64,
                        size: pattern.len(),
                        write: Some(self.write),
                        access,
                        byte_offset: pos - self.starts[first],
                        access_size: g.accesses[access].size,
                        last_access: self.accesses[last],
                        ..Hit::default()
                    },
                    options,
                );
                *order += 1;
            }
        }
        self.bytes.clear();
        self.starts.clear();
        self.accesses.clear();
    }
}
fn find_bytes(options: Options, patterns: Vec<Vec<u8>>) -> Result<Response, CliError> {
    if options.across_events {
        return find_byte_runs(options, patterns);
    }
    let mut candidates: [Vec<usize>; 256] = std::array::from_fn(|_| vec![]);
    for (key, p) in patterns.iter().enumerate() {
        candidates[p[0] as usize].push(key);
    }
    let mut pages: Vec<Page> = (0..patterns.len()).map(|_| Page::default()).collect();
    let (mut order, mut unknown_reads) = (0, 0);
    let mut span = Span::new();
    let info = replay::read_evidence(input(&options.path).map_err(core_error)?, |g, _| {
        if g.seq < options.from || g.seq > options.to {
            return;
        }
        for (access, a) in g.accesses.iter().enumerate() {
            let write = a.kind == Kind::Write;
            if options.read && write || options.write && !write {
                span.flush(&g, &patterns, &candidates, &mut pages, &options, &mut order);
                continue;
            }
            if a.detail == 0 {
                unknown_reads += 1;
                span.flush(&g, &patterns, &candidates, &mut pages, &options, &mut order);
                continue;
            }
            if !span.bytes.is_empty()
                && (g.gap
                    || write != span.write
                    || a.address != span.base + span.bytes.len() as u64)
            {
                span.flush(&g, &patterns, &candidates, &mut pages, &options, &mut order);
            }
            if span.bytes.is_empty() {
                span.base = a.address;
                span.write = write;
            }
            span.starts.push(span.bytes.len());
            span.accesses.push(access);
            span.bytes.extend_from_slice(
                &(a.low as u128 | ((a.high as u128) << 64)).to_le_bytes()[..a.size as usize],
            );
        }
        span.flush(&g, &patterns, &candidates, &mut pages, &options, &mut order);
    })
    .map_err(core_error)?;
    finish(options, &info, pages, &[], &patterns, unknown_reads, false)
}

#[derive(Clone, Copy, Default)]
struct ByteLocation {
    ev: u64,
    pc: u64,
    address: u64,
    access: usize,
    size: u64,
    offset: usize,
    local_epoch: u64,
}
/// Only the last 64 adjacent recorded bytes, never an inferred memory image.
struct ByteRun {
    bytes: [u8; 64],
    locations: [ByteLocation; 64],
    next: usize,
    len: usize,
    write: bool,
}
impl ByteRun {
    fn new() -> Self {
        Self {
            bytes: [0; 64],
            locations: [ByteLocation::default(); 64],
            next: 0,
            len: 0,
            write: false,
        }
    }
    fn clear(&mut self) {
        self.len = 0;
    }
    fn location(&self, back: usize) -> ByteLocation {
        self.locations[(self.next + 64 - back) % 64]
    }
    fn push(&mut self, byte: u8, location: ByteLocation) {
        self.bytes[self.next] = byte;
        self.locations[self.next] = location;
        self.next = (self.next + 1) % 64;
        self.len = (self.len + 1).min(64);
    }
    fn matches(&self, pattern: &[u8]) -> bool {
        pattern.len() <= self.len
            && pattern
                .iter()
                .enumerate()
                .all(|(i, b)| self.bytes[(self.next + 64 - pattern.len() + i) % 64] == *b)
    }
}
fn find_byte_runs(options: Options, patterns: Vec<Vec<u8>>) -> Result<Response, CliError> {
    let mut candidates: [Vec<usize>; 256] = std::array::from_fn(|_| vec![]);
    for (key, p) in patterns.iter().enumerate() {
        candidates[*p.last().unwrap() as usize].push(key);
    }
    let mut pages: Vec<Page> = (0..patterns.len()).map(|_| Page::default()).collect();
    // A late unpositioned gap invalidates joins. Keep independently paginated
    // intra-instruction matches during the same scan; filtering a page is wrong.
    let mut local_pages: Vec<Page> = (0..patterns.len()).map(|_| Page::default()).collect();
    let (mut order, mut unknown_reads, mut local_epoch) = (0, 0, 0u64);
    let mut run = ByteRun::new();
    let info = replay::read_evidence(input(&options.path).map_err(core_error)?, |g, _| {
        if g.seq < options.from || g.seq > options.to {
            return;
        }
        local_epoch = local_epoch.wrapping_add(1);
        for (access, a) in g.accesses.iter().enumerate() {
            if g.gap {
                run.clear();
            }
            let write = a.kind == Kind::Write;
            let selected = !(options.read && write || options.write && !write);
            if a.detail == 0 {
                if selected {
                    unknown_reads += 1;
                }
                run.clear();
                local_epoch = local_epoch.wrapping_add(1);
                continue;
            }
            if !selected {
                // Ignore only known disjoint accesses of the other direction.
                // Overlaps cannot establish an uninterrupted recorded byte run.
                if run.len != 0
                    && a.address <= run.location(1).address
                    && a.address.saturating_add(a.size - 1) >= run.location(run.len).address
                {
                    run.clear();
                }
                local_epoch = local_epoch.wrapping_add(1);
                continue;
            }
            if run.len != 0
                && (write != run.write || run.location(1).address.checked_add(1) != Some(a.address))
            {
                run.clear();
            }
            run.write = write;
            let bytes = (a.low as u128 | ((a.high as u128) << 64)).to_le_bytes();
            for (offset, byte) in bytes[..a.size as usize].iter().copied().enumerate() {
                let last = ByteLocation {
                    ev: g.seq,
                    pc: g.pc,
                    address: a.address + offset as u64,
                    access,
                    size: a.size,
                    offset,
                    local_epoch,
                };
                run.push(byte, last);
                for &key in &candidates[byte as usize] {
                    let pattern = &patterns[key];
                    if !run.matches(pattern) {
                        continue;
                    }
                    let first = run.location(pattern.len());
                    let hit = Hit {
                        key,
                        order,
                        ev: first.ev,
                        pc: first.pc,
                        address: first.address,
                        access: first.access,
                        size: pattern.len(),
                        write: Some(write),
                        byte_offset: first.offset,
                        access_size: first.size,
                        last_access: last.access,
                        last_ev: last.ev,
                        last_pc: last.pc,
                        ..Hit::default()
                    };
                    if first.local_epoch == last.local_epoch {
                        local_pages[key].add(hit.clone(), &options);
                    }
                    pages[key].add(hit, &options);
                    order += 1;
                }
            }
        }
        if g.gap {
            run.clear();
        }
    })
    .map_err(core_error)?;
    finish(
        options,
        &info,
        if info.unpositioned_gap {
            local_pages
        } else {
            pages
        },
        &[],
        &patterns,
        unknown_reads,
        false,
    )
}

fn finish(
    options: Options,
    info: &Info,
    pages: Vec<Page>,
    values: &[u128],
    patterns: &[Vec<u8>],
    unknown_reads: u64,
    registers: bool,
) -> Result<Response, CliError> {
    let byte_mode = !patterns.is_empty();
    let mut hits = vec![];
    let mut total = 0;
    let mut truncated = false;
    let mut per_key = vec![];
    for (key, page) in pages.into_iter().enumerate() {
        let more = page.truncated(&options);
        total += page.total;
        truncated |= more;
        let mut row = json!({"total":page.total,"shown":page.hits.len(),"truncated":more});
        row[if byte_mode { "bytes" } else { "val" }] = if byte_mode {
            json!(hex_bytes(&patterns[key]))
        } else {
            hx(values[key])
        };
        per_key.push(row);
        hits.extend(page.hits);
    }
    hits.sort_by_key(|h| h.order);
    let mut continuation = String::new();
    if truncated && options.last == 0 {
        continuation = format!("traceq find-value {}", shell_arg(&options.path));
        if byte_mode {
            for p in patterns {
                continuation += &format!(" --bytes {}", hex_bytes(p));
            }
        } else {
            for v in values {
                continuation += &format!(" --value 0x{v:x}");
            }
        }
        if options.read {
            continuation += " --read";
        }
        if options.write {
            continuation += " --write";
        }
        if options.across_events {
            continuation += " --across-events";
        }
        continuation += &format!(
            " --from {} --to {} --limit {} --offset {}",
            options.from,
            options.to,
            options.limit,
            options.offset.wrapping_add(options.limit)
        );
        if options.context != 0 {
            continuation += &format!(" --context {}", options.context);
        }
        if options.json {
            continuation += " --json";
        }
    }
    let mut context_command = String::new();
    let mut context_rows = vec![];
    if let Some(first) = hits.first() {
        let span = if options.context != 0 {
            options.context
        } else {
            2
        };
        let last_ev = if options.across_events {
            first.last_ev
        } else {
            first.ev
        };
        let anchors = if last_ev != first.ev {
            format!("--at-ev {} --at-ev {last_ev}", first.ev)
        } else {
            format!("--at-ev {}", first.ev)
        };
        context_command = format!(
            "traceq context {} {anchors} --before {span} --after {span} --limit {}",
            shell_arg(&options.path),
            (2 * span + 1) * if last_ev != first.ev { 2 } else { 1 }
        );
        let selected = if let Some(slot) = first.slot {
            let name = slot_name(slot);
            context_command += &format!(" --reg {name}");
            vec![reg(&name)?]
        } else {
            vec![]
        };
        if options.json {
            context_command += " --json";
        }
        if options.context != 0 {
            let begin = first.ev.saturating_sub(span);
            let end = first.ev.saturating_add(span);
            let last_begin = last_ev.saturating_sub(span);
            let last_end = last_ev.saturating_add(span);
            let mut groups = vec![];
            let context_info = replay::read_selected(
                input(&options.path).map_err(core_error)?,
                |seq| seq >= begin && seq <= end || seq >= last_begin && seq <= last_end,
                |g, _| groups.push(g.clone()),
            )
            .map_err(core_error)?;
            for group in groups {
                context_rows.push(context_row(
                    &group,
                    &context_info,
                    &selected,
                    group.seq == first.ev || group.seq == last_ev,
                    false,
                    0,
                ));
            }
        }
    }
    let rows=hits.iter().map(|hit|{
        let mut row=json!({"ev":hit.ev,"pc":hx(hit.pc),"off":hx(hit.pc.wrapping_sub(info.header.code_base)),"size":hit.size,"known":true});
        row[if byte_mode{"bytes"}else{"val"}]=if byte_mode{json!(hex_bytes(&patterns[hit.key]))}else{hx(values[hit.key])};
        if let Some(write)=hit.write {
            row["kind"]=json!("mem");row["lane"]=json!(if write{"mem_w"}else{"mem_r"});row["rw"]=json!(if write{"w"}else{"r"});row["addr"]=hx(hit.address);row["access_index"]=json!(hit.access);
            if byte_mode{row["byte_offset"]=json!(hit.byte_offset);row["access_size"]=json!(hit.access_size);row["last_access_index"]=json!(hit.last_access);}
            if options.across_events {row["last_ev"]=json!(hit.last_ev);row["last_pc"]=hx(hit.last_pc);row["last_off"]=hx(hit.last_pc.wrapping_sub(info.header.code_base));}
        } else {let name=slot_name(hit.slot.unwrap());let phase=if hit.post{"post"}else{"pre"};row["kind"]=json!("reg");row["reg"]=json!(name);row["phase"]=json!(phase);row["lane"]=json!(format!("reg_{phase}:{name}"));}
        row
    }).collect::<Vec<_>>();
    let mut meta=json!({"total":total,"shown":rows.len(),"truncated":truncated,"next":continuation,"context_command":context_command,"instructions":info.instructions,"capture_gaps":info.gaps,"unpositioned_gap":info.unpositioned_gap,"register_matches_suppressed":registers&&info.unpositioned_gap,"skipped_unknown_reads":unknown_reads,"code_base":hx(info.header.code_base),"matching":if byte_mode{"recorded_memory_byte_subsequence"}else{"exact_unsigned_numeric_value"},"scope":if byte_mode{"known recorded memory bytes; contiguous spans stay within one instruction/direction without gaps; no current-memory or writer-provenance claim"}else{"recorded register observations and memory access values; no current-memory or writer-provenance claim"},"validation":"full stream through END","scans":if options.context!=0&&!hits.is_empty(){2}else{1}}).as_object().unwrap().clone();
    meta.insert(
        if byte_mode { "patterns" } else { "values" }.into(),
        json!(per_key),
    );
    if options.across_events {
        meta.insert("matching".into(), json!("recorded_memory_byte_run"));
        meta.insert("scope".into(), json!("adjacent increasing recorded byte accesses across events; selected direction may skip known disjoint opposite accesses; gaps, unknowns, overlaps and selected address/direction changes break runs; historical observations only, no current-memory or writer-provenance claim"));
        meta.insert("ordering".into(), json!("match completion byte, then pattern order; ev/access_index identify the first byte, last_ev/last_access_index the last byte"));
        meta.insert(
            "cross_event_matches_suppressed".into(),
            json!(info.unpositioned_gap),
        );
    }
    scope_meta(&mut meta, info);
    if options.context == 0 || hits.is_empty() {
        return Ok(response(rows, Value::Object(meta), options.json));
    }
    if options.json {
        let mut context = json!({"ev":hits[0].ev,"rows":context_rows});
        if options.across_events {
            context["last_ev"] = json!(hits[0].last_ev);
        }
        Ok(Response::text(format!(
            "{}\n",
            json!({"data":rows,"meta":meta,"context":context})
        )))
    } else {
        let mut result = response(rows, Value::Object(meta), false);
        result
            .stdout
            .extend_from_slice(format!("context: {}\n", json!(context_rows)).as_bytes());
        Ok(result)
    }
}
