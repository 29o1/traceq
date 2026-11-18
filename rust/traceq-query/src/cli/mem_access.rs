use super::*;
use std::ops::{Range, RangeInclusive};

const COLUMNS: [&str; 9] = [
    "ev",
    "pc",
    "off",
    "rw",
    "addr",
    "size",
    "known",
    "val",
    "access_index",
];

struct Options<'a> {
    path: &'a str,
    ranges: Vec<Range<u64>>,
    events: RangeInclusive<u64>,
    direction: Option<Kind>,
    limit: usize,
    offset: u64,
    compact: bool,
    access_index: bool,
    json: bool,
}

impl<'a> Options<'a> {
    fn parse(args: &'a [String]) -> Result<Option<Self>, CliError> {
        let json = args.iter().any(|a| a == "--json");
        let mut path = "";
        let mut ranges = Vec::new();
        let (mut from, mut to, mut limit, mut offset) = (0, u64::MAX, 20, 0);
        let (mut read, mut write, mut compact) = (false, false, false);
        let mut access_index = false;
        let mut i = 1;
        while i < args.len() {
            let flag = &args[i];
            i += 1;
            match flag.as_str() {
                "--help" | "-h" => return Ok(None),
                "--json" => {}
                "--range" => {
                    let value = next(args, &mut i, flag)?;
                    if ranges.len() == 64 {
                        return Err("mem-access accepts at most 64 ranges".to_string().into());
                    }
                    let (base, len) = parse_range(value)?;
                    ranges.push(base..base + len);
                }
                "--from" => from = parse_u64(next(args, &mut i, flag)?, false)?,
                "--to" => to = parse_u64(next(args, &mut i, flag)?, false)?,
                "--limit" => limit = parse_page_number("mem-access", next(args, &mut i, flag)?)?,
                "--offset" => offset = parse_u64(next(args, &mut i, flag)?, false)?,
                "--read" => read = true,
                "--write" => write = true,
                "--compact" => compact = true,
                "--access-index" => access_index = true,
                "--addr" | "--len" | "--size" => {
                    return Err(format!("unsupported memory selector {flag}; {RANGE_HINT}").into());
                }
                "--at-ev" | "--at-seq" | "--phase" | "--checkpoint" => {
                    return Err(format!("{flag} does not apply to mem-access; use --from/--to for events or mem-state for a checkpoint").into());
                }
                _ if !flag.starts_with('-') && path.is_empty() => path = flag,
                _ => return Err(format!("unsupported argument: {flag}").into()),
            }
        }

        if path.is_empty() || !(1..=4096).contains(&limit) || from > to || read && write {
            return Err("invalid file, limits, window or phase".to_string().into());
        }
        if ranges.is_empty() {
            return Err(format!("--range is required; {RANGE_HINT}").into());
        }
        if compact && !json {
            return Err(
                "--compact requires last-writers, mem-access or mem-state --json (profile 2)"
                    .to_string()
                    .into(),
            );
        }
        if access_index && !json {
            return Err("--access-index requires mem-access --json"
                .to_string()
                .into());
        }
        let direction = if read {
            Some(Kind::Read)
        } else if write {
            Some(Kind::Write)
        } else {
            None
        };
        Ok(Some(Self {
            path,
            ranges,
            events: from..=to,
            direction,
            limit: limit as usize,
            offset,
            compact,
            access_index,
            json,
        }))
    }
}

pub(super) fn run(args: &[String]) -> Result<Response, CliError> {
    let Some(options) = Options::parse(args)? else {
        return Ok(Response::text(include_str!("../cli_state_help.txt")));
    };
    let mut rows = Vec::new();
    let mut sources = Vec::new();
    let mut total = 0;
    let stream = input(options.path)?;
    let header = stream.header;
    let range_ok = options
        .ranges
        .iter()
        .all(|r| header.contains_data(r.start, r.end - r.start));
    let info = replay::read_evidence(stream, |g, _| {
        if !range_ok || !options.events.contains(&g.seq) {
            return;
        }
        for (ordinal, a) in g.accesses.iter().enumerate() {
            if options.direction.is_some_and(|kind| a.kind != kind)
                || !options
                    .ranges
                    .iter()
                    .any(|r| a.address < r.end && a.address + a.size > r.start)
            {
                continue;
            }
            let index = total;
            total += 1;
            if index < options.offset || rows.len() >= options.limit {
                continue;
            }
            let rw = if a.kind == Kind::Read { "r" } else { "w" };
            let source = memory_source(a.kind, g.word);
            let off = g.pc.wrapping_sub(header.code_base);
            let value = if a.detail == 1 {
                hx(a.low as u128 | ((a.high as u128) << 64))
            } else {
                Value::Null
            };
            let mut row = if options.compact {
                sources.push(source);
                json!([
                    g.seq,
                    hx(g.pc),
                    hx(off),
                    rw,
                    hx(a.address),
                    a.size,
                    a.detail == 1,
                    value
                ])
            } else {
                json!({
                    "ev": g.seq,
                    "pc": hx(g.pc),
                    "off": hx(off),
                    "rw": rw,
                    "addr": hx(a.address),
                    "size": a.size,
                    "known": a.detail == 1,
                    "val": value,
                    "value_source": source
                })
            };
            if options.access_index {
                if let Value::Array(cells) = &mut row {
                    cells.push(json!(ordinal));
                } else {
                    row["access_index"] = json!(ordinal);
                }
            }
            rows.push(row);
        }
    })?;
    if !range_ok {
        return Err("query extends outside declared data range"
            .to_string()
            .into());
    }
    let mut meta = capture_meta(&info);
    meta.extend(page_meta(args, total, rows.len(), options.offset));
    if options.compact {
        compact_page(&mut rows, sources, options.access_index, &mut meta);
    }
    Ok(response(rows, Value::Object(meta), options.json))
}

fn compact_page(
    rows: &mut [Value],
    sources: Vec<&'static str>,
    indexed: bool,
    meta: &mut Map<String, Value>,
) {
    let columns = if indexed {
        &COLUMNS[..]
    } else {
        &COLUMNS[..COLUMNS.len() - 1]
    };
    let mut writes = rows
        .iter()
        .zip(&sources)
        .filter(|(row, _)| row[3] == "w")
        .map(|(_, &source)| source);
    let write_source = writes.next().unwrap_or(MEMORY_WRITE_SOURCE);
    if writes.any(|source| source != write_source) {
        // Column pages have one source per direction. Mixed pages retain named rows.
        for (row, source) in rows.iter_mut().zip(sources) {
            let Value::Array(cells) = std::mem::take(row) else {
                unreachable!()
            };
            let mut fields: Map<String, Value> = columns
                .iter()
                .copied()
                .zip(cells)
                .map(|(key, value)| (key.into(), value))
                .collect();
            fields.insert("value_source".into(), json!(source));
            *row = Value::Object(fields);
        }
        meta.insert("compact_fallback".into(), json!("mixed_write_sources"));
    } else {
        let format = if indexed { "columns-v2" } else { "columns-v1" };
        meta.insert("mem_access_format".into(), json!(format));
        meta.insert("columns".into(), json!(columns));
        meta.insert(
            "value_sources".into(),
            json!({"r":MEMORY_READ_SOURCE,"w":write_source}),
        );
    }
}
