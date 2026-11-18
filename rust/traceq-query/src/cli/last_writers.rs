use super::*;
use std::{
    fmt::Write as _,
    io::{Cursor, Read},
};
use traceq_core::wire::{CHUNK_MAGIC, Event, FLAT_MAGIC};

struct Selection {
    pub base: u64,
    pub len: u64,
    pub at: Option<u64>,
    pub limit: u64,
    pub offset: u64,
    pub compact: bool,
    pub runs: bool,
}

struct Gap {
    seq: u64,
    pc: u64,
    reasons: u64,
    exit: replay::Exit,
    reentry: Option<u64>,
}

impl Gap {
    fn render(&self, info: &Info) -> Value {
        let scope_exit = if self.exit.transfer == 0 {
            Value::Null
        } else {
            json!({
                "transfer": transfer(self.exit.transfer),
                "target": location(self.exit.target, info),
                "reentry_ev": self.reentry,
                "memory_effects": "unobserved"
            })
        };
        json!({
            "ev": self.seq,
            "pc": hx(self.pc),
            "pc_offset": hx(self.pc.wrapping_sub(info.header.code_base)),
            "reasons": reasons(self.reasons),
            "scope_exit": scope_exit
        })
    }
}

#[derive(Default)]
struct CompactGaps {
    index_by_event: BTreeMap<u64, usize>,
    rows: Vec<Value>,
}

impl CompactGaps {
    fn reference(&mut self, gap: &Gap, info: &Info) -> usize {
        // Each finalized event has a single first-gap record. Render it only
        // when the first byte on this page references it.
        *self.index_by_event.entry(gap.seq).or_insert_with(|| {
            let index = self.rows.len();
            self.rows.push(gap.render(info));
            index
        })
    }
}

struct ObservedWrite {
    value: u8,
    seq: u64,
    pc: u64,
    epoch: u64,
    first_gap: Option<Gap>,
}

impl ObservedWrite {
    fn is_current(&self, info: &Info) -> bool {
        self.first_gap.is_none() && !info.unpositioned_gap
    }
}

struct History {
    bytes: Vec<Option<ObservedWrite>>,
    epoch: u64,
    last_gap_seq: u64,
}

impl History {
    fn new(len: usize) -> Self {
        Self {
            bytes: (0..len).map(|_| None).collect(),
            epoch: 0,
            last_gap_seq: 0,
        }
    }

    fn observe(&mut self, group: replay::EvidenceGroup<'_>, base: u64) {
        // A reentry can annotate an earlier exit, but does not restore the bytes.
        if group.reentered {
            for write in self.bytes.iter_mut().flatten() {
                if let Some(gap) = &mut write.first_gap
                    && gap.exit.transfer != 0
                    && gap.seq == group.exit_seq
                {
                    gap.reentry = Some(group.seq);
                }
            }
        }
        if group.gap {
            self.epoch += group.gap_count;
            self.last_gap_seq = group.seq;
            for write in self.bytes.iter_mut().flatten() {
                if write.first_gap.is_none() {
                    write.first_gap = Some(Gap {
                        seq: group.seq,
                        pc: group.pc,
                        reasons: group.gap_reason_mask,
                        exit: group.exit.clone(),
                        reentry: None,
                    });
                }
            }
        }
        let end = base + self.bytes.len() as u64;
        for access in group.accesses.iter().filter(|a| a.kind == Kind::Write) {
            for address in base.max(access.address)..end.min(access.address + access.size) {
                let lane = address - access.address;
                self.bytes[(address - base) as usize] =
                    (access.detail == 1).then(|| ObservedWrite {
                        value: if lane < 8 {
                            (access.low >> (lane * 8)) as u8
                        } else {
                            (access.high >> ((lane - 8) * 8)) as u8
                        },
                        seq: group.seq,
                        pc: group.pc,
                        epoch: self.epoch,
                        first_gap: None,
                    });
            }
        }
    }

    fn row(
        &self,
        address: u64,
        observed: Option<&ObservedWrite>,
        info: &Info,
        compact_gaps: Option<&mut CompactGaps>,
    ) -> Value {
        // A gap invalidates present knowledge while retaining historical evidence.
        let current = observed.filter(|write| write.is_current(info));
        let mut row = json!({
            "address": hx(address),
            "known": current.is_some(),
            "value": current.map(|write| hx(write.value)),
            "writer_seq": current.map(|write| write.seq),
            "pc": current.map(|write| hx(write.pc))
        });
        if let Some(write) = current {
            row["pc_offset"] = hx(write.pc.wrapping_sub(info.header.code_base));
        }
        row["last_observed_write"] = if let Some(write) = observed {
            let mut evidence = self.evidence(write, info, compact_gaps);
            evidence["value"] = hx(write.value);
            evidence
        } else {
            Value::Null
        };
        row
    }

    fn evidence(
        &self,
        write: &ObservedWrite,
        info: &Info,
        table: Option<&mut CompactGaps>,
    ) -> Value {
        let gaps_since = self.epoch - write.epoch;
        let mut evidence = json!({
            "writer_seq": write.seq,
            "pc": hx(write.pc),
            "pc_offset": hx(write.pc.wrapping_sub(info.header.code_base)),
            "gaps_since": gaps_since,
            "latest_gap_ev": (gaps_since != 0).then_some(self.last_gap_seq)
        });
        let gap = write.first_gap.as_ref();
        if let Some(table) = table {
            evidence["first_located_gap_ref"] = json!(gap.map(|gap| table.reference(gap, info)));
        } else {
            evidence["first_located_gap"] = gap.map_or(Value::Null, |gap| gap.render(info));
        }
        evidence
    }

    fn runs(&self, mut address: u64, info: &Info, gaps: &mut CompactGaps) -> Vec<Value> {
        // Writes from the same event share the PC and the same subsequent gap
        // history. Group only adjacent bytes and only within the current page.
        let event = |byte: &Option<ObservedWrite>| byte.as_ref().map(|write| write.seq);
        let mut rows = Vec::new();
        for run in self.bytes.chunk_by(|a, b| event(a) == event(b)) {
            let first = run[0].as_ref();
            let evidence = if let Some(write) = first {
                let mut hex = String::with_capacity(run.len() * 2);
                for byte in run.iter().flatten() {
                    write!(&mut hex, "{:02x}", byte.value).expect("write to a string");
                }
                let mut evidence = self.evidence(write, info, Some(gaps));
                evidence["data_hex"] = Value::String(hex);
                evidence
            } else {
                Value::Null
            };
            rows.push(json!({
                "address": hx(address),
                "size": run.len(),
                "known": first.is_some_and(|write| write.is_current(info)),
                "last_observed_write": evidence
            }));
            address += run.len() as u64;
        }
        rows
    }
}

fn profile2(
    args: &[String],
    stream: Input<impl Read>,
    selection: Selection,
    json: bool,
) -> Result<Response, CliError> {
    let start = selection.offset.min(selection.len);
    let shown = selection.limit.min(selection.len - start);
    let page_base = selection.base + start;
    let mut history = History::new(shown as usize);
    let range_ok = stream.header.contains_data(selection.base, selection.len);
    let info = replay::read_evidence(stream, |group, _| {
        if range_ok && shown != 0 && selection.at.is_none_or(|at| group.seq <= at) {
            history.observe(group, page_base);
        }
    })?;
    if !range_ok {
        return Err("query extends outside declared data range"
            .to_string()
            .into());
    }
    if selection.at.is_some_and(|at| at >= info.instructions) {
        return Err("requested instruction is outside the capture"
            .to_string()
            .into());
    }
    let mut gaps = CompactGaps::default();
    let rows = if selection.runs {
        history.runs(page_base, &info, &mut gaps)
    } else {
        history
            .bytes
            .iter()
            .enumerate()
            .map(|(i, write)| {
                history.row(
                    page_base + i as u64,
                    write.as_ref(),
                    &info,
                    selection.compact.then_some(&mut gaps),
                )
            })
            .collect()
    };
    let mut meta = capture_meta(&info);
    meta.extend(page_meta(
        args,
        selection.len,
        history.bytes.len(),
        selection.offset,
    ));
    meta.insert(
        "as_of_ev".into(),
        json!(selection.at.or_else(|| info.instructions.checked_sub(1))),
    );
    meta.insert(
        "state_position".into(),
        json!("after_recorded_accesses_at_event"),
    );
    if selection.runs {
        meta.insert("last_writers_format".into(), json!("runs-v1"));
    }
    if selection.compact || selection.runs {
        meta.insert("located_gaps".into(), Value::Array(gaps.rows));
    }
    Ok(response(rows, Value::Object(meta), json))
}

const HELP: &str = "usage: traceq last-writers trace.gtsw --range BASE,LEN [--at-seq N] [--limit N] [--offset N] [--compact | --runs] [--json]\n  last observed completed store per byte, inside the declared scope\n  LEN and limit must be 1..4096\n  profile 2 / GTSC also exposes last_observed_write.first_located_gap\n  for the earliest positioned loss of continuity; external memory effects remain unobserved\n  JSON meta.as_of_ev marks the state cutoff after recorded accesses at that instruction; null for an empty capture\n  profile 2: --compact --json replaces first_located_gap with first_located_gap_ref, indexing this page's meta.located_gaps\n  --runs --json sets meta.last_writers_format to runs-v1 for profile 2.\n  Each row has address, size, known and last_observed_write. Adjacent bytes from\n  one writer event share its provenance and a data_hex string in address order.\n  A null last_observed_write means no retained write. Only known runs have a\n  current value equal to data_hex. Gap refs are page-local. Limits, offsets,\n  meta.shown and meta.total count bytes, including unknowns.\n";
fn p1_failure(code: &str, message: impl Into<String>, status: i32, json_output: bool) -> Response {
    let message = message.into();
    if json_output {
        Response {
            stdout: format!("{}\n", json!({"error":{"code":code,"message":message}})).into_bytes(),
            stderr: vec![],
            status,
        }
    } else {
        Response {
            stdout: vec![],
            stderr: format!("last-writers: {code}: {message}\n").into_bytes(),
            status,
        }
    }
}
pub(super) fn run(args: &[String]) -> Result<Response, CliError> {
    let json = args.iter().any(|arg| arg == "--json");
    let mut path = None;
    let mut range = None;
    let mut at = None;
    let mut use_at_ev = false;
    let (mut limit, mut offset) = (20, 0);
    let mut compact = false;
    let mut runs = false;
    let mut i = 1;
    while i < args.len() {
        let flag = &args[i];
        i += 1;
        match flag.as_str() {
            "--help" | "-h" => return Ok(Response::text(HELP)),
            "--json" => {}
            "--compact" => compact = true,
            "--runs" => runs = true,
            "--range" => {
                let value = next(args, &mut i, flag)?;
                if range.is_some() {
                    return Err("one --range BASE,LEN is required".to_string().into());
                }
                range = Some(parse_range(value)?);
            }
            "--at-ev" | "--at-seq" => {
                at = Some(parse_u64(next(args, &mut i, flag)?, false)?);
                use_at_ev |= flag == "--at-ev";
            }
            "--phase" => {
                return Err("last-writers selects state after recorded accesses; use mem-state --checkpoint E:pre for pre-instruction state".to_string().into());
            }
            "--limit" => limit = parse_page_number("last-writers", next(args, &mut i, flag)?)?,
            "--offset" => offset = parse_u64(next(args, &mut i, flag)?, false)?,
            "--addr" | "--len" | "--size" => {
                return Err(format!("unsupported memory selector {flag}; {RANGE_HINT}").into());
            }
            _ if !flag.is_empty() && !flag.starts_with('-') && path.is_none() => {
                path = Some(flag.as_str())
            }
            _ => return Err(format!("unsupported argument: {flag}").into()),
        }
    }
    let Some(path) = path.filter(|_| (1..=4096).contains(&limit)) else {
        return Err("invalid file, limits, window or phase".to_string().into());
    };
    let Some((base, len)) = range else {
        return Err(format!("--range is required; {RANGE_HINT}").into());
    };
    if runs && !json {
        return Err("--runs requires last-writers --json (profile 2)"
            .to_string()
            .into());
    }
    let Ok(file) = File::open(path) else {
        return Ok(p1_failure("OPEN", format!("cannot open {path}"), 1, json));
    };
    let mut file = BufReader::with_capacity(64 * 1024, file);
    let mut header = [0; 64];
    if file.read_exact(&mut header).is_err() {
        return Ok(p1_failure("FORMAT", "expected a GTSW v1 header", 1, json));
    }
    let selection = Selection {
        base,
        len,
        at,
        limit,
        offset,
        compact,
        runs,
    };
    if &header[..8] == CHUNK_MAGIC
        || (&header[..8] == FLAT_MAGIC
            && u64::from_le_bytes(header[48..56].try_into().unwrap()) == 2)
    {
        if compact && !json {
            return Err(
                "--compact requires last-writers, mem-access or mem-state --json (profile 2)"
                    .to_string()
                    .into(),
            );
        }
        return profile2(
            args,
            Input::new(Cursor::new(header).chain(file))?,
            selection,
            json,
        );
    }
    if runs {
        return Err("--runs requires last-writers --json (profile 2)"
            .to_string()
            .into());
    }
    if compact || use_at_ev {
        let flag = if compact { "--compact" } else { "--at-ev" };
        return Err(format!("unexpected argument: {flag}").into());
    }
    if &header[..8] != FLAT_MAGIC {
        return Ok(p1_failure("FORMAT", "expected a GTSW v1 header", 1, json));
    }
    if offset > len {
        return Err("invalid path, range, limit or offset".to_string().into());
    }
    profile1(file, header, path, selection, json)
}

fn profile1(
    mut file: BufReader<File>,
    mut frame: [u8; 64],
    path: &str,
    selection: Selection,
    json_output: bool,
) -> Result<Response, CliError> {
    let Selection {
        base,
        len: length,
        at,
        limit,
        offset,
        ..
    } = selection;
    let at = at.unwrap_or(u64::MAX);
    let word =
        |index: usize| u64::from_le_bytes(frame[index * 8..index * 8 + 8].try_into().unwrap());
    let (code_base, code_size, data_base, data_size, thread_id, profile, frame_size) = (
        word(1),
        word(2),
        word(3),
        word(4),
        word(5),
        word(6),
        word(7),
    );
    if code_size == 0
        || code_base.checked_add(code_size).is_none()
        || data_size == 0
        || data_base.checked_add(data_size).is_none()
        || profile != 1
        || frame_size != 64
    {
        return Ok(p1_failure(
            "FORMAT",
            "unsupported or invalid capture profile",
            1,
            json_output,
        ));
    }
    let range_ok =
        base >= data_base && length <= data_size && base - data_base <= data_size - length;
    let mut bytes = vec![None; length as usize];
    let (mut instructions, mut writes, mut gaps, mut selected_gaps, mut current_pc) =
        (0u64, 0u64, 0u64, 0u64, 0u64);
    loop {
        if file.read_exact(&mut frame).is_err() {
            return Ok(p1_failure(
                "TRUNCATED",
                "missing or incomplete END frame",
                1,
                json_output,
            ));
        }
        let words = std::array::from_fn(|i| {
            u64::from_le_bytes(frame[i * 8..i * 8 + 8].try_into().unwrap())
        });
        let e = match Event::from_words(words) {
            Ok(e) => e,
            Err(_) => return Ok(p1_failure("FORMAT", "unknown frame kind", 1, json_output)),
        };
        match e.kind {
            Kind::Exec => {
                if e.seq != instructions
                    || e.pc < code_base
                    || e.pc - code_base >= code_size
                    || (e.pc - code_base) % 4 != 0
                    || e.address != 0
                    || e.size != 0
                    || e.low != 0
                    || e.high != 0
                    || e.detail != 0
                {
                    return Ok(p1_failure(
                        "FORMAT",
                        "invalid instruction sequence",
                        1,
                        json_output,
                    ));
                }
                instructions += 1;
                current_pc = e.pc;
            }
            Kind::Write => {
                if instructions == 0
                    || e.seq != instructions - 1
                    || e.pc != current_pc
                    || e.size == 0
                    || e.size > 16
                    || e.detail != 1
                    || e.address < data_base
                    || e.size > data_size
                    || e.address - data_base > data_size - e.size
                {
                    return Ok(p1_failure("FORMAT", "invalid store frame", 1, json_output));
                }
                writes += 1;
                if !range_ok || e.seq > at {
                    continue;
                }
                let low = base.max(e.address);
                let high = (base + length).min(e.address + e.size);
                let value = (e.low as u128 | ((e.high as u128) << 64)).to_le_bytes();
                for address in low..high {
                    bytes[(address - base) as usize] =
                        Some((value[(address - e.address) as usize], e.seq, e.pc));
                }
            }
            Kind::Gap => {
                if [e.address, e.size, e.low, e.high] != [0; 4]
                    || e.seq > instructions
                    || (e.seq < instructions && e.seq != instructions - 1)
                    || e.detail < 1
                    || e.detail > 5
                {
                    return Ok(p1_failure("FORMAT", "invalid gap frame", 1, json_output));
                }
                gaps += 1;
                if e.seq <= at || e.detail == 4 {
                    selected_gaps += 1;
                    bytes.fill(None);
                }
            }
            Kind::End => {
                if e.seq != instructions
                    || e.address != writes
                    || e.size != gaps
                    || e.detail != 1
                    || e.pc != 0
                    || e.low != 0
                    || e.high != 0
                {
                    return Ok(p1_failure("FORMAT", "invalid END counters", 1, json_output));
                }
                let mut tail = [0];
                if !matches!(file.read(&mut tail), Ok(0)) {
                    return Ok(p1_failure(
                        "FORMAT",
                        "trailing bytes or read error",
                        1,
                        json_output,
                    ));
                }
                break;
            }
            _ => return Ok(p1_failure("FORMAT", "unknown frame kind", 1, json_output)),
        }
    }
    if !range_ok {
        return Ok(p1_failure(
            "RANGE",
            "query extends outside declared data range",
            2,
            json_output,
        ));
    }
    if at != u64::MAX && at >= instructions {
        return Ok(p1_failure(
            "RANGE",
            "at-seq is outside captured instructions",
            2,
            json_output,
        ));
    }
    let shown = limit.min(length - offset);
    let truncated = offset + shown < length;
    let mut continuation = String::new();
    if truncated {
        continuation = format!(
            "traceq last-writers {} --range 0x{base:x},{length} --limit {limit} --offset {}",
            shell_arg(path),
            offset + shown
        );
        if at != u64::MAX {
            continuation += &format!(" --at-seq {at}");
        }
        if json_output {
            continuation += " --json";
        }
    }
    let mut rows = vec![];
    let mut text = String::new();
    for index in offset..offset + shown {
        let address = base + index;
        let mut row = json!({"address":hx(address),"known":bytes[index as usize].is_some()});
        if let Some((value, seq, pc)) = bytes[index as usize] {
            row["value"] = hx(value);
            row["writer_seq"] = json!(seq);
            row["pc"] = hx(pc);
            row["pc_offset"] = hx(pc - code_base);
            text += &format!("0x{address:x} 0x{value:02x} writer={seq} pc=0x{pc:x}\n");
        } else {
            row["value"] = Value::Null;
            row["writer_seq"] = Value::Null;
            row["pc"] = Value::Null;
            text += &format!("0x{address:x} unknown\n");
        }
        rows.push(row);
    }
    if !json_output {
        text += &format!(
            "shown={shown} total={length} gaps={gaps}{}\n",
            if truncated { " (truncated)" } else { "" }
        );
        return Ok(Response::text(text));
    }
    let meta = json!({"total":length,"shown":shown,"truncated":truncated,"next":continuation,"instructions":instructions,"stores":writes,"capture_gaps":gaps,"selected_gaps":selected_gaps,"thread_id":hx(thread_id),"as_of_ev":if instructions==0{Value::Null}else{json!(if at==u64::MAX{instructions-1}else{at})},"state_position":"after_recorded_accesses_at_event","scope":"last observed stores in declared single-thread code/data ranges","value_source":"pre-instruction source bits; store completion confirmed by post callback"});
    Ok(response(rows, meta, true))
}
