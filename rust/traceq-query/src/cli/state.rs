use super::*;
use std::fmt::Write as _;
struct View<'a> {
    seq: u64,
    pc: u64,
    word: u64,
    committed: bool,
    gap: bool,
    exit: &'a replay::Exit,
    reentered: bool,
    full: Option<&'a Group>,
}
impl<'a> View<'a> {
    fn from_group(g: &'a Group) -> Self {
        Self {
            seq: g.seq,
            pc: g.pc,
            word: g.word,
            committed: g.committed,
            gap: g.gap,
            exit: &g.exit,
            reentered: g.reentered,
            full: Some(g),
        }
    }
    fn from_evidence(g: replay::EvidenceGroup<'a>) -> Self {
        Self {
            seq: g.seq,
            pc: g.pc,
            word: g.word,
            committed: g.committed,
            gap: g.gap,
            exit: g.exit,
            reentered: g.reentered,
            full: None,
        }
    }
}
fn byte_row(address: u64, cell: Option<memory::Observation>, info: &Info) -> Value {
    let mut row = json!({"address":hx(address),"known":cell.is_some()});
    if let Some(b) = cell {
        row["value"] = hx(b.value);
        row["observed_ev"] = json!(b.seq);
        row["pc"] = hx(b.pc);
        row["pc_offset"] = hx(b.pc.wrapping_sub(info.header.code_base));
    } else {
        row["value"] = Value::Null;
        row["writer_seq"] = Value::Null;
        row["pc"] = Value::Null;
    }
    row
}
#[derive(Default)]
struct CompactMemory {
    indices: BTreeMap<u64, usize>,
    pcs: Vec<Value>,
}
impl CompactMemory {
    fn frame(&mut self, address: u64, cells: &[Option<memory::Observation>], info: &Info) -> Value {
        let mut bytes = String::with_capacity(cells.len() * 2);
        let mut sources = Vec::with_capacity(cells.len());
        for cell in cells {
            if let Some(b) = cell {
                write!(&mut bytes, "{:02x}", b.value).unwrap();
                let index = if let Some(&index) = self.indices.get(&b.pc) {
                    index
                } else {
                    let index = self.pcs.len();
                    self.pcs.push(json!({"pc":hx(b.pc),"pc_offset":hx(b.pc.wrapping_sub(info.header.code_base))}));
                    self.indices.insert(b.pc, index);
                    index
                };
                sources.push(json!([b.seq, index]));
            } else {
                bytes.push_str("00");
                sources.push(Value::Null);
            }
        }
        json!({"address":hx(address),"size":cells.len(),"data_hex":bytes,"sources":sources})
    }
    fn metadata(self, meta: &mut Map<String, Value>) {
        meta.extend(json!({"mem_state_format":"hex-v1","source_columns":["observed_ev","pc_index"],"pc_table":self.pcs}).as_object().unwrap().clone());
    }
}
struct Instruction {
    seq: u64,
    pc: u64,
    word: u64,
    committed: bool,
    gap: bool,
}
fn instruction_row(g: &Instruction, info: &Info) -> Value {
    json!({"ev":g.seq,"pc":hx(g.pc),"off":hx(g.pc.wrapping_sub(info.header.code_base)),"opcode":hx(g.word),"text":text(info,g.pc),"completion":if g.committed {"confirmed"} else {"unobserved"},"post_observed":g.committed,"gap":g.gap})
}
pub(super) fn run(args: &[String]) -> Result<Response, CliError> {
    let name = args[0].as_str();
    let json = args.iter().any(|s| s == "--json");
    let memory_query = name == "mem-state";
    let event_window = matches!(name, "instructions" | "find-pc" | "boundaries");
    let point_query = matches!(name, "mem-state" | "reg-state");
    let mut path = String::new();
    let mut phase = if name == "reg-state" {
        Phase::Pre
    } else {
        Phase::Post
    };
    let (mut base, mut len, mut at, mut from, mut to, mut limit, mut offset) =
        (0, 0, u64::MAX, 0, u64::MAX, 20, 0);
    let (
        mut has_range,
        mut has_at,
        mut read_only,
        mut write_only,
        mut gaps_only,
        mut compact,
        mut has_phase,
    ) = (false, false, false, false, false, false, false);
    let mut checkpoints = vec![];
    let mut registers = vec![];
    let mut pcs = vec![];
    let mut offs = vec![];
    let mut i = 1;
    while i < args.len() {
        let a = &args[i];
        i += 1;
        match a.as_str() {
            "--help" | "-h" => return Ok(Response::text(include_str!("../cli_state_help.txt"))),
            "--json" => {}
            "--compact" => compact = true,
            "--gaps" => gaps_only = true,
            "--range" if memory_query => {
                let value = next(args, &mut i, a)?;
                if has_range {
                    return Err("one --range BASE,LEN is required".to_string().into());
                }
                (base, len) = parse_range(value)?;
                has_range = true;
            }
            "--at-ev" | "--at-seq" if point_query => {
                at = parse_u64(next(args, &mut i, a)?, false)?;
                has_at = true;
            }
            "--checkpoint" => {
                let value = next(args, &mut i, a)?;
                let Some((event, position)) = value.split_once(':') else {
                    return Err("--checkpoint requires E:pre or E:post".to_string().into());
                };
                if !matches!(position, "pre" | "post") {
                    return Err("--checkpoint requires E:pre or E:post".to_string().into());
                }
                checkpoints.push(Checkpoint {
                    at: parse_u64(event, false)?,
                    phase: if position == "pre" {
                        Phase::Pre
                    } else {
                        Phase::Post
                    },
                });
            }
            "--from" if event_window => from = parse_u64(next(args, &mut i, a)?, false)?,
            "--to" if event_window => to = parse_u64(next(args, &mut i, a)?, false)?,
            "--limit" => limit = parse_page_number(name, next(args, &mut i, a)?)?,
            "--offset" => offset = parse_u64(next(args, &mut i, a)?, false)?,
            "--phase" => {
                if name == "boundaries" {
                    return Err(
                        "boundaries exposes exit/reentry pre states; --phase does not apply"
                            .to_string()
                            .into(),
                    );
                }
                if !point_query {
                    return Err(format!("--phase does not apply to {name}").into());
                }
                phase = match next(args, &mut i, a)? {
                    "pre" => Phase::Pre,
                    "post" => Phase::Post,
                    _ => return Err("invalid file, limits, window or phase".to_string().into()),
                };
                has_phase = true;
            }
            "--reg" => registers.push(reg(next(args, &mut i, a)?)?),
            "--addr" | "--len" | "--size" if memory_query => {
                return Err(format!("unsupported memory selector {a}; {RANGE_HINT}").into());
            }
            "--addr" => pcs.push(parse_u64(next(args, &mut i, a)?, false)?),
            "--off" => offs.push(parse_u64(next(args, &mut i, a)?, false)?),
            "--read" => read_only = true,
            "--write" => write_only = true,
            _ if !a.starts_with('-') && path.is_empty() => path = a.clone(),
            _ => return Err(format!("unsupported argument: {a}").into()),
        }
    }
    if path.is_empty() || limit == 0 || limit > 4096 || from > to || read_only && write_only {
        return Err("invalid file, limits, window or phase".to_string().into());
    }
    if memory_query && !has_range {
        return Err(format!("--range is required; {RANGE_HINT}").into());
    }
    if matches!(name, "mem-state" | "reg-state") && !has_at && checkpoints.is_empty() {
        return Err("--at-ev is required".to_string().into());
    }
    if !checkpoints.is_empty()
        && (name != "mem-state" || has_at || has_phase || checkpoints.len() > 64)
    {
        return Err("1..64 checkpoints apply only to mem-state and cannot mix with --at-ev/--at-seq/--phase".to_string().into());
    }
    if !checkpoints.is_empty() && checkpoints.len() as u64 * limit.min(len - len.min(offset)) > 4096
    {
        return Err("checkpoint page exceeds 4096 byte cells; reduce --limit"
            .to_string()
            .into());
    }
    if name == "find-pc" && pcs.is_empty() && offs.is_empty() {
        return Err("--addr or --off is required".to_string().into());
    }
    if registers.len() > 65 {
        return Err("at most 65 registers per query".to_string().into());
    }
    if !registers.is_empty() && !matches!(name, "reg-state" | "boundaries") {
        return Err("--reg applies to reg-state or boundaries"
            .to_string()
            .into());
    }
    if (!pcs.is_empty() || !offs.is_empty()) && name != "find-pc" {
        return Err("PC selectors apply to find-pc".to_string().into());
    }
    if read_only || write_only {
        return Err("--read/--write apply to mem-access".to_string().into());
    }
    if gaps_only && name != "instructions" {
        return Err("--gaps applies to instructions".to_string().into());
    }
    if compact && (name != "mem-state" || !json) {
        return Err(
            "--compact requires last-writers, mem-access or mem-state --json (profile 2)"
                .to_string()
                .into(),
        );
    }
    if registers.is_empty() && matches!(name, "reg-state" | "boundaries") {
        for n in ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"] {
            registers.push(reg(n)?);
        }
        for n in if name == "boundaries" {
            vec!["x8", "sp", "lr"]
        } else {
            vec!["nzcv"]
        } {
            registers.push(reg(n)?);
        }
    }
    if name == "mem-state" {
        if !checkpoints.is_empty() {
            let batch = memory::snapshots(
                input(&path)?,
                base,
                len as usize,
                &checkpoints,
                offset,
                limit as usize,
            )?;
            let info = &batch.info;
            if !batch.range_valid {
                return Err("query extends outside declared data range"
                    .to_string()
                    .into());
            }
            if checkpoints.iter().any(|p| p.at >= info.instructions) {
                return Err("requested instruction is outside the capture"
                    .to_string()
                    .into());
            }
            let first = offset.min(len);
            let shown = limit.min(len - first);
            let truncated = first + shown < len;
            let mut rows = vec![];
            let mut packing = CompactMemory::default();
            for point in &batch.points {
                let data = if compact {
                    packing.frame(base + first, &point.cells, info)
                } else {
                    Value::Array(
                        point
                            .cells
                            .iter()
                            .enumerate()
                            .map(|(j, c)| byte_row(base + first + j as u64, *c, info))
                            .collect(),
                    )
                };
                rows.push(json!({"ev":point.checkpoint.at,"phase":if point.checkpoint.phase==Phase::Pre{"pre"}else{"post"},"pc":hx(point.pc),"instruction_completion":if point.committed{"confirmed"}else{"unobserved"},"gap":point.gap,"gap_count":point.gap_count,"gap_reasons":reasons(point.gap_reasons),"data":data,"meta":{"total":len,"shown":shown,"truncated":truncated}}));
            }
            let mut meta = capture_meta(info);
            meta.extend(json!({"total":len*checkpoints.len() as u64,"shown":shown*checkpoints.len() as u64,"truncated":truncated,"next":if truncated{next_command(args,first+shown)}else{String::new()},"memory_format":"checkpoints-v1","pagination_unit":"bytes_per_checkpoint","checkpoints":checkpoints.len(),"byte_offset":offset,"byte_limit":limit,"range_base":hx(base),"range_size":len,"validation":"one stream through END"}).as_object().unwrap().clone());
            if compact {
                packing.metadata(&mut meta);
            }
            return Ok(response(rows, Value::Object(meta), json));
        }
        let snapshot = memory::snapshot(input(&path)?, base, len as usize, at, phase)?;
        let info = &snapshot.info;
        if !snapshot.range_valid {
            return Err("query extends outside declared data range"
                .to_string()
                .into());
        }
        if at >= info.instructions {
            return Err("requested instruction is outside the capture"
                .to_string()
                .into());
        }
        let first = offset.min(len) as usize;
        let shown = (limit as usize).min(snapshot.cells.len() - first);
        let mut packing = CompactMemory::default();
        let rows = if compact {
            vec![packing.frame(
                base + first as u64,
                &snapshot.cells[first..first + shown],
                info,
            )]
        } else {
            snapshot
                .cells
                .iter()
                .enumerate()
                .skip(first)
                .take(shown)
                .map(|(j, c)| byte_row(base + j as u64, *c, info))
                .collect::<Vec<_>>()
        };
        let mut meta = capture_meta(info);
        meta.extend(page_meta(args, len, shown, offset));
        meta.insert(
            "phase".into(),
            json!(if phase == Phase::Pre { "pre" } else { "post" }),
        );
        if compact {
            packing.metadata(&mut meta);
        }
        return Ok(response(rows, Value::Object(meta), json));
    }
    let mut selected: Option<Group> = None;
    let mut instruction_rows = vec![];
    let mut rows = vec![];
    let mut total = 0u64;
    let mut spans: Vec<(Group, Option<Group>)> = vec![];
    let mut pending: Option<Group> = None;
    let mut on_group = |g: View<'_>, state: &Info| {
        if name == "reg-state" && g.seq == at {
            selected = Some(g.full.unwrap().clone());
        }

        if name == "boundaries" {
            if g.reentered
                && let Some(exit) = pending.take()
                && exit.seq >= from
                && exit.seq <= to
            {
                let n = total;
                total += 1;
                if n >= offset && (spans.len() as u64) < limit {
                    spans.push((exit, Some(g.full.unwrap().clone())));
                }
            }
            if g.exit.transfer != 0 {
                pending = Some(g.full.unwrap().clone());
            }
        }
        if matches!(name, "instructions" | "find-pc")
            && g.seq >= from
            && g.seq <= to
            && (!gaps_only || g.gap)
            && (name != "find-pc"
                || pcs.contains(&g.pc)
                || offs.contains(&g.pc.wrapping_sub(state.header.code_base)))
        {
            let n = total;
            total += 1;
            if n >= offset && (instruction_rows.len() as u64) < limit {
                instruction_rows.push(Instruction {
                    seq: g.seq,
                    pc: g.pc,
                    word: g.word,
                    committed: g.committed,
                    gap: g.gap,
                });
            }
        }
    };
    let stream = input(&path)?;
    let info = if name == "boundaries" {
        replay::read(stream, |g, info| on_group(View::from_group(g), info))?
    } else if name == "reg-state" {
        replay::read_selected(
            stream,
            |seq| seq == at,
            |g, info| on_group(View::from_group(g), info),
        )?
    } else {
        replay::read_evidence(stream, |g, info| on_group(View::from_evidence(g), info))?
    };
    if has_at && at >= info.instructions {
        return Err("requested instruction is outside the capture"
            .to_string()
            .into());
    }
    if matches!(name, "instructions" | "find-pc") {
        rows = instruction_rows
            .iter()
            .map(|g| instruction_row(g, &info))
            .collect();
    }
    if name == "boundaries" {
        if let Some(exit) = pending
            && exit.seq >= from
            && exit.seq <= to
        {
            let n = total;
            total += 1;
            if n >= offset && (spans.len() as u64) < limit {
                spans.push((exit, None));
            }
        }
        for (g, entry) in spans {
            let mut row = json!({"exit_ev":g.seq,"source":location(g.pc,&info),"source_off":hx(g.pc.wrapping_sub(info.header.code_base)),"instruction":text(&info,g.pc),"target":location(g.exit.target,&info),"transfer":transfer(g.exit.transfer),"status":if entry.is_some(){"reentered"}else{"no_reentry_observed"},"expected_return_address":if g.exit.expected_return!=0{hx(g.exit.expected_return)}else{Value::Null},"exit_registers":register_values(&g.pre,&registers,info.unpositioned_gap,false),"memory_effects":"unobserved"});
            if let Some(entry) = entry {
                row["reentry_ev"] = json!(entry.seq);
                row["reentry"] = location(entry.pc, &info);
                row["reentry_registers"] =
                    register_values(&entry.pre, &registers, info.unpositioned_gap, false);
                row["reentry_matches_expected_return"] = if g.exit.expected_return != 0 {
                    json!(entry.pc == g.exit.expected_return)
                } else {
                    Value::Null
                };
            } else {
                for key in [
                    "reentry_ev",
                    "reentry",
                    "reentry_registers",
                    "reentry_matches_expected_return",
                ] {
                    row[key] = Value::Null;
                }
            }
            rows.push(row);
        }
    } else if name == "stat" {
        total = 1;
        if offset == 0 {
            rows.push(json!({"format":if info.chunked{"GTSC001"}else{"GTSW001"},"profile":2,"sites":info.sites.len(),"register_slots":65}));
        }
    } else if name == "reg-state" {
        let Some(g) = selected else {
            return Err("requested state was not observed".to_string().into());
        };
        total = registers.len() as u64;
        let values = if phase == Phase::Pre { &g.pre } else { &g.post };
        for r in registers
            .iter()
            .skip(offset.min(total) as usize)
            .take(limit as usize)
        {
            let known = r.slot.is_none()
                || (!info.unpositioned_gap
                    && (phase == Phase::Pre || g.committed)
                    && values.is_known(r.slot.unwrap()));
            rows.push(json!({"reg":r.name,"known":known,"val":if known {hx(r.slot.map_or(0,|slot|masked(values.bits[slot],r.bits)))}else{Value::Null}}));
        }
    }
    let mut meta = capture_meta(&info);
    meta.extend(page_meta(args, total, rows.len(), offset));
    if name == "boundaries" {
        meta.insert(
            "pairing".into(),
            json!("each exit to next observed in-scope instruction; not call/return matching"),
        );
    }
    if name == "stat" {
        let counts = info
            .unsupported_mnemonics
            .iter()
            .map(|(name, count)| (String::from_utf8_lossy(name).into_owned(), *count))
            .collect::<BTreeMap<_, _>>();
        meta.insert(
            "gap_reasons".into(),
            json!(
                (1..7)
                    .map(|i| (LABELS[i].to_string(), json!(info.gap_reasons[i])))
                    .collect::<Map<String, Value>>()
            ),
        );
        meta.insert("unsupported_mnemonics".into(), json!(counts));
    }
    if name == "reg-state" {
        meta.insert(
            "phase".into(),
            json!(if phase == Phase::Pre { "pre" } else { "post" }),
        );
    }
    Ok(response(rows, Value::Object(meta), json))
}
