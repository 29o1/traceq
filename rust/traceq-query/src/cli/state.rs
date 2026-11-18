use super::*;
use std::fmt::Write as _;
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

fn byte_rows(base: u64, cells: &[Option<memory::Observation>], info: &Info) -> Vec<Value> {
    cells
        .iter()
        .enumerate()
        .map(|(index, &cell)| byte_row(base + index as u64, cell, info))
        .collect()
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
                    self.pcs.push(json!({
                        "pc": hx(b.pc),
                        "pc_offset": hx(b.pc.wrapping_sub(info.header.code_base))
                    }));
                    self.indices.insert(b.pc, index);
                    index
                };
                sources.push(json!([b.seq, index]));
            } else {
                bytes.push_str("00");
                sources.push(Value::Null);
            }
        }
        json!({
            "address": hx(address),
            "size": cells.len(),
            "data_hex": bytes,
            "sources": sources
        })
    }
    fn metadata(self, meta: &mut Map<String, Value>) {
        meta.insert("mem_state_format".into(), json!("hex-v1"));
        meta.insert("source_columns".into(), json!(["observed_ev", "pc_index"]));
        meta.insert("pc_table".into(), Value::Array(self.pcs));
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
    json!({
        "ev": g.seq,
        "pc": hx(g.pc),
        "off": hx(g.pc.wrapping_sub(info.header.code_base)),
        "opcode": hx(g.word),
        "text": text(info, g.pc),
        "completion": if g.committed { "confirmed" } else { "unobserved" },
        "post_observed": g.committed,
        "gap": g.gap
    })
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
        let batch_requested = !checkpoints.is_empty();
        if !batch_requested {
            checkpoints.push(Checkpoint { at, phase });
        }
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
        if checkpoints
            .iter()
            .any(|point| point.at >= info.instructions)
        {
            return Err("requested instruction is outside the capture"
                .to_string()
                .into());
        }
        let first = offset.min(len);
        let shown = limit.min(len - first);
        let page_base = base + first;
        let mut packing = CompactMemory::default();
        let mut meta = capture_meta(info);
        let rows = if batch_requested {
            let count = checkpoints.len() as u64;
            let truncated = first + shown < len;
            meta.extend(page_meta(args, len, shown as usize, offset));
            meta.insert("total".into(), json!(len * count));
            meta.insert("shown".into(), json!(shown * count));
            meta.extend(Map::from_iter([
                ("memory_format".into(), json!("checkpoints-v1")),
                ("pagination_unit".into(), json!("bytes_per_checkpoint")),
                ("checkpoints".into(), json!(count)),
                ("byte_offset".into(), json!(offset)),
                ("byte_limit".into(), json!(limit)),
                ("range_base".into(), hx(base)),
                ("range_size".into(), json!(len)),
                ("validation".into(), json!("one stream through END")),
            ]));
            batch
                .points
                .iter()
                .map(|point| {
                    let data = if compact {
                        packing.frame(page_base, &point.cells, info)
                    } else {
                        Value::Array(byte_rows(page_base, &point.cells, info))
                    };
                    json!({
                        "ev": point.checkpoint.at,
                        "phase": if point.checkpoint.phase == Phase::Pre { "pre" } else { "post" },
                        "pc": hx(point.pc),
                        "instruction_completion": if point.committed { "confirmed" } else { "unobserved" },
                        "gap": point.gap,
                        "gap_count": point.gap_count,
                        "gap_reasons": reasons(point.gap_reasons),
                        "data": data,
                        "meta": {"total": len, "shown": shown, "truncated": truncated}
                    })
                })
                .collect()
        } else {
            meta.extend(page_meta(args, len, shown as usize, offset));
            meta.insert(
                "phase".into(),
                json!(if phase == Phase::Pre { "pre" } else { "post" }),
            );
            let cells = &batch.points[0].cells;
            if compact {
                vec![packing.frame(page_base, cells, info)]
            } else {
                byte_rows(page_base, cells, info)
            }
        };
        if compact {
            packing.metadata(&mut meta);
        }
        return Ok(response(rows, Value::Object(meta), json));
    }
    let stream = input(&path)?;
    let (info, rows, total) = match name {
        "instructions" | "find-pc" => {
            let mut total = 0;
            let mut page = Vec::new();
            let info = replay::read_evidence(stream, |g, state| {
                if g.seq < from
                    || g.seq > to
                    || gaps_only && !g.gap
                    || name == "find-pc"
                        && !pcs.contains(&g.pc)
                        && !offs.contains(&g.pc.wrapping_sub(state.header.code_base))
                {
                    return;
                }
                if total >= offset && (page.len() as u64) < limit {
                    page.push(Instruction {
                        seq: g.seq,
                        pc: g.pc,
                        word: g.word,
                        committed: g.committed,
                        gap: g.gap,
                    });
                }
                total += 1;
            })?;
            let rows = page.iter().map(|g| instruction_row(g, &info)).collect();
            (info, rows, total)
        }
        "boundaries" => {
            let mut total = 0;
            let mut spans: Vec<(Group, Option<Group>)> = Vec::new();
            let mut pending = None;
            // An exit at the right edge can reenter at the next instruction.
            let through = to.saturating_add(1);
            let info = replay::read_selected(
                stream,
                |seq| (from..=through).contains(&seq),
                |g, _| {
                    if g.reentered
                        && let Some(exit) = pending.take()
                    {
                        if total >= offset && (spans.len() as u64) < limit {
                            spans.push((exit, Some(g.clone())));
                        }
                        total += 1;
                    }
                    if g.exit.transfer != 0 && g.seq <= to {
                        pending = Some(g.clone());
                    }
                },
            )?;
            if let Some(exit) = pending {
                if total >= offset && (spans.len() as u64) < limit {
                    spans.push((exit, None));
                }
                total += 1;
            }
            let rows = spans
                .iter()
                .map(|(exit, entry)| boundary_row(exit, entry.as_ref(), &registers, &info))
                .collect();
            (info, rows, total)
        }
        "stat" => {
            let info = replay::read_evidence(stream, |_, _| {})?;
            let mut rows = Vec::new();
            if offset == 0 {
                rows.push(json!({
                    "format": if info.chunked { "GTSC001" } else { "GTSW001" },
                    "profile": 2,
                    "sites": info.sites.len(),
                    "register_slots": replay::REGISTER_COUNT
                }));
            }
            (info, rows, 1)
        }
        "reg-state" => {
            let mut selected = None;
            let info =
                replay::read_selected(stream, |seq| seq == at, |g, _| selected = Some(g.clone()))?;
            if at >= info.instructions {
                return Err("requested instruction is outside the capture"
                    .to_string()
                    .into());
            }
            let Some(g) = selected else {
                return Err("requested state was not observed".to_string().into());
            };
            let total = registers.len() as u64;
            let values = if phase == Phase::Pre { &g.pre } else { &g.post };
            let unknown = info.unpositioned_gap || (phase == Phase::Post && !g.committed);
            let rows = registers
                .iter()
                .skip(offset.min(total) as usize)
                .take(limit as usize)
                .map(|r| {
                    let value = register_value(values, r, unknown);
                    json!({"reg": r.name, "known": !value.is_null(), "val": value})
                })
                .collect();
            (info, rows, total)
        }
        _ => unreachable!("state command dispatch"),
    };
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

fn boundary_row(g: &Group, entry: Option<&Group>, registers: &[Register], info: &Info) -> Value {
    let expected = (g.exit.expected_return != 0).then_some(g.exit.expected_return);
    json!({
        "exit_ev": g.seq,
        "source": location(g.pc, info),
        "source_off": hx(g.pc.wrapping_sub(info.header.code_base)),
        "instruction": text(info, g.pc),
        "target": location(g.exit.target, info),
        "transfer": transfer(g.exit.transfer),
        "status": if entry.is_some() { "reentered" } else { "no_reentry_observed" },
        "expected_return_address": expected.map(hx),
        "exit_registers": register_values(&g.pre, registers, info.unpositioned_gap, false),
        "memory_effects": "unobserved",
        "reentry_ev": entry.map(|next| next.seq),
        "reentry": entry.map(|next| location(next.pc, info)),
        "reentry_registers": entry.map(|next| register_values(&next.pre, registers, info.unpositioned_gap, false)),
        "reentry_matches_expected_return": entry.zip(expected).map(|(next, expected)| next.pc == expected)
    })
}
