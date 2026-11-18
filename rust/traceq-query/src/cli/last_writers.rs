use super::*;

pub(super) struct Selection {
    pub base: u64,
    pub len: u64,
    pub at: Option<u64>,
    pub limit: u64,
    pub offset: u64,
    pub compact: bool,
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

struct ObservedWrite {
    value: u8,
    seq: u64,
    pc: u64,
    epoch: u64,
    first_gap: Option<Gap>,
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
        for access in group.accesses.iter().filter(|a| a.kind == Kind::Write) {
            let end = base + self.bytes.len() as u64;
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
        compact_gaps: Option<&mut Vec<Value>>,
    ) -> Value {
        // A gap invalidates present knowledge while retaining historical evidence.
        let current = observed.filter(|write| write.first_gap.is_none() && !info.unpositioned_gap);
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
            let gaps_since = self.epoch - write.epoch;
            let mut evidence = json!({
                "value": hx(write.value),
                "writer_seq": write.seq,
                "pc": hx(write.pc),
                "pc_offset": hx(write.pc.wrapping_sub(info.header.code_base)),
                "gaps_since": gaps_since,
                "latest_gap_ev": (gaps_since != 0).then_some(self.last_gap_seq)
            });
            let gap = write.first_gap.as_ref().map(|gap| gap.render(info));
            if let Some(table) = compact_gaps {
                let reference = gap.map(|value| {
                    table
                        .iter()
                        .position(|other| *other == value)
                        .unwrap_or_else(|| {
                            table.push(value);
                            table.len() - 1
                        })
                });
                evidence["first_located_gap_ref"] = json!(reference);
            } else {
                evidence["first_located_gap"] = gap.unwrap_or(Value::Null);
            }
            evidence
        } else {
            Value::Null
        };
        row
    }
}

pub(super) fn run(
    args: &[String],
    stream: Input<BufReader<File>>,
    selection: Selection,
    json: bool,
) -> Result<Response, CliError> {
    let mut history = History::new(selection.len as usize);
    let mut range_ok = true;
    let info = replay::read_evidence(stream, |group, info| {
        let header = &info.header;
        if selection.base < header.data_base
            || selection.len > header.data_size
            || selection.base - header.data_base > header.data_size - selection.len
        {
            range_ok = false;
            return;
        }
        if selection.at.is_none_or(|at| group.seq <= at) {
            history.observe(group, selection.base);
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
    let mut gaps = Vec::new();
    let rows = history
        .bytes
        .iter()
        .enumerate()
        .skip(selection.offset.min(selection.len) as usize)
        .take(selection.limit as usize)
        .map(|(i, write)| {
            history.row(
                selection.base + i as u64,
                write.as_ref(),
                &info,
                selection.compact.then_some(&mut gaps),
            )
        })
        .collect::<Vec<_>>();
    let mut meta = capture_meta(&info);
    meta.extend(page_meta(args, selection.len, rows.len(), selection.offset));
    meta.insert(
        "as_of_ev".into(),
        json!(selection.at.or_else(|| info.instructions.checked_sub(1))),
    );
    meta.insert(
        "state_position".into(),
        json!("after_recorded_accesses_at_event"),
    );
    if selection.compact {
        meta.insert("located_gaps".into(), json!(gaps));
    }
    Ok(response(rows, Value::Object(meta), json))
}
