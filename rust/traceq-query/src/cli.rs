//! Native product command policy and presentation. All query callbacks stage
//! bounded results; nothing is published before complete stream validation.
use serde_json::{Map, Value, json};
use std::{
    cell::Cell,
    collections::{BTreeMap, HashSet},
    fs::File,
    io::BufReader,
};
use traceq_core::{
    memory::{self, Checkpoint, Phase},
    replay::{self, Group, Info, Registers},
    wire::{Input, Kind},
};
mod find;
mod last_writers;
mod mem_access;
mod state;

pub struct Response {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub status: i32,
}
impl Response {
    pub(crate) fn text(text: impl Into<String>) -> Self {
        Self {
            stdout: text.into().into_bytes(),
            stderr: vec![],
            status: 0,
        }
    }
}
pub(crate) fn failure(command: &str, message: &str, code: i32, json: bool) -> Response {
    if json {
        Response { stdout: format!("{}\n", json!({"error":{"code":if code==2 {"ARGUMENT"} else {"TRACE_ERROR"},"message":message}})).into_bytes(), stderr: vec![], status: code }
    } else {
        Response {
            stdout: vec![],
            stderr: format!("{command}: {message}\n").into_bytes(),
            status: code,
        }
    }
}
pub(crate) fn response(rows: Vec<Value>, meta: Value, json: bool) -> Response {
    if json {
        Response::text(format!(
            "{{\"data\":{},\"meta\":{meta}}}\n",
            Value::Array(rows)
        ))
    } else {
        let mut text = String::new();
        for row in rows {
            text += &format!("{row}\n");
        }
        text += &format!("meta: {meta}\n");
        Response::text(text)
    }
}
pub(crate) fn parse_u64(text: &str, decimal: bool) -> Result<u64, CliError> {
    let (base, digits) = if decimal {
        (10, text)
    } else if text.starts_with("0x") || text.starts_with("0X") {
        (16, &text[2..])
    } else if text.len() > 1 && text.starts_with('0') {
        (8, text)
    } else {
        (10, text)
    };
    if digits.is_empty()
        || !digits
            .bytes()
            .all(|c| c.is_ascii_digit() || base == 16 && c.is_ascii_hexdigit())
    {
        return Err(format!("invalid unsigned integer: '{text}'").into());
    }
    u64::from_str_radix(digits, base)
        .map_err(|_| format!("invalid unsigned integer: '{text}'").into())
}
pub(crate) fn number128(text: &str) -> Result<u128, CliError> {
    let (base, digits) = if text.starts_with("0x") || text.starts_with("0X") {
        (16, &text[2..])
    } else if text.len() > 1 && text.starts_with('0') {
        (8, text)
    } else {
        (10, text)
    };
    if digits.is_empty()
        || !digits
            .bytes()
            .all(|c| c.is_ascii_digit() || base == 16 && c.is_ascii_hexdigit())
    {
        return Err(format!("invalid unsigned 128-bit value: {text}").into());
    }
    u128::from_str_radix(digits, base)
        .map_err(|_| format!("invalid unsigned 128-bit value: {text}").into())
}
pub(crate) fn hx(value: impl Into<u128>) -> Value {
    Value::String(format!("0x{:x}", value.into()))
}
pub(crate) fn input(path: &str) -> traceq_core::Result<Input<BufReader<File>>> {
    Input::new(BufReader::with_capacity(64 * 1024, File::open(path)?))
}
pub(crate) fn shell_arg(s: &str) -> String {
    if !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_./:-".contains(&b))
    {
        return s.to_owned();
    }
    format!("'{}'", s.replace('\'', "'\\''"))
}
pub(crate) fn next_command(args: &[String], offset: u64) -> String {
    let mut next = format!("traceq {}", args[0]);
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--offset" {
            i += 2;
            continue;
        }
        next.push(' ');
        next += &shell_arg(&args[i]);
        i += 1;
    }
    next += &format!(" --offset {offset}");
    next
}
pub(crate) fn page_meta(
    args: &[String],
    total: u64,
    shown: usize,
    offset: u64,
) -> Map<String, Value> {
    let truncated = offset < total && (shown as u64) < total - offset;
    json!({"total":total,"shown":shown,"truncated":truncated,"next":if truncated {next_command(args,offset+shown as u64)} else {String::new()}}).as_object().unwrap().clone()
}
const LABELS: [&str; 7] = [
    "unused",
    "unsupported",
    "unconfirmed_store",
    "foreign_thread",
    "exclusive_region",
    "outside_data_range",
    "outside_code_range",
];
pub(crate) fn reasons(mask: u64) -> Value {
    json!(
        (1..7)
            .filter(|i| mask & (1 << i) != 0)
            .map(|i| LABELS[i])
            .collect::<Vec<_>>()
    )
}
pub(crate) fn scope_meta(meta: &mut Map<String, Value>, info: &Info) {
    if !info.ranges.is_empty() {
        meta.insert("code_scope".into(), json!("explicit_ranges"));
        meta.insert("code_envelope_only".into(), json!(true));
        meta.insert(
            "code_ranges".into(),
            json!(
                info.ranges
                    .iter()
                    .map(|&(base, size)| json!({"base":hx(base),"size":size}))
                    .collect::<Vec<_>>()
            ),
        );
    }
}
pub(crate) fn capture_meta(info: &Info) -> Map<String, Value> {
    let h = info.header;
    let mut meta=json!({"capture_gaps":info.gaps,"instructions":info.instructions,"reads":info.reads,"unknown_reads":info.unknown_reads,"stores":info.writes,"confirmed_instructions":info.commits,"unpositioned_gap":info.unpositioned_gap,"boundary_capture":info.boundary_capture,"external_execution":if info.external_followed {"followed_without_instruction_records"} else {"excluded_or_unspecified"},"scope_exits":info.exits,"scope_reentries":info.reentries,"thread_id":hx(h.thread_id),"code_base":hx(h.code_base),"code_size":h.code_size,"data_base":hx(h.data_base),"data_size":if h.data_size>9007199254740991 {hx(h.data_size)} else {json!(h.data_size)},"scope":"observations within declared single-thread code/data ranges"}).as_object().unwrap().clone();
    scope_meta(&mut meta, info);
    meta
}
#[derive(Clone)]
pub(crate) struct Register {
    pub name: String,
    pub slot: Option<usize>,
    pub bits: u32,
}
pub(crate) fn reg(name: &str) -> Result<Register, CliError> {
    let named = match name {
        "sp" => Some((Some(31), 64)),
        "wsp" => Some((Some(31), 32)),
        "fp" => Some((Some(29), 64)),
        "lr" => Some((Some(30), 64)),
        "nzcv" => Some((Some(32), 64)),
        "xzr" => Some((None, 64)),
        "wzr" => Some((None, 32)),
        _ => None,
    };
    if let Some((slot, bits)) = named {
        return Ok(Register {
            name: name.into(),
            slot,
            bits,
        });
    }
    if name.len() < 2 || !name.is_ascii() {
        return Err(format!("invalid register: {name}").into());
    }
    let n = parse_u64(&name[1..], true)?;
    let c = name.as_bytes()[0];
    if (c == b'x' || c == b'w') && n <= 30 {
        return Ok(Register {
            name: name.into(),
            slot: Some(n as usize),
            bits: if c == b'x' { 64 } else { 32 },
        });
    }
    let bits = match c {
        b'v' | b'q' => 128,
        b'd' => 64,
        b's' => 32,
        b'h' => 16,
        b'b' => 8,
        _ => 0,
    };
    if n > 31 || bits == 0 {
        return Err(format!("invalid register: {name}").into());
    }
    Ok(Register {
        name: name.into(),
        slot: Some(33 + n as usize),
        bits,
    })
}
pub(crate) fn slot_name(slot: usize) -> String {
    if slot < 31 {
        format!("x{slot}")
    } else if slot == 31 {
        "sp".into()
    } else if slot == 32 {
        "nzcv".into()
    } else {
        format!("v{}", slot - 33)
    }
}
fn masked(value: u128, bits: u32) -> u128 {
    if bits == 128 {
        value
    } else {
        value & ((1u128 << bits) - 1)
    }
}
pub(crate) fn register_values(
    values: &Registers,
    selected: &[Register],
    unknown: bool,
    array: bool,
) -> Value {
    let items = selected.iter().map(|r| match r.slot {
        None => hx(0u64),
        Some(slot) if !unknown && values.is_known(slot) => hx(masked(values.bits[slot], r.bits)),
        _ => Value::Null,
    });
    if array {
        Value::Array(items.collect())
    } else {
        Value::Object(selected.iter().map(|r| r.name.clone()).zip(items).collect())
    }
}
pub(crate) fn location(address: u64, info: &Info) -> Value {
    // Reverse declaration order matches the prior C++ unordered map's normal
    // insertion traversal for nested module envelopes; explicit scope is separate.
    for base in info.module_order.iter().rev() {
        let m = &info.modules[base];
        if address >= *base && address - *base < m.size {
            return json!({"address":hx(address),"module":String::from_utf8_lossy(&m.name),"module_base":hx(*base),"offset":hx(address-*base)});
        }
    }
    json!({"address":hx(address),"module":null,"module_base":null,"offset":null})
}
pub(crate) fn transfer(t: u64) -> &'static str {
    match t {
        1 => "call",
        3 => "return",
        _ => "branch",
    }
}
fn text(info: &Info, pc: u64) -> String {
    String::from_utf8_lossy(&info.sites[&pc].text).into_owned()
}
fn automatic_registers(g: &Group, text: &str) -> Vec<Register> {
    let mut slots = [false; 65];
    slots[30] = true;
    slots[31] = true;
    slots[32] = true;
    let mut zero = false;
    for token in text.split(|c: char| !c.is_ascii_alphanumeric() && c != '_') {
        let named = matches!(token, "sp" | "wsp" | "lr" | "fp" | "nzcv" | "xzr" | "wzr");
        let numbered = token.len() > 1
            && "xwvqdsbh".contains(token.as_bytes()[0] as char)
            && token.as_bytes()[1..].iter().all(u8::is_ascii_digit);
        if (named || numbered)
            && let Ok(r) = reg(token)
        {
            if let Some(slot) = r.slot {
                slots[slot] = true;
            } else {
                zero = true;
            }
        }
    }
    if g.committed {
        for (i, used) in slots.iter_mut().enumerate() {
            if g.pre.is_known(i) && g.post.is_known(i) && g.pre.bits[i] != g.post.bits[i] {
                *used = true;
            }
        }
    }
    let mut chosen = slots
        .iter()
        .enumerate()
        .filter(|(_, s)| **s)
        .map(|(i, _)| reg(&slot_name(i)).unwrap())
        .collect::<Vec<_>>();
    if zero {
        chosen.push(reg("xzr").unwrap());
    }
    chosen
}
const MEMORY_READ_SOURCE: &str = "load destination bits after completion";
const MEMORY_WRITE_SOURCE: &str = "store source bits; post callback confirmed";
fn memory_source(kind: Kind, word: u64) -> &'static str {
    if kind == Kind::Read {
        MEMORY_READ_SOURCE
    } else if traceq_core::arm64_memory::atomic_add(word as u32).is_some() {
        traceq_core::arm64_memory::ATOMIC_WRITE_SOURCE
    } else {
        MEMORY_WRITE_SOURCE
    }
}
pub(crate) fn memory_json(g: &Group) -> Value {
    json!(g.accesses.iter().map(|a|json!({"rw":if a.kind==Kind::Read {"r"}else{"w"},"addr":hx(a.address),"size":a.size,"known":a.detail==1,"val":if a.detail==1 {hx(a.low as u128|((a.high as u128)<<64))}else{Value::Null},"value_source":memory_source(a.kind,g.word)})).collect::<Vec<_>>())
}
pub(crate) fn context_row(
    g: &Group,
    info: &Info,
    chosen: &[Register],
    focus: bool,
    compact: bool,
    register_set: usize,
) -> Value {
    let automatic = if chosen.is_empty() {
        automatic_registers(g, &text(info, g.pc))
    } else {
        vec![]
    };
    let chosen = if chosen.is_empty() {
        &automatic
    } else {
        chosen
    };
    let mut fields = vec![
        ("ev", json!(g.seq)),
        ("pc", hx(g.pc)),
        ("off", hx(g.pc.wrapping_sub(info.header.code_base))),
        ("opcode", hx(g.word)),
        ("text", json!(text(info, g.pc))),
        ("focus", json!(focus)),
        (
            "completion",
            json!(if g.committed {
                "confirmed"
            } else {
                "unobserved"
            }),
        ),
        ("gap", json!(g.gap)),
        ("gap_reasons", reasons(g.gap_reason_mask)),
    ];
    if compact {
        fields.push(("register_set", json!(register_set)));
    }
    fields.extend([
        (
            "pre",
            register_values(&g.pre, chosen, info.unpositioned_gap, compact),
        ),
        (
            "post",
            if g.committed {
                register_values(&g.post, chosen, info.unpositioned_gap, compact)
            } else {
                Value::Null
            },
        ),
        ("memory", memory_json(g)),
        (
            "scope_exit",
            if g.exit.transfer != 0 {
                json!({"transfer":transfer(g.exit.transfer),"target":location(g.exit.target,info)})
            } else {
                Value::Null
            },
        ),
        (
            "scope_reentry",
            if g.reentered {
                json!({"exit_ev":g.exit_seq})
            } else {
                Value::Null
            },
        ),
    ]);
    if compact {
        Value::Array(fields.into_iter().map(|(_, v)| v).collect())
    } else {
        Value::Object(fields.into_iter().map(|(k, v)| (k.into(), v)).collect())
    }
}
fn context(args: &[String]) -> Result<Response, CliError> {
    let json = args.iter().any(|s| s == "--json");
    let mut compact = false;
    let mut path = String::new();
    let (mut before, mut after, mut limit, mut offset) = (2, 2, 20, 0);
    let mut anchors = vec![];
    let mut registers = vec![];
    let mut i = 1;
    while i < args.len() {
        let a = &args[i];
        i += 1;
        match a.as_str() {
            "--help" | "-h" => return Ok(Response::text(include_str!("cli_context_help.txt"))),
            "--json" => {}
            "--compact" => compact = true,
            "--at-ev" => anchors.push(parse_u64(next(args, &mut i, a)?, false)?),
            "--before" => before = parse_u64(next(args, &mut i, a)?, false)?,
            "--after" => after = parse_u64(next(args, &mut i, a)?, false)?,
            "--limit" => limit = parse_u64(next(args, &mut i, a)?, false)?,
            "--offset" => offset = parse_u64(next(args, &mut i, a)?, false)?,
            "--reg" => registers.push(reg(next(args, &mut i, a)?)?),
            _ if !a.starts_with('-') && path.is_empty() => path = a.clone(),
            _ => return Err(CliError(format!("unsupported argument: {a}"), 2)),
        }
    }
    if path.is_empty()
        || anchors.is_empty()
        || anchors.len() > 64
        || before > 4096
        || after > 4096
        || limit == 0
        || limit > 4096
        || registers.len() > 65
    {
        return Err(CliError(
            "require FILE, 1..64 events, before/after 0..4096, limit 1..4096, at most 65 registers"
                .into(),
            2,
        ));
    }
    if compact && !json {
        return Err(CliError("--compact requires --json".into(), 2));
    }
    anchors.sort_unstable();
    anchors.dedup();
    let mut windows: Vec<(u64, u64)> = vec![];
    for at in &anchors {
        let start = at.saturating_sub(before);
        let end = at.saturating_add(after);
        if let Some(last) = windows.last_mut()
            && start <= last.1.saturating_add(1)
        {
            last.1 = end;
        } else {
            windows.push((start, end));
        }
    }
    let total = Cell::new(0u64);
    let shown = Cell::new(0usize);
    let mut window = 0;
    let mut selected = vec![];
    let info = replay::read_selected(
        input(&path).map_err(trace_error)?,
        |seq| {
            while window < windows.len() && seq > windows[window].1 {
                window += 1;
            }
            if window == windows.len() || seq < windows[window].0 {
                return false;
            }
            let n = total.get();
            total.set(n + 1);
            let capture = n >= offset && (shown.get() as u64) < limit;
            if capture {
                shown.set(shown.get() + 1);
            }
            capture
        },
        |g, _| selected.push(g.clone()),
    )
    .map_err(trace_error)?;
    if *anchors.last().unwrap() >= info.instructions {
        return Err(CliError("requested event is outside the capture".into(), 2));
    }
    let mut rows = vec![];
    let mut register_sets = vec![];
    for g in &selected {
        if compact {
            let chosen = if registers.is_empty() {
                automatic_registers(g, &text(&info, g.pc))
            } else {
                registers.clone()
            };
            let mut seen = HashSet::new();
            let chosen = chosen
                .into_iter()
                .filter(|r| seen.insert(r.name.clone()))
                .collect::<Vec<_>>();
            let names = json!(chosen.iter().map(|r| &r.name).collect::<Vec<_>>());
            let n = register_sets
                .iter()
                .position(|v| *v == names)
                .unwrap_or_else(|| {
                    register_sets.push(names);
                    register_sets.len() - 1
                });
            rows.push(context_row(
                g,
                &info,
                &chosen,
                anchors.binary_search(&g.seq).is_ok(),
                true,
                n,
            ));
        } else {
            rows.push(context_row(
                g,
                &info,
                &registers,
                anchors.binary_search(&g.seq).is_ok(),
                false,
                0,
            ));
        }
    }
    let mut meta = capture_meta(&info);
    meta.extend(page_meta(args, total.get(), rows.len(), offset));
    meta.extend(json!({"requested_events":anchors,"before":before,"after":after,"register_selection":if registers.is_empty(){"operand_and_changed_full_slots_plus_x30_sp_nzcv"}else{"explicit"},"validation":"full stream through END"}).as_object().unwrap().clone());
    if compact {
        meta.extend(json!({"context_format":"columns-v1","columns":["ev","pc","off","opcode","text","focus","completion","gap","gap_reasons","register_set","pre","post","memory","scope_exit","scope_reentry"],"register_sets":register_sets}).as_object().unwrap().clone());
    }
    Ok(response(rows, Value::Object(meta), json))
}
fn next<'a>(args: &'a [String], i: &mut usize, arg: &str) -> Result<&'a str, CliError> {
    let value = args
        .get(*i)
        .ok_or_else(|| CliError(format!("missing {arg} value"), 2))?;
    *i += 1;
    Ok(value)
}
fn trace_error(e: traceq_core::Error) -> CliError {
    CliError(e.message, 1)
}
impl From<String> for CliError {
    fn from(message: String) -> Self {
        Self(message, 2)
    }
}
#[derive(Debug)]
pub(crate) struct CliError(pub String, pub i32);
impl From<traceq_core::Error> for CliError {
    fn from(e: traceq_core::Error) -> Self {
        Self(e.message, 1)
    }
}
// Query implementations use a small local error type for argument propagation.

const USAGE: &str = "traceq: structured execution trace queries\nusage: traceq COMMAND FILE [options]\n  agent-query [--manifest tools.json] TRACE_ID COMMAND [options]\n  context       --at-ev E [--at-ev E ...] [--before N --after N]\n  instructions  [--from E --to E] [--limit N --offset N]\n  reg-state     --at-ev E [--phase pre|post] [--reg x0 ...]\n  mem-state     --range BASE,LEN (--at-ev E | --checkpoint E:pre ...)\n  mem-access    --range BASE,LEN [--read|--write] [--from E --to E]\n  last-writers  --range BASE,LEN [--at-seq E]\n  find-pc       (--off OFFSET | --addr ADDRESS)...\n  find-value    VALUE FILE | FILE --value VALUE... | FILE --bytes HEX...\n  boundaries    [--from E --to E] [--reg x0 ...]\n  stat          [--json]\nUse traceq COMMAND --help for command-specific options.\nInput: structured GTSW/GTSC captures; execution-state queries require profile 2.\nNumeric values use hexadecimal strings; unknown, gaps, boundaries and completion stay explicit.\nQueries validate the complete stream through END and its suffix.\n\n";
pub fn run(args: &[String]) -> Response {
    run_with_backend(args, std::env::var("TRACEQ_QUERY_BACKEND").ok().as_deref())
}
pub(crate) fn run_with_backend(args: &[String], backend: Option<&str>) -> Response {
    if args.is_empty() {
        let mut r = Response::text(USAGE);
        r.status = 2;
        return r;
    }
    let command = args[0].as_str();
    let json = args.iter().any(|s| s == "--json");
    if matches!(command, "help" | "--help" | "-h") {
        return Response::text(USAGE);
    }
    if matches!(
        command,
        "context" | "instructions" | "reg-state" | "mem-state"
    ) && backend.is_some_and(|value| value != "rust" && value != "cpp")
        && !args.iter().any(|s| s == "--help" || s == "-h")
    {
        return failure(command, "TRACEQ_QUERY_BACKEND must be rust or cpp", 2, json);
    }
    let result = match command {
        "context" => context(args),
        "find-value" => find::run(args),
        "mem-access" => mem_access::run(args),
        "instructions" | "reg-state" | "mem-state" | "last-writers" | "find-pc" | "boundaries"
        | "stat" => state::run(args),
        _ => Err(CliError(
            format!(
                "unsupported command: {command}; use traceq --help. Historical text/GTB2 commands have been retired."
            ),
            2,
        )),
    };
    match result {
        Ok(r) => r,
        Err(CliError(message, code)) => failure(command, &message, code, json),
    }
}
