//! One active capture; callbacks access mutable state only on its owner thread.
//! The atomic address is an identity token, never dereferenced by foreign threads.
use crate::{
    code_scope::CodeScope,
    gum,
    plan::{self, Plan},
    storage::{Mode, Storage},
};
use std::cell::Cell;
use std::collections::HashSet;
use std::path::Path;
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use traceq_core::wire::{Event, Header, Kind};
use traceq_observer::CpuContext;

static ACTIVE: AtomicPtr<Session> = AtomicPtr::new(ptr::null_mut());
static RESERVED: AtomicBool = AtomicBool::new(false);
static FOREIGN: AtomicBool = AtomicBool::new(false);
thread_local! {static OWNER:Cell<*mut Session>=const{Cell::new(ptr::null_mut())};}
#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct Summary {
    pub instructions: u64,
    pub reads: u64,
    pub writes: u64,
    pub gaps: u64,
    pub commits: u64,
}
#[derive(Clone, Copy)]
struct Instruction {
    seq: u64,
    pc: u64,
}

#[derive(Default)]
struct PreparedMemory {
    address: u64,
    values: [u128; 4],
}

// The pointer is only an identity token. Gum owns immutable plans until their
// callouts are reclaimed. The session owns the one execution awaiting a post.
struct Pending {
    plan: *const Plan,
    instruction: Instruction,
    memory_valid: bool,
}
struct Session {
    header: Header,
    code_scope: CodeScope,
    observation: u32,
    storage: Storage,
    counts: Summary,
    state: [u128; 65],
    known: [bool; 65],
    gpr_bank: [u64; 29],
    complete: bool,
    sites: HashSet<u64>,
    failed: bool,
    exclusive: bool,
    pending: Option<Pending>,
    memory: PreparedMemory,
    outside: bool,
    return_exit: bool,
    exit_seq: u64,
    exit_pc: u64,
}
fn owner_ptr() -> *mut Session {
    let p = OWNER.with(Cell::get);
    if !p.is_null() && ACTIVE.load(Ordering::Acquire) == p {
        p
    } else {
        ptr::null_mut()
    }
}
pub fn active() -> bool {
    !ACTIVE.load(Ordering::Acquire).is_null()
}
pub fn owns() -> bool {
    !owner_ptr().is_null()
}
fn check_owner() -> *mut Session {
    let p = owner_ptr();
    if p.is_null() && active() {
        FOREIGN.store(true, Ordering::Relaxed);
    }
    p
}
pub fn fail() {
    let p = owner_ptr();
    if !p.is_null() {
        unsafe {
            (*p).failed = true;
        }
    } else if active() {
        FOREIGN.store(true, Ordering::Relaxed);
    }
}
pub fn code_contains(address: u64, size: u64) -> bool {
    let p = owner_ptr();
    !p.is_null() && unsafe { (*p).code_scope.contains(address, size) }
}
pub fn config() -> Option<(Header, u32)> {
    let p = owner_ptr();
    if p.is_null() {
        None
    } else {
        Some(unsafe { ((*p).header, (*p).observation) })
    }
}
pub fn exclusive() {
    let p = owner_ptr();
    if !p.is_null() {
        unsafe {
            (*p).exclusive = true;
        }
    }
}
#[allow(clippy::too_many_arguments)]
#[inline]
fn event(
    kind: Kind,
    seq: u64,
    pc: u64,
    address: u64,
    size: u64,
    low: u64,
    high: u64,
    detail: u64,
) -> Event {
    Event {
        kind,
        seq,
        pc,
        address,
        size,
        low,
        high,
        detail,
    }
}
#[inline(always)]
fn emit_to(s: &mut Session, e: Event) {
    if !s.failed && s.storage.append(e).is_err() {
        s.failed = true;
    }
}
fn gap(s: &mut Session, seq: u64, pc: u64, reason: u64) {
    s.counts.gaps += 1;
    emit_to(s, event(Kind::Gap, seq, pc, 0, 0, 0, 0, reason));
    s.known.fill(false);
    s.complete = false;
}
pub fn emit(e: Event) {
    let p = owner_ptr();
    if !p.is_null() {
        unsafe {
            emit_to(&mut *p, e);
        }
    }
}
fn fragments(kind: Kind, pc: u64, address: u64, bytes: &[u8]) {
    for (i, b) in bytes.chunks(24).enumerate() {
        let mut words = [0; 24];
        words[..b.len()].copy_from_slice(b);
        emit(event(
            kind,
            (i * 24) as u64,
            pc,
            address,
            b.len() as u64,
            u64::from_le_bytes(words[..8].try_into().unwrap()),
            u64::from_le_bytes(words[8..16].try_into().unwrap()),
            u64::from_le_bytes(words[16..].try_into().unwrap()),
        ));
    }
}
pub fn emit_site(ins: &gum::Insn) {
    let p = owner_ptr();
    if p.is_null() {
        return;
    }
    if unsafe { (*p).sites.insert(ins.address) } {
        let mut text = [0u8; 193]; // 32-byte mnemonic, space, 160-byte operands.
        let mnemonic_len = ins
            .mnemonic
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(ins.mnemonic.len());
        let operands_len = ins
            .op_str
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(ins.op_str.len());
        text[..mnemonic_len].copy_from_slice(&ins.mnemonic[..mnemonic_len]);
        text[mnemonic_len] = b' ';
        let len = mnemonic_len + 1 + operands_len;
        text[mnemonic_len + 1..len].copy_from_slice(&ins.op_str[..operands_len]);
        fragments(
            Kind::Site,
            ins.address,
            u32::from_le_bytes(ins.bytes[..4].try_into().unwrap()) as u64,
            &text[..len],
        );
    }
}
unsafe extern "C" fn record_module(module: *mut gum::Module, _: *mut core::ffi::c_void) -> i32 {
    crate::ffi_guard(|| unsafe {
        let r = &*gum::gum_module_get_range(module);
        let name = gum::gum_module_get_name(module);
        if !name.is_null() {
            fragments(
                Kind::Module,
                r.base_address,
                r.size as u64,
                std::ffi::CStr::from_ptr(name).to_bytes(),
            );
        }
    });
    1
}
pub fn begin(path: &Path, header: Header, observation: u32, mode: Mode, external: bool) -> bool {
    begin_scoped(
        path,
        header,
        observation,
        mode,
        external,
        CodeScope::single(header.code_base, header.code_size),
    )
}
pub fn begin_scoped(
    path: &Path,
    header: Header,
    observation: u32,
    mode: Mode,
    external: bool,
    code_scope: CodeScope,
) -> bool {
    if header.code_size == 0
        || header.data_size == 0
        || header.code_base.checked_add(header.code_size).is_none()
        || header.data_base.checked_add(header.data_size).is_none()
        || observation > 2
        || code_scope.envelope() != (header.code_base, header.code_size)
        || (header.profile != 2 && code_scope.ranges().len() > 1)
        || (header.profile != 1 && header.profile != 2)
        || (header.profile == 1 && mode == Mode::Chunked)
    {
        return false;
    }
    if RESERVED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
        .is_err()
    {
        return false;
    }
    // A reservation is released on all setup errors and on unwinding.
    struct Reservation(bool);
    impl Drop for Reservation {
        fn drop(&mut self) {
            if self.0 {
                RESERVED.store(false, Ordering::Release);
            }
        }
    }
    let mut reservation = Reservation(true);
    let Ok(storage) = Storage::open(path, header, mode) else {
        return false;
    };
    let s = Box::new(Session {
        header,
        code_scope,
        observation,
        storage,
        counts: Summary::default(),
        state: [0; 65],
        known: [false; 65],
        gpr_bank: [0; 29],
        complete: false,
        sites: HashSet::new(),
        failed: false,
        exclusive: false,
        pending: None,
        memory: PreparedMemory::default(),
        outside: false,
        return_exit: false,
        exit_seq: 0,
        exit_pc: 0,
    });
    let p = Box::into_raw(s);
    OWNER.with(|v| v.set(p));
    FOREIGN.store(false, Ordering::Relaxed);
    ACTIVE.store(p, Ordering::Release);
    reservation.0 = false;
    if header.profile == 2 {
        let count = unsafe { (*p).code_scope.ranges().len() };
        let explicit = count > 1;
        emit(event(
            Kind::Features,
            0,
            0,
            if explicit { 3 } else { 1 },
            if explicit { count as u64 } else { 0 },
            external as u64,
            0,
            0,
        ));
        if explicit {
            for index in 0..count {
                let range = unsafe { (*p).code_scope.ranges()[index] };
                emit(event(
                    Kind::CodeRange,
                    index as u64,
                    range.base,
                    range.size,
                    0,
                    0,
                    0,
                    0,
                ));
            }
        }
        unsafe {
            gum::gum_process_enumerate_modules(Some(record_module), ptr::null_mut());
        }
    }
    !unsafe { (*p).failed }
}
pub fn end() -> Option<(bool, Summary)> {
    let p = owner_ptr();
    if p.is_null() {
        return None;
    }
    // Unfollow on the owner before end. Plans remain alive until the caller's
    // later Gum garbage collection, including the pending final observation.
    let mut s = unsafe { Box::from_raw(p) };
    struct Deactivate;
    impl Drop for Deactivate {
        fn drop(&mut self) {
            ACTIVE.store(ptr::null_mut(), Ordering::Release);
            OWNER.with(|v| v.set(ptr::null_mut()));
            RESERVED.store(false, Ordering::Release);
        }
    }
    // On unwind, clear identity before the owning Box releases its allocation.
    let _deactivate = Deactivate;
    if FOREIGN.load(Ordering::Relaxed) {
        s.failed = true;
    }
    discard_pending(&mut s);
    if s.exclusive {
        let seq = s.counts.instructions;
        gap(&mut s, seq, 0, 4);
    }
    let n = s.counts;
    let profile = s.header.profile;
    emit_to(
        &mut s,
        event(
            Kind::End,
            n.instructions,
            0,
            n.writes,
            n.gaps,
            n.reads,
            n.commits,
            profile,
        ),
    );
    let ok = s.storage.finish().is_ok() && !s.failed;
    Some((ok, n))
}
fn discard_pending(s: &mut Session) {
    if let Some(pending) = s.pending.take() {
        gap(s, pending.instruction.seq, pending.instruction.pc, 2);
    }
}

fn next_instruction(s: &mut Session, pc: u64) -> Instruction {
    let seq = s.counts.instructions;
    s.counts.instructions += 1;
    Instruction { seq, pc }
}

fn take_pending(s: &mut Session, p: &Plan) -> Option<Pending> {
    if s.pending
        .as_ref()
        .is_some_and(|pending| ptr::eq(pending.plan, p))
    {
        s.pending.take()
    } else {
        None
    }
}

fn observe_slot(s: &mut Session, slot: usize, value: u128, instruction: Instruction, kind: Kind) {
    if !s.known[slot] || s.state[slot] != value {
        emit_to(
            s,
            event(
                kind,
                instruction.seq,
                instruction.pc,
                slot as u64,
                if slot < 33 { 8 } else { 16 },
                value as u64,
                (value >> 64) as u64,
                1,
            ),
        );
        s.state[slot] = value;
        s.known[slot] = true;
    }
}
fn state_delta(s: &mut Session, c: &CpuContext, instruction: Instruction, kind: Kind) {
    if s.observation == 0 || !s.complete || s.gpr_bank != c.x {
        for (i, v) in c.x.iter().enumerate() {
            observe_slot(s, i, *v as u128, instruction, kind);
        }
        s.gpr_bank = c.x;
    }
    for (i, v) in [(29, c.fp), (30, c.lr), (31, c.sp), (32, c.nzcv)] {
        observe_slot(s, i, v as u128, instruction, kind);
    }
    // Keep the bank comparison, followed only on change by scalar deltas.
    let vectors = unsafe { std::slice::from_raw_parts(s.state.as_ptr().add(33).cast::<u8>(), 512) };
    let cpu_vectors = unsafe { std::slice::from_raw_parts(c.vectors.as_ptr().cast::<u8>(), 512) };
    if s.observation == 0 || !s.complete || vectors != cpu_vectors {
        for (i, v) in c.vectors.iter().enumerate() {
            observe_slot(s, i + 33, u128::from_le_bytes(*v), instruction, kind);
        }
    }
    s.complete = true;
}
fn before_state(s: &mut Session, c: &CpuContext, p: &Plan, shared: bool) {
    discard_pending(s);
    let reenter = s.outside;
    if reenter && s.return_exit {
        gap(s, s.exit_seq, s.exit_pc, 6);
    }
    let instruction = next_instruction(s, p.pc);
    emit_to(
        s,
        event(
            Kind::Exec,
            instruction.seq,
            p.pc,
            p.word as u64,
            0,
            0,
            0,
            p.post as u64,
        ),
    );
    if !shared || !s.complete {
        state_delta(s, c, instruction, Kind::RegPre);
    }
    if reenter {
        emit_to(
            s,
            event(
                Kind::ScopeReenter,
                instruction.seq,
                p.pc,
                s.exit_seq,
                0,
                0,
                0,
                1,
            ),
        );
        s.outside = false;
    }
    if p.unsupported {
        gap(s, instruction.seq, p.pc, 1);
        return;
    }
    if p.check_target {
        let target = if p.target_register != 0 {
            plan::reg_value(p.target_register, c).map(|v| v as u64)
        } else {
            Some(p.target_address)
        };
        let Some(target) = target else {
            gap(s, instruction.seq, p.pc, 1);
            return;
        };
        if !s.code_scope.contains(target, 4) {
            emit_to(
                s,
                event(
                    Kind::ScopeExit,
                    instruction.seq,
                    p.pc,
                    target,
                    p.transfer,
                    if p.transfer == 1 {
                        p.pc.wrapping_add(4)
                    } else {
                        0
                    },
                    0,
                    1,
                ),
            );
            s.outside = true;
            s.return_exit = p.transfer == 3;
            s.exit_seq = instruction.seq;
            s.exit_pc = p.pc;
            if !s.return_exit {
                gap(s, instruction.seq, p.pc, 6);
            }
            return;
        }
    }
    let memory_valid = memory_before(s, c, p, instruction);
    if p.post {
        s.pending = Some(Pending {
            plan: p,
            instruction,
            memory_valid,
        });
    }
}
fn memory_before(s: &mut Session, c: &CpuContext, p: &Plan, instruction: Instruction) -> bool {
    if p.count == 0 {
        return false;
    }
    let address = if p.mem.kind == gum::ARM64_OP_IMM {
        p.mem.imm() as u64
    } else {
        let mem = p.mem.mem();
        let (Some(base), Some(index)) = (
            plan::reg_value(mem.base, c),
            if mem.index != 0 {
                plan::reg_value(mem.index, c)
            } else {
                Some(0)
            },
        ) else {
            gap(s, instruction.seq, p.pc, 1);
            return false;
        };
        let mut ix = index as u64;
        if p.mem.ext == gum::ARM64_EXT_UXTW {
            ix = ix as u32 as u64;
        }
        if p.mem.ext == gum::ARM64_EXT_SXTW {
            ix = ix as i32 as i64 as u64;
        }
        (base as u64)
            .wrapping_add(ix.wrapping_shl(p.mem.shift.value))
            .wrapping_add(mem.disp as u64)
    };
    if p.ordered_memory && !address.is_multiple_of(p.width as u64) {
        gap(s, instruction.seq, p.pc, 1);
        return false;
    }
    if !plan::contains(
        s.header.data_base,
        s.header.data_size,
        address,
        (p.width * p.count) as u64,
    ) {
        gap(s, instruction.seq, p.pc, 5);
        return false;
    }
    if !p.load && !plan::store_values(c, p, &mut s.memory.values) {
        gap(s, instruction.seq, p.pc, 1);
        return false;
    }
    s.memory.address = address;
    true
}
fn after_state(s: &mut Session, c: &CpuContext, p: &Plan) {
    let Some(Pending {
        instruction,
        memory_valid,
        ..
    }) = take_pending(s, p)
    else {
        return;
    };
    if memory_valid {
        let address = s.memory.address;
        if let Some(width) = p.atomic_width {
            // The completed destination is the actual atomic old value. The
            // saved source survives Rs==Rt; never sample the raced memory.
            if let Some(old) = plan::reg_value(p.sources[1], c) {
                for (kind, value) in [
                    (Kind::Read, width.mask(old as u64)),
                    (
                        Kind::Write,
                        width.add(old as u64, s.memory.values[0] as u64),
                    ),
                ] {
                    emit_to(
                        s,
                        event(
                            kind,
                            instruction.seq,
                            p.pc,
                            address,
                            p.width as u64,
                            value,
                            0,
                            1,
                        ),
                    );
                }
                s.counts.reads += 1;
                s.counts.writes += 1;
            } else {
                gap(s, instruction.seq, p.pc, 1);
            }
        } else {
            // Structured loads deinterleave memory into destination registers. The
            // actual post registers are packed back into bounded memory-order chunks.
            let structured_load = p.load && p.structure_element != 0;
            let structure_known =
                !structured_load || plan::store_values(c, p, &mut s.memory.values);
            for i in 0..p.count as usize {
                let (mut value, known) = if structured_load {
                    let value = if structure_known {
                        s.memory.values[i]
                    } else {
                        0
                    };
                    (value, structure_known)
                } else if p.load {
                    let observed = if p.sources[i] == gum::ARM64_REG_XZR
                        || p.sources[i] == gum::ARM64_REG_WZR
                    {
                        None
                    } else {
                        plan::reg_value(p.sources[i], c)
                    };
                    let mut value = observed.unwrap_or(0);
                    if p.structure_lane >= 0 {
                        value >>= p.structure_lane as u32 * p.width * 8;
                    }
                    (value, observed.is_some())
                } else {
                    (s.memory.values[i], true)
                };
                if p.width < 16 {
                    value &= (1u128 << (p.width * 8)) - 1;
                }
                emit_to(
                    s,
                    event(
                        if p.load { Kind::Read } else { Kind::Write },
                        instruction.seq,
                        p.pc,
                        address.wrapping_add(i as u64 * p.width as u64),
                        p.width as u64,
                        value as u64,
                        (value >> 64) as u64,
                        known as u64,
                    ),
                );
                if p.load {
                    s.counts.reads += 1;
                } else {
                    s.counts.writes += 1;
                }
            }
        }
    }
    state_delta(s, c, instruction, Kind::RegPost);
    emit_to(s, event(Kind::Commit, instruction.seq, p.pc, 0, 0, 0, 0, 1));
    s.counts.commits += 1;
}
// Gum proxy contexts can be unaligned. Copy only that exceptional path before
// constructing a Rust reference; normal aligned contexts stay in place.
unsafe fn cpu(c: *mut CpuContext, copy: &mut std::mem::MaybeUninit<CpuContext>) -> &CpuContext {
    if (c as usize).is_multiple_of(std::mem::align_of::<CpuContext>()) {
        unsafe { &*c }
    } else {
        copy.write(unsafe { ptr::read_unaligned(c) });
        unsafe { copy.assume_init_ref() }
    }
}
/// # Safety
/// Gum provides a live CPU context and distinct live Plan objects owned by its code cache.
pub unsafe fn before(c: *mut CpuContext, p: *const Plan) {
    let s = check_owner();
    if s.is_null() || c.is_null() || p.is_null() {
        return;
    }
    let mut copy = std::mem::MaybeUninit::uninit();
    let c = unsafe { cpu(c, &mut copy) };
    let (s, p) = unsafe { (&mut *s, &*p) };
    if s.header.profile == 2 {
        before_state(s, c, p, false);
        return;
    }
    discard_pending(s);
    let instruction = next_instruction(s, p.pc);
    emit_to(s, event(Kind::Exec, instruction.seq, p.pc, 0, 0, 0, 0, 0));
    if p.unsupported {
        gap(s, instruction.seq, p.pc, 1);
        return;
    }
    if memory_before(s, c, p, instruction) {
        s.pending = Some(Pending {
            plan: p,
            instruction,
            memory_valid: true,
        });
    }
}
/// # Safety
/// Gum provides a live CPU context and distinct live Plan objects owned by its code cache.
pub unsafe fn after(c: *mut CpuContext, p: *const Plan) {
    let s = check_owner();
    if s.is_null() || c.is_null() || p.is_null() {
        return;
    }
    let mut copy = std::mem::MaybeUninit::uninit();
    let c = unsafe { cpu(c, &mut copy) };
    let (s, p) = unsafe { (&mut *s, &*p) };
    if s.header.profile == 2 {
        after_state(s, c, p);
        return;
    }
    let Some(Pending {
        instruction,
        memory_valid: true,
        ..
    }) = take_pending(s, p)
    else {
        return;
    };
    let address = s.memory.address;
    for i in 0..p.count as usize {
        let mut v = s.memory.values[i];
        if p.width < 16 {
            v &= (1u128 << (p.width * 8)) - 1;
        }
        emit_to(
            s,
            event(
                Kind::Write,
                instruction.seq,
                p.pc,
                address.wrapping_add(i as u64 * p.width as u64),
                p.width as u64,
                v as u64,
                (v >> 64) as u64,
                1,
            ),
        );
        s.counts.writes += 1;
    }
}
/// # Safety
/// Gum provides a live CPU context and distinct live Plan objects owned by its code cache.
pub unsafe fn shared_boundary(c: *mut CpuContext, previous: *const Plan, current: *const Plan) {
    let s = check_owner();
    if s.is_null() || c.is_null() {
        return;
    }
    let mut copy = std::mem::MaybeUninit::uninit();
    let c = unsafe { cpu(c, &mut copy) };
    let s = unsafe { &mut *s };
    let confirmed = s
        .pending
        .as_ref()
        .is_some_and(|pending| pending.plan == previous);
    if confirmed {
        unsafe {
            after_state(s, c, &*previous);
        }
    }
    unsafe {
        before_state(s, c, &*current, confirmed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use traceq_core::wire::Input;
    fn set(cpu: &mut CpuContext, slot: usize, value: u128) {
        match slot {
            0..=28 => cpu.x[slot] = value as u64,
            29 => cpu.fp = value as u64,
            30 => cpu.lr = value as u64,
            31 => cpu.sp = value as u64,
            32 => cpu.nzcv = value as u64,
            _ => cpu.vectors[slot - 33] = value.to_le_bytes(),
        }
    }
    fn value(cpu: &CpuContext, slot: usize) -> u128 {
        match slot {
            0..=28 => cpu.x[slot] as u128,
            29 => cpu.fp as u128,
            30 => cpu.lr as u128,
            31 => cpu.sp as u128,
            32 => cpu.nzcv as u128,
            _ => u128::from_le_bytes(cpu.vectors[slot - 33]),
        }
    }
    #[test]
    fn full65_runtime_deltas_match_independent_scalar_oracle() {
        let mut cpu = CpuContext {
            pc: 0,
            sp: 0,
            nzcv: 0,
            x: [0; 29],
            fp: 0,
            lr: 0,
            vectors: [[0; 16]; 32],
        };
        let mut steps = vec![
            (cpu, false, false),
            (cpu, false, false),
            (cpu, true, false),
            (cpu, false, true),
        ];
        for slot in 0..65 {
            set(
                &mut cpu,
                slot,
                if slot < 33 {
                    0x8000_0000_0000_0001 + slot as u128
                } else {
                    (1u128 << (64 + slot % 64)) | 0x7ff8_0000_0000_0001
                },
            );
            steps.push((cpu, false, false));
            steps.push((cpu, false, false));
            if slot >= 33 {
                set(&mut cpu, slot, (1u128 << 127) | 0x7ff8_0000_0000_0001);
                steps.push((cpu, false, false));
            }
        }
        let mut random = 0x7472_6163_6571u64;
        let mut next = || {
            random ^= random << 13;
            random ^= random >> 7;
            random ^= random << 17;
            random
        };
        for n in 0..1536 {
            if n % 7 != 0 {
                for _ in 0..if n % 31 == 0 {
                    65
                } else if n % 11 == 0 {
                    8
                } else {
                    1
                } {
                    let slot = (next() % 65) as usize;
                    set(&mut cpu, slot, (next() as u128) | ((next() as u128) << 64));
                }
            }
            steps.push((cpu, n % 97 == 0, n % 127 == 0));
        }
        for mode in 0..=2 {
            let path = std::env::temp_dir().join(format!(
                "traceq-runtime-observer-{}-{}",
                std::process::id(),
                mode
            ));
            let header = Header {
                code_base: 4096,
                code_size: 64,
                data_base: 0,
                data_size: u64::MAX,
                thread_id: 1,
                profile: 2,
            };
            let storage = Storage::open(&path, header, Mode::Flat).unwrap();
            let mut s = Session {
                header,
                code_scope: CodeScope::single(header.code_base, header.code_size),
                observation: mode,
                storage,
                counts: Summary::default(),
                state: [0; 65],
                known: [false; 65],
                gpr_bank: [0; 29],
                complete: false,
                sites: HashSet::new(),
                failed: false,
                exclusive: false,
                pending: None,
                memory: PreparedMemory::default(),
                outside: false,
                return_exit: false,
                exit_seq: 0,
                exit_pc: 0,
            };
            let mut previous = [None; 65];
            let mut expected = Vec::new();
            for (seq, (cpu, invalid, restart)) in steps.iter().enumerate() {
                if *restart {
                    s.known.fill(false);
                    s.complete = false;
                    previous.fill(None);
                }
                if *invalid {
                    gap(&mut s, seq as u64, 4096, 1);
                    previous.fill(None);
                    expected.push(event(Kind::Gap, seq as u64, 4096, 0, 0, 0, 0, 1));
                }
                let instruction = Instruction {
                    seq: seq as u64,
                    pc: 4096,
                };
                let kind = if seq % 2 == 0 {
                    Kind::RegPre
                } else {
                    Kind::RegPost
                };
                state_delta(&mut s, cpu, instruction, kind);
                for (slot, prior) in previous.iter_mut().enumerate() {
                    let observed = value(cpu, slot);
                    if *prior != Some(observed) {
                        expected.push(event(
                            kind,
                            seq as u64,
                            4096,
                            slot as u64,
                            if slot < 33 { 8 } else { 16 },
                            observed as u64,
                            (observed >> 64) as u64,
                            1,
                        ));
                        *prior = Some(observed);
                    }
                    assert_eq!(s.state[slot], observed);
                    assert!(s.known[slot]);
                }
            }
            assert!(!s.failed);
            s.storage.finish().unwrap();
            let mut input = Input::new(std::fs::File::open(&path).unwrap()).unwrap();
            for e in expected {
                assert_eq!(input.next_event().unwrap(), e);
            }
            input.finish().unwrap();
            std::fs::remove_file(path).unwrap();
        }
    }
    #[test]
    fn atomic_alias_range_end_and_block_boundaries_restore_exact_accesses() {
        for mode in [Mode::Flat, Mode::Chunked] {
            let path = std::env::temp_dir().join(format!(
                "traceq-atomic-boundary-{}-{}",
                std::process::id(),
                mode as u8
            ));
            let header = Header {
                code_base: 4096,
                code_size: 64,
                data_base: 8192,
                data_size: 4,
                thread_id: 1,
                profile: 2,
            };
            let mut s = Session {
                header,
                code_scope: CodeScope::single(4096, 64),
                observation: 0,
                storage: Storage::open(&path, header, mode).unwrap(),
                counts: Summary::default(),
                state: [0; 65],
                known: [false; 65],
                gpr_bank: [0; 29],
                complete: false,
                sites: HashSet::new(),
                failed: false,
                exclusive: false,
                pending: None,
                memory: PreparedMemory::default(),
                outside: false,
                return_exit: false,
                exit_seq: 0,
                exit_pc: 0,
            };
            let text = b"ldadd w0, w0, [x1]";
            let mut bytes = [0; 24];
            bytes[..text.len()].copy_from_slice(text);
            let words: Vec<_> = bytes
                .chunks_exact(8)
                .map(|c| u64::from_le_bytes(c.try_into().unwrap()))
                .collect();
            emit_to(
                &mut s,
                event(
                    Kind::Site,
                    0,
                    4096,
                    0xb8200020,
                    text.len() as u64,
                    words[0],
                    words[1],
                    words[2],
                ),
            );
            let p = Plan {
                pc: 4096,
                word: 0xb8200020,
                width: 4,
                count: 1,
                post: true,
                ordered_memory: true,
                atomic_width: Some(traceq_core::arm64_memory::Width::W32),
                sources: [gum::ARM64_REG_W0, gum::ARM64_REG_W0, 0, 0],
                mem: gum::Arm64Op {
                    kind: gum::ARM64_OP_MEM,
                    value: gum::OperandValue {
                        mem: gum::Mem {
                            base: gum::ARM64_REG_X0 + 1,
                            index: 0,
                            disp: 0,
                        },
                    },
                    ..gum::Arm64Op::default()
                },
                ..Plan::default()
            };
            let mut c = CpuContext {
                pc: 4096,
                sp: 0,
                nzcv: 0,
                x: [0; 29],
                fp: 0,
                lr: 0,
                vectors: [[0; 16]; 32],
            };
            let mut counter = 1u32;
            for seq in 0..302 {
                c.x[0] = 0xfeedbeef_ffffffff;
                c.x[1] = if seq == 300 {
                    8193
                } else if seq == 301 {
                    8196
                } else {
                    8192
                };
                before_state(&mut s, &c, &p, false);
                c.x[0] = counter as u64;
                after_state(&mut s, &c, &p);
                if seq < 300 {
                    counter = counter.wrapping_sub(1);
                }
            }
            assert_eq!(
                (
                    s.counts.reads,
                    s.counts.writes,
                    s.counts.gaps,
                    s.counts.commits
                ),
                (300, 300, 2, 302)
            );
            emit_to(&mut s, event(Kind::End, 302, 0, 300, 2, 300, 302, 2));
            s.storage.finish().unwrap();
            let mut count = 0u64;
            let mut expected = 1u32;
            let info = traceq_core::replay::read(
                Input::new(std::fs::File::open(&path).unwrap()).unwrap(),
                |g, _| {
                    if g.seq < 300 {
                        assert!(!g.gap && g.committed);
                        assert_eq!(g.accesses.len(), 2);
                        assert_eq!(
                            (g.accesses[0].kind, g.accesses[0].low),
                            (Kind::Read, expected as u64)
                        );
                        expected = expected.wrapping_sub(1);
                        assert_eq!(
                            (g.accesses[1].kind, g.accesses[1].low),
                            (Kind::Write, expected as u64)
                        );
                        assert!(
                            g.accesses
                                .iter()
                                .all(|a| a.address == 8192 && a.size == 4 && a.detail == 1)
                        );
                    } else {
                        assert!(g.gap && g.accesses.is_empty());
                    }
                    count += 1;
                },
            )
            .unwrap();
            assert_eq!(
                (count, info.reads, info.writes, info.gaps),
                (302, 300, 300, 2)
            );
            std::fs::remove_file(path).unwrap();
        }
    }
    #[test]
    fn unaligned_proxy_context_copy_preserves_every_bit() {
        let expected = CpuContext {
            pc: 1,
            sp: 2,
            nzcv: 3,
            x: [u64::MAX; 29],
            fp: 4,
            lr: 5,
            vectors: [[0xa5; 16]; 32],
        };
        let mut bytes = vec![0u8; std::mem::size_of::<CpuContext>() + 1];
        unsafe {
            ptr::write_unaligned(bytes.as_mut_ptr().add(1).cast::<CpuContext>(), expected);
        }
        let mut copy = std::mem::MaybeUninit::uninit();
        let observed = unsafe { cpu(bytes.as_mut_ptr().add(1).cast(), &mut copy) };
        assert_eq!(*observed, expected);
    }
}
