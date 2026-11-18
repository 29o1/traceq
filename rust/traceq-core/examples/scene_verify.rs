//! Independent controlled-buffer and ELF evidence oracle. This is validation
//! code: it consumes the public Rust replay API and never participates in capture.
use std::{fs, fs::File, io::BufReader};
use traceq_core::{
    replay,
    wire::{Input, Kind},
};

type Check<T> = Result<T, String>;
fn need(ok: bool, message: &str) -> Check<()> {
    if ok { Ok(()) } else { Err(message.into()) }
}
fn load(path: &str) -> Check<Vec<u8>> {
    fs::read(path).map_err(|e| format!("{path}: {e}"))
}
fn number(text: &str) -> Check<u64> {
    let (radix, digits) = if text.starts_with("0x") || text.starts_with("0X") {
        (16, &text[2..])
    } else if text.len() > 1 && text.starts_with('0') {
        (8, text)
    } else {
        (10, text)
    };
    u64::from_str_radix(digits, radix).map_err(|e| e.to_string())
}
fn word(bytes: &[u8], offset: u64, len: usize) -> Check<u64> {
    let offset = usize::try_from(offset).map_err(|_| "ELF bounds".to_string())?;
    need(
        offset <= bytes.len() && len <= bytes.len() - offset,
        "ELF bounds",
    )?;
    let mut result = 0;
    for (i, b) in bytes[offset..offset + len].iter().enumerate() {
        result |= u64::from(*b) << (8 * i);
    }
    Ok(result)
}
fn elf_word(bytes: &[u8], address: u64, opcode: u64) -> Check<bool> {
    let offset = word(bytes, 32, 8)?;
    let step = word(bytes, 54, 2)?;
    let count = word(bytes, 56, 2)?;
    for index in 0..count {
        let p = offset
            .checked_add(index.checked_mul(step).ok_or("ELF bounds")?)
            .ok_or("ELF bounds")?;
        if word(bytes, p, 4)? != 1 {
            continue;
        }
        let base = word(bytes, p + 16, 8)?;
        let size = word(bytes, p + 32, 8)?;
        if address >= base && size >= 4 && address - base <= size - 4 {
            let file_offset = word(bytes, p + 8, 8)?
                .checked_add(address - base)
                .ok_or("ELF bounds")?;
            return Ok(word(bytes, file_offset, 4)? == opcode);
        }
    }
    Ok(false)
}
fn mix(hash: u64, value: u64) -> u64 {
    (hash ^ value).wrapping_mul(1099511628211)
}
fn run(args: &[String]) -> Check<()> {
    need(
        args.len() == 9 || args.len() == 10,
        "TRACE ELF IMAGE_BASE INITIAL EXPECTED TARGET copy|codec INPUT_BASE INPUT [ENTRIES]",
    )?;
    let elf = load(&args[1])?;
    let mut physical = load(&args[3])?;
    let expected = load(&args[4])?;
    let input = load(&args[8])?;
    need(physical.len() == expected.len(), "image sizes")?;
    let base = number(&args[2])?;
    let target = number(&args[5])?;
    let input_base = number(&args[7])?;
    let expected_entries = if args.len() == 10 {
        number(&args[9])?
    } else {
        1
    };
    let copy = args[6] == "copy";
    need(copy || args[6] == "codec", "mode must be copy or codec")?;
    let (mut groups, mut post, mut entries, mut target_count) = (0, 0, 0, 0);
    let (mut pc_hash, mut mem_hash) = (1469598103934665603u64, 1469598103934665603u64);
    let (mut read_bytes, mut write_bytes, mut skipped_reads, mut other_accesses) = (0, 0, 0, 0);
    let mut inside = false;
    let mut known = vec![true; physical.len()];
    let mut written = vec![false; physical.len()];
    let mut gaps = vec![];
    let (mut first, mut last) = (u64::MAX, 0);
    let mut historical = physical.clone();
    let mut failure = None;
    let stream = Input::new(BufReader::with_capacity(
        64 * 1024,
        File::open(&args[0]).map_err(|e| e.to_string())?,
    ))
    .map_err(|e| e.message)?;
    replay::read(stream, |g, info| {
        if failure.is_some() {
            return;
        }
        let checked = (|| -> Check<()> {
            groups += 1;
            need(g.pre.all_known(), "incomplete65 pre")?;
            if g.committed {
                need(g.post.all_known(), "incomplete65 post")?;
                post += 1;
            } else {
                need(g.post.known == [0, 0], "unobserved post leaked")?;
            }
            need(
                g.pc >= info.header.code_base
                    && elf_word(&elf, g.pc - info.header.code_base, g.word)?,
                "ELF opcode mismatch",
            )?;
            if g.pc == target {
                entries += 1;
                inside = true;
                need(
                    g.pre.bits[0] as u64 == base + if copy { 141 } else { 0 },
                    "target ABI output",
                )?;
                if copy {
                    need(
                        g.pre.bits[1] as u64 == base + 128 && g.pre.bits[2] as u64 == 257,
                        "copy ABI source/length",
                    )?;
                } else {
                    need(
                        g.pre.bits[2] as u64 == input_base
                            && g.pre.bits[3] as u64 == input.len() as u64,
                        "codec ABI input",
                    )?;
                }
            }
            if inside {
                target_count += 1;
                for v in [
                    g.pc - info.header.code_base,
                    g.word,
                    u64::from(g.committed),
                    u64::from(g.gap),
                    g.gap_count,
                    g.gap_reason_mask,
                    g.exit.transfer,
                    u64::from(g.reentered),
                ] {
                    pc_hash = mix(pc_hash, v);
                }
            }
            if g.gap {
                gaps.push(g.seq);
                if !copy {
                    known.fill(false);
                }
            }
            for event in &g.accesses {
                let end = event
                    .address
                    .checked_add(event.size)
                    .ok_or("address overflow")?;
                let image = event.address >= base && end - base <= physical.len() as u64;
                let source =
                    !copy && event.address >= input_base && end - input_base <= input.len() as u64;
                if !image && !source {
                    other_accesses += 1;
                    continue;
                }
                if inside {
                    mem_hash = mix(mem_hash, g.pc - info.header.code_base);
                    mem_hash = mix(mem_hash, event.kind as u64);
                    mem_hash = mix(mem_hash, if image { 1 } else { 2 });
                    mem_hash = mix(
                        mem_hash,
                        event.address - if image { base } else { input_base },
                    );
                    for v in [event.size, event.low, event.high, event.detail] {
                        mem_hash = mix(mem_hash, v);
                    }
                }
                if image {
                    first = first.min(g.seq);
                    last = g.seq;
                }
                if event.detail == 0 {
                    continue;
                }
                let value = event.low as u128 | ((event.high as u128) << 64);
                for j in 0..event.size {
                    let byte = (value >> (8 * j)) as u8;
                    if event.kind == Kind::Read {
                        if image && known[(event.address - base + j) as usize] {
                            need(
                                physical[(event.address - base + j) as usize] == byte,
                                "physical mutable read",
                            )?;
                            read_bytes += 1;
                        } else if !image && source {
                            need(
                                input[(event.address - input_base + j) as usize] == byte,
                                "compressed source read",
                            )?;
                            read_bytes += 1;
                        } else {
                            skipped_reads += 1;
                        }
                    } else if image {
                        let position = (event.address - base + j) as usize;
                        physical[position] = byte;
                        historical[position] = byte;
                        known[position] = true;
                        written[position] = true;
                        write_bytes += 1;
                    }
                }
            }
            if inside && g.exit.transfer == 3 {
                inside = false;
            }
            Ok(())
        })();
        if let Err(error) = checked {
            failure = Some(format!("event {}: {error}", g.seq));
        }
    })
    .map_err(|e| e.message)?;
    if let Some(error) = failure {
        return Err(error);
    }
    need(entries == expected_entries, "entry count")?;
    if copy {
        for gap in gaps {
            need(
                first == u64::MAX || gap <= first || gap >= last,
                "internal copy memory gap",
            )?;
        }
        need(physical == expected, "copy physical fold")?;
    }
    let (mut written_count, mut historical_match, mut current_checked) = (0, 0, 0);
    for j in 0..known.len() {
        if written[j] {
            written_count += 1;
            historical_match += usize::from(historical[j] == expected[j]);
        }
        if !copy && known[j] {
            need(physical[j] == expected[j], "final known byte mismatch")?;
            current_checked += 1;
        }
    }
    println!(
        "{{\"pass\":true,\"groups\":{groups},\"post_groups\":{post},\"all65_ELF_END\":true,\"target_groups\":{target_count},\"target_pc_hash\":{pc_hash},\"relevant_memory_hash\":{mem_hash},\"read_bytes_checked\":{read_bytes},\"write_bytes_checked\":{write_bytes},\"written_output_positions\":{written_count},\"historical_matches_final_positions\":{historical_match},\"current_known_final_bytes_checked\":{current_checked},\"reads_without_physical_prior_fact\":{skipped_reads},\"other_accesses_recorded_not_independently_checked\":{other_accesses}}}"
    );
    Ok(())
}
fn main() {
    if let Err(error) = run(&std::env::args().skip(1).collect::<Vec<_>>()) {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
