//! Check independent Python golden vectors in one bounded test process.
use std::io::Read;
use traceq_core::wire::{Event, decode_block, encode_block};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut file = std::fs::File::open(std::env::args().nth(1).ok_or("pass vectors")?)?;
    let mut vectors = 0;
    loop {
        let mut count = [0; 4];
        if file.read(&mut count[..1])? == 0 {
            break;
        }
        file.read_exact(&mut count[1..])?;
        let count = u32::from_le_bytes(count) as usize;
        if count == 0 || count > 1024 {
            return Err("invalid vector count".into());
        }
        let mut size = [0; 4];
        file.read_exact(&mut size)?;
        let size = u32::from_le_bytes(size) as usize;
        if size > count * 61 {
            return Err("invalid vector size".into());
        }
        let mut events = Vec::with_capacity(count);
        for _ in 0..count {
            let mut bytes = [0; 64];
            file.read_exact(&mut bytes)?;
            let mut words = [0; 8];
            for (i, v) in words.iter_mut().enumerate() {
                *v = u64::from_le_bytes(bytes[i * 8..i * 8 + 8].try_into()?);
            }
            events.push(Event::from_words(words)?);
        }
        let mut packed = vec![0; size];
        file.read_exact(&mut packed)?;
        if encode_block(&events)? != packed || decode_block(&packed, count)? != events {
            return Err("golden vector mismatch".into());
        }
        vectors += 1;
    }
    println!("{{\"vectors\":{vectors},\"pass\":true}}");
    Ok(())
}
