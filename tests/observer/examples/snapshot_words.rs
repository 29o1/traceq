fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write;
    let mut words = [0; 80];
    let n =
        traceq_observer_lab::snapshot::generate(0x123456789abcdef0, 0xfedcba9876543210, &mut words)
            .ok_or("generation failed")?;
    let mut out = std::fs::File::options()
        .write(true)
        .create_new(true)
        .open(std::env::args().nth(1).ok_or("pass output")?)?;
    for word in &words[..n] {
        out.write_all(&word.to_le_bytes())?;
    }
    println!("{n} words");
    Ok(())
}
