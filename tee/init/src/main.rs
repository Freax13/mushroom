use anyhow::{Context, Result};

fn main() -> Result<()> {
    for i in 0..5 {
        let _ = std::thread::spawn(move || println!("Hi {}", i)).join();
    }

    let mut input = std::fs::File::open("/dev/input").context("failed to open input file")?;
    let mut output =
        std::fs::File::create("/dev/output").context("failed to create output file")?;
    std::io::copy(&mut input, &mut output).context("failed to copy")?;
    Ok(())
}
