use std::io::Read;

use anyhow::{Context, Result};

fn main() -> Result<()> {
    let mut input = std::fs::File::open("/dev/input").context("failed to open input file")?;
    input.read_exact(&mut [0; 0x1000])?;

    Ok(())
}
