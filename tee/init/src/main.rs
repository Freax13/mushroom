use std::{fs::OpenOptions, os::unix::prelude::OpenOptionsExt, process::Command};

use anyhow::{Context, Result};

fn main() -> Result<()> {
    let this = std::env::args().next().unwrap();
    if this == "/bin/init" {
        let mut input = std::fs::File::open("/bin/init").context("failed to open input file")?;
        let mut output = OpenOptions::new()
            .write(true)
            .create(true)
            .mode(0o755)
            .open("/bin/proc")
            .context("failed to create output file")?;
        std::io::copy(&mut input, &mut output).context("failed to copy")?;

        let status = Command::new("/bin/proc").status().unwrap();
        assert!(status.success());
    } else {
        let mut input = std::fs::File::open("/dev/input").context("failed to open input file")?;
        let mut output =
            std::fs::File::create("/dev/output").context("failed to create output file")?;
        std::io::copy(&mut input, &mut output).context("failed to copy")?;
    }
    Ok(())
}
