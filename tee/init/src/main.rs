use std::{fs::File, process::Command};

use anyhow::Result;
use tar::Archive;

fn main() -> Result<()> {
    let root = "/";

    // Unpack tar archive.
    let file = File::open("/dev/input")?;
    let mut archive = Archive::new(file);
    archive.unpack(root)?;

    // Execute busybox.
    let status = Command::new("/bin/busybox")
        .stdout(File::create("/dev/output")?)
        .status()?;
    assert!(status.success());

    Ok(())
}
