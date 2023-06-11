use std::{fs::File, process::Command};

use anyhow::Result;
use tar::Archive;

fn main() -> Result<()> {
    let root = "/";

    std::fs::remove_dir_all("/bin")?;

    // Unpack tar archive.
    let file = File::open("/dev/input")?;
    let mut archive = Archive::new(file);
    archive.unpack(root)?;

    std::fs::write("/test.c", "int main() { return 1; }")?;

    // Execute busybox.
    let status = Command::new("/usr/bin/gcc")
        .arg("/test.c")
        .arg("-o")
        .arg("test")
        .arg("-v")
        .status()?;
    assert!(status.success());

    let mut output = File::create("/dev/output")?;
    let mut res = File::open("test")?;
    std::io::copy(&mut res, &mut output)?;

    Ok(())
}
