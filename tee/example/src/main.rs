use std::{
    io::{BufReader, Cursor},
    process::Command,
};

use anyhow::{Context, Result};
use flate2::bufread::GzDecoder;
use nix::mount::{MsFlags, mount};
use tar::Archive;

#[cfg(has_gcc_archive)]
const BYTES: Option<&[u8]> = Some(include_bytes!("../gcc.tar.gz"));
#[cfg(not(has_gcc_archive))]
const BYTES: Option<&[u8]> = None;

fn main() -> Result<()> {
    let root = "/";

    mount(
        Some("devtmpfs"),
        "/dev",
        Some("devtmpfs"),
        MsFlags::empty(),
        None::<&str>,
    )
    .context("failed to mount /dev")?;

    // Unpack tar archive.
    let bytes = BYTES.expect("gcc.tar.gz file was missing at compile time");
    let file = Cursor::new(bytes);
    let buf_reader = BufReader::new(file);
    let reader = GzDecoder::new(buf_reader);
    let mut archive = Archive::new(reader);
    archive.unpack(root)?;

    // Execute busybox.
    let status = Command::new("/bin/init").status()?;
    assert!(status.success());

    Ok(())
}
