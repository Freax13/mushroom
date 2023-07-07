use std::{
    io::{BufReader, Cursor},
    process::Command,
};

use anyhow::{Context, Result};
use flate2::bufread::GzDecoder;
use nix::mount::{mount, MsFlags};
use tar::Archive;

const BYTES: &[u8] = include_bytes!("../../gcc.tar.gz");

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
    let file = Cursor::new(BYTES);
    let buf_reader = BufReader::new(file);
    let reader = GzDecoder::new(buf_reader);
    let mut archive = Archive::new(reader);
    archive.unpack(root)?;

    // Execute busybox.
    let status = Command::new("/bin/init").status()?;
    assert!(status.success());

    Ok(())
}
