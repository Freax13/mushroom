use std::{
    fs::File, io::BufReader, os::unix::process::CommandExt, process::Command, time::Duration,
};

use anyhow::{Context, Result};
use nix::{
    mount::{MsFlags, mount},
    sys::time::TimeSpec,
    time::{ClockId, clock_settime},
};
use tar::Archive;

fn main() -> Result<()> {
    let root = "/";

    clock_settime(
        ClockId::CLOCK_REALTIME,
        TimeSpec::from_duration(Duration::from_secs(1735214326)),
    )?;

    mount(
        Some("devtmpfs"),
        "/dev",
        Some("devtmpfs"),
        MsFlags::empty(),
        None::<&str>,
    )
    .context("failed to mount /dev")?;
    mount(
        Some("procfs"),
        "/proc",
        Some("procfs"),
        MsFlags::empty(),
        None::<&str>,
    )
    .context("failed to mount /proc")?;

    // Unpack tar archive.
    let file = File::open("/dev/input").context("failed to open input file")?;
    let buf_reader = BufReader::new(file);
    let mut archive = Archive::new(buf_reader);
    archive.unpack(root).context("failed to unpack image")?;

    // Execute the build.
    let status = Command::new("/bin/sh")
        .arg("-c")
        .arg("source /build/dev-env && set -e && dontInstall=1 && dontFixup=1 && genericBuild")
        .current_dir("/build/")
        .uid(1000)
        .gid(1000)
        .status()?;
    assert!(status.success());

    Ok(())
}
