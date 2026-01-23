use std::{
    fs::File, io::BufReader, os::unix::process::CommandExt, process::Command, time::Duration,
};

use anyhow::{Context, Result, ensure};
use nix::{
    libc::personality,
    mount::{MsFlags, mount},
    sys::{
        time::TimeSpec,
        wait::{WaitStatus, wait},
    },
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
    archive.set_preserve_permissions(true);
    archive.set_preserve_ownerships(true);
    archive.unpack(root).context("failed to unpack image")?;

    let env = std::fs::read_to_string("/build/dev-env")?;
    if env.contains("HOSTTYPE='i686'") {
        assert_eq!(unsafe { personality(8) }, 0);
    }

    // Execute the build.
    let child = Command::new("/bin/sh")
        .arg("-c")
        .arg("source /build/dev-env && set -e && dontFixup=1 && genericBuild")
        .current_dir("/build/")
        .uid(1000)
        .gid(1000)
        .spawn()?;

    // Reap zombies until the build process finishes.
    let status = loop {
        let status = wait().unwrap();
        let WaitStatus::Exited(pid, status) = status else {
            continue;
        };
        if pid.as_raw() as u32 == child.id() {
            break status;
        }
    };

    // Make sure the build succeeded.
    ensure!(status == 0);

    Ok(())
}
