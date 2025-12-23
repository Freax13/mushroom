use std::{ffi::CStr, fs::File, os::unix::fs::OpenOptionsExt};

use nix::{
    mount::{MsFlags, mount},
    unistd::execve,
};

fn main() -> ! {
    mount(
        Some("devtmpfs"),
        "/dev",
        Some("devtmpfs"),
        MsFlags::empty(),
        None::<&str>,
    )
    .expect("failed to mount /dev");
    mount(
        Some("procfs"),
        "/proc",
        Some("procfs"),
        MsFlags::empty(),
        None::<&str>,
    )
    .expect("failed to mount /proc");

    let mut input = File::open("/dev/input").expect("failed to open /dev/input");
    let mut file = File::options()
        .mode(0o755)
        .create_new(true)
        .write(true)
        .open("/init")
        .expect("failed to create /init");

    std::io::copy(&mut input, &mut file).expect("failed to copy content");

    match execve::<_, &CStr>(c"/init", &[c"/init"], &[]).unwrap() {}
}
