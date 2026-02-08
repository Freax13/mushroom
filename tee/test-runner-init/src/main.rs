use std::{
    ffi::CStr,
    fs::{File, create_dir_all},
};

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

    let input = File::open("/dev/input").expect("failed to open /dev/input");
    let mut archive = tar::Archive::new(input);
    archive.unpack("/").expect("failed to unpack files");

    create_dir_all("/etc").unwrap();
    std::fs::write(
        "/etc/passwd",
        "root:x:0:0:System administrator:/root:/bin/bash\n",
    )
    .unwrap();

    create_dir_all("/tmp").unwrap();

    match execve::<_, &CStr>(
        c"/cargo-nextest",
        &[
            c"/cargo-nextest",
            c"nextest",
            c"run",
            c"--archive-file",
            c"tests.tar.zst",
            c"--workspace-remap",
            c"/",
        ],
        &[],
    )
    .unwrap() {}
}
