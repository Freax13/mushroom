use std::{
    fs::{File, remove_dir_all},
    io::Read,
    os::fd::{FromRawFd, IntoRawFd, OwnedFd},
    path::Path,
};

use nix::{
    fcntl::{OFlag, OpenHow, ResolveFlag, open, openat, openat2},
    sys::stat::Mode,
    unistd::{mkdir, symlinkat, write},
};

#[test]
fn resolve_in_root() {
    let dir = <_ as AsRef<Path>>::as_ref("fake-root");
    mkdir(dir, Mode::from_bits_retain(0o777)).unwrap();

    let dfd = open(dir, OFlag::O_DIRECTORY, Mode::empty()).unwrap();

    // Create a simple file directly in the root directory.
    let file1 = "file";
    let fd = openat(
        &dfd,
        file1,
        OFlag::O_WRONLY | OFlag::O_CREAT,
        Mode::from_bits_retain(0o644),
    )
    .unwrap();
    write(fd, b"file1").unwrap();
    // Create a symlink to it.
    let symlink1 = "symlink1";
    symlinkat("/file", &dfd, symlink1).unwrap();

    // Create a file in a directory.
    mkdir(&dir.join("nested-dir"), Mode::from_bits_retain(0o777)).unwrap();
    let file = "nested-dir/file";
    let fd = openat(
        &dfd,
        file,
        OFlag::O_WRONLY | OFlag::O_CREAT,
        Mode::from_bits_retain(0o644),
    )
    .unwrap();
    write(fd, b"file2").unwrap();
    let symlink2 = "symlink2";
    symlinkat("/nested-dir/file", &dfd, symlink2).unwrap();

    // Create a symlink to one of the other symlinks.
    let symlink3 = "symlink3";
    symlinkat("/symlink2", &dfd, symlink3).unwrap();

    fn openat2_and_read(dfd: &OwnedFd, path: &str, how: OpenHow) -> nix::Result<&'static str> {
        // Open the file.
        let fd = openat2(dfd, path, how)?;

        // Read the whole thing.
        let mut file = unsafe { File::from_raw_fd(fd.into_raw_fd()) };
        let mut buf = String::new();
        file.read_to_string(&mut buf).unwrap();
        Ok(String::leak(buf))
    }

    let open_how = OpenHow::new().resolve(ResolveFlag::RESOLVE_IN_ROOT);

    // Test a bunch of cases.

    assert_eq!(openat2_and_read(&dfd, "/file", open_how), Ok("file1"));
    assert_eq!(openat2_and_read(&dfd, "file", open_how), Ok("file1"));
    assert_eq!(openat2_and_read(&dfd, "../file", open_how), Ok("file1"));

    assert_eq!(
        openat2_and_read(&dfd, "/nested-dir/file", open_how),
        Ok("file2")
    );
    assert_eq!(
        openat2_and_read(&dfd, "nested-dir/file", open_how),
        Ok("file2")
    );
    assert_eq!(
        openat2_and_read(&dfd, "../nested-dir/file", open_how),
        Ok("file2")
    );

    assert_eq!(openat2_and_read(&dfd, "/symlink1", open_how), Ok("file1"));
    assert_eq!(openat2_and_read(&dfd, "symlink1", open_how), Ok("file1"));
    assert_eq!(openat2_and_read(&dfd, "../symlink1", open_how), Ok("file1"));

    assert_eq!(openat2_and_read(&dfd, "/symlink2", open_how), Ok("file2"));
    assert_eq!(openat2_and_read(&dfd, "symlink2", open_how), Ok("file2"));
    assert_eq!(openat2_and_read(&dfd, "../symlink2", open_how), Ok("file2"));

    assert_eq!(openat2_and_read(&dfd, "/symlink3", open_how), Ok("file2"));
    assert_eq!(openat2_and_read(&dfd, "symlink3", open_how), Ok("file2"));
    assert_eq!(openat2_and_read(&dfd, "../symlink3", open_how), Ok("file2"));

    // Clean up.
    remove_dir_all(dir).unwrap();
}
