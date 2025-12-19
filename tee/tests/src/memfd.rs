use std::fs::File;

use nix::{
    errno::Errno,
    fcntl::{FcntlArg, SealFlag, fcntl},
    sys::memfd::{MFdFlags, memfd_create},
    unistd::{ftruncate, unlink},
};

#[test]
fn create_allow_sealing() {
    memfd_create("test", MFdFlags::MFD_CLOEXEC | MFdFlags::MFD_ALLOW_SEALING).unwrap();
}

#[test]
fn add_seal() {
    let fd = memfd_create("test", MFdFlags::MFD_CLOEXEC | MFdFlags::MFD_ALLOW_SEALING).unwrap();

    assert_eq!(
        fcntl(&fd, FcntlArg::F_ADD_SEALS(SealFlag::F_SEAL_SEAL)),
        Ok(0)
    );
}

#[test]
fn add_seal_without_allowed() {
    let fd = memfd_create("test", MFdFlags::MFD_CLOEXEC).unwrap();

    assert_eq!(
        fcntl(&fd, FcntlArg::F_ADD_SEALS(SealFlag::F_SEAL_SEAL)),
        Err(Errno::EPERM)
    );
}

#[test]
fn get_seal() {
    let fd = memfd_create("test", MFdFlags::MFD_CLOEXEC | MFdFlags::MFD_ALLOW_SEALING).unwrap();

    assert_eq!(fcntl(&fd, FcntlArg::F_GET_SEALS), Ok(0));

    assert_eq!(
        fcntl(&fd, FcntlArg::F_ADD_SEALS(SealFlag::F_SEAL_SEAL)),
        Ok(0)
    );

    assert_eq!(
        fcntl(&fd, FcntlArg::F_GET_SEALS),
        Ok(SealFlag::F_SEAL_SEAL.bits())
    );
}

#[test]
fn get_seal_without_allowed() {
    let fd = memfd_create("test", MFdFlags::MFD_CLOEXEC).unwrap();

    assert_eq!(
        fcntl(&fd, FcntlArg::F_GET_SEALS),
        Ok(SealFlag::F_SEAL_SEAL.bits())
    );
}

// This test technically doesn't belong in the memfd module, but
// sealing is currently only supported by memfd, so all sealing tests
// are here.
#[test]
fn seal_regular_file() {
    let path = "seal-test-file";
    let file = File::create(path).unwrap();

    assert_eq!(
        fcntl(&file, FcntlArg::F_ADD_SEALS(SealFlag::F_SEAL_SEAL)),
        Err(Errno::EINVAL)
    );

    assert_eq!(fcntl(&file, FcntlArg::F_GET_SEALS), Err(Errno::EINVAL));

    unlink(path).unwrap();
}

#[test]
fn seal_shrink() {
    let fd = memfd_create("test", MFdFlags::MFD_CLOEXEC | MFdFlags::MFD_ALLOW_SEALING).unwrap();

    let size = 1024;
    ftruncate(&fd, size).unwrap();

    assert_eq!(
        fcntl(&fd, FcntlArg::F_ADD_SEALS(SealFlag::F_SEAL_SHRINK)),
        Ok(0)
    );

    // Shrinking is no longer allowed.
    assert_eq!(ftruncate(&fd, size - 1), Err(Errno::EPERM));

    // Truncating to the same size is allowed.
    assert_eq!(ftruncate(&fd, size), Ok(()));

    // Growing is allowed.
    assert_eq!(ftruncate(&fd, size + 1), Ok(()));
}

#[test]
fn seal_grow() {
    let fd = memfd_create("test", MFdFlags::MFD_CLOEXEC | MFdFlags::MFD_ALLOW_SEALING).unwrap();

    let size = 1024;
    ftruncate(&fd, size).unwrap();

    assert_eq!(
        fcntl(&fd, FcntlArg::F_ADD_SEALS(SealFlag::F_SEAL_GROW)),
        Ok(0)
    );

    // Growing is no longer allowed.
    assert_eq!(ftruncate(&fd, size + 1), Err(Errno::EPERM));

    // Truncating to the same size is allowed.
    assert_eq!(ftruncate(&fd, size), Ok(()));

    // Shrinking is allowed.
    assert_eq!(ftruncate(&fd, size - 1), Ok(()));
}
