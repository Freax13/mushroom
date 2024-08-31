use crate::{
    char_dev::{
        mem::{Null, Random, URandom, Zero},
        mushroom::Output,
        CharDev,
    },
    fs::{path::Path, StaticFile},
    user::process::thread::{Gid, Uid},
};

use crate::{error::Result, fs::path::FileName, user::process::syscall::args::FileMode};

use super::{
    directory::MountLocation,
    tmpfs::{TmpFs, TmpFsDir},
    DynINode, INode,
};

pub fn new(location: MountLocation) -> Result<DynINode> {
    let tmp_fs_dir = TmpFsDir::new(
        TmpFs::new(),
        location,
        FileMode::from_bits_truncate(0o755),
        Uid::SUPER_USER,
        Gid::SUPER_USER,
    );

    let input_name = FileName::new(b"input").unwrap();
    let input_file = tmp_fs_dir
        .create_file(
            input_name,
            FileMode::from_bits_truncate(0o444),
            Uid::SUPER_USER,
            Gid::SUPER_USER,
        )?
        .ok()
        .unwrap();
    StaticFile::input_file().copy_to(&input_file)?;

    let output_name = FileName::new(b"output").unwrap();
    tmp_fs_dir.create_char_dev(
        output_name,
        Output::MAJOR,
        Output::MINOR,
        FileMode::OWNER_READ | FileMode::OWNER_WRITE,
        Uid::SUPER_USER,
        Gid::SUPER_USER,
    )?;

    let null_name = FileName::new(b"null").unwrap();
    tmp_fs_dir.create_char_dev(
        null_name,
        Null::MAJOR,
        Null::MINOR,
        FileMode::ALL_READ_WRITE,
        Uid::SUPER_USER,
        Gid::SUPER_USER,
    )?;

    let null_name = FileName::new(b"zero").unwrap();
    tmp_fs_dir.create_char_dev(
        null_name,
        Zero::MAJOR,
        Zero::MINOR,
        FileMode::ALL_READ_WRITE,
        Uid::SUPER_USER,
        Gid::SUPER_USER,
    )?;

    let random_name = FileName::new(b"random").unwrap();
    tmp_fs_dir.create_char_dev(
        random_name,
        Random::MAJOR,
        Random::MINOR,
        FileMode::ALL_READ_WRITE,
        Uid::SUPER_USER,
        Gid::SUPER_USER,
    )?;
    let urandom_name = FileName::new(b"urandom").unwrap();
    tmp_fs_dir.create_char_dev(
        urandom_name,
        URandom::MAJOR,
        URandom::MINOR,
        FileMode::ALL_READ_WRITE,
        Uid::SUPER_USER,
        Gid::SUPER_USER,
    )?;

    let fd_name = FileName::new(b"fd").unwrap();
    tmp_fs_dir.create_link(
        fd_name,
        Path::new(b"/proc/self/fd".to_vec()).unwrap(),
        Uid::SUPER_USER,
        Gid::SUPER_USER,
        true,
    )?;

    Ok(tmp_fs_dir)
}
