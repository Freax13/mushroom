use crate::{
    char_dev::{
        mem::{Null, Random, URandom},
        mushroom::Output,
        CharDev,
    },
    fs::fd::{dir::MountLocation, file::File},
};
use alloc::sync::Arc;

use crate::{
    error::Result,
    fs::{path::FileName, INPUT},
    user::process::syscall::args::FileMode,
};

use super::{
    fdfs,
    tmpfs::{TmpFsDir, TmpFsFile},
    DynINode, INode,
};

pub fn new(location: MountLocation) -> Result<DynINode> {
    let tmp_fs_dir = TmpFsDir::new(location, FileMode::from_bits_truncate(0o755));

    let input_name = FileName::new(b"input").unwrap();
    let input_file = TmpFsFile::new(FileMode::from_bits_truncate(0o444));
    input_file.write(0, *INPUT)?;
    tmp_fs_dir.mount(input_name, input_file)?;

    let output_name = FileName::new(b"output").unwrap();
    tmp_fs_dir.create_char_dev(output_name, Output::MAJOR, Output::MINOR)?;

    let null_name = FileName::new(b"null").unwrap();
    tmp_fs_dir.create_char_dev(null_name, Null::MAJOR, Null::MINOR)?;

    let random_name = FileName::new(b"random").unwrap();
    tmp_fs_dir.create_char_dev(random_name, Random::MAJOR, Random::MINOR)?;
    let urandom_name = FileName::new(b"urandom").unwrap();
    tmp_fs_dir.create_char_dev(urandom_name, URandom::MAJOR, URandom::MINOR)?;

    let fd_name = FileName::new(b"fd").unwrap();
    let fd = fdfs::new(
        MountLocation::new(Arc::downgrade(&tmp_fs_dir) as _, fd_name.clone()),
        FileMode::from_bits_truncate(0o777),
    );
    tmp_fs_dir.mount(fd_name, fd)?;

    Ok(tmp_fs_dir)
}
