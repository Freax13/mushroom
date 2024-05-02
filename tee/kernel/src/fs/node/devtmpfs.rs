use crate::{
    char_dev::{
        mem::{Null, Random, URandom},
        mushroom::Output,
        CharDev,
    },
    fs::{fd::file::File, path::Path},
};

use crate::{
    error::Result,
    fs::{path::FileName, INPUT},
    user::process::syscall::args::FileMode,
};

use super::{directory::MountLocation, new_dev, tmpfs::TmpFsDir, DynINode, INode};

pub fn new(location: MountLocation) -> Result<DynINode> {
    let tmp_fs_dir = TmpFsDir::new(new_dev(), location, FileMode::from_bits_truncate(0o755));

    let input_name = FileName::new(b"input").unwrap();
    let input_file = tmp_fs_dir
        .create_file(input_name, FileMode::from_bits_truncate(0o444))?
        .ok()
        .unwrap();
    input_file.write(0, *INPUT)?;

    let output_name = FileName::new(b"output").unwrap();
    tmp_fs_dir.create_char_dev(output_name, Output::MAJOR, Output::MINOR)?;

    let null_name = FileName::new(b"null").unwrap();
    tmp_fs_dir.create_char_dev(null_name, Null::MAJOR, Null::MINOR)?;

    let random_name = FileName::new(b"random").unwrap();
    tmp_fs_dir.create_char_dev(random_name, Random::MAJOR, Random::MINOR)?;
    let urandom_name = FileName::new(b"urandom").unwrap();
    tmp_fs_dir.create_char_dev(urandom_name, URandom::MAJOR, URandom::MINOR)?;

    let fd_name = FileName::new(b"fd").unwrap();
    tmp_fs_dir.create_link(fd_name, Path::new(b"/proc/self/fd".to_vec()).unwrap(), true)?;

    Ok(tmp_fs_dir)
}
