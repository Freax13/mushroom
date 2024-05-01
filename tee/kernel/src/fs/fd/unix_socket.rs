use alloc::boxed::Box;
use async_trait::async_trait;
use futures::{select_biased, FutureExt};

use super::{pipe, Events, OpenFileDescription};
use crate::{
    error::Result,
    fs::node::new_ino,
    user::process::{
        memory::VirtualMemory,
        syscall::args::{
            FileMode, FileType, FileTypeAndMode, OpenFlags, Pipe2Flags, Pointer, SocketPairType,
            Stat, Timespec,
        },
    },
};

pub struct StreamUnixSocket {
    ino: u64,
    write_half: pipe::WriteHalf,
    read_half: pipe::ReadHalf,
}

impl StreamUnixSocket {
    pub fn new_pair(r#type: SocketPairType) -> (Self, Self) {
        let mut flags = Pipe2Flags::empty();
        flags.set(
            Pipe2Flags::NON_BLOCK,
            r#type.contains(SocketPairType::NON_BLOCK),
        );
        flags.set(
            Pipe2Flags::CLOEXEC,
            r#type.contains(SocketPairType::CLOEXEC),
        );

        let (read_half1, write_half1) = pipe::new(flags);
        let (read_half2, write_half2) = pipe::new(flags);

        (
            Self {
                ino: new_ino(),
                write_half: write_half1,
                read_half: read_half2,
            },
            Self {
                ino: new_ino(),
                write_half: write_half2,
                read_half: read_half1,
            },
        )
    }
}

#[async_trait]
impl OpenFileDescription for StreamUnixSocket {
    fn flags(&self) -> OpenFlags {
        self.read_half.flags()
    }

    fn set_flags(&self, flags: OpenFlags) {
        self.write_half.set_flags(flags);
        self.read_half.set_flags(flags);
    }

    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        self.read_half.read(buf)
    }

    fn read_to_user(
        &self,
        vm: &VirtualMemory,
        pointer: Pointer<[u8]>,
        len: usize,
    ) -> Result<usize> {
        self.read_half.read_to_user(vm, pointer, len)
    }

    fn recv_from(&self, vm: &VirtualMemory, pointer: Pointer<[u8]>, len: usize) -> Result<usize> {
        self.read_half.read_to_user(vm, pointer, len)
    }

    fn write(&self, buf: &[u8]) -> Result<usize> {
        self.write_half.write(buf)
    }

    fn write_from_user(
        &self,
        vm: &VirtualMemory,
        pointer: Pointer<[u8]>,
        len: usize,
    ) -> Result<usize> {
        self.write_half.write_from_user(vm, pointer, len)
    }

    fn poll_ready(&self, events: Events) -> Events {
        self.write_half.poll_ready(events & Events::WRITE)
            | self.read_half.poll_ready(events & Events::READ)
    }

    fn epoll_ready(&self, events: Events) -> Result<Events> {
        Ok(self.poll_ready(events))
    }

    async fn ready(&self, events: Events) -> Result<Events> {
        let write_ready = self.write_half.ready(events & Events::WRITE);
        let read_ready = self.read_half.ready(events & Events::READ);
        select_biased! {
            res = write_ready.fuse() => res,
            res = read_ready.fuse() => res,
        }
    }

    fn stat(&self) -> Result<Stat> {
        Ok(Stat {
            dev: 0,
            ino: self.ino,
            nlink: 1,
            mode: FileTypeAndMode::new(FileType::Socket, FileMode::from_bits_truncate(0o600)),
            uid: 0,
            gid: 0,
            rdev: 0,
            size: 0,
            blksize: 0,
            blocks: 0,
            atime: Timespec::ZERO,
            mtime: Timespec::ZERO,
            ctime: Timespec::ZERO,
        })
    }
}
