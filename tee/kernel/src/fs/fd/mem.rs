use alloc::{boxed::Box, ffi::CString, sync::Arc, vec::Vec};

use async_trait::async_trait;
use x86_64::structures::paging::{PageSize, Size4KiB};

use crate::{
    error::Result,
    fs::{
        FileSystem,
        fd::{BsdFileLock, Events, NonEmptyEvents, OpenFileDescription},
        node::{FileAccessContext, new_ino},
        ownership::Ownership,
        path::Path,
    },
    memory::page::{Buffer, KernelPage},
    spin::mutex::Mutex,
    user::{
        futex::Futexes,
        syscall::args::{
            FileMode, FileType, FileTypeAndMode, MemfdCreateFlags, OpenFlags, Stat, Timespec,
        },
        thread::{Gid, Uid},
    },
};

pub struct MemFd {
    ino: u64,
    name: CString,
    internal: Mutex<InternalMemFd>,
    futexes: Arc<Futexes>,
}

struct InternalMemFd {
    ownership: Ownership,
    buffer: Buffer,
}

impl MemFd {
    pub fn new(name: CString, _: MemfdCreateFlags, ctx: &FileAccessContext) -> Self {
        Self {
            ino: new_ino(),
            name,
            internal: Mutex::new(InternalMemFd {
                ownership: Ownership::new(
                    FileMode::all(),
                    ctx.filesystem_user_id(),
                    ctx.filesystem_group_id(),
                ),
                buffer: Buffer::new(),
            }),
            futexes: Arc::new(Futexes::new()),
        }
    }
}

#[async_trait]
impl OpenFileDescription for MemFd {
    fn flags(&self) -> OpenFlags {
        OpenFlags::RDWR
    }

    fn path(&self) -> Result<Path> {
        let mut path = Vec::new();
        path.extend_from_slice(b"memfd:");
        path.extend_from_slice(self.name.to_bytes());
        Path::new(path)
    }

    fn chmod(&self, mode: FileMode, ctx: &FileAccessContext) -> Result<()> {
        let mut guard = self.internal.lock();
        guard.ownership.chmod(mode, ctx)
    }

    fn chown(&self, uid: Uid, gid: Gid, ctx: &FileAccessContext) -> Result<()> {
        let mut guard = self.internal.lock();
        guard.ownership.chown(uid, gid, ctx)
    }

    fn stat(&self) -> Result<Stat> {
        let guard = self.internal.lock();
        Ok(Stat {
            dev: 0,
            ino: self.ino,
            nlink: 1,
            mode: FileTypeAndMode::new(FileType::File, guard.ownership.mode()),
            uid: guard.ownership.uid(),
            gid: guard.ownership.gid(),
            rdev: 0,
            size: guard.buffer.len() as i64,
            blksize: Size4KiB::SIZE as i64,
            blocks: 0,
            atime: Timespec::ZERO,
            mtime: Timespec::ZERO,
            ctime: Timespec::ZERO,
        })
    }

    fn truncate(&self, length: usize, _: &FileAccessContext) -> Result<()> {
        let mut guard = self.internal.lock();
        guard.buffer.truncate(length)
    }

    fn get_page(&self, page_idx: usize, shared: bool) -> Result<KernelPage> {
        let mut guard = self.internal.lock();
        guard.buffer.get_page(page_idx, shared)
    }

    fn futexes(&self) -> Option<Arc<Futexes>> {
        Some(self.futexes.clone())
    }

    fn fs(&self) -> Result<Arc<dyn FileSystem>> {
        todo!()
    }

    fn poll_ready(&self, _: Events, _: &FileAccessContext) -> Option<NonEmptyEvents> {
        todo!()
    }

    async fn ready(&self, _: Events, _: &FileAccessContext) -> NonEmptyEvents {
        todo!()
    }

    fn bsd_file_lock(&self) -> Result<&BsdFileLock> {
        todo!()
    }
}
