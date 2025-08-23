use alloc::sync::Arc;
use core::cmp;

use self::{fd::KernelWriteBuf, node::tmpfs::TmpFsFile};
use crate::{
    error::Result,
    fs::{fd::file::File, node::INode},
    spin::lazy::Lazy,
};

pub mod fd;
pub mod node;
pub mod ownership;
pub mod path;

unsafe extern "C" {
    #[link_name = "init_file"]
    static INIT_FILE: StaticFile;
    #[link_name = "input_file"]
    static INPUT_FILE: StaticFile;
}

/// This type represents a static file that was mapped into memory with the
/// kernel by the loader.
///
/// The file is made up of a page containing the size of the file, followed by
/// pages containing the content of the file. Note that there is no shadow
/// mapping for the content of the file.
#[repr(C, align(4096))]
pub struct StaticFile {
    size: usize,
}

impl StaticFile {
    pub fn init_file() -> &'static Self {
        unsafe { &INIT_FILE }
    }

    pub fn input_file() -> &'static Self {
        unsafe { &INPUT_FILE }
    }

    pub fn copy_to(&self, dst: &Arc<TmpFsFile>) -> Result<()> {
        let mut len = 0;
        let mut offset = 0;
        let mut buffer = [0; 0x1000];
        loop {
            /// Copy memory, but bypass KASAN checks.
            ///
            /// FIXME: Add mappings for KASAN.
            unsafe fn copy_without_kasan<T>(src: *const T, dst: *mut T, len: usize) {
                unsafe {
                    core::arch::asm!(
                        "rep movsb",
                        inout("rsi") src => _,
                        inout("rdi") dst => _,
                        inout("rcx") size_of::<T>() * len => _,
                    );
                }
            }

            let mut chunk_len = 0;
            unsafe {
                copy_without_kasan(
                    core::ptr::from_ref(self).byte_add(offset).cast(),
                    &mut chunk_len,
                    1,
                );
            }
            offset += 0x1000;

            if chunk_len == !0 {
                break;
            }

            let chunk_offset = len;
            len += chunk_len;
            dst.truncate(len)?;

            for i in (0..chunk_len).step_by(0x1000) {
                let remaining_len = chunk_len - i;
                let buffer_len = cmp::min(remaining_len, 0x1000);
                let buffer = &mut buffer[0..buffer_len];

                unsafe {
                    copy_without_kasan(
                        core::ptr::from_ref(self).byte_add(offset).cast::<u8>(),
                        buffer.as_mut_ptr(),
                        buffer_len,
                    );
                }
                offset += 0x1000;

                dst.write(chunk_offset + i, &KernelWriteBuf::new(buffer))?;
            }
        }

        Ok(())
    }
}

pub trait FileSystem: Send + Sync {
    fn stat(&self) -> StatFs;
}

#[derive(Clone, Copy)]
pub struct StatFs {
    pub ty: i64,
    pub bsize: i64,
    pub blocks: i64,
    pub bfree: i64,
    pub bavail: i64,
    pub files: i64,
    pub ffree: i64,
    pub fsid: [i32; 2],
    pub namelen: i64,
    pub frsize: i64,
    pub flags: i64,
}

pub static ANON_INODE_FS: Lazy<Arc<AnonInodeFs>> = Lazy::new(|| Arc::new(AnonInodeFs));

pub struct AnonInodeFs;

impl FileSystem for AnonInodeFs {
    fn stat(&self) -> StatFs {
        StatFs {
            ty: 0x50495045,
            bsize: 0x1000,
            blocks: 0,
            bfree: 0,
            bavail: 0,
            files: 0,
            ffree: 0,
            fsid: [0, 0],
            namelen: 255,
            frsize: 0,
            flags: 0,
        }
    }
}
