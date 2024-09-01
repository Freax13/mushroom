use core::cmp;

use alloc::sync::Arc;
use node::tmpfs::TmpFsFile;

use crate::error::Result;
use crate::fs::fd::file::File;
use crate::spin::lazy::Lazy;

pub mod fd;
pub mod node;
pub mod ownership;
pub mod path;

extern "C" {
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

    fn as_ptr(&self) -> *const [u8] {
        // The content starts at the page following the header.
        core::ptr::slice_from_raw_parts(
            (self as *const Self).cast::<u8>().wrapping_add(0x1000),
            self.size,
        )
    }

    pub fn len(&self) -> usize {
        self.as_ptr().len()
    }

    pub fn read(&self, offset: usize, buffer: &mut [u8]) {
        let ptr = self.as_ptr();
        let end_index = offset + buffer.len();
        assert!(end_index <= ptr.len());
        unsafe {
            core::ptr::copy_nonoverlapping(
                ptr.cast::<u8>().add(offset),
                buffer.as_mut_ptr(),
                buffer.len(),
            );
        }
    }

    pub fn copy_to(&self, dst: &Arc<TmpFsFile>) -> Result<()> {
        dst.truncate(self.len())?;
        let mut buffer = [0; 0x1000];
        for i in (0..self.len()).step_by(0x1000) {
            let remaining_len = self.len() - i;
            let buffer_len = cmp::min(remaining_len, 0x1000);
            let buffer = &mut buffer[0..buffer_len];
            self.read(i, buffer);
            dst.write(i, buffer)?;
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
