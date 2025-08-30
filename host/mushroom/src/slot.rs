use std::{
    ffi::c_void,
    mem::size_of,
    num::NonZeroUsize,
    os::fd::{AsFd, BorrowedFd, OwnedFd},
    ptr::{NonNull, copy_nonoverlapping},
    sync::Arc,
};

use anyhow::{Context, Result, ensure};
use bytemuck::{CheckedBitPattern, Pod};
use nix::{
    fcntl::{FallocateFlags, fallocate},
    sys::mman::{MapFlags, ProtFlags, mmap_anonymous, munmap},
};
use volatile::VolatilePtr;
use x86_64::{
    PhysAddr,
    structures::paging::{PageSize, PhysFrame},
};

use crate::kvm::{KvmGuestMemFdFlags, Page, VmHandle};

pub struct Slot {
    gpa: PhysFrame,
    len: usize,
    shared_mapping: Option<Arc<AnonymousPrivateMapping>>,
    restricted_fd: Option<OwnedFd>,
}

impl Slot {
    pub fn new(
        vm: &VmHandle,
        gpa: PhysFrame<impl PageSize>,
        len: usize,
        shared: bool,
        private: bool,
    ) -> Result<Self> {
        let shared_mapping = shared
            .then(|| AnonymousPrivateMapping::new(len).map(Arc::new))
            .transpose()?;

        let len_u64 = u64::try_from(len)?;
        let restricted_fd = private
            .then(|| {
                let fd = vm
                    .create_guest_memfd(len_u64, KvmGuestMemFdFlags::empty())
                    .context("failed to create guest memfd")?;
                fallocate(&fd, FallocateFlags::FALLOC_FL_KEEP_SIZE, 0, len_u64 as i64)
                    .context("failed to reserve memory")?;
                Result::<_>::Ok(fd)
            })
            .transpose()?;

        Ok(Self {
            gpa: PhysFrame::from_start_address(gpa.start_address()).unwrap(),
            len,
            shared_mapping,
            restricted_fd,
        })
    }

    pub fn with_content(
        vm: &VmHandle,
        gpa: PhysFrame,
        pages: &[Page],
        shared: bool,
        private: bool,
    ) -> Result<Self> {
        let this = Self::new(vm, gpa, pages.len() * 0x1000, shared, private)?;

        if let Some(shared_mapping) = this.shared_mapping.as_ref() {
            unsafe {
                copy_nonoverlapping(
                    pages.as_ptr(),
                    shared_mapping.ptr.as_ptr().cast(),
                    pages.len(),
                );
            }
        }

        Ok(this)
    }

    pub fn gpa(&self) -> PhysFrame {
        self.gpa
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn shared_mapping(&self) -> Option<&Arc<AnonymousPrivateMapping>> {
        self.shared_mapping.as_ref()
    }

    pub fn restricted_fd(&self) -> Option<BorrowedFd<'_>> {
        self.restricted_fd.as_ref().map(OwnedFd::as_fd)
    }

    pub fn read<T>(&self, gpa: PhysAddr) -> Result<T>
    where
        T: CheckedBitPattern,
    {
        let offset = gpa - self.gpa.start_address();
        let offset = usize::try_from(offset)?;
        let end = offset
            .checked_add(size_of::<T>())
            .context("offset too big")?;
        let shared_mapping = self
            .shared_mapping
            .as_ref()
            .context("can't read from slot without shared mapping")?;
        ensure!(end <= shared_mapping.len.get(), "offset too big");
        let bits = unsafe {
            let ptr = shared_mapping.ptr.as_ptr().byte_add(offset).cast::<u8>();
            &*core::ptr::slice_from_raw_parts(ptr, size_of::<T>())
        };
        let value = bytemuck::checked::try_pod_read_unaligned(bits)?;
        Ok(value)
    }

    pub fn shared_ptr<T>(&self, gpa: PhysAddr) -> Result<VolatilePtr<'_, T>>
    where
        T: Pod,
    {
        let offset = gpa - self.gpa.start_address();
        let offset = usize::try_from(offset)?;
        let end = offset
            .checked_add(size_of::<T>())
            .context("offset too big")?;
        let shared_mapping = self
            .shared_mapping
            .as_ref()
            .context("can't create pointer into slot without shared mapping")?;
        ensure!(end <= shared_mapping.len.get(), "offset too big");
        unsafe {
            let ptr = shared_mapping.ptr.as_ptr().byte_add(offset).cast();
            let ptr = NonNull::new_unchecked(ptr);
            Ok(VolatilePtr::new(ptr))
        }
    }
}

pub struct AnonymousPrivateMapping {
    ptr: NonNull<c_void>,
    len: NonZeroUsize,
}

impl AnonymousPrivateMapping {
    pub fn new(len: usize) -> Result<Self> {
        let len = NonZeroUsize::new(len).context("cannot create empty mmap")?;

        let res = unsafe {
            mmap_anonymous(
                None,
                len,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_ANONYMOUS | MapFlags::MAP_PRIVATE,
            )
        };
        let ptr = res.context("failed to mmap memory")?;

        Ok(Self { ptr, len })
    }

    pub fn as_ptr(&self) -> NonNull<c_void> {
        self.ptr
    }

    pub fn len(&self) -> NonZeroUsize {
        self.len
    }
}

unsafe impl Send for AnonymousPrivateMapping {}
unsafe impl Sync for AnonymousPrivateMapping {}

impl Drop for AnonymousPrivateMapping {
    fn drop(&mut self) {
        let res = unsafe { munmap(self.ptr, self.len.get()) };
        res.unwrap();
    }
}
