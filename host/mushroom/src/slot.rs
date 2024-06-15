use std::{
    ffi::c_void,
    mem::size_of,
    num::NonZeroUsize,
    os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd},
    ptr::{copy_nonoverlapping, NonNull},
    sync::Arc,
};

use anyhow::{ensure, Context, Result};
use bytemuck::{CheckedBitPattern, Pod};
use nix::{
    fcntl::{fallocate, FallocateFlags},
    sys::mman::{mmap_anonymous, munmap, MapFlags, ProtFlags},
};
use volatile::VolatilePtr;
use x86_64::{
    structures::paging::{PhysFrame, Size2MiB},
    PhysAddr,
};

use crate::kvm::{KvmGuestMemFdFlags, Page, VmHandle};

pub struct Slot {
    gpa: PhysFrame,
    shared_mapping: Arc<AnonymousPrivateMapping>,
    restricted_fd: Option<OwnedFd>,
}

impl Slot {
    pub fn for_launch_update(
        vm: &VmHandle,
        gpa: PhysFrame,
        pages: &[Page],
        private: bool,
    ) -> Result<Self> {
        let shared_mapping = AnonymousPrivateMapping::for_private_mapping(pages)?;
        let shared_mapping = Arc::new(shared_mapping);

        let len = u64::try_from(pages.len() * 0x1000)?;
        let restricted_fd = private
            .then(|| {
                vm.create_guest_memfd(len, KvmGuestMemFdFlags::empty())
                    .context("failed to create guest memfd")
            })
            .transpose()?;

        Ok(Self {
            gpa,
            shared_mapping,
            restricted_fd,
        })
    }

    pub fn new(vm: &VmHandle, gpa: PhysFrame<Size2MiB>, private: bool) -> Result<Self> {
        let len = 512 * 0x1000;
        let shared_mapping = AnonymousPrivateMapping::new(len)?;
        let shared_mapping = Arc::new(shared_mapping);

        let len = u64::try_from(len)?;
        let restricted_fd = private
            .then(|| {
                let fd = vm
                    .create_guest_memfd(len, KvmGuestMemFdFlags::HUGE_PMD)
                    .context("failed to create guest memfd")?;
                fallocate(
                    fd.as_raw_fd(),
                    FallocateFlags::FALLOC_FL_KEEP_SIZE,
                    0,
                    len as i64,
                )
                .context("failed to reserve memory")?;
                Result::<_>::Ok(fd)
            })
            .transpose()?;

        Ok(Self {
            gpa: PhysFrame::from_start_address(gpa.start_address()).unwrap(),
            shared_mapping,
            restricted_fd,
        })
    }

    pub fn gpa(&self) -> PhysFrame {
        self.gpa
    }

    pub fn shared_mapping(&self) -> &Arc<AnonymousPrivateMapping> {
        &self.shared_mapping
    }

    pub fn restricted_fd(&self) -> Option<BorrowedFd> {
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
        ensure!(end <= self.shared_mapping.len.get(), "offset too big");
        let bits = unsafe {
            let ptr = self
                .shared_mapping
                .ptr
                .as_ptr()
                .byte_add(offset)
                .cast::<u8>();
            &*core::ptr::slice_from_raw_parts(ptr, size_of::<T>())
        };
        let value = bytemuck::checked::try_pod_read_unaligned(bits)?;
        Ok(value)
    }

    pub fn shared_ptr<T>(&self, gpa: PhysAddr) -> Result<VolatilePtr<T>>
    where
        T: Pod,
    {
        let offset = gpa - self.gpa.start_address();
        let offset = usize::try_from(offset)?;
        let end = offset
            .checked_add(size_of::<T>())
            .context("offset too big")?;
        ensure!(end <= self.shared_mapping.len.get(), "offset too big");
        unsafe {
            let ptr = self.shared_mapping.ptr.as_ptr().byte_add(offset).cast();
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
    pub fn for_private_mapping(pages: &[Page]) -> Result<Self> {
        let this = Self::new(pages.len() * 0x1000)?;

        unsafe {
            copy_nonoverlapping(pages.as_ptr(), this.ptr.as_ptr().cast(), pages.len());
        }

        Ok(this)
    }

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
