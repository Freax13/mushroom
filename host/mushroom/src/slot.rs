use std::{
    ffi::c_void,
    mem::size_of,
    num::NonZeroUsize,
    os::fd::{AsFd, BorrowedFd, OwnedFd},
    ptr::{copy_nonoverlapping, NonNull},
};

use anyhow::{ensure, Context, Result};
use bytemuck::{CheckedBitPattern, Pod};
use nix::sys::mman::{mmap, munmap, MapFlags, ProtFlags};
use volatile::VolatilePtr;
use x86_64::{structures::paging::PhysFrame, PhysAddr};

use crate::kvm::{KvmGuestMemFdFlags, Page, VmHandle};

pub struct Slot {
    gpa: PhysFrame,
    shared_mapping: AnonymousPrivateMapping,
    restricted_fd: OwnedFd,
}

impl Slot {
    pub fn for_launch_update(vm: &VmHandle, gpa: PhysFrame, pages: &[Page]) -> Result<Self> {
        let shared_mapping = AnonymousPrivateMapping::for_private_mapping(pages)?;

        let len = u64::try_from(pages.len() * 0x1000)?;
        let restricted_fd = vm
            .create_guest_memfd(len, KvmGuestMemFdFlags::empty())
            .context("failed to create guest memfd")?;

        Ok(Self {
            gpa,
            shared_mapping,
            restricted_fd,
        })
    }

    pub fn new(vm: &VmHandle, gpa: PhysFrame) -> Result<Self> {
        let len = 512 * 0x1000;
        let shared_mapping = AnonymousPrivateMapping::new(len)?;

        let len = u64::try_from(len)?;
        // FIXME: We should be able to pass `HUGE_PMD`, but it currently appears to be buggy.
        let restricted_fd = vm
            .create_guest_memfd(len, KvmGuestMemFdFlags::empty())
            .context("failed to create guest memfd")?;

        Ok(Self {
            gpa,
            shared_mapping,
            restricted_fd,
        })
    }

    pub fn gpa(&self) -> PhysFrame {
        self.gpa
    }

    pub fn shared_mapping(&self) -> &AnonymousPrivateMapping {
        &self.shared_mapping
    }

    pub fn restricted_fd(&self) -> BorrowedFd {
        self.restricted_fd.as_fd()
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
            mmap(
                None,
                len,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_ANONYMOUS | MapFlags::MAP_PRIVATE,
                0,
                0,
            )
        };
        let ptr = res.context("failed to mmap memory")?;
        let ptr = NonNull::new(ptr).unwrap();

        Ok(Self { ptr, len })
    }

    pub fn as_ptr(&self) -> NonNull<c_void> {
        self.ptr
    }

    pub fn len(&self) -> NonZeroUsize {
        self.len
    }
}

impl Drop for AnonymousPrivateMapping {
    fn drop(&mut self) {
        let res = unsafe { munmap(self.ptr.as_ptr(), self.len.get()) };
        res.unwrap();
    }
}
