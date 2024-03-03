use core::ops::{Deref, DerefMut};

use crate::{
    error::Result,
    memory::pagetable::{PageTableFlags, PresentPageTableEntry},
    user::process::memory::MemoryPermissions,
};

use super::KernelPage;

/// A `KernelPage` that can be mapped into userspace.
pub struct UserPage {
    page: KernelPage,
    perms: MemoryPermissions,
}

impl UserPage {
    pub fn new(page: KernelPage, perms: MemoryPermissions) -> Self {
        Self { page, perms }
    }

    pub fn clone(&mut self) -> Result<Self> {
        Ok(Self {
            perms: self.perms,
            page: self.page.clone()?,
        })
    }

    pub fn entry(&self) -> PresentPageTableEntry {
        let mut flags = PageTableFlags::USER;
        flags.set(
            PageTableFlags::WRITABLE,
            self.perms.contains(MemoryPermissions::WRITE) && self.mutable(),
        );
        flags.set(
            PageTableFlags::EXECUTABLE,
            self.perms.contains(MemoryPermissions::EXECUTE),
        );
        PresentPageTableEntry::new(self.frame(), flags)
    }

    pub fn perms(&self) -> MemoryPermissions {
        self.perms
    }

    pub fn set_perms(&mut self, perms: MemoryPermissions) {
        self.perms = perms;
    }
}

impl Deref for UserPage {
    type Target = KernelPage;

    fn deref(&self) -> &Self::Target {
        &self.page
    }
}

impl DerefMut for UserPage {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.page
    }
}
