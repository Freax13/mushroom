use core::{arch::asm, cell::Cell, sync::atomic::AtomicBool};

use constants::ApIndex;

#[repr(C)]
pub struct PerCpu {
    this: *mut Self,
    pub vcpu_index: ApIndex,
    pub interrupted: AtomicBool,
    pub ghcb_in_use: Cell<bool>,
    pub ghcb_registered: Cell<bool>,
}

impl PerCpu {
    pub const fn new(this: *mut Self, vcpu_index: ApIndex) -> Self {
        Self {
            this,
            vcpu_index,
            interrupted: AtomicBool::new(false),
            ghcb_in_use: Cell::new(false),
            ghcb_registered: Cell::new(false),
        }
    }

    pub fn get() -> &'static Self {
        unsafe {
            let this: *const Self;
            asm!("mov {}, fs:[0]", out(reg) this, options(pure, nomem, nostack, preserves_flags));
            &*this
        }
    }

    pub fn current_vcpu_index() -> ApIndex {
        Self::get().vcpu_index
    }
}
