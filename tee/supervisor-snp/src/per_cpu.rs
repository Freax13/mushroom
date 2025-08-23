use core::{arch::asm, cell::Cell, mem::offset_of, sync::atomic::AtomicBool};

use constants::ApIndex;

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
            asm!(
                "mov {}, fs:[{THIS_OFFSET}]",
                out(reg) this,
                THIS_OFFSET = const offset_of!(Self, this),
                options(pure, nomem, nostack, preserves_flags),
            );
            &*this
        }
    }

    pub fn current_vcpu_index() -> ApIndex {
        Self::get().vcpu_index
    }
}
