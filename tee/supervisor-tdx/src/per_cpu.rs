use core::{arch::asm, cell::Cell};

use constants::ApIndex;
use x86_64::instructions::interrupts;

#[repr(C)]
pub struct PerCpu {
    this: *mut Self,
    pub vcpu_index: ApIndex,
    pub pending_flushes: Cell<bool>,
}

impl PerCpu {
    pub fn new(this: *mut Self, vcpu_index: ApIndex) -> Self {
        Self {
            this,
            vcpu_index,
            pending_flushes: Cell::new(false),
        }
    }

    pub fn with<R>(f: impl FnOnce(&Self) -> R) -> R {
        interrupts::without_interrupts(|| {
            let this = unsafe {
                let this: *mut Self;
                asm!("mov {}, fs:[0]", out(reg) this, options(pure, nomem, nostack, preserves_flags));
                &*this
            };
            f(this)
        })
    }

    pub fn current_vcpu_index() -> ApIndex {
        Self::with(|per_cpu| per_cpu.vcpu_index)
    }
}
