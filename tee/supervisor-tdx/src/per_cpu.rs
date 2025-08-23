use core::{arch::asm, mem::offset_of};

use constants::ApIndex;
use x86_64::instructions::interrupts;

pub struct PerCpu {
    this: *mut Self,
    pub vcpu_index: ApIndex,
}

impl PerCpu {
    pub fn new(this: *mut Self, vcpu_index: ApIndex) -> Self {
        Self { this, vcpu_index }
    }

    pub fn with<R>(f: impl FnOnce(&Self) -> R) -> R {
        interrupts::without_interrupts(|| {
            let this = unsafe {
                let this: *mut Self;
                asm!(
                    "mov {}, fs:[{THIS_OFFSET}]",
                    out(reg) this,
                    THIS_OFFSET = const offset_of!(Self, this),
                    options(pure, nomem, nostack, preserves_flags),
                );
                &*this
            };
            f(this)
        })
    }

    pub fn current_vcpu_index() -> ApIndex {
        Self::with(|per_cpu| per_cpu.vcpu_index)
    }
}
