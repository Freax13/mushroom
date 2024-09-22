use core::{
    arch::{asm, x86_64::__cpuid},
    iter::Step,
    ops::RangeInclusive,
};

use bit_field::BitField;
use bitflags::bitflags;
use x86_64::{
    instructions::tlb::{Invlpgb, Pcid},
    registers::model_specific::Msr,
    structures::paging::Page,
};

use crate::spin::lazy::Lazy;

pub static INVLPGB: Lazy<InvlpgbCompat> = Lazy::new(InvlpgbCompat::new);

pub enum InvlpgbCompat {
    /// Use the native `invlpgb` and `tlbsync` instructions. This should always
    /// be available on EPYC CPUs supporting SEV-SNP.
    Invlpgb(Invlpgb),
    /// Fall back to using Hyper-V instructions to emulate `invlpgb` and
    /// `tlbsync`.
    HyperV,
}

impl InvlpgbCompat {
    fn new() -> Self {
        Invlpgb::new().map_or(Self::HyperV, Self::Invlpgb)
    }

    pub fn flush_all(&self) {
        match self {
            InvlpgbCompat::Invlpgb(invlpgb) => {
                invlpgb.build().flush();
                invlpgb.tlbsync();
            }
            InvlpgbCompat::HyperV => hv_flush_all(),
        }
    }

    pub fn flush_pcid(&self, pcid: Pcid) {
        match self {
            InvlpgbCompat::Invlpgb(invlpgb) => {
                unsafe {
                    invlpgb.build().pcid(pcid).flush();
                }
                invlpgb.tlbsync();
            }
            InvlpgbCompat::HyperV => hv_flush_all(),
        }
    }

    pub fn flush_page(&self, page: Page, global: bool) {
        match self {
            InvlpgbCompat::Invlpgb(invlpgb) => {
                let flush = invlpgb.build();
                let next_page = Step::forward(page, 1);
                let mut flush = flush.pages(Page::range(page, next_page));
                if global {
                    flush.include_global();
                }
                flush.flush();
                invlpgb.tlbsync();
            }
            InvlpgbCompat::HyperV => hv_flush_all(),
        }
    }

    /// Flush a range of pages.
    pub unsafe fn flush_user_pages(&self, pcid: Pcid, pages: RangeInclusive<Page>) {
        match self {
            InvlpgbCompat::Invlpgb(invlpgb) => {
                let mut flush = invlpgb.build();

                unsafe {
                    flush.pcid(pcid);
                }

                if pages.clone().count() < 64 {
                    let exlusive_end = Step::forward(*pages.end(), 1);
                    let page_range = Page::range(*pages.start(), exlusive_end);
                    flush = flush.pages(page_range);
                }

                flush.flush();
                invlpgb.tlbsync();
            }
            InvlpgbCompat::HyperV => hv_flush_all(),
        }
    }
}

enum Hypercall {
    Vmmcall,
    Vmcall,
}

static HYPERCALL: Lazy<Hypercall> = Lazy::new(|| {
    let svm = unsafe { __cpuid(0x8000_0001) }.ecx.get_bit(2);
    if svm {
        Hypercall::Vmmcall
    } else {
        Hypercall::Vmcall
    }
});

fn hv_flush_all() {
    const HV_X64_MSR_GUEST_OS_ID: u32 = 0x40000000;
    unsafe {
        Msr::new(HV_X64_MSR_GUEST_OS_ID).write(1);
    }

    let mut hypercall_input = 0;
    hypercall_input.set_bits(0..=15, 0x0002); // call code: HvCallFlushVirtualAddressSpace
    hypercall_input.set_bit(16, true); // fast

    let flags = HvCallFlushVirtualAddressSpaceFlags::HV_FLUSH_ALL_PROCESSORS
        | HvCallFlushVirtualAddressSpaceFlags::HV_FLUSH_ALL_VIRTUAL_ADDRESS_SPACES;

    let result: u64;

    match *HYPERCALL {
        Hypercall::Vmmcall => unsafe {
            asm! {
                "vpxor xmm0, xmm0, xmm0",
                "vmmcall",
                in("rcx") hypercall_input,
                in("rdx") flags.bits(),
                inout("rax") 0x5a5a5a5a5a5a5a5au64 => result,
            };
        },
        Hypercall::Vmcall => unsafe {
            asm! {
                "vpxor xmm0, xmm0, xmm0",
                "vmcall",
                in("rcx") hypercall_input,
                in("rdx") flags.bits(),
                inout("rax") 0x5a5a5a5a5a5a5a5au64 => result,
            };
        },
    }

    assert_eq!(result.get_bits(0..=15), 0);
}

bitflags! {
    #[derive(Clone, Copy)]
    #[repr(transparent)]
    pub struct HvCallFlushVirtualAddressSpaceFlags: u64 {
        const HV_FLUSH_ALL_PROCESSORS = 1 << 0;
        const HV_FLUSH_ALL_VIRTUAL_ADDRESS_SPACES = 1 << 1;
        const HV_FLUSH_NON_GLOBAL_MAPPINGS_ONLY = 1 << 2;
    }
}
