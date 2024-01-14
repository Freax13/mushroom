use core::{arch::asm, iter::Step};

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
}

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

    unsafe {
        asm! {
            "vpxor xmm0, xmm0, xmm0",
            "vmmcall",
            in("rcx") hypercall_input,
            in("rdx") flags.bits(),
            inout("rax") 0x5a5a5a5a5a5a5a5au64 => result,
        };
    }

    assert_eq!(result.get_bits(0..=15), 0);
}

bitflags! {
    #[repr(transparent)]
    pub struct HvCallFlushVirtualAddressSpaceFlags: u64 {
        const HV_FLUSH_ALL_PROCESSORS = 1 << 0;
        const HV_FLUSH_ALL_VIRTUAL_ADDRESS_SPACES = 1 << 1;
        const HV_FLUSH_NON_GLOBAL_MAPPINGS_ONLY = 1 << 2;
    }
}
