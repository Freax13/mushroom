use core::{arch::asm, ops::RangeInclusive};

use bit_field::BitField;
use constants::{ApBitmap, ApIndex, AtomicApBitmap};
use x86_64::{
    instructions::tlb::{self, InvPicdCommand, Invlpgb},
    registers::{
        control::{Cr3, Cr4, Cr4Flags},
        model_specific::Msr,
    },
    structures::{idt::InterruptStackFrame, paging::Page},
};

use crate::{per_cpu::PerCpu, spin::lazy::Lazy};

use super::ActivePageTableGuard;

pub const TLB_VECTOR: u8 = 0x20;

static INVLPGB: Lazy<Option<Invlpgb>> = Lazy::new(Invlpgb::new);

static ACTIVE_APS: AtomicApBitmap = AtomicApBitmap::empty();
static PENDING_TLB_SHOOTDOWN: AtomicApBitmap = AtomicApBitmap::empty();
static PENDING_GLOBAL_TLB_SHOOTDOWN: AtomicApBitmap = AtomicApBitmap::empty();

pub fn init() {
    post_halt();
}

pub fn pre_halt() {
    ACTIVE_APS.take(PerCpu::get().idx);
}

pub fn post_halt() {
    let idx = PerCpu::get().idx;
    ACTIVE_APS.set(idx);
    process_flushes(idx);
}

fn process_flushes(idx: ApIndex) {
    let need_global_flush = PENDING_GLOBAL_TLB_SHOOTDOWN.take(idx);
    let need_non_global_flush = PENDING_TLB_SHOOTDOWN.take(idx);
    if need_global_flush {
        if Cr4::read().contains(Cr4Flags::PCID) {
            unsafe {
                tlb::flush_pcid(tlb::InvPicdCommand::All);
            }
        } else {
            tlb::flush_all();
        }
    } else if need_non_global_flush {
        if Cr4::read().contains(Cr4Flags::PCID) {
            // Flush the entire PCID.
            // TODO: Flush less.
            let (_, pcid) = Cr3::read_pcid();
            unsafe {
                tlb::flush_pcid(tlb::InvPicdCommand::Single(pcid));
            }
        } else {
            tlb::flush_all();
        }
    }
}

pub extern "x86-interrupt" fn tlb_shootdown_handler(_: InterruptStackFrame) {
    // This handler is only used for TDX. The value returned by `rdpid` can be
    // controlled by the host on SNP, so if we ever need to use this handler on
    // SNP, we'll have to use something else.
    let ap_id: u64;
    unsafe {
        asm!(
            "rdpid {}",
            out(reg) ap_id,
        );
    }
    let idx = ApIndex::new(ap_id as u8);

    process_flushes(idx);

    // Signal EOI.
    unsafe {
        Msr::new(0x80b).write(0);
    }
}

fn send_tlb_ipis(aps: ApBitmap) {
    for ap in aps {
        let mut bits = 0;
        bits.set_bits(0..8, u64::from(TLB_VECTOR));
        bits.set_bits(8..11, 0); // Delivery Mode: Fixed
        bits.set_bit(11, false); // Destination Mode: Physical
        bits.set_bit(14, true); // Level: Assert
        bits.set_bits(18..20, 0b00); // Destination Shorthand: Destination
        bits.set_bits(32.., u64::from(ap.as_u8())); // Destination
        unsafe {
            Msr::new(0x830).write(bits);
        }
    }
}

impl ActivePageTableGuard {
    pub fn flush_all(&self) {
        let idx = PerCpu::get().idx;

        let mut guard = self.guard.flush_state.lock();
        let state = &mut *guard;

        state.needs_flush |= state.used;
        state.used = state.active;
        // Unmark this vCPU from needing to be flushed. We'll flush the current
        // AP immediately.
        state.needs_flush.set(idx, false);

        // Check if the current AP is the only active AP.
        let mut other_active_aps = state.active;
        other_active_aps.set(idx, false);

        // If the current AP is the only active AP, we don't need to tell other
        // APs to flush immediately. We only need to flush the TLB on the
        // current AP.
        if other_active_aps.is_empty() {
            drop(guard);
            return self.flush_all_local();
        }

        // We have to flush the TLB on other APs :(

        // If invlpgb is supported, use it.
        if let Some(invlpgb) = INVLPGB.as_ref() {
            // Note that we don't drop `guard` until we're done flushing.

            let pcid_allocation = self.guard.pcid_allocation.as_ref().unwrap();
            unsafe {
                invlpgb.build().pcid(pcid_allocation.pcid).flush();
            }
            invlpgb.tlbsync();

            state.needs_flush = ApBitmap::empty();

            return;
        }

        // We've run out of optimizations :(
        // Flush on the current processor and send IPIs to the other relevant
        // APs.

        drop(guard);

        PENDING_TLB_SHOOTDOWN.set_all(other_active_aps);
        send_tlb_ipis(other_active_aps);

        self.flush_all_local();

        let mut remaining_aps = other_active_aps;
        while !remaining_aps.is_empty() {
            remaining_aps &= PENDING_TLB_SHOOTDOWN.get_all();
        }
    }

    pub fn flush_all_local(&self) {
        if let Some(pcid_allocation) = self.guard.pcid_allocation.as_ref() {
            unsafe {
                tlb::flush_pcid(InvPicdCommand::Single(pcid_allocation.pcid));
            }
        } else {
            tlb::flush_all();
        }
    }

    pub fn flush_pages(&self, pages: RangeInclusive<Page>) {
        let num_pages = pages.clone().count();
        if num_pages > 32 {
            return self.flush_all();
        }

        let idx = PerCpu::get().idx;

        let mut guard = self.guard.flush_state.lock();
        let state = &mut *guard;

        // Check if the current AP is the only active AP.
        let mut other_active_aps = state.active;
        other_active_aps.set(idx, false);

        // If the current AP is the only active AP, we don't need to tell other
        // APs to flush immediately. We only need to flush the TLB on the
        // current AP.
        if other_active_aps.is_empty() {
            drop(guard);
            return self.flush_pages_local(pages);
        }

        // We have to flush the TLB on other APs :(

        // If invlpgb is supported, use it.
        if let Some(invlpgb) = INVLPGB.as_ref() {
            // Note that we don't drop `guard` until we're done flushing.

            let pcid_allocation = self.guard.pcid_allocation.as_ref().unwrap();
            let mut builder = invlpgb.build();
            unsafe {
                builder.pcid(pcid_allocation.pcid);
            }
            if num_pages < usize::from(invlpgb.invlpgb_count_max()) {
                builder = builder.pages(Page::range(*pages.start(), *pages.end() + 1));
            }
            builder.flush();
            invlpgb.tlbsync();

            return;
        }

        // We've run out of optimizations :(
        // Flush on the current processor and send IPIs to the other relevant
        // APs.
        state.needs_flush |= state.used;
        drop(guard);

        PENDING_TLB_SHOOTDOWN.set_all(other_active_aps);
        send_tlb_ipis(other_active_aps);

        self.flush_pages_local(pages);

        let mut remaining_aps = other_active_aps;
        while !remaining_aps.is_empty() {
            remaining_aps &= PENDING_TLB_SHOOTDOWN.get_all();
        }
    }

    pub fn flush_pages_local(&self, pages: RangeInclusive<Page>) {
        for page in pages {
            tlb::flush(page.start_address());
        }
    }
}

pub(super) trait FlushGuard {
    fn flush_page(&self, page: Page);
}

impl FlushGuard for ActivePageTableGuard {
    fn flush_page(&self, page: Page) {
        // TODO: Check that the page is a userspace page.
        // TODO: Check that the pml4 is active.
        self.flush_pages(page..=page);
    }
}

pub(super) struct GlobalFlushGuard;

impl FlushGuard for GlobalFlushGuard {
    fn flush_page(&self, page: Page) {
        if let Some(invlpgb) = &*INVLPGB {
            invlpgb
                .build()
                .pages(Page::range(page, page + 1))
                .include_global()
                .flush();
            invlpgb.tlbsync();
            return;
        }

        // Tell all other APs to flush their entire TLBs.
        let mut all_other_aps = ApBitmap::all();
        all_other_aps.set(PerCpu::get().idx, false);
        PENDING_GLOBAL_TLB_SHOOTDOWN.set_all(all_other_aps);

        // Send IPIs to all other currently active APs.
        let other_active_aps = ACTIVE_APS.get_all() & all_other_aps;
        send_tlb_ipis(other_active_aps);

        // Flush the local TLB entry.
        tlb::flush(page.start_address());

        // Wait for the APS to acknowledge the IPI.
        let mut remaining_aps = other_active_aps;
        while !remaining_aps.is_empty() {
            remaining_aps &= PENDING_GLOBAL_TLB_SHOOTDOWN.get_all();
        }
    }
}
