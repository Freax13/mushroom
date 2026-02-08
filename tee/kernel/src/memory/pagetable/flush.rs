use core::{
    arch::{asm, x86_64::__cpuid},
    ops::RangeInclusive,
};

use bit_field::{BitArray, BitField};
use constants::{ApBitmap, ApIndex, AtomicApBitmap, MAX_APS_COUNT, TLB_VECTOR};
use x86_64::{
    instructions::tlb::{self, InvPcidCommand, Invlpgb},
    registers::{
        control::{Cr3, Cr4, Cr4Flags},
        model_specific::Msr,
    },
    structures::paging::Page,
};

use crate::{
    exception::{Interrupt, start_interrupt_handler},
    memory::pagetable::ActivePageTableGuard,
    per_cpu::{PerCpu, PerCpuSync},
    spin::lazy::Lazy,
};

static INVLPGB: Lazy<Option<Invlpgb>> = Lazy::new(Invlpgb::new);

static ACTIVE_APS: AtomicApBitmap = AtomicApBitmap::empty();
static PENDING_TLB_SHOOTDOWN: AtomicApBitmap = AtomicApBitmap::empty();
static PENDING_GLOBAL_TLB_SHOOTDOWN: AtomicApBitmap = AtomicApBitmap::empty();
static LAZY_PENDING_GLOBAL_TLB_SHOOTDOWN: AtomicApBitmap = AtomicApBitmap::empty();

pub fn init() {
    post_halt();
}

pub fn pre_halt() {
    ACTIVE_APS.take(PerCpu::get().idx);
}

pub fn post_halt() {
    ACTIVE_APS.set(PerCpu::get().idx);
    process_flushes();
}

fn process_flushes() {
    let idx = PerCpuSync::get().idx;
    let need_global_flush =
        PENDING_GLOBAL_TLB_SHOOTDOWN.take(idx) | LAZY_PENDING_GLOBAL_TLB_SHOOTDOWN.take(idx);
    let need_non_global_flush = PENDING_TLB_SHOOTDOWN.take(idx);
    if need_global_flush {
        if Cr4::read().contains(Cr4Flags::PCID) {
            unsafe {
                tlb::flush_pcid(tlb::InvPcidCommand::All);
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
                tlb::flush_pcid(tlb::InvPcidCommand::Single(pcid));
            }
        } else {
            tlb::flush_all();
        }
    }
}

pub extern "C" fn tlb_shootdown_handler() {
    start_interrupt_handler(Interrupt::TlbShootdown, process_flushes);
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

        // If the hypervisor supports Hyper-V hypercalls, use them.
        if let Some(hyper_v) = *HYPER_V {
            hyper_v.flush_all(state.needs_flush);
            self.flush_all_local();
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
                tlb::flush_pcid(InvPcidCommand::Single(pcid_allocation.pcid));
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

        let mut other_used = state.used;
        other_used.set(idx, false);

        // Check if the current AP is the only active AP.
        let mut other_active_aps = state.active;
        other_active_aps.set(idx, false);

        // If the current AP is the only active AP, we don't need to tell other
        // APs to flush immediately. We only need to flush the TLB on the
        // current AP.
        if other_active_aps.is_empty() {
            state.needs_flush |= other_used;
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
            } else {
                state.needs_flush = ApBitmap::empty();
            }
            builder.flush();
            invlpgb.tlbsync();

            return;
        }

        // If the hypervisor supports Hyper-V hypercalls, use them.
        if let Some(hyper_v) = *HYPER_V {
            guard.needs_flush |= other_used;
            drop(guard);

            hyper_v.flush_address_list(pages.clone(), other_active_aps);
            self.flush_pages_local(pages);
            return;
        }

        // We've run out of optimizations :(
        // Flush on the current processor and send IPIs to the other relevant
        // APs.
        state.needs_flush |= other_used;
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
        // If invlpgb is supported, use it.
        if let Some(invlpgb) = &*INVLPGB {
            invlpgb
                .build()
                .pages(Page::range(page, page + 1))
                .include_global()
                .flush();
            invlpgb.tlbsync();
            return;
        }

        let mut all_other_aps = ApBitmap::all();
        all_other_aps.set(PerCpu::get().idx, false);

        // If the hypervisor supports Hyper-V hypercalls, use them.
        if let Some(hyper_v) = *HYPER_V {
            hyper_v.flush_address_list(page..=page, all_other_aps);

            // Flush the local TLB entry.
            tlb::flush(page.start_address());
            return;
        }

        // For all other active APs, set the bit in `PENDING_GLOBAL_TLB_SHOOTDOWN`.
        // We'll send an IPI to those and expect them to process the flush
        // request right away. For all other inactive APs, set the bit in
        // `LAZY_PENDING_GLOBAL_TLB_SHOOTDOWN` and don't send an IPI. We expect
        // them to flush this once they wake up. Note that we only need to poll
        // from `PENDING_GLOBAL_TLB_SHOOTDOWN` to read back if the flushed have
        // finished. It's important that we don't set any bits in
        // `PENDING_GLOBAL_TLB_SHOOTDOWN` if we're not also sending an IPI. If
        // we set the bit without sending an IPI, there's a chance that another
        // thread is waiting for the bit to be cleared, but the AP is actually
        // clearing the bit, but then we're setting it again without sending an
        // IPI, so the other thread thinks that the bit was never cleared and
        // it won't get cleared again because we didn't set another IPI.
        let active_aps = ACTIVE_APS.get_all();
        let inactive_aps = !active_aps & all_other_aps;
        LAZY_PENDING_GLOBAL_TLB_SHOOTDOWN.set_all(inactive_aps);
        // Re-fetch `ACTIVE_APS` after setting `LAZY_PENDING_GLOBAL_TLB_SHOOTDOWN`.
        // If we don't do this, there's a race condition:
        // +----------------------------------------------------------------------------------+
        // | this AP                                 | other AP                               |
        // | ...                                     | inactive                               |
        // | read ACTIVE_APS                         |                                        |
        // |                                         | wake up                                |
        // |                                         | set ACTIVE_APS                         |
        // |                                         | read LAZY_PENDING_GLOBAL_TLB_SHOOTDOWN |
        // | write LAZY_PENDING_GLOBAL_TLB_SHOOTDOWN |                                        |
        // +----------------------------------------------------------------------------------+
        let active_aps = active_aps | ACTIVE_APS.get_all();
        let other_active_aps = active_aps & all_other_aps;
        PENDING_GLOBAL_TLB_SHOOTDOWN.set_all(other_active_aps);

        // Send IPIs to all other currently active APs.
        send_tlb_ipis(other_active_aps);

        // Flush the local TLB entry.
        tlb::flush(page.start_address());

        // Wait for the APs to acknowledge the IPI.
        let mut remaining_aps = other_active_aps;
        while !remaining_aps.is_empty() {
            remaining_aps &= PENDING_GLOBAL_TLB_SHOOTDOWN.get_all();
        }
    }
}

#[derive(Clone, Copy)]
enum Hypercall {
    Vmmcall,
    Vmcall,
}

impl Hypercall {
    fn get() -> Self {
        let svm = unsafe { __cpuid(0x8000_0001) }.ecx.get_bit(2);
        if svm {
            Hypercall::Vmmcall
        } else {
            Hypercall::Vmcall
        }
    }
}

static HYPER_V: Lazy<Option<HyperV>> = Lazy::new(HyperV::new);

#[derive(Clone, Copy)]
struct HyperV(Hypercall);

impl HyperV {
    pub fn new() -> Option<Self> {
        // Make sure the hypervisor supports the HyperV hypercall ABI.
        let cpuid_result = unsafe {
            // SAFETY: If `cpuid` isn't available, we have bigger problems.
            __cpuid(0x40000001)
        };
        // Check the interface id.
        if cpuid_result.eax != 0x31237648 {
            return None;
        }

        // Enable HyperV hypercalls.
        const HV_X64_MSR_GUEST_OS_ID: u32 = 0x40000000;
        unsafe {
            Msr::new(HV_X64_MSR_GUEST_OS_ID).write(1);
        }

        Some(Self(Hypercall::get()))
    }

    const HV_FLUSH_ALL_VIRTUAL_ADDRESS_SPACES: u64 = 1 << 1;

    pub fn flush_address_list(&self, range: RangeInclusive<Page>, aps: ApBitmap) {
        let count = range.clone().count();
        let gva_range = match count {
            0 => {
                //  There's nothing to flush.
                return;
            }
            1..1024 => range.start().start_address().as_u64() + (count as u64 - 1),
            _ => {
                // We can't encode the range. Fall back to flushing the entire TLB.
                return self.flush_all(aps);
            }
        };

        let mut input_value = 0;
        input_value.set_bits(0..16, 0x0014); // Call Code: 0x0014
        input_value.set_bit(16, true); // Fast: true
        input_value.set_bits(17..27, NUM_BANKS); // Variable header size: NUM_BANKS
        input_value.set_bit(31, false); // Is Nested: false
        input_value.set_bits(32..44, 1); // Rep Count: 1
        input_value.set_bits(48..60, 0); // Rep Start Index: 0

        #[repr(C, align(16))]
        struct HvFlushVirtualAddressListEx {
            // header
            address_space: u64,
            flags: u64,
            processor_set: HvVpSet,
            // list
            gva_range: u64,
        }

        let input = HvFlushVirtualAddressListEx {
            address_space: 0,
            flags: Self::HV_FLUSH_ALL_VIRTUAL_ADDRESS_SPACES,
            processor_set: HvVpSet::from_iter(aps),
            gva_range,
        };

        // Assert that we can fit `HvFlushVirtualAddressListEx` into two GPRs
        // and 2 XMM registers.
        const {
            assert!(size_of::<HvFlushVirtualAddressListEx>().div_ceil(16) - 1 == 2);
        }

        let output: u64;
        unsafe {
            asm!(
                "mov rdx, qword ptr [{input} + 0]",
                "mov r8,  qword ptr [{input} + 8]",
                "movdqa xmm0, xmmword ptr [{input} + 16]",
                "movdqa xmm1, xmmword ptr [{input} + 32]",
                "test {variant}, {VMCALL}",
                "jnz 65f",
                "vmmcall",
                "jmp 66f",
                "65:",
                "vmcall",
                "66:",
                inout("rcx") input_value => _,
                input = in(reg) &input,
                variant = in(reg) self.0 as u64,
                VMCALL = const Hypercall::Vmcall as u8,
                out("rax") output,
                out("rdx") _,
                out("r8") _,
                out("xmm0") _,
                out("xmm1") _,
                options(nostack),
            );
        }

        assert_eq!(output.get_bits(0..16), 0); // Check result
        assert_eq!(output.get_bits(32..44), 1); // Check resps completed
    }

    pub fn flush_all(&self, aps: ApBitmap) {
        let mut input_value = 0;
        input_value.set_bits(0..16, 0x0013); // Call Code: 0x0013
        input_value.set_bit(16, true); // Fast: true
        input_value.set_bits(17..27, NUM_BANKS); // Variable header size: NUM_BANKS
        input_value.set_bit(31, false); // Is Nested: false
        input_value.set_bits(32..44, 0); // Rep Count: 1
        input_value.set_bits(48..60, 0); // Rep Start Index: 0

        #[repr(C, align(16))]
        struct HvCallFlushVirtualAddressSpaceEx {
            // header
            address_space: u64,
            flags: u64,
            processor_set: HvVpSet,
        }

        let input = HvCallFlushVirtualAddressSpaceEx {
            address_space: 0,
            flags: Self::HV_FLUSH_ALL_VIRTUAL_ADDRESS_SPACES,
            processor_set: HvVpSet::from_iter(aps),
        };

        // Assert that we can fit `HvCallFlushVirtualAddressSpaceEx` into two GPRs
        // and 2 XMM registers.
        const {
            assert!(size_of::<HvCallFlushVirtualAddressSpaceEx>().div_ceil(16) - 1 == 2);
        }

        let output: u64;
        unsafe {
            asm!(
                "mov rdx, qword ptr [{input} + 0]",
                "mov r8,  qword ptr [{input} + 8]",
                "movdqa xmm0, xmmword ptr [{input} + 16]",
                "movdqa xmm1, xmmword ptr [{input} + 32]",
                "test {variant}, {VMCALL}",
                "jnz 65f",
                "vmmcall",
                "jmp 66f",
                "65:",
                "vmcall",
                "66:",
                inout("rcx") input_value => _,
                input = in(reg) &input,
                variant = in(reg) self.0 as u64,
                VMCALL = const Hypercall::Vmcall as u8,
                out("rax") output,
                out("rdx") _,
                out("r8") _,
                out("xmm0") _,
                out("xmm1") _,
                options(nostack),
            );
        }

        assert_eq!(output.get_bits(0..16), 0); // Check result
    }
}

const NUM_BANKS: usize = (MAX_APS_COUNT as usize).div_ceil(64);

#[repr(C)]
struct HvVpSet {
    format: u64,
    valid_banks_mask: u64,
    bank_contents: [u64; NUM_BANKS],
}

impl FromIterator<ApIndex> for HvVpSet {
    fn from_iter<T: IntoIterator<Item = ApIndex>>(iter: T) -> Self {
        let mut this = Self::default();
        for ap in iter {
            this.bank_contents.set_bit(usize::from(ap.as_u8()), true);
        }
        this
    }
}

impl Default for HvVpSet {
    fn default() -> Self {
        Self {
            format: 0,
            valid_banks_mask: (1 << NUM_BANKS) - 1,
            bank_contents: [0; NUM_BANKS],
        }
    }
}
