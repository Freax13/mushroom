use core::arch::asm;

use bit_field::BitField;
use constants::{ApBitmap, ApIndex, AtomicApBitmap};
use x86_64::{
    instructions::tlb,
    registers::{
        control::{Cr3, Cr4, Cr4Flags},
        model_specific::Msr,
    },
    structures::idt::InterruptStackFrame,
};

pub const TLB_VECTOR: u8 = 0x20;

static PENDING_TLB_SHOOTDOWN: AtomicApBitmap = AtomicApBitmap::empty();
static PENDING_GLOBAL_TLB_SHOOTDOWN: AtomicApBitmap = AtomicApBitmap::empty();

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
