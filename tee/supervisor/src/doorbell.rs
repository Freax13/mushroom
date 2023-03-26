use core::{
    cell::SyncUnsafeCell,
    num::NonZeroU8,
    sync::atomic::{AtomicU16, AtomicU8, Ordering},
};

use bit_field::BitField;
use x86_64::structures::paging::PhysFrame;

use crate::{ghcb::set_doorbell, pa_of};

#[link_section = ".shared"]
pub static DOORBELL: Doorbell = Doorbell::new();

/// Initialize the doorbell page required for restricted injection.
pub fn init() {
    let addr = pa_of!(DOORBELL);
    let frame = PhysFrame::from_start_address(addr).unwrap();

    // Register the doorbell page.
    set_doorbell(frame).expect("failed to set doorbell");
}

#[repr(C, align(4096))]
pub struct Doorbell {
    pending_event: AtomicU16,
    no_eoi_required: AtomicU8,
    _reserved: SyncUnsafeCell<[u8; 61]>,
    // This padding field ensures that there aren't any soundness problems
    // regarding the host modifying padding bytes.
    _padding: SyncUnsafeCell<[u8; 0x1000 - 64]>,
}

impl Doorbell {
    const fn new() -> Self {
        Self {
            pending_event: AtomicU16::new(0),
            no_eoi_required: AtomicU8::new(0),
            _reserved: SyncUnsafeCell::new([0; 61]),
            _padding: SyncUnsafeCell::new([0; 0x1000 - 64]),
        }
    }

    /// Atomically fetch the pending_event field written by the host.
    pub fn fetch_pending_event(&self) -> PendingEvent {
        let pending_event = self.pending_event.swap(0, Ordering::SeqCst);
        PendingEvent::new(pending_event)
    }

    /// Returns whether the host requires us to send a notification when the
    /// interrupt has been handled.
    pub fn requires_eoi(&self) -> bool {
        self.no_eoi_required.swap(0, Ordering::SeqCst) == 0
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PendingEvent {
    vector: Option<NonZeroU8>,
    nmi: bool,
    mc: bool,
}

impl PendingEvent {
    fn new(value: u16) -> Self {
        let vector = value.get_bits(0..=7) as u8;
        let vector = NonZeroU8::new(vector);
        let nmi = value.get_bit(8);
        let mc = value.get_bit(9);
        Self { vector, nmi, mc }
    }

    /// Returns true if the host has signaled some event to us.
    pub fn is_empty(&self) -> bool {
        self.vector.is_none() && !self.nmi && !self.mc
    }

    /// Returns the vector of an interrupt the host has signaled if one exists.
    pub fn vector(&self) -> Option<NonZeroU8> {
        self.vector
    }

    /// Returns whether the host has signaled a non maskable interrupt.
    pub fn nmi(&self) -> bool {
        self.nmi
    }

    /// Returns whether the host has signaled a non machine check exception.
    pub fn mc(&self) -> bool {
        self.mc
    }
}
