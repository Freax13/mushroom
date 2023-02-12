use core::{
    cell::UnsafeCell,
    num::NonZeroU8,
    sync::atomic::{AtomicU16, AtomicU8, Ordering},
};

use bit_field::BitField;
use x86_64::structures::paging::PhysFrame;

use crate::{ghcb::set_doorbell, pagetable::ref_to_pa};

#[link_section = ".shared"]
pub static DOORBELL: Doorbell = Doorbell::new();

pub fn init() {
    let addr = ref_to_pa(&DOORBELL).unwrap();
    let frame = PhysFrame::from_start_address(addr).unwrap();

    set_doorbell(frame).expect("failed to set doorbell");
}

#[repr(C, align(4096))]
pub struct Doorbell {
    pending_event: AtomicU16,
    no_eoi_required: AtomicU8,
    _reserved: UnsafeCell<[u8; 61]>,
}

impl Doorbell {
    pub const fn new() -> Self {
        Self {
            pending_event: AtomicU16::new(0),
            no_eoi_required: AtomicU8::new(0),
            _reserved: UnsafeCell::new([0; 61]),
        }
    }

    pub fn fetch_pending_event(&self) -> PendingEvent {
        let pending_event = self.pending_event.swap(0, Ordering::SeqCst);
        PendingEvent::new(pending_event)
    }

    pub fn requires_eoi(&self) -> bool {
        self.no_eoi_required.swap(0, Ordering::SeqCst) == 0
    }
}

// FIXME: This should be a thread local.
unsafe impl Sync for Doorbell {}

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

    pub fn is_empty(&self) -> bool {
        self.vector.is_none() && !self.nmi && !self.mc
    }

    pub fn vector(&self) -> Option<NonZeroU8> {
        self.vector
    }

    pub fn nmi(&self) -> bool {
        self.nmi
    }

    pub fn mc(&self) -> bool {
        self.mc
    }
}
