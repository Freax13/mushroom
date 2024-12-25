//! This crate contains the interfaces the supervisor and workload kernel use
//! to communicate.

#![no_std]
#![forbid(unsafe_code)]

pub enum SupervisorCallNr {
    StartNextAp,
    Halt,
    Kick,
    AllocateMemory,
    DeallocateMemory,
    UpdateOutput,
    FinishOutput,
    FailOutput,
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct SlotIndex(u16);

impl SlotIndex {
    pub const EMPTY: Self = Self(0xffff);

    pub fn new(value: u16) -> Self {
        assert!(value < u16::MAX / 2);
        Self(value)
    }

    pub const fn get(&self) -> u16 {
        assert!(self.0 < u16::MAX / 2);
        self.0
    }
}
