use core::fmt;

use bit_field::BitField;
use bytemuck::{CheckedBitPattern, Pod, Zeroable};
use x86_64::{structures::paging::PhysFrame, PhysAddr};

use crate::Reserved;

pub mod msr_protocol;

#[derive(Clone, Copy, Debug, CheckedBitPattern, Zeroable)]
#[repr(C, align(4096))]
pub struct Ghcb {
    _reserved1: Reserved<0xcb>,
    pub cpl: u8,
    _reserved2: Reserved<0x74>,
    pub xss: u64,
    _reserved3: Reserved<0x18>,
    pub dr7: u64,
    _reserved4: Reserved<0x90>,
    pub rax: u64,
    _reserved5: Reserved<0x100>,
    _reserved6: Reserved<8>,
    pub rcx: u64,
    pub rdx: u64,
    pub rbx: u64,
    _reserved7: Reserved<0x70>,
    pub sw_exit_code: u64,
    pub sw_exit_info1: u64,
    pub sw_exit_info2: u64,
    pub sw_scratch: u64,
    _reserved8: Reserved<0x38>,
    pub xcr0: u64,
    pub valid_bitmap: u128,
    pub x87_state_gpa: u64,
    _reserved9: Reserved<0x3f8>,
    pub shared_buffer: [u8; 0x7f0],
    _reserved10: Reserved<0xa>,
    pub protocol_version: ProtocolVersion,
    pub ghcb_usage: GhcbUsage,
}

impl Ghcb {
    pub const ZERO: Self = Self {
        _reserved1: Reserved([0; 0xcb]),
        cpl: 0,
        _reserved2: Reserved([0; 0x74]),
        xss: 0,
        _reserved3: Reserved([0; 0x18]),
        dr7: 0,
        _reserved4: Reserved([0; 0x90]),
        rax: 0,
        _reserved5: Reserved([0; 0x100]),
        _reserved6: Reserved([0; 8]),
        rcx: 0,
        rdx: 0,
        rbx: 0,
        _reserved7: Reserved([0; 0x70]),
        sw_exit_code: 0,
        sw_exit_info1: 0,
        sw_exit_info2: 0,
        sw_scratch: 0,
        _reserved8: Reserved([0; 0x38]),
        xcr0: 0,
        valid_bitmap: 0,
        x87_state_gpa: 0,
        _reserved9: Reserved([0; 0x3f8]),
        shared_buffer: [0; 0x7f0],
        _reserved10: Reserved([0; 0xa]),
        protocol_version: ProtocolVersion(0),
        ghcb_usage: GhcbUsage(0),
    };
}

#[derive(Clone, Copy, PartialEq, Eq, Pod, Zeroable)]
#[repr(transparent)]
pub struct ProtocolVersion(pub u16);

impl ProtocolVersion {
    pub const VERSION1: Self = Self(1);
    pub const VERSION2: Self = Self(2);
}

impl fmt::Debug for ProtocolVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::VERSION1 => f.pad("Version 1"),
            Self::VERSION2 => f.pad("Version 2"),
            _ => f.pad("Unknown version"),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Pod, Zeroable)]
#[repr(transparent)]
pub struct GhcbUsage(pub u32);

impl GhcbUsage {
    pub const AMD_STANDARD: Self = Self(0);
}

impl fmt::Debug for GhcbUsage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::AMD_STANDARD => f.pad("AMD Standard Usage"),
            _ => f.pad("Unknown usage"),
        }
    }
}

#[derive(Debug, Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct PageStateChangeHeader {
    pub cur_entry: u16,
    pub end_entry: u16,
    _reserved: u32,
}

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(transparent)]
pub struct PageStateChangeEntry(u64);

impl PageStateChangeEntry {
    pub fn page_assign_private_4kib(frame: PhysFrame) -> Self {
        let mut value = 0;
        value.set_bits(0..=11, 0); // Current page must be zero if the page size is 4K.
        value.set_bits(12..=51, frame.start_address().as_u64().get_bits(12..));
        value.set_bits(52..=55, 1); // Page operation: Page assignment, Private
        value.set_bit(56, false); // Page size: 4K
        value.set_bits(57..=63, 0); // Reserved, must be zero
        Self(value)
    }

    pub fn page_assign_shared_4kib(frame: PhysFrame) -> Self {
        let mut value = 0;
        value.set_bits(0..=11, 0); // Current page must be zero if the page size is 4K.
        value.set_bits(12..=51, frame.start_address().as_u64().get_bits(12..));
        value.set_bits(52..=55, 2); // Page operation: Page assignment, Shared
        value.set_bit(56, false); // Page size: 4K
        value.set_bits(57..=63, 0); // Reserved, must be zero
        Self(value)
    }

    pub fn page_operation(&self) -> Result<PageOperation, u8> {
        match self.0.get_bits(52..=55) as u8 {
            1 => Ok(PageOperation::PageAssignmentPrivate),
            2 => Ok(PageOperation::PageAssignmentShared),
            other => Err(other),
        }
    }

    pub fn page_size(&self) -> PageSize {
        match self.0.get_bit(56) {
            true => PageSize::Size2MiB,
            false => PageSize::Size4KiB,
        }
    }

    pub fn gfn(&self) -> PhysFrame {
        PhysFrame::containing_address(PhysAddr::new_truncate(self.0))
    }
}

#[derive(Debug)]
pub enum PageOperation {
    PageAssignmentPrivate = 1,
    PageAssignmentShared = 2,
}

#[derive(Debug, PartialEq, Eq)]
pub enum PageSize {
    Size4KiB,
    Size2MiB,
}
