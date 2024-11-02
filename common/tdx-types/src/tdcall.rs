use bit_field::BitField;
use bitflags::bitflags;
use bytemuck::{Pod, Zeroable};
use x86_64::registers::rflags::RFlags;

pub const TDX_SUCCESS: u32 = 0x00000000;
pub const TDX_L2_EXIT_HOST_ROUTED_ASYNC: u32 = 0x00001100;
pub const TDX_L2_EXIT_PENDING_INTERRUPT: u32 = 0x00001102;
pub const TDX_PENDING_INTERRUPT: u32 = 0x00001120;

#[derive(Debug, Clone, Copy)]
#[repr(C, align(256))]
pub struct GuestState {
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rbx: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rflags: RFlags,
    pub rip: u64,
    pub ssp: u64,
    pub guest_interrupt_status: u16,
}

#[derive(Debug, Clone, Copy)]
pub struct MdFieldId(u64);

impl MdFieldId {
    pub const VMX_VIRTUAL_APIC_PAGE_ADDRESS: Self = Self::vmcs1(0x2012);
    pub const VMX_GUEST_IA32_EFER: Self = Self::vmcs1(0x2806);
    pub const VMX_VM_ENTRY_CONTROL: Self = Self::vmcs1(0x4012);
    pub const VMX_VM_EXECUTION_CONTROL_SECONDARY_PROC_BASED: Self = Self::vmcs1(0x401E);
    pub const VMX_GUEST_CS_ARBYTE: Self = Self::vmcs1(0x4816);
    pub const VMX_GUEST_CR0: Self = Self::vmcs1(0x6800);
    pub const VMX_GUEST_CR3: Self = Self::vmcs1(0x6802);
    pub const VMX_GUEST_CR4: Self = Self::vmcs1(0x6804);

    pub const STAR_WRITE: Self = Self::msr_bitmaps1(0xC000_0081, true);
    pub const STAR_WRITE_MASK: u64 = Self::msr_bitmaps_mask(0xC000_0081);

    pub const LSTAR_WRITE: Self = Self::msr_bitmaps1(0xC000_0082, true);
    pub const LSTAR_WRITE_MASK: u64 = Self::msr_bitmaps_mask(0xC000_0082);

    pub const SFMASK_WRITE: Self = Self::msr_bitmaps1(0xC000_0084, true);
    pub const SFMASK_WRITE_MASK: u64 = Self::msr_bitmaps_mask(0xC000_0084);

    pub const TDVPS_L2_CTLS1: Self = Self::new(
        81,
        ElementSizeCode::SixtyFour,
        0,
        0,
        false,
        ContextCode::TdVcpu,
        32,
        true,
    );

    #[allow(clippy::too_many_arguments)]
    const fn new(
        field_code: u32,
        element_size_code: ElementSizeCode,
        last_element_in_field: u8,
        last_element_in_sequence: u16,
        inc_size: bool,
        context_code: ContextCode,
        class_code: u8,
        non_arch: bool,
    ) -> Self {
        assert!(field_code < 1 << 24);
        assert!(last_element_in_field < 1 << 4);
        assert!(last_element_in_sequence < 1 << 9);
        assert!(last_element_in_sequence < 1 << 6);

        let mut bits = 0;
        bits |= field_code as u64;
        bits |= (element_size_code as u64) << 32;
        bits |= (last_element_in_field as u64) << 34;
        bits |= (last_element_in_sequence as u64) << 38;
        bits |= (inc_size as u64) << 50;
        bits |= (context_code as u64) << 52;
        bits |= (class_code as u64) << 56;
        bits |= (non_arch as u64) << 63;

        Self(bits)
    }

    const fn vmcs1(vmcs_field_code: u16) -> Self {
        Self::new(
            vmcs_field_code as u32,
            ElementSizeCode::SixtyFour,
            0,
            0,
            false,
            ContextCode::TdVcpu,
            36,
            false,
        )
    }

    const fn msr_bitmaps1(msr: u32, write: bool) -> Self {
        let mut bitmap_offset = match msr {
            0x0000_0000..0x0000_1FFF => 0,
            0xC000_0000..0xC000_1FFF => 1024,
            _ => panic!("invalid MSR"),
        };
        if write {
            bitmap_offset += 2048;
        }
        let offset = bitmap_offset + (msr & 0x1FFF) / 8;

        Self::new(
            offset / 8,
            ElementSizeCode::SixtyFour,
            0,
            0,
            false,
            ContextCode::TdVcpu,
            37,
            false,
        )
    }

    const fn msr_bitmaps_mask(msr: u32) -> u64 {
        1 << (msr & 0x3f)
    }

    pub const fn get(&self) -> u64 {
        self.0
    }

    pub fn last_element_in_field(&self) -> u8 {
        self.0.get_bits(34..=37) as u8
    }

    pub fn last_element_in_sequence(&self) -> u16 {
        self.0.get_bits(38..=46) as u16
    }

    pub fn set_write_mask_valid(&mut self, value: bool) {
        self.0.set_bit(51, value);
    }
}

#[derive(Debug, Clone, Copy)]
pub enum ElementSizeCode {
    Eight,
    SixTeen,
    ThirtyTwo,
    SixtyFour,
}

#[derive(Debug, Clone, Copy)]
pub enum ContextCode {
    Platform,
    Td,
    TdVcpu,
}

bitflags! {
    #[derive(Debug, Clone, Copy, Pod, Zeroable)]
    #[repr(transparent)]
    pub struct GpaAttr: u16 {
        const READ = 1 << 0;
        const WRITE = 1 << 1;
        const EXECUTE_SUPERVISOR = 1 << 2;
        const EXECUTE_USER = 1 << 3;
        const VERIFY_GUEST_PAGING = 1 << 4;
        const PAGE_WRITE_ACCESS = 1 << 5;
        const SUPERVISOR_SHADOW_STACK = 1 << 6;
        const VALID = 1 << 15;
    }
}

#[derive(Debug, Clone, Copy)]
pub enum InvdTranslations {
    None,
    IncludingEPxE,
    All,
    ExcludingGlobal,
}

#[derive(Debug, Clone, Copy)]
pub enum VmIndex {
    One = 1,
    Two,
    Three,
}

#[repr(C, align(4096))]
pub struct Apic([u8; 4096]);

impl Default for Apic {
    fn default() -> Self {
        Self([0; 4096])
    }
}
