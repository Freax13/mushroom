use core::{
    arch::asm,
    mem::{MaybeUninit, offset_of},
};

use bit_field::BitField;
use tdx_types::{
    ghci::VMCALL_SUCCESS,
    report::{ReportData, TdReport},
    tdcall::{GpaAttr, GuestState, InvdTranslations, MdFieldId, VmIndex},
};
use x86_64::structures::paging::{
    PageSize, PhysFrame, Size1GiB, Size2MiB, Size4KiB, frame::PhysFrameRange,
    page::NotGiantPageSize,
};

#[derive(Debug)]
#[repr(C)]
pub struct Tdcall {
    rax: u64,
    rbx: u64,
    rcx: u64,
    rdx: u64,
    rbp: u64,
    rsi: u64,
    rdi: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    with_sti: bool,
}

impl Tdcall {
    fn new(leaf: u16) -> Self {
        Self {
            rax: u64::from(leaf),
            rbx: 0,
            rcx: 0,
            rdx: 0,
            rbp: 0,
            rsi: 0,
            rdi: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            with_sti: false,
        }
    }

    unsafe fn execute(&mut self) {
        unsafe {
            asm!(
                "xchg [rax + {OFFSET_RBX}], rbx",
                "xchg [rax + {OFFSET_RCX}], rcx",
                "xchg [rax + {OFFSET_RDX}], rdx",
                "xchg [rax + {OFFSET_RBP}], rbp",
                "xchg [rax + {OFFSET_RSI}], rsi",
                "xchg [rax + {OFFSET_RDI}], rdi",
                "xchg [rax + {OFFSET_R8}], r8",
                "xchg [rax + {OFFSET_R9}], r9",
                "xchg [rax + {OFFSET_R10}], r10",
                "xchg [rax + {OFFSET_R11}], r11",
                "xchg [rax + {OFFSET_R12}], r12",
                "xchg [rax + {OFFSET_R13}], r13",
                "xchg [rax + {OFFSET_R14}], r14",
                "xchg [rax + {OFFSET_R15}], r15",
                "push [rax + {OFFSET_RAX}]",
                "test byte ptr [rax + {OFFSET_WITH_STI}], 1",
                "xchg [rsp], rax",
                "jz 2f",
                "sti",
                "2:",
                "tdcall",
                "xchg [rsp], rax",
                "pop qword ptr [rax + {OFFSET_RAX}]",
                "xchg [rax + {OFFSET_RBX}], rbx",
                "xchg [rax + {OFFSET_RCX}], rcx",
                "xchg [rax + {OFFSET_RDX}], rdx",
                "xchg [rax + {OFFSET_RBP}], rbp",
                "xchg [rax + {OFFSET_RSI}], rsi",
                "xchg [rax + {OFFSET_RDI}], rdi",
                "xchg [rax + {OFFSET_R8}], r8",
                "xchg [rax + {OFFSET_R9}], r9",
                "xchg [rax + {OFFSET_R10}], r10",
                "xchg [rax + {OFFSET_R11}], r11",
                "xchg [rax + {OFFSET_R12}], r12",
                "xchg [rax + {OFFSET_R13}], r13",
                "xchg [rax + {OFFSET_R14}], r14",
                "xchg [rax + {OFFSET_R15}], r15",
                in("rax") self,
                OFFSET_RAX = const offset_of!(Tdcall, rax),
                OFFSET_RBX = const offset_of!(Tdcall, rbx),
                OFFSET_RCX = const offset_of!(Tdcall, rcx),
                OFFSET_RDX = const offset_of!(Tdcall, rdx),
                OFFSET_RBP = const offset_of!(Tdcall, rbp),
                OFFSET_RSI = const offset_of!(Tdcall, rsi),
                OFFSET_RDI = const offset_of!(Tdcall, rdi),
                OFFSET_R8 = const offset_of!(Tdcall, r8),
                OFFSET_R9 = const offset_of!(Tdcall, r9),
                OFFSET_R10 = const offset_of!(Tdcall, r10),
                OFFSET_R11 = const offset_of!(Tdcall, r11),
                OFFSET_R12 = const offset_of!(Tdcall, r12),
                OFFSET_R13 = const offset_of!(Tdcall, r13),
                OFFSET_R14 = const offset_of!(Tdcall, r14),
                OFFSET_R15 = const offset_of!(Tdcall, r15),
                OFFSET_WITH_STI = const offset_of!(Tdcall, with_sti),
            );
        }
    }

    pub unsafe fn mem_page_accept<S>(gpa: PhysFrame<S>)
    where
        S: NotGiantPageSize,
    {
        let mut tdcall = Self::new(6);
        tdcall.rcx = gpa.start_address().as_u64();
        tdcall.rcx.set_bit(0, S::SIZE > Size4KiB::SIZE);

        unsafe {
            tdcall.execute();
        }

        if tdcall.rax == 0xc000_0b0b_0000_0001 {
            assert_ne!(S::SIZE, Size4KiB::SIZE);

            for i in 0..512 {
                let mut tdcall = Self::new(6);
                tdcall.rcx = gpa.start_address().as_u64() + i * Size4KiB::SIZE;

                unsafe {
                    tdcall.execute();
                }

                assert_eq!(tdcall.rax, 0);
            }
        } else {
            assert_eq!(tdcall.rax, 0);
        }
    }

    pub unsafe fn mem_page_attr_wr<S>(
        frame: PhysFrame<S>,
        attr_vm1: GpaAttr,
        flags_vm1: GpaAttr,
        invept1: bool,
    ) where
        S: PageSize,
    {
        let mut tdcall = Self::new(24);
        tdcall.rcx = frame.start_address().as_u64();
        let size = match S::SIZE {
            Size4KiB::SIZE => 0,
            Size2MiB::SIZE => 1,
            Size1GiB::SIZE => 2,
            _ => unreachable!(),
        };
        tdcall.rcx.set_bits(0..=2, size);
        tdcall.rdx.set_bits(16..32, u64::from(attr_vm1.bits()));
        tdcall.r8.set_bits(16..31, u64::from(flags_vm1.bits()));
        tdcall.r8.set_bit(31, invept1);

        unsafe {
            tdcall.execute();
        }

        assert_eq!(tdcall.rax, 0);
    }

    pub fn mr_report(report_data: [u8; 64]) -> TdReport {
        let report_data = ReportData(report_data);
        let mut report = MaybeUninit::<TdReport>::uninit();

        let mut tdcall = Self::new(4);
        tdcall.rcx = report.as_mut_ptr() as u64;
        tdcall.rcx = report.as_mut_ptr() as u64;
        tdcall.rdx = core::ptr::from_ref(&report_data) as u64;
        tdcall.r8 = 0;

        unsafe {
            tdcall.execute();
        }

        assert_eq!(tdcall.rax, 0);

        unsafe { report.assume_init() }
    }

    #[expect(dead_code)]
    pub fn vp_rd(field: MdFieldId) -> u64 {
        assert_eq!(field.last_element_in_field(), 0);
        assert_eq!(field.last_element_in_sequence(), 0);

        let mut tdcall = Self::new(9);
        tdcall.rdx = field.get();

        unsafe {
            tdcall.execute();
        }

        assert_eq!(tdcall.rax, 0);
        tdcall.r8
    }

    pub unsafe fn vp_wr(field: MdFieldId, value: u64, mask: u64) {
        assert_eq!(field.last_element_in_field(), 0);
        assert_eq!(field.last_element_in_sequence(), 0);

        let mut tdcall = Self::new(10);
        tdcall.rdx = field.get();
        tdcall.r8 = value;
        tdcall.r9 = mask;

        unsafe {
            tdcall.execute();
        }

        assert_eq!(tdcall.rax, 0);
    }

    pub fn vp_enter(
        index: VmIndex,
        invd_translations: InvdTranslations,
        guest_state: &mut GuestState,
        with_sti: bool,
    ) -> VmExit {
        let mut tdcall = Self::new(25);
        tdcall.rcx.set_bits(0..=1, invd_translations as u64);
        tdcall.rcx.set_bits(52..=53, index as u64);
        tdcall.rdx = core::ptr::from_mut(guest_state) as u64;
        tdcall.with_sti = with_sti;
        unsafe {
            tdcall.execute();
        }

        VmExit {
            class: tdcall.rax.get_bits(32..=47) as u16,
            exit_reason: tdcall.rax as u32,
            exit_qualification: tdcall.rcx,
            guest_linear_address: tdcall.rdx,
            cs_selector: tdcall.rsi.get_bits(0..=15) as u16,
            cs_ar_bit: tdcall.rsi.get_bits(16..=31) as u16,
            cs_limit: tdcall.rsi.get_bits(32..) as u32,
            cs_base: tdcall.rdi,
            guest_physical_address: tdcall.r8,
            vm_exit_interruption_information: tdcall.r9.get_bits(..=31) as u32,
            vm_exit_interruption_error_code: tdcall.r9.get_bits(32..) as u32,
            idt_vectoring_information: tdcall.r10.get_bits(..=31) as u32,
            idt_vectoring_error_code: tdcall.r10.get_bits(32..) as u32,
            vm_exit_instruction_information: tdcall.r11.get_bits(..=31) as u32,
            vm_exit_instruction_length: tdcall.r11.get_bits(32..) as u32,
            cpl: tdcall.r12.get_bits(0..=1) as u8,
            extended_exit_qualification: tdcall.r13.get_bits(..=3) as u8,
        }
    }

    pub fn vp_veinfo_get() -> VeInfo {
        let mut tdcall = Self::new(3);
        unsafe {
            tdcall.execute();
        }

        assert_eq!(tdcall.rax, 0);
        VeInfo {
            exit_reason: tdcall.rcx as u32,
            exit_qualification: tdcall.rdx,
            guest_linear_address: tdcall.r8,
            guest_physical_address: tdcall.r9,
            instruction_length: tdcall.r10 as u32,
            instruction_information: (tdcall.r10 >> 32) as u32,
        }
    }
}

#[derive(Debug)]
#[expect(dead_code)]
pub struct VmExit {
    pub class: u16,
    pub exit_reason: u32,
    pub exit_qualification: u64,
    pub guest_linear_address: u64,
    pub cs_selector: u16,
    pub cs_ar_bit: u16,
    pub cs_limit: u32,
    pub cs_base: u64,
    pub guest_physical_address: u64,
    pub vm_exit_interruption_information: u32,
    pub vm_exit_interruption_error_code: u32,
    pub idt_vectoring_information: u32,
    pub idt_vectoring_error_code: u32,
    pub vm_exit_instruction_information: u32,
    pub vm_exit_instruction_length: u32,
    pub cpl: u8,
    pub extended_exit_qualification: u8,
}

#[expect(dead_code)]
pub struct VeInfo {
    pub exit_reason: u32,
    pub exit_qualification: u64,
    pub guest_linear_address: u64,
    pub guest_physical_address: u64,
    pub instruction_length: u32,
    pub instruction_information: u32,
}

pub struct Vmcall {
    rbx: Option<u64>,
    rdx: Option<u64>,
    rbp: Option<u64>,
    rsi: Option<u64>,
    rdi: Option<u64>,
    r8: Option<u64>,
    r9: Option<u64>,
    r10: Option<u64>,
    r11: Option<u64>,
    r12: Option<u64>,
    r13: Option<u64>,
    r14: Option<u64>,
    r15: Option<u64>,
    with_sti: bool,
}

impl Vmcall {
    fn new(sub_fn: u64) -> Self {
        Self {
            rbx: None,
            rdx: None,
            rbp: None,
            rsi: None,
            rdi: None,
            r8: None,
            r9: None,
            r10: Some(0),
            r11: Some(sub_fn),
            r12: None,
            r13: None,
            r14: None,
            r15: None,
            with_sti: false,
        }
    }

    unsafe fn execute(&mut self) {
        let mut tdcall = Tdcall::new(0);
        tdcall.with_sti = self.with_sti;

        macro_rules! copy_reg_in {
            ($reg:ident, $bit:literal) => {
                tdcall.rcx.set_bit($bit, self.$reg.is_some());
                tdcall.$reg = self.$reg.unwrap_or_default();
            };
        }
        copy_reg_in!(rdx, 2);
        copy_reg_in!(rdx, 2);
        copy_reg_in!(rbx, 3);
        copy_reg_in!(rbp, 5);
        copy_reg_in!(rsi, 6);
        copy_reg_in!(rdi, 7);
        copy_reg_in!(r8, 8);
        copy_reg_in!(r9, 9);
        copy_reg_in!(r10, 10);
        copy_reg_in!(r11, 11);
        copy_reg_in!(r12, 12);
        copy_reg_in!(r13, 13);
        copy_reg_in!(r14, 14);
        copy_reg_in!(r15, 15);

        unsafe {
            tdcall.execute();
        }

        macro_rules! copy_reg_out {
            ($reg:ident, $bit:literal) => {
                self.$reg = tdcall.rcx.get_bit($bit).then_some(tdcall.$reg);
            };
        }
        copy_reg_out!(rdx, 2);
        copy_reg_out!(rdx, 2);
        copy_reg_out!(rbx, 3);
        copy_reg_out!(rbp, 5);
        copy_reg_out!(rsi, 6);
        copy_reg_out!(rdi, 7);
        copy_reg_out!(r8, 8);
        copy_reg_out!(r9, 9);
        copy_reg_out!(r10, 10);
        copy_reg_out!(r11, 11);
        copy_reg_out!(r12, 12);
        copy_reg_out!(r13, 13);
        copy_reg_out!(r14, 14);
        copy_reg_out!(r15, 15);
    }

    pub fn map_gpa(gpa: PhysFrameRange, private: bool) {
        let mut vmcall = Self::new(0x10001);
        let mut address = gpa.start.start_address().as_u64();
        address.set_bit(51, !private);
        vmcall.r12 = Some(address);
        vmcall.r13 = Some(gpa.end - gpa.start);

        unsafe {
            vmcall.execute();
        }

        assert_eq!(vmcall.r10, Some(VMCALL_SUCCESS));
    }

    pub fn instruction_hlt(interrupt_blocked: bool, with_sti: bool) {
        debug_assert_eq!(
            !interrupt_blocked,
            x86_64::instructions::interrupts::are_enabled() || with_sti
        );

        let mut vmcall = Self::new(12);
        vmcall.r12 = Some(u64::from(interrupt_blocked));
        vmcall.with_sti = with_sti;

        unsafe {
            vmcall.execute();
        }

        assert_eq!(vmcall.r10, Some(VMCALL_SUCCESS));
    }

    pub fn instruction_io_write32(port: u16, value: u32) {
        let mut vmcall = Self::new(30);
        vmcall.r12 = Some(4);
        vmcall.r13 = Some(1);
        vmcall.r14 = Some(u64::from(port));
        vmcall.r15 = Some(u64::from(value));

        unsafe {
            vmcall.execute();
        }

        assert_eq!(vmcall.r10, Some(VMCALL_SUCCESS));
    }

    pub fn instruction_wrmsr(msr: u32, value: u64) {
        let mut vmcall = Self::new(32);
        vmcall.r12 = Some(u64::from(msr));
        vmcall.r13 = Some(value);

        unsafe {
            vmcall.execute();
        }

        assert_eq!(vmcall.r10, Some(VMCALL_SUCCESS));
    }
}
