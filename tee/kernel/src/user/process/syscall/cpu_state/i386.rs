use core::arch::asm;
use core::mem::offset_of;

use alloc::vec::Vec;
use log::debug;
use x86_64::{
    instructions::tables::{lgdt, sgdt},
    registers::segmentation::{Segment64, FS},
    structures::DescriptorTablePointer,
    VirtAddr,
};

use crate::{error::Error, per_cpu::PerCpu, user::process::syscall::traits::SyscallArgs};
use crate::{error::Result, user::process::syscall::traits::SyscallResult};

use super::super::super::thread::KernelRegisters;
use super::Abi;

#[derive(Clone)]
pub struct I386 {
    registers: UserspaceRegisters,
    gdt: Vec<u64>,
}

impl I386 {
    pub fn new(eip: u32, esp: u32) -> Self {
        debug!("start abi32 eip={eip:#x} esp={esp:#x}");

        let gdt = PerCpu::get().gdt.get().unwrap().as_raw_slice().to_vec();

        Self {
            registers: UserspaceRegisters {
                eip,
                esp,
                ..UserspaceRegisters::DEFAULT
            },
            gdt,
        }
    }

    pub unsafe fn run_userspace(&mut self) -> Result<()> {
        macro_rules! kernel_reg_offset {
            ($ident:ident) => {{
                offset_of!(PerCpu, kernel_registers) + offset_of!(KernelRegisters, $ident)
            }};
        }
        macro_rules! userspace_reg_offset {
            ($ident:ident) => {{
                offset_of!(PerCpu, userspace32_registers) + offset_of!(UserspaceRegisters, $ident)
            }};
        }

        let per_cpu = PerCpu::get();
        per_cpu.userspace32_registers.set(self.registers);

        unsafe {
            FS::write_base(VirtAddr::new(self.registers.fs_base));
        }

        // Save the current GDT.
        let prev_pointer = sgdt();

        // Load the thread's GDT.
        let pointer = DescriptorTablePointer {
            limit: u16::try_from(self.gdt.len() * 8 - 1)?,
            base: VirtAddr::from_ptr(self.gdt.as_ptr()),
        };
        unsafe {
            lgdt(&pointer);
        }

        unsafe {
            asm!(
                // Set callback address.
                "lea rax, [rip+66f]",
                "mov gs:[{INT0X80_HANDLER_OFFSET}], rax",
                // Save the kernel registers.
                "mov gs:[{K_RAX_OFFSET}], rax",
                "mov gs:[{K_RBX_OFFSET}], rbx",
                "mov gs:[{K_RCX_OFFSET}], rcx",
                "mov gs:[{K_RDX_OFFSET}], rdx",
                "mov gs:[{K_RSI_OFFSET}], rsi",
                "mov gs:[{K_RDI_OFFSET}], rdi",
                "mov gs:[{K_RSP_OFFSET}], rsp",
                "mov gs:[{K_RBP_OFFSET}], rbp",
                "mov gs:[{K_R8_OFFSET}], r8",
                "mov gs:[{K_R9_OFFSET}], r9",
                "mov gs:[{K_R10_OFFSET}], r10",
                "mov gs:[{K_R11_OFFSET}], r11",
                "mov gs:[{K_R12_OFFSET}], r12",
                "mov gs:[{K_R13_OFFSET}], r13",
                "mov gs:[{K_R14_OFFSET}], r14",
                "mov gs:[{K_R15_OFFSET}], r15",
                // Save RFLAGS.
                "pushfq",
                "pop rax",
                "mov gs:[{K_RFLAGS_OFFSET}], rax",
                // Setup stack frame for iretq.
                // SS
                "push 0x23",
                "mov ax, 0x23",
                "mov es, ax",
                "mov ds, ax",
                // RSP
                "mov eax, gs:[{U_ESP_OFFSET}]",
                "push rax",
                // RFLAGS
                "mov eax, gs:[{U_EFLAGS_OFFSET}]",
                "push rax",
                // CS
                "push 0x1b",
                // RIP
                "mov eax, gs:[{U_EIP_OFFSET}]",
                "push rax",
                // Restore userspace registers.
                "mov eax, gs:[{U_EAX_OFFSET}]",
                "mov ebx, gs:[{U_EBX_OFFSET}]",
                "mov ecx, gs:[{U_ECX_OFFSET}]",
                "mov edx, gs:[{U_EDX_OFFSET}]",
                "mov esi, gs:[{U_ESI_OFFSET}]",
                "mov edi, gs:[{U_EDI_OFFSET}]",
                "mov ebp, gs:[{U_EBP_OFFSET}]",
                "vmovdqa ymm0, gs:[{U_YMM_OFFSET}+32*0]",
                "vmovdqa ymm1, gs:[{U_YMM_OFFSET}+32*1]",
                "vmovdqa ymm2, gs:[{U_YMM_OFFSET}+32*2]",
                "vmovdqa ymm3, gs:[{U_YMM_OFFSET}+32*3]",
                "vmovdqa ymm4, gs:[{U_YMM_OFFSET}+32*4]",
                "vmovdqa ymm5, gs:[{U_YMM_OFFSET}+32*5]",
                "vmovdqa ymm6, gs:[{U_YMM_OFFSET}+32*6]",
                "vmovdqa ymm7, gs:[{U_YMM_OFFSET}+32*7]",
                "ldmxcsr gs:[{U_MXCSR_OFFSET}]",
                // Swap in userspace GS.
                "swapgs",
                // Enter usermdoe
                "iretq",
                "66:",
                // Save userspace registers.
                "mov gs:[{U_EAX_OFFSET}], eax",
                "mov gs:[{U_EBX_OFFSET}], ebx",
                "mov gs:[{U_ECX_OFFSET}], ecx",
                "mov gs:[{U_EDX_OFFSET}], edx",
                "mov gs:[{U_ESI_OFFSET}], esi",
                "mov gs:[{U_EDI_OFFSET}], edi",
                "mov gs:[{U_EBP_OFFSET}], ebp",
                "pop rax", // pop EIP
                "mov gs:[{U_EIP_OFFSET}], eax",
                "pop rax", // pop CS,
                "pop rax", // pop RFLAGS
                "mov gs:[{U_EFLAGS_OFFSET}], eax",
                "pop rax", // pop RSP
                "mov gs:[{U_ESP_OFFSET}], rax",
                "pop rax", // pop SS
                "vmovdqa gs:[{U_YMM_OFFSET}+32*0], ymm0",
                "vmovdqa gs:[{U_YMM_OFFSET}+32*1], ymm1",
                "vmovdqa gs:[{U_YMM_OFFSET}+32*2], ymm2",
                "vmovdqa gs:[{U_YMM_OFFSET}+32*3], ymm3",
                "vmovdqa gs:[{U_YMM_OFFSET}+32*4], ymm4",
                "vmovdqa gs:[{U_YMM_OFFSET}+32*5], ymm5",
                "vmovdqa gs:[{U_YMM_OFFSET}+32*6], ymm6",
                "vmovdqa gs:[{U_YMM_OFFSET}+32*7], ymm7",
                "stmxcsr gs:[{U_MXCSR_OFFSET}]",
                // Restore the kernel registers.
                "mov rax, gs:[{K_RAX_OFFSET}]",
                "mov rbx, gs:[{K_RBX_OFFSET}]",
                "mov rcx, gs:[{K_RCX_OFFSET}]",
                "mov rdx, gs:[{K_RDX_OFFSET}]",
                "mov rsi, gs:[{K_RSI_OFFSET}]",
                "mov rdi, gs:[{K_RDI_OFFSET}]",
                "mov rsp, gs:[{K_RSP_OFFSET}]",
                "mov rbp, gs:[{K_RBP_OFFSET}]",
                "mov r8, gs:[{K_R8_OFFSET}]",
                "mov r9, gs:[{K_R9_OFFSET}]",
                "mov r10, gs:[{K_R10_OFFSET}]",
                "mov r11, gs:[{K_R11_OFFSET}]",
                "mov r12, gs:[{K_R12_OFFSET}]",
                "mov r13, gs:[{K_R13_OFFSET}]",
                "mov r14, gs:[{K_R14_OFFSET}]",
                "mov r15, gs:[{K_R15_OFFSET}]",
                // Restore RFLAGS.
                "mov rax, gs:[{K_RFLAGS_OFFSET}]",
                "push rax",
                "popfq",
                INT0X80_HANDLER_OFFSET = const offset_of!(PerCpu, int0x80_handler),
                K_RAX_OFFSET = const kernel_reg_offset!(rax),
                K_RBX_OFFSET = const kernel_reg_offset!(rbx),
                K_RCX_OFFSET = const kernel_reg_offset!(rcx),
                K_RDX_OFFSET = const kernel_reg_offset!(rdx),
                K_RSI_OFFSET = const kernel_reg_offset!(rsi),
                K_RDI_OFFSET = const kernel_reg_offset!(rdi),
                K_RSP_OFFSET = const kernel_reg_offset!(rsp),
                K_RBP_OFFSET = const kernel_reg_offset!(rbp),
                K_R8_OFFSET = const kernel_reg_offset!(r8),
                K_R9_OFFSET = const kernel_reg_offset!(r9),
                K_R10_OFFSET = const kernel_reg_offset!(r10),
                K_R11_OFFSET = const kernel_reg_offset!(r11),
                K_R12_OFFSET = const kernel_reg_offset!(r12),
                K_R13_OFFSET = const kernel_reg_offset!(r13),
                K_R14_OFFSET = const kernel_reg_offset!(r14),
                K_R15_OFFSET = const kernel_reg_offset!(r15),
                K_RFLAGS_OFFSET = const kernel_reg_offset!(rflags),
                U_EAX_OFFSET = const userspace_reg_offset!(eax),
                U_EBX_OFFSET = const userspace_reg_offset!(ebx),
                U_ECX_OFFSET = const userspace_reg_offset!(ecx),
                U_EDX_OFFSET = const userspace_reg_offset!(edx),
                U_ESI_OFFSET = const userspace_reg_offset!(esi),
                U_EDI_OFFSET = const userspace_reg_offset!(edi),
                U_ESP_OFFSET = const userspace_reg_offset!(esp),
                U_EBP_OFFSET = const userspace_reg_offset!(ebp),
                U_EIP_OFFSET = const userspace_reg_offset!(eip),
                U_EFLAGS_OFFSET = const userspace_reg_offset!(eflags),
                U_YMM_OFFSET = const userspace_reg_offset!(ymm),
                U_MXCSR_OFFSET = const userspace_reg_offset!(mxcsr),
                out("rax") _,
                out("rdx") _,
                out("rcx") _,
                options(preserves_flags)
            );
        }

        // Restore the old GDT.
        unsafe {
            lgdt(&prev_pointer);
        }

        self.registers = per_cpu.userspace32_registers.get();

        Ok(())
    }

    pub fn syscall_args(&self) -> Result<SyscallArgs> {
        // eax	eax	ebx	ecx	edx	esi	edi	ebp
        let UserspaceRegisters {
            eax: no,
            ebx: arg0,
            ecx: arg1,
            edx: arg2,
            esi: arg3,
            edi: arg4,
            ebp: arg5,
            ..
        } = self.registers;
        Ok(SyscallArgs {
            abi: Abi::I386,
            no: u64::from(no),
            args: [
                u64::from(arg0),
                u64::from(arg1),
                u64::from(arg2),
                u64::from(arg3),
                u64::from(arg4),
                u64::from(arg5),
            ],
        })
    }

    pub fn set_result(&mut self, result: SyscallResult) -> Result<()> {
        let result = match result {
            Ok(result) => {
                let result = u32::try_from(result)?;
                let is_error = (-4095..=-1).contains(&(result as i64));
                if is_error {
                    return Err(Error::inval(()));
                }
                result
            }
            Err(err) => (-(err.kind() as i32)) as u32,
        };
        self.registers.eax = result;
        Ok(())
    }

    pub fn set_stack_pointer(&mut self, sp: u64) -> Result<()> {
        self.registers.esp = sp.try_into()?;
        Ok(())
    }

    pub fn set_tls(&mut self, tls: u64) -> Result<()> {
        self.registers.fs_base = tls;
        Ok(())
    }

    pub fn add_gd(&mut self, desc: u64) -> Result<u16> {
        self.gdt.push(desc);
        let num = u16::try_from(self.gdt.len() - 1)?;
        Ok(num)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct UserspaceRegisters {
    eax: u32,
    ebx: u32,
    ecx: u32,
    edx: u32,
    esi: u32,
    edi: u32,
    esp: u32,
    ebp: u32,
    eip: u32,
    eflags: u32,
    fs_base: u64,
    ymm: [Ymm; 8],
    mxcsr: u64,
}

impl UserspaceRegisters {
    pub const ZERO: Self = Self {
        eax: 0,
        ebx: 0,
        ecx: 0,
        edx: 0,
        esi: 0,
        edi: 0,
        esp: 0,
        ebp: 0,
        eip: 0,
        eflags: 0,
        fs_base: 0,
        ymm: [Ymm::ZERO; 8],
        mxcsr: 0,
    };

    const DEFAULT: Self = Self {
        mxcsr: 0x1f80,
        ..Self::ZERO
    };
}

#[derive(Debug, Clone, Copy)]
#[repr(C, align(32))]
struct Ymm([u8; 32]);

impl Ymm {
    pub const ZERO: Self = Self([0; 32]);
}
