use core::arch::asm;
use core::mem::offset_of;

use x86_64::{
    registers::segmentation::{Segment64, FS},
    VirtAddr,
};

use crate::{error::Error, per_cpu::PerCpu, user::process::syscall::traits::SyscallArgs};
use crate::{error::Result, user::process::syscall::traits::SyscallResult};

use super::super::super::thread::KernelRegisters;
use super::Abi;

#[derive(Clone)]
pub struct Amd64 {
    registers: UserspaceRegisters,
}

impl Amd64 {
    pub fn new(rip: u64, rsp: u64) -> Self {
        Self {
            registers: UserspaceRegisters {
                rip,
                rsp,
                ..UserspaceRegisters::DEFAULT
            },
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
                offset_of!(PerCpu, userspace64_registers) + offset_of!(UserspaceRegisters, $ident)
            }};
        }

        let per_cpu = PerCpu::get();
        per_cpu.userspace64_registers.set(self.registers);

        unsafe {
            FS::write_base(VirtAddr::new(self.registers.fs_base));
        }

        unsafe {
            asm!(
                // Set LSTAR
                "lea rax, [rip+66f]",
                "mov rdx, rax",
                "shr rdx, 32",
                "mov ecx, 0xC0000082",
                "wrmsr",
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
                // Restore userspace registers.
                "mov rax, gs:[{U_RAX_OFFSET}]",
                "mov rbx, gs:[{U_RBX_OFFSET}]",
                "mov rdx, gs:[{U_RDX_OFFSET}]",
                "mov rsi, gs:[{U_RSI_OFFSET}]",
                "mov rdi, gs:[{U_RDI_OFFSET}]",
                "mov rsp, gs:[{U_RSP_OFFSET}]",
                "mov rbp, gs:[{U_RBP_OFFSET}]",
                "mov r8, gs:[{U_R8_OFFSET}]",
                "mov r9, gs:[{U_R9_OFFSET}]",
                "mov r10, gs:[{U_R10_OFFSET}]",
                "mov r12, gs:[{U_R12_OFFSET}]",
                "mov r13, gs:[{U_R13_OFFSET}]",
                "mov r14, gs:[{U_R14_OFFSET}]",
                "mov r15, gs:[{U_R15_OFFSET}]",
                "mov rcx, gs:[{U_RIP_OFFSET}]",
                "mov r11, gs:[{U_RFLAGS_OFFSET}]",
                "vmovdqa ymm0, gs:[{U_YMM_OFFSET}+32*0]",
                "vmovdqa ymm1, gs:[{U_YMM_OFFSET}+32*1]",
                "vmovdqa ymm2, gs:[{U_YMM_OFFSET}+32*2]",
                "vmovdqa ymm3, gs:[{U_YMM_OFFSET}+32*3]",
                "vmovdqa ymm4, gs:[{U_YMM_OFFSET}+32*4]",
                "vmovdqa ymm5, gs:[{U_YMM_OFFSET}+32*5]",
                "vmovdqa ymm6, gs:[{U_YMM_OFFSET}+32*6]",
                "vmovdqa ymm7, gs:[{U_YMM_OFFSET}+32*7]",
                "vmovdqa ymm8, gs:[{U_YMM_OFFSET}+32*8]",
                "vmovdqa ymm9, gs:[{U_YMM_OFFSET}+32*9]",
                "vmovdqa ymm10, gs:[{U_YMM_OFFSET}+32*10]",
                "vmovdqa ymm11, gs:[{U_YMM_OFFSET}+32*11]",
                "vmovdqa ymm12, gs:[{U_YMM_OFFSET}+32*12]",
                "vmovdqa ymm13, gs:[{U_YMM_OFFSET}+32*13]",
                "vmovdqa ymm14, gs:[{U_YMM_OFFSET}+32*14]",
                "vmovdqa ymm15, gs:[{U_YMM_OFFSET}+32*15]",
                "ldmxcsr gs:[{U_MXCSR_OFFSET}]",
                // Swap in userspace GS.
                "swapgs",
                // Enter usermode
                "sysretq",
                "66:",
                // Swap in kernel GS.
                "swapgs",
                // Save userspace registers.
                "mov gs:[{U_RAX_OFFSET}], rax",
                "mov gs:[{U_RBX_OFFSET}], rbx",
                "mov gs:[{U_RDX_OFFSET}], rdx",
                "mov gs:[{U_RSI_OFFSET}], rsi",
                "mov gs:[{U_RDI_OFFSET}], rdi",
                "mov gs:[{U_RSP_OFFSET}], rsp",
                "mov gs:[{U_RBP_OFFSET}], rbp",
                "mov gs:[{U_R8_OFFSET}], r8",
                "mov gs:[{U_R9_OFFSET}], r9",
                "mov gs:[{U_R10_OFFSET}], r10",
                "mov gs:[{U_R12_OFFSET}], r12",
                "mov gs:[{U_R13_OFFSET}], r13",
                "mov gs:[{U_R14_OFFSET}], r14",
                "mov gs:[{U_R15_OFFSET}], r15",
                "mov gs:[{U_RIP_OFFSET}], rcx",
                "mov gs:[{U_RFLAGS_OFFSET}], r11",
                "vmovdqa gs:[{U_YMM_OFFSET}+32*0], ymm0",
                "vmovdqa gs:[{U_YMM_OFFSET}+32*1], ymm1",
                "vmovdqa gs:[{U_YMM_OFFSET}+32*2], ymm2",
                "vmovdqa gs:[{U_YMM_OFFSET}+32*3], ymm3",
                "vmovdqa gs:[{U_YMM_OFFSET}+32*4], ymm4",
                "vmovdqa gs:[{U_YMM_OFFSET}+32*5], ymm5",
                "vmovdqa gs:[{U_YMM_OFFSET}+32*6], ymm6",
                "vmovdqa gs:[{U_YMM_OFFSET}+32*7], ymm7",
                "vmovdqa gs:[{U_YMM_OFFSET}+32*8], ymm8",
                "vmovdqa gs:[{U_YMM_OFFSET}+32*9], ymm9",
                "vmovdqa gs:[{U_YMM_OFFSET}+32*10], ymm10",
                "vmovdqa gs:[{U_YMM_OFFSET}+32*11], ymm11",
                "vmovdqa gs:[{U_YMM_OFFSET}+32*12], ymm12",
                "vmovdqa gs:[{U_YMM_OFFSET}+32*13], ymm13",
                "vmovdqa gs:[{U_YMM_OFFSET}+32*14], ymm14",
                "vmovdqa gs:[{U_YMM_OFFSET}+32*15], ymm15",
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
                U_RAX_OFFSET = const userspace_reg_offset!(rax),
                U_RBX_OFFSET = const userspace_reg_offset!(rbx),
                U_RDX_OFFSET = const userspace_reg_offset!(rdx),
                U_RSI_OFFSET = const userspace_reg_offset!(rsi),
                U_RDI_OFFSET = const userspace_reg_offset!(rdi),
                U_RSP_OFFSET = const userspace_reg_offset!(rsp),
                U_RBP_OFFSET = const userspace_reg_offset!(rbp),
                U_R8_OFFSET = const userspace_reg_offset!(r8),
                U_R9_OFFSET = const userspace_reg_offset!(r9),
                U_R10_OFFSET = const userspace_reg_offset!(r10),
                U_R12_OFFSET = const userspace_reg_offset!(r12),
                U_R13_OFFSET = const userspace_reg_offset!(r13),
                U_R14_OFFSET = const userspace_reg_offset!(r14),
                U_R15_OFFSET = const userspace_reg_offset!(r15),
                U_RIP_OFFSET = const userspace_reg_offset!(rip),
                U_RFLAGS_OFFSET = const userspace_reg_offset!(rflags),
                U_YMM_OFFSET = const userspace_reg_offset!(ymm),
                U_MXCSR_OFFSET = const userspace_reg_offset!(mxcsr),
                out("rax") _,
                out("rdx") _,
                out("rcx") _,
                options(preserves_flags)
            );
        }

        self.registers = per_cpu.userspace64_registers.get();

        Ok(())
    }

    pub fn syscall_args(&self) -> Result<SyscallArgs> {
        let UserspaceRegisters {
            rax: no,
            rdi: arg0,
            rsi: arg1,
            rdx: arg2,
            r10: arg3,
            r8: arg4,
            r9: arg5,
            ..
        } = self.registers;
        Ok(SyscallArgs {
            abi: Abi::Amd64,
            no,
            args: [arg0, arg1, arg2, arg3, arg4, arg5],
        })
    }

    pub fn set_result(&mut self, result: SyscallResult) -> Result<()> {
        let result = match result {
            Ok(result) => {
                let is_error = (-4095..=-1).contains(&(result as i64));
                if is_error {
                    return Err(Error::inval(()));
                }
                result
            }
            Err(err) => (-(err.kind() as i64)) as u64,
        };
        self.registers.rax = result;
        Ok(())
    }

    pub fn set_stack_pointer(&mut self, sp: u64) -> Result<()> {
        self.registers.rsp = sp;
        Ok(())
    }

    pub fn set_tls(&mut self, tls: u64) -> Result<()> {
        self.registers.fs_base = tls;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct UserspaceRegisters {
    rax: u64,
    rbx: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
    rsp: u64,
    rbp: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    rip: u64,
    rflags: u64,
    fs_base: u64,
    ymm: [Ymm; 16],
    mxcsr: u64,
}

impl UserspaceRegisters {
    pub const ZERO: Self = Self {
        rax: 0,
        rbx: 0,
        rdx: 0,
        rsi: 0,
        rdi: 0,
        rsp: 0,
        rbp: 0,
        r8: 0,
        r9: 0,
        r10: 0,
        r12: 0,
        r13: 0,
        r14: 0,
        r15: 0,
        rip: 0,
        rflags: 0,
        fs_base: 0,
        ymm: [Ymm::ZERO; 16],
        mxcsr: 0,
    };

    const DEFAULT: Self = Self {
        rax: 0,
        rbx: 0,
        rdx: 0,
        rsi: 0,
        rdi: 0,
        rsp: 0,
        rbp: 0,
        r8: 0,
        r9: 0,
        r10: 0,
        r12: 0,
        r13: 0,
        r14: 0,
        r15: 0,
        rip: 0,
        rflags: 0,
        fs_base: 0,
        ymm: [Ymm::ZERO; 16],
        mxcsr: 0x1f80,
    };
}

#[derive(Debug, Clone, Copy)]
#[repr(C, align(32))]
struct Ymm([u8; 32]);

impl Ymm {
    pub const ZERO: Self = Self([0; 32]);
}
