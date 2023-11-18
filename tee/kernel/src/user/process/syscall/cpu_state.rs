use core::arch::{asm, x86_64::__cpuid_count};

use alloc::{vec, vec::Vec};
use bit_field::BitField;
use x86_64::registers::xcontrol::XCr0Flags;

use crate::{
    error::{Error, Result},
    spin::lazy::Lazy,
};

use super::traits::{SyscallArgs, SyscallResult};

pub mod amd64;
pub mod i386;

#[derive(Clone)]
#[allow(clippy::large_enum_variant)]
pub enum CpuState {
    None,
    I386(i386::I386),
    Amd64(amd64::Amd64),
}

impl CpuState {
    pub unsafe fn run_userspace(&mut self) -> Result<()> {
        match self {
            CpuState::None => Err(Error::no_sys(())),
            CpuState::I386(i386) => unsafe { i386.run_userspace() },
            CpuState::Amd64(amd64) => unsafe { amd64.run_userspace() },
        }
    }

    pub fn syscall_args(&self) -> Result<SyscallArgs> {
        match self {
            CpuState::None => Err(Error::no_sys(())),
            CpuState::I386(i386) => i386.syscall_args(),
            CpuState::Amd64(amd64) => amd64.syscall_args(),
        }
    }

    pub fn set_syscall_result(&mut self, result: SyscallResult) -> Result<()> {
        match self {
            CpuState::None => Err(Error::no_sys(())),
            CpuState::I386(i386) => i386.set_result(result),
            CpuState::Amd64(amd64) => amd64.set_result(result),
        }
    }

    pub fn set_stack_pointer(&mut self, sp: u64) -> Result<()> {
        match self {
            CpuState::None => Err(Error::no_sys(())),
            CpuState::I386(i386) => i386.set_stack_pointer(sp),
            CpuState::Amd64(amd64) => amd64.set_stack_pointer(sp),
        }
    }

    pub fn set_tls(&mut self, tls: u64) -> Result<()> {
        match self {
            CpuState::None => Err(Error::no_sys(())),
            CpuState::I386(i386) => i386.set_tls(tls),
            CpuState::Amd64(amd64) => amd64.set_tls(tls),
        }
    }

    pub fn add_gd(&mut self, desc: u64) -> Result<u16> {
        match self {
            CpuState::None => Err(Error::no_sys(())),
            CpuState::I386(i386) => i386.add_gd(desc),
            CpuState::Amd64(_) => Err(Error::no_sys(())),
        }
    }
}

/// The ABI used during a syscall.
// FIXME: This shouldn't be fixed depending on the cpu states. amd64 can also
// issue i386 syscalls through int 0x80 (though this is rarely used).
#[derive(Debug, Clone, Copy)]
pub enum Abi {
    I386,
    Amd64,
}

#[derive(Clone)]
struct XSaveArea {
    data: Vec<u8>,
}

impl XSaveArea {
    pub fn new() -> Self {
        static SIZE: Lazy<usize> = Lazy::new(|| {
            let res = unsafe { __cpuid_count(0xd, 0x0) };
            res.ecx as usize
        });

        let mut data = vec![0; *SIZE];
        data[0..2].copy_from_slice(&0x37fu16.to_ne_bytes()); // FCW
        data[5] = 0xff; // FTW
        data[24..28].copy_from_slice(&0x1f80u32.to_ne_bytes()); // MXCSR

        Self { data }
    }

    fn save(&mut self) {
        let flags = XCr0Flags::X87 | XCr0Flags::SSE | XCr0Flags::AVX;
        let bits = flags.bits();
        let lower = bits.get_bits(..32);
        let upper = bits.get_bits(32..);

        unsafe {
            asm!(
                "xsave64 [{xsave_area}]",
                xsave_area = in(reg) self.data.as_mut_ptr(),
                in("rax") lower,
                in("rdx") upper,
            );
        }
    }

    fn load(&self) {
        let flags = XCr0Flags::X87 | XCr0Flags::SSE | XCr0Flags::AVX;
        let bits = flags.bits();
        let lower = bits.get_bits(..32);
        let upper = bits.get_bits(32..);

        unsafe {
            asm!(
                "xrstor64 [{xsave_area}]",
                xsave_area = in(reg) self.data.as_ptr(),
                in("rax") lower,
                in("rdx") upper,
            );
        }
    }
}
