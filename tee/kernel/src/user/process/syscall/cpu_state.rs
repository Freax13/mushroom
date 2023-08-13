use crate::error::{Error, Result};

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
}

/// The ABI used during a syscall.
// FIXME: This shouldn't be fixed depending on the cpu states. amd64 can also
// issue i386 syscalls through int 0x80 (though this is rarely used).
#[derive(Debug, Clone, Copy)]
pub enum Abi {
    I386,
    Amd64,
}
