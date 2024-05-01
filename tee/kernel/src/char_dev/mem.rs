use core::iter::from_fn;

use kernel_macros::register;
use usize_conversions::FromUsize;
use x86_64::instructions::random::RdRand;

use crate::{
    error::{bail, Result},
    fs::fd::{Events, OpenFileDescription},
    memory::page::KernelPage,
    spin::lazy::Lazy,
    user::process::{
        memory::VirtualMemory,
        syscall::args::{OpenFlags, Pointer, Stat},
    },
};

use super::CharDev;

const MAJOR: u16 = 1;

pub struct Null {
    flags: OpenFlags,
    stat: Stat,
}

#[register]
impl CharDev for Null {
    const MAJOR: u16 = MAJOR;
    const MINOR: u8 = 3;

    fn new(flags: OpenFlags, stat: Stat) -> Result<Self> {
        Ok(Self { flags, stat })
    }
}

impl OpenFileDescription for Null {
    fn flags(&self) -> OpenFlags {
        self.flags
    }

    fn stat(&self) -> Result<Stat> {
        Ok(self.stat)
    }

    fn poll_ready(&self, events: Events) -> Events {
        events & (Events::READ | Events::WRITE)
    }

    fn read(&self, _buf: &mut [u8]) -> Result<usize> {
        Ok(0)
    }

    fn read_to_user(
        &self,
        _vm: &VirtualMemory,
        _pointer: Pointer<[u8]>,
        _len: usize,
    ) -> Result<usize> {
        Ok(0)
    }

    fn pread(&self, _pos: usize, _buf: &mut [u8]) -> Result<usize> {
        Ok(0)
    }

    fn write(&self, buf: &[u8]) -> Result<usize> {
        Ok(buf.len())
    }

    fn write_from_user(
        &self,
        _vm: &VirtualMemory,
        _pointer: Pointer<[u8]>,
        len: usize,
    ) -> crate::error::Result<usize> {
        Ok(len)
    }

    fn pwrite(&self, _pos: usize, buf: &[u8]) -> Result<usize> {
        Ok(buf.len())
    }

    fn truncate(&self, _length: usize) -> Result<()> {
        Ok(())
    }

    fn get_page(&self, _page_idx: usize) -> Result<KernelPage> {
        bail!(NoDev)
    }
}

pub fn random_bytes() -> impl Iterator<Item = u8> {
    static RD_RAND: Lazy<RdRand> = Lazy::new(|| RdRand::new().unwrap());
    from_fn(|| RD_RAND.get_u64()).flat_map(u64::to_ne_bytes)
}

pub struct Random {
    flags: OpenFlags,
    stat: Stat,
}

#[register]
impl CharDev for Random {
    const MAJOR: u16 = MAJOR;
    const MINOR: u8 = 8;

    fn new(flags: OpenFlags, stat: Stat) -> Result<Self> {
        Ok(Self { flags, stat })
    }
}

impl OpenFileDescription for Random {
    fn flags(&self) -> OpenFlags {
        self.flags
    }

    fn stat(&self) -> Result<Stat> {
        Ok(self.stat)
    }

    fn poll_ready(&self, events: Events) -> Events {
        events & (Events::READ | Events::WRITE)
    }

    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        let mut len = 0;
        for (buf, random) in buf.iter_mut().zip(random_bytes()) {
            *buf = random;
            len += 1;
        }
        Ok(len)
    }

    fn read_to_user(
        &self,
        vm: &VirtualMemory,
        pointer: Pointer<[u8]>,
        len: usize,
    ) -> Result<usize> {
        for (offset, b) in (0..len).zip(random_bytes()) {
            vm.write_bytes(pointer.get() + u64::from_usize(offset), &[b])?;
        }
        Ok(len)
    }

    fn write(&self, buf: &[u8]) -> Result<usize> {
        Ok(buf.len())
    }

    fn write_from_user(
        &self,
        _vm: &VirtualMemory,
        _pointer: Pointer<[u8]>,
        len: usize,
    ) -> crate::error::Result<usize> {
        Ok(len)
    }

    fn truncate(&self, _length: usize) -> Result<()> {
        Ok(())
    }

    fn get_page(&self, _page_idx: usize) -> Result<KernelPage> {
        bail!(NoDev)
    }
}

pub struct URandom {
    flags: OpenFlags,
    stat: Stat,
}

#[register]
impl CharDev for URandom {
    const MAJOR: u16 = MAJOR;
    const MINOR: u8 = 9;

    fn new(flags: OpenFlags, stat: Stat) -> Result<Self> {
        Ok(Self { flags, stat })
    }
}

impl OpenFileDescription for URandom {
    fn flags(&self) -> OpenFlags {
        self.flags
    }

    fn stat(&self) -> Result<Stat> {
        Ok(self.stat)
    }

    fn poll_ready(&self, events: Events) -> Events {
        events & (Events::READ | Events::WRITE)
    }

    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        let mut len = 0;
        for (buf, random) in buf.iter_mut().zip(random_bytes()) {
            *buf = random;
            len += 1;
        }
        Ok(len)
    }

    fn read_to_user(
        &self,
        vm: &VirtualMemory,
        pointer: Pointer<[u8]>,
        len: usize,
    ) -> Result<usize> {
        for (offset, b) in (0..len).zip(random_bytes()) {
            vm.write_bytes(pointer.get() + u64::from_usize(offset), &[b])?;
        }
        Ok(len)
    }

    fn write(&self, buf: &[u8]) -> Result<usize> {
        Ok(buf.len())
    }

    fn write_from_user(
        &self,
        _vm: &VirtualMemory,
        _pointer: Pointer<[u8]>,
        len: usize,
    ) -> crate::error::Result<usize> {
        Ok(len)
    }

    fn truncate(&self, _length: usize) -> Result<()> {
        Ok(())
    }

    fn get_page(&self, _page_idx: usize) -> Result<KernelPage> {
        bail!(NoDev)
    }
}
