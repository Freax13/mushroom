use core::{cmp, ptr::NonNull};

use alloc::vec::Vec;
use usize_conversions::{FromUsize, usize_from};
use x86_64::VirtAddr;

use crate::{
    error::Result,
    user::process::{
        memory::VirtualMemory,
        syscall::args::{Iovec, Pointer},
    },
};

pub trait ReadBuf {
    fn buffer_len(&self) -> usize;
    fn write(&mut self, offset: usize, bytes: &[u8]) -> Result<()>;
    unsafe fn write_volatile(&mut self, offset: usize, bytes: NonNull<[u8]>) -> Result<()>;
    fn fill(&mut self, byte: u8) -> Result<()>;
}

pub struct KernelReadBuf<'a>(&'a mut [u8]);

impl<'a> KernelReadBuf<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self(buf)
    }
}

impl ReadBuf for KernelReadBuf<'_> {
    fn buffer_len(&self) -> usize {
        self.0.len()
    }

    fn write(&mut self, offset: usize, bytes: &[u8]) -> Result<()> {
        self.0[offset..][..bytes.len()].copy_from_slice(bytes);
        Ok(())
    }

    unsafe fn write_volatile(&mut self, offset: usize, bytes: NonNull<[u8]>) -> Result<()> {
        assert!(self.0.len() >= offset + bytes.len());
        unsafe {
            core::intrinsics::copy_nonoverlapping(
                bytes.as_ptr().cast(),
                self.0.as_mut_ptr().byte_add(offset),
                bytes.len(),
            )
        };
        Ok(())
    }

    fn fill(&mut self, byte: u8) -> Result<()> {
        self.0.fill(byte);
        Ok(())
    }
}

pub struct UserBuf<'a> {
    vm: &'a VirtualMemory,
    pointer: Pointer<[u8]>,
    len: usize,
}

impl<'a> UserBuf<'a> {
    pub fn new(vm: &'a VirtualMemory, pointer: Pointer<[u8]>, len: usize) -> Self {
        Self { vm, pointer, len }
    }
}

impl ReadBuf for UserBuf<'_> {
    fn buffer_len(&self) -> usize {
        self.len
    }

    fn write(&mut self, offset: usize, bytes: &[u8]) -> Result<()> {
        assert!(self.len >= offset + bytes.len());
        self.vm
            .write_bytes(self.pointer.bytes_offset(offset).get(), bytes)
    }

    unsafe fn write_volatile(&mut self, offset: usize, bytes: NonNull<[u8]>) -> Result<()> {
        assert!(self.len >= offset + bytes.len());
        let addr = self.pointer.bytes_offset(offset).get();
        unsafe { self.vm.write_bytes_volatile(addr, bytes) }
    }

    fn fill(&mut self, byte: u8) -> Result<()> {
        for i in 0..self.len {
            self.vm
                .write_bytes(self.pointer.bytes_offset(i).get(), &[byte])?;
        }
        Ok(())
    }
}

pub struct VectoredUserBuf<'a> {
    vm: &'a VirtualMemory,
    iovec: Vec<Iovec>,
}

impl<'a> VectoredUserBuf<'a> {
    pub fn new(vm: &'a VirtualMemory) -> Self {
        Self {
            vm,
            iovec: Vec::new(),
        }
    }

    pub fn push(&mut self, buf: Iovec) {
        self.iovec.push(buf);
    }
}

impl ReadBuf for VectoredUserBuf<'_> {
    fn buffer_len(&self) -> usize {
        self.iovec.iter().map(|iv| usize_from(iv.len)).sum()
    }

    fn write(&mut self, mut offset: usize, mut bytes: &[u8]) -> Result<()> {
        for iv in self.iovec.iter() {
            if let Some(new_offset) = offset.checked_sub(usize_from(iv.len)) {
                offset = new_offset;
                continue;
            }

            let chunk_len = cmp::min(usize_from(iv.len) - offset, bytes.len());
            let chunk;
            (chunk, bytes) = bytes.split_at(chunk_len);
            self.vm
                .write_bytes(VirtAddr::new(iv.base + u64::from_usize(offset)), chunk)?;
            offset = 0;
            if bytes.is_empty() {
                return Ok(());
            }
        }
        if offset == 0 && bytes.is_empty() {
            return Ok(());
        }
        unreachable!("wrote too many bytes to buffer")
    }

    unsafe fn write_volatile(&mut self, mut offset: usize, mut bytes: NonNull<[u8]>) -> Result<()> {
        for iv in self.iovec.iter() {
            if let Some(new_offset) = offset.checked_sub(usize_from(iv.len)) {
                offset = new_offset;
                continue;
            }

            let chunk_len = cmp::min(usize_from(iv.len) - offset, bytes.len());
            let chunk = NonNull::from_raw_parts(bytes.cast::<u8>(), chunk_len);
            let addr = VirtAddr::new(iv.base + u64::from_usize(offset));
            unsafe {
                self.vm.write_bytes_volatile(addr, chunk)?;
            }
            bytes = NonNull::from_raw_parts(
                unsafe { bytes.cast::<u8>().add(chunk_len) },
                bytes.len() - chunk_len,
            );
            offset = 0;
            if bytes.is_empty() {
                return Ok(());
            }
        }
        if offset == 0 && bytes.is_empty() {
            return Ok(());
        }
        unreachable!("wrote too many bytes to buffer")
    }

    fn fill(&mut self, byte: u8) -> Result<()> {
        for iv in self.iovec.iter_mut() {
            for i in 0..iv.len {
                self.vm.write(Pointer::new(iv.base + i), byte)?;
            }
        }
        Ok(())
    }
}
