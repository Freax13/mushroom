use core::{cmp, ptr::NonNull};

use alloc::vec::Vec;
use usize_conversions::{FromUsize, IntoUsize, usize_from};
use x86_64::VirtAddr;

use crate::{
    error::Result,
    user::process::{
        memory::VirtualMemory,
        syscall::{
            args::{Iovec, Pointer},
            traits::Abi,
        },
    },
};

pub trait ReadBuf {
    fn buffer_len(&self) -> usize;
    fn write(&mut self, offset: usize, bytes: &[u8]) -> Result<()>;
    unsafe fn write_volatile(&mut self, offset: usize, bytes: NonNull<[u8]>) -> Result<()>;
    fn fill(&mut self, offset: usize, len: usize, byte: u8) -> Result<()>;
    fn fill_all(&mut self, byte: u8) -> Result<()>;
}

pub trait WriteBuf {
    fn buffer_len(&self) -> usize;
    fn read(&self, offset: usize, bytes: &mut [u8]) -> Result<()>;
    unsafe fn read_volatile(&self, offset: usize, bytes: NonNull<[u8]>) -> Result<()>;
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

    fn fill(&mut self, offset: usize, len: usize, byte: u8) -> Result<()> {
        self.0[offset..][..len].fill(byte);
        Ok(())
    }

    fn fill_all(&mut self, byte: u8) -> Result<()> {
        self.0.fill(byte);
        Ok(())
    }
}

pub struct KernelWriteBuf<'a>(&'a [u8]);

impl<'a> KernelWriteBuf<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self(buf)
    }
}

impl WriteBuf for KernelWriteBuf<'_> {
    fn buffer_len(&self) -> usize {
        self.0.len()
    }

    fn read(&self, offset: usize, bytes: &mut [u8]) -> Result<()> {
        bytes.copy_from_slice(&self.0[offset..][..bytes.len()]);
        Ok(())
    }

    unsafe fn read_volatile(&self, offset: usize, bytes: NonNull<[u8]>) -> Result<()> {
        assert!(self.0.len() >= offset + bytes.len());
        unsafe {
            core::intrinsics::copy_nonoverlapping(
                self.0.as_ptr().byte_add(offset),
                bytes.as_mut_ptr().cast(),
                bytes.len(),
            )
        };
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

    fn fill(&mut self, offset: usize, len: usize, byte: u8) -> Result<()> {
        assert!(self.len >= offset + len);
        self.vm
            .set_bytes(self.pointer.bytes_offset(offset).get(), len, byte)?;
        Ok(())
    }

    fn fill_all(&mut self, byte: u8) -> Result<()> {
        self.vm.set_bytes(self.pointer.get(), self.len, byte)?;
        Ok(())
    }
}

impl WriteBuf for UserBuf<'_> {
    fn buffer_len(&self) -> usize {
        self.len
    }

    fn read(&self, offset: usize, bytes: &mut [u8]) -> Result<()> {
        assert!(self.len >= offset + bytes.len());
        self.vm
            .read_bytes(self.pointer.bytes_offset(offset).get(), bytes)
    }

    unsafe fn read_volatile(&self, offset: usize, bytes: NonNull<[u8]>) -> Result<()> {
        assert!(self.len >= offset + bytes.len());
        let addr = self.pointer.bytes_offset(offset).get();
        unsafe { self.vm.read_bytes_volatile(addr, bytes) }
    }
}

pub struct VectoredUserBuf<'a> {
    vm: &'a VirtualMemory,
    iovec: Vec<Iovec>,
}

impl<'a> VectoredUserBuf<'a> {
    pub fn new(
        vm: &'a VirtualMemory,
        iov: Pointer<Iovec>,
        iovlen: impl IntoUsize,
        abi: Abi,
    ) -> Result<Self> {
        Self::with_remote_virtual_memory(vm, iov, iovlen, abi, vm)
    }

    pub fn with_remote_virtual_memory(
        vm: &VirtualMemory,
        mut iov: Pointer<Iovec>,
        iovlen: impl IntoUsize,
        abi: Abi,
        remote: &'a VirtualMemory,
    ) -> Result<Self> {
        let mut vectored_buf = Self {
            vm: remote,
            iovec: Vec::new(),
        };
        for _ in 0..iovlen.into_usize() {
            let (size, value) = vm.read_sized_with_abi(iov, abi)?;
            vectored_buf.push(value);
            iov = iov.bytes_offset(size);
        }
        Ok(vectored_buf)
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

    fn fill(&mut self, mut offset: usize, mut len: usize, byte: u8) -> Result<()> {
        for iv in self.iovec.iter_mut() {
            let iv_len = usize_from(iv.len);
            if let Some(chunk_len) = iv_len.checked_sub(offset).filter(|&len| len > 0) {
                let chunk_len = cmp::max(chunk_len, len);
                self.vm.set_bytes(
                    VirtAddr::new(iv.base + u64::from_usize(offset)),
                    chunk_len,
                    byte,
                )?;
                offset = 0;
                len -= chunk_len;
                if len == 0 {
                    break;
                }
            } else {
                offset -= iv_len;
            }
        }
        assert_eq!(len, 0);
        Ok(())
    }

    fn fill_all(&mut self, byte: u8) -> Result<()> {
        for iv in self.iovec.iter_mut() {
            self.vm
                .set_bytes(VirtAddr::new(iv.base), usize_from(iv.len), byte)?;
        }
        Ok(())
    }
}

impl WriteBuf for VectoredUserBuf<'_> {
    fn buffer_len(&self) -> usize {
        self.iovec.iter().map(|iv| usize_from(iv.len)).sum()
    }

    fn read(&self, mut offset: usize, mut bytes: &mut [u8]) -> Result<()> {
        for iv in self.iovec.iter() {
            if let Some(new_offset) = offset.checked_sub(usize_from(iv.len)) {
                offset = new_offset;
                continue;
            }

            let chunk_len = cmp::min(usize_from(iv.len) - offset, bytes.len());
            let chunk;
            (chunk, bytes) = bytes.split_at_mut(chunk_len);
            self.vm
                .read_bytes(VirtAddr::new(iv.base + u64::from_usize(offset)), chunk)?;
            offset = 0;
            if bytes.is_empty() {
                return Ok(());
            }
        }
        if offset == 0 && bytes.is_empty() {
            return Ok(());
        }
        unreachable!("read too many bytes from buffer")
    }

    unsafe fn read_volatile(&self, mut offset: usize, mut bytes: NonNull<[u8]>) -> Result<()> {
        for iv in self.iovec.iter() {
            if let Some(new_offset) = offset.checked_sub(usize_from(iv.len)) {
                offset = new_offset;
                continue;
            }

            let chunk_len = cmp::min(usize_from(iv.len) - offset, bytes.len());
            let chunk = NonNull::from_raw_parts(bytes.cast::<u8>(), chunk_len);
            let addr = VirtAddr::new(iv.base + u64::from_usize(offset));
            unsafe {
                self.vm.read_bytes_volatile(addr, chunk)?;
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
        unreachable!("read too many bytes from buffer")
    }
}

pub struct OffsetBuf<'a, B> {
    buffer: &'a B,
    offset: usize,
}

impl<'a, B> OffsetBuf<'a, B> {
    pub fn new(buffer: &'a B, offset: usize) -> Self {
        Self { buffer, offset }
    }
}

impl<B> WriteBuf for OffsetBuf<'_, B>
where
    B: WriteBuf,
{
    fn buffer_len(&self) -> usize {
        self.buffer.buffer_len() - self.offset
    }

    fn read(&self, offset: usize, bytes: &mut [u8]) -> Result<()> {
        self.buffer.read(offset + self.offset, bytes)
    }

    unsafe fn read_volatile(&self, offset: usize, bytes: NonNull<[u8]>) -> Result<()> {
        unsafe { self.buffer.read_volatile(offset + self.offset, bytes) }
    }
}
