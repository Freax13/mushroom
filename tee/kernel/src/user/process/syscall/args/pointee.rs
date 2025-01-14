//! This module contains various traits for userspace pointers.

use core::{
    ffi::{c_void, CStr},
    fmt,
    marker::PhantomData,
    mem::{size_of, MaybeUninit},
};

use alloc::ffi::CString;
use bytemuck::{
    bytes_of, bytes_of_mut, cast, checked::try_pod_read_unaligned, CheckedBitPattern, NoUninit,
    Pod, Zeroable,
};
use usize_conversions::{usize_from, FromUsize};
use x86_64::VirtAddr;

use crate::{
    error::{ensure, Error, Result},
    fs::{
        node::{DirEntry, OldDirEntry},
        path::{Path, PATH_MAX},
        StatFs,
    },
    user::process::{
        memory::VirtualMemory,
        syscall::traits::Abi,
        thread::{
            Gid, SigContext, SigFields, SigInfo, Sigaction, SigactionFlags, Sigset, Stack,
            StackFlags, ThreadGuard, UContext, Uid,
        },
    },
};

use super::{
    FdNum, Iovec, LinuxDirent64, LongOffset, Offset, PSelectSigsetArg, Pointer, RLimit, Rusage,
    SocketAddr, Stat, SysInfo, Time, Timespec, Timeval, WStatus,
};

/// This trait is implemented by types for which userspace pointers can exist.
pub trait Pointee {
    /// Format a userspace pointer for syscall logs.
    fn display(f: &mut dyn fmt::Write, addr: VirtAddr, thread: &ThreadGuard) -> fmt::Result {
        let _ = thread;
        write!(f, "{:#x}", addr.as_u64())
    }
}

/// A pointee which can be read from userspace.
///
/// The extra generic parameter `T` only exists to allow multiple blankets
/// implementations to exist.
pub trait ReadablePointee<T = Custom>: Pointee + Sized {
    fn read(addr: VirtAddr, vm: &VirtualMemory, abi: Abi) -> Result<(usize, Self)>;
}

/// A pointee which can be written to userspace.
///
/// The extra generic parameter `T` only exists to allow multiple blankets
/// implementations to exist.
pub trait WritablePointee<T = Custom>: Pointee {
    fn write(&self, addr: VirtAddr, vm: &VirtualMemory, abi: Abi) -> Result<usize>;
}

pub trait SizedPointee<T = Custom>: Pointee {
    fn size(&self, abi: Abi) -> usize;
}

/// A marker type used for the custom impls of `Pointee` traits.
pub struct Custom;

/// A primitive pointee.
///
/// Primitive pointees always have the same size and layout on all abi.
///
/// Primitive pointees can be read if they implement `CheckedBitPattern` and
/// can be written if the implement `NoUninit`.
pub trait PrimitivePointee: Pointee {}

/// A marker type used for the blanket impls of `PrimitivePointee`s.
pub enum Primitive {}

impl<T> ReadablePointee<Primitive> for T
where
    T: PrimitivePointee + CheckedBitPattern,
    [(); size_of::<T>()]: Sized,
{
    fn read(addr: VirtAddr, vm: &VirtualMemory, _: Abi) -> Result<(usize, Self)> {
        let mut bytes = [0; size_of::<T>()];
        vm.read_bytes(addr, &mut bytes)?;
        let value = try_pod_read_unaligned::<T>(&bytes)?;
        Ok((bytes.len(), value))
    }
}

impl<T> WritablePointee<Primitive> for T
where
    T: PrimitivePointee + NoUninit,
{
    fn write(&self, addr: VirtAddr, vm: &VirtualMemory, _: Abi) -> Result<usize> {
        vm.write_bytes(addr, bytes_of(self))?;
        Ok(size_of::<Self>())
    }
}

impl<T> SizedPointee<Primitive> for T
where
    T: PrimitivePointee,
{
    fn size(&self, _: Abi) -> usize {
        size_of::<T>()
    }
}

/// An ABI dependent pointee.
///
/// ABI dependent pointees can have a different size and layout dependent on
/// the ABI.
///
/// ABI dependent pointees can be read if they be implement `TryFrom` for their
/// variants and those variants implement `CheckedBitPattern`. They can be
/// written if they implement `TryInto` for their variants and those variants
/// implement `NoUninit`.
pub trait AbiDependentPointee: Pointee {
    /// Variant of the pointee that is used for the i386 ABI.
    type I386;
    /// Variant of the pointee that is used for the Amd64 ABI.
    type Amd64;
}

/// A marker type used for the blanket impls of `AbiDependentPointee`s.
pub enum ArchitectureDependent {}

impl<T> ReadablePointee<ArchitectureDependent> for T
where
    T: AbiDependentPointee,
    T::I386: CheckedBitPattern + TryInto<Self>,
    <T::I386 as CheckedBitPattern>::Bits: NoUninit,
    T::Amd64: CheckedBitPattern + TryInto<Self>,
    <T::Amd64 as CheckedBitPattern>::Bits: NoUninit,
    Error: From<<T::I386 as TryInto<Self>>::Error> + From<<T::Amd64 as TryInto<Self>>::Error>,
{
    fn read(addr: VirtAddr, vm: &VirtualMemory, abi: Abi) -> Result<(usize, Self)> {
        match abi {
            Abi::I386 => {
                let mut bits = <T::I386 as CheckedBitPattern>::Bits::zeroed();
                let bytes = bytes_of_mut(&mut bits);
                vm.read_bytes(addr, bytes)?;
                let value = try_pod_read_unaligned::<T::I386>(bytes)?;
                Ok((bytes.len(), value.try_into()?))
            }
            Abi::Amd64 => {
                let mut bits = <T::Amd64 as CheckedBitPattern>::Bits::zeroed();
                let bytes = bytes_of_mut(&mut bits);
                vm.read_bytes(addr, bytes)?;
                let value = try_pod_read_unaligned::<T::Amd64>(bytes)?;
                Ok((bytes.len(), value.try_into()?))
            }
        }
    }
}

impl<T> WritablePointee<ArchitectureDependent> for T
where
    T: AbiDependentPointee,
    T::I386: NoUninit,
    T::Amd64: NoUninit,
    Self: TryInto<T::I386> + TryInto<T::Amd64> + Copy,
    Error: From<<Self as TryInto<T::I386>>::Error> + From<<Self as TryInto<T::Amd64>>::Error>,
{
    fn write(&self, addr: VirtAddr, vm: &VirtualMemory, abi: Abi) -> Result<usize> {
        match abi {
            Abi::I386 => {
                let value: T::I386 = (*self).try_into()?;
                vm.write_bytes(addr, bytes_of(&value))?;
                Ok(size_of::<T::I386>())
            }
            Abi::Amd64 => {
                let value: T::Amd64 = (*self).try_into()?;
                vm.write_bytes(addr, bytes_of(&value))?;
                Ok(size_of::<T::Amd64>())
            }
        }
    }
}

impl<T> SizedPointee<ArchitectureDependent> for T
where
    T: AbiDependentPointee,
{
    fn size(&self, abi: Abi) -> usize {
        match abi {
            Abi::I386 => size_of::<T::I386>(),
            Abi::Amd64 => size_of::<T::Amd64>(),
        }
    }
}

/// A pointee which has the same size and layout for all architectures, but is
/// not necessairly primitive (e.g. also arrays).
pub trait AbiAgnosticPointee {}

impl<T> AbiAgnosticPointee for T where T: PrimitivePointee {}
impl<T> AbiAgnosticPointee for [T] where T: AbiAgnosticPointee {}
impl<T, const N: usize> AbiAgnosticPointee for [T; N] where T: AbiAgnosticPointee {}

impl<T> Pointee for [T] where T: Pointee {}

/// A marker type used for the blanket impls of array, slice and vector
/// pointees.
pub struct Array<T>(T);

impl<T, P> WritablePointee<Array<P>> for [T]
where
    T: WritablePointee<P>,
{
    fn write(&self, addr: VirtAddr, vm: &VirtualMemory, abi: Abi) -> Result<usize> {
        let mut total_len = 0;
        for value in self.iter() {
            let size = value.write(addr + u64::from_usize(total_len), vm, abi)?;
            total_len += size;
        }
        Ok(total_len)
    }
}

impl<T, const N: usize> Pointee for [T; N] where T: Pointee {}

impl<T, P, const N: usize> ReadablePointee<Array<P>> for [T; N]
where
    T: ReadablePointee<P>,
{
    fn read(addr: VirtAddr, vm: &VirtualMemory, abi: Abi) -> Result<(usize, Self)> {
        /// A container for a partially initialized array.
        struct PartiallyInitialized<T, const N: usize> {
            initialized: usize,
            arr: [MaybeUninit<T>; N],
        }

        impl<T, const N: usize> PartiallyInitialized<T, N> {
            fn new() -> Self {
                Self {
                    initialized: 0,
                    arr: MaybeUninit::uninit_array(),
                }
            }

            fn push(&mut self, value: T) {
                self.arr[self.initialized].write(value);
                self.initialized += 1;
            }

            fn take(mut self) -> [T; N] {
                assert_eq!(self.initialized, N);
                self.initialized = 0;
                let arr = core::mem::replace(&mut self.arr, MaybeUninit::uninit_array());
                unsafe { MaybeUninit::array_assume_init(arr) }
            }
        }

        impl<T, const N: usize> Drop for PartiallyInitialized<T, N> {
            fn drop(&mut self) {
                for value in self.arr[..self.initialized].iter_mut() {
                    unsafe {
                        value.assume_init_drop();
                    }
                }
            }
        }

        let mut total_len = 0;
        let mut arr = PartiallyInitialized::new();
        for _ in 0..N {
            let (len, value) = ReadablePointee::read(addr + u64::from_usize(total_len), vm, abi)?;
            total_len += len;
            arr.push(value);
        }
        Ok((total_len, arr.take()))
    }
}

impl<T, P, const N: usize> WritablePointee<Array<P>> for [T; N]
where
    T: WritablePointee<P>,
{
    fn write(&self, addr: VirtAddr, vm: &VirtualMemory, abi: Abi) -> Result<usize> {
        self.as_slice().write(addr, vm, abi)
    }
}

impl Pointee for u8 {}
impl PrimitivePointee for u8 {}

impl Pointee for u32 {}
impl PrimitivePointee for u32 {}

impl Pointee for i32 {}
impl PrimitivePointee for i32 {}

impl Pointee for CStr {
    fn display(f: &mut dyn fmt::Write, addr: VirtAddr, thread: &ThreadGuard) -> fmt::Result {
        let res = thread
            .virtual_memory()
            .read_cstring(Pointer::from(addr), 128);
        match res {
            Ok(value) => write!(f, "{value:?}"),
            Err(_) => write!(f, "{:#x} (invalid ptr)", addr.as_u64()),
        }
    }
}

impl AbiAgnosticPointee for CStr {}

impl WritablePointee for CStr {
    fn write(&self, addr: VirtAddr, vm: &VirtualMemory, _abi: Abi) -> Result<usize> {
        let bytes = self.to_bytes_with_nul();
        vm.write_bytes(addr, bytes)?;
        Ok(bytes.len())
    }
}

impl Pointee for CString {
    fn display(f: &mut dyn fmt::Write, addr: VirtAddr, thread: &ThreadGuard) -> fmt::Result {
        CStr::display(f, addr, thread)
    }
}

impl AbiAgnosticPointee for CString {}

impl Pointee for Path {
    fn display(f: &mut dyn fmt::Write, addr: VirtAddr, thread: &ThreadGuard) -> fmt::Result {
        CStr::display(f, addr, thread)
    }
}

impl AbiAgnosticPointee for Path {}

impl ReadablePointee for Path {
    fn read(addr: VirtAddr, vm: &VirtualMemory, _abi: Abi) -> Result<(usize, Self)> {
        let pathname = vm.read_cstring(Pointer::from(addr), PATH_MAX)?;
        let len = pathname.to_bytes_with_nul().len();
        let value = Path::new(pathname.into_bytes())?;
        Ok((len, value))
    }
}

impl WritablePointee for Path {
    fn write(&self, addr: VirtAddr, vm: &VirtualMemory, _abi: Abi) -> Result<usize> {
        vm.write_bytes(addr, self.as_bytes())?;
        vm.write_bytes(addr + u64::from_usize(self.as_bytes().len()), b"\0")?;
        Ok(self.as_bytes().len() + 1)
    }
}

impl<T> Pointee for Pointer<T> where T: ?Sized {}

impl<T> AbiDependentPointee for Pointer<T>
where
    T: ?Sized,
{
    type I386 = Pointer32<T>;
    type Amd64 = Pointer64<T>;
}

#[repr(transparent)]
pub struct Pointer32<T>(u32, PhantomData<T>)
where
    T: ?Sized;

#[repr(transparent)]
pub struct Pointer64<T>(u64, PhantomData<T>)
where
    T: ?Sized;

impl<T> Clone for Pointer32<T>
where
    T: ?Sized,
{
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for Pointer32<T> where T: ?Sized {}

unsafe impl<T> Pod for Pointer32<T> where T: ?Sized + 'static {}
unsafe impl<T> Zeroable for Pointer32<T> where T: ?Sized {}

impl<T> From<Pointer32<T>> for Pointer<T>
where
    T: ?Sized,
{
    fn from(value: Pointer32<T>) -> Self {
        Self {
            value: u64::from(value.0),
            _marker: PhantomData,
        }
    }
}

impl<T> TryFrom<Pointer<T>> for Pointer32<T>
where
    T: ?Sized,
{
    type Error = Error;

    fn try_from(value: Pointer<T>) -> Result<Self> {
        Ok(Self(value.value.try_into()?, PhantomData))
    }
}

impl<T> Clone for Pointer64<T>
where
    T: ?Sized,
{
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for Pointer64<T> where T: ?Sized {}

unsafe impl<T> Pod for Pointer64<T> where T: ?Sized + 'static {}
unsafe impl<T> Zeroable for Pointer64<T> where T: ?Sized {}

impl<T> From<Pointer64<T>> for Pointer<T>
where
    T: ?Sized,
{
    fn from(value: Pointer64<T>) -> Self {
        Self {
            value: value.0,
            _marker: PhantomData,
        }
    }
}

impl<T> From<Pointer<T>> for Pointer64<T>
where
    T: ?Sized,
{
    fn from(value: Pointer<T>) -> Self {
        Self(value.value, PhantomData)
    }
}

impl Pointee for FdNum {}

impl PrimitivePointee for FdNum {}

impl Pointee for SigInfo {}

impl AbiDependentPointee for SigInfo {
    type I386 = SigInfo32;
    type Amd64 = SigInfo64;
}

#[derive(Clone, Copy, NoUninit)]
#[repr(C)]
pub struct SigInfo32 {
    si_signo: i32,
    si_errno: i32,
    si_code: i32,
    _sifields: [i32; 29],
}

impl From<SigInfo> for SigInfo32 {
    fn from(value: SigInfo) -> Self {
        let mut _sifields = [0; 29];
        let dst = bytes_of_mut(&mut _sifields);
        macro_rules! pack {
            ($expr:expr) => {{
                let value = $expr;
                let src = bytes_of(&value);
                dst[..src.len()].copy_from_slice(src);
            }};
        }
        match value.fields {
            SigFields::None => {}
            SigFields::SigChld(sig_chld) => {
                pack!(SigChld32 {
                    pid: sig_chld.pid,
                    uid: sig_chld.uid,
                    status: sig_chld.status.raw() as i32,
                    utime: sig_chld.utime as i32,
                    stime: sig_chld.stime as i32,
                })
            }
            SigFields::SigFault(sig_fault) => {
                pack!(SigFault32 {
                    addr: sig_fault.addr as u32,
                })
            }
        }
        Self {
            si_signo: value.signal.get() as i32,
            si_errno: 0,
            si_code: value.code.get(),
            _sifields,
        }
    }
}

#[derive(Clone, Copy, NoUninit)]
#[repr(C)]
struct SigChld32 {
    pid: i32,
    uid: u32,
    status: i32,
    utime: i32,
    stime: i32,
}

#[derive(Clone, Copy, NoUninit)]
#[repr(C)]
struct SigFault32 {
    addr: u32,
}

#[derive(Clone, Copy, NoUninit)]
#[repr(C)]
pub struct SigInfo64 {
    si_signo: i32,
    si_errno: i32,
    si_code: i32,
    _padding: i32,
    _sifields: [i32; 28],
}

impl From<SigInfo> for SigInfo64 {
    fn from(value: SigInfo) -> Self {
        let mut _sifields = [0; 28];
        let dst = bytes_of_mut(&mut _sifields);
        macro_rules! pack {
            ($expr:expr) => {{
                let value = $expr;
                let src = bytes_of(&value);
                dst[..src.len()].copy_from_slice(src);
            }};
        }
        match value.fields {
            SigFields::None => {}
            SigFields::SigChld(sig_chld) => {
                pack!(SigChld64 {
                    pid: sig_chld.pid,
                    uid: sig_chld.uid,
                    status: sig_chld.status.raw() as i32,
                    utime: sig_chld.utime,
                    stime: sig_chld.stime,
                })
            }
            SigFields::SigFault(sig_fault) => {
                pack!(SigFault64 {
                    addr: sig_fault.addr,
                })
            }
        }
        Self {
            si_signo: value.signal.get() as i32,
            si_errno: 0,
            si_code: value.code.get(),
            _padding: 0,
            _sifields,
        }
    }
}

#[derive(Clone, Copy, NoUninit)]
#[repr(C, packed(4))]
struct SigChld64 {
    pid: i32,
    uid: u32,
    status: i32,
    utime: i64,
    stime: i64,
}

#[derive(Clone, Copy, NoUninit)]
#[repr(C)]
struct SigFault64 {
    addr: u64,
}

impl Pointee for Sigaction {}

impl AbiDependentPointee for Sigaction {
    type I386 = Sigaction32;
    type Amd64 = Sigaction64;
}

#[derive(Debug, Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct Sigaction32 {
    sa_handler_or_sigaction: u32,
    sa_flags: u32,
    sa_restorer: u32,
    sa_mask: [u32; 2],
}

#[derive(Debug, Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct Sigaction64 {
    sa_handler_or_sigaction: u64,
    sa_flags: u64,
    sa_restorer: u64,
    sa_mask: Sigset,
}

impl TryFrom<Sigaction> for Sigaction32 {
    type Error = Error;

    fn try_from(value: Sigaction) -> Result<Self> {
        Ok(Self {
            sa_handler_or_sigaction: value.sa_handler_or_sigaction.try_into()?,
            sa_flags: value.sa_flags.bits(),
            sa_restorer: value.sa_restorer.try_into()?,
            sa_mask: cast(value.sa_mask),
        })
    }
}

impl From<Sigaction> for Sigaction64 {
    fn from(value: Sigaction) -> Self {
        Self {
            sa_handler_or_sigaction: value.sa_handler_or_sigaction,
            sa_flags: u64::from(value.sa_flags.bits()),
            sa_restorer: value.sa_restorer,
            sa_mask: value.sa_mask,
        }
    }
}

impl From<Sigaction32> for Sigaction {
    fn from(value: Sigaction32) -> Self {
        Self {
            sa_handler_or_sigaction: u64::from(value.sa_handler_or_sigaction),
            sa_flags: SigactionFlags::from_bits_retain(value.sa_flags),
            sa_restorer: u64::from(value.sa_restorer),
            sa_mask: cast(value.sa_mask),
        }
    }
}

impl From<Sigaction64> for Sigaction {
    fn from(value: Sigaction64) -> Self {
        Self {
            sa_handler_or_sigaction: value.sa_handler_or_sigaction,
            sa_mask: value.sa_mask,
            sa_flags: SigactionFlags::from_bits_retain(value.sa_flags as u32),
            sa_restorer: value.sa_restorer,
        }
    }
}

impl Pointee for Iovec {}
impl AbiDependentPointee for Iovec {
    type I386 = Iovec32;
    type Amd64 = Iovec64;
}

#[derive(Debug, Clone, Copy, Zeroable, Pod)]
#[repr(C)]
pub struct Iovec32 {
    base: u32,
    len: u32,
}

#[derive(Debug, Clone, Copy, Zeroable, Pod)]
#[repr(C)]
pub struct Iovec64 {
    base: u64,
    len: u64,
}

impl From<Iovec32> for Iovec {
    fn from(value: Iovec32) -> Self {
        Self {
            base: u64::from(value.base),
            len: u64::from(value.len),
        }
    }
}

impl From<Iovec64> for Iovec {
    fn from(value: Iovec64) -> Self {
        Self {
            base: value.base,
            len: value.len,
        }
    }
}

impl Pointee for Timespec {}

impl AbiDependentPointee for Timespec {
    type I386 = Timespec32;
    type Amd64 = Timespec64;
}

#[derive(Debug, Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct Timespec32 {
    pub tv_sec: u32,
    pub tv_nsec: u32,
}

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct Timespec64 {
    pub tv_sec: u64,
    pub tv_nsec: u64,
}

impl From<Timespec> for Timespec32 {
    fn from(value: Timespec) -> Self {
        Self {
            tv_sec: value.tv_sec,
            tv_nsec: value.tv_nsec,
        }
    }
}

impl From<Timespec> for Timespec64 {
    fn from(value: Timespec) -> Self {
        Self {
            tv_sec: u64::from(value.tv_sec),
            tv_nsec: u64::from(value.tv_nsec),
        }
    }
}

impl TryFrom<Timespec32> for Timespec {
    type Error = Error;

    fn try_from(value: Timespec32) -> Result<Self> {
        if !matches!(value.tv_nsec, Self::UTIME_NOW | Self::UTIME_OMIT) {
            ensure!(value.tv_nsec < 1_000_000_000, Inval);
        }
        Ok(Self {
            tv_sec: value.tv_sec,
            tv_nsec: value.tv_nsec,
        })
    }
}

impl TryFrom<Timespec64> for Timespec {
    type Error = Error;

    fn try_from(value: Timespec64) -> Result<Self> {
        let tv_nsec = u32::try_from(value.tv_nsec)?;

        if matches!(tv_nsec, Self::UTIME_NOW | Self::UTIME_OMIT) {
            // If tv_nsec is set to one of these special values ignore tv_sec.
            Ok(Self { tv_sec: 0, tv_nsec })
        } else {
            ensure!(tv_nsec < 1_000_000_000, Inval);
            Ok(Self {
                tv_sec: u32::try_from(value.tv_sec)?,
                tv_nsec,
            })
        }
    }
}

impl Pointee for c_void {}

impl Pointee for Stat {}

impl AbiDependentPointee for Stat {
    type I386 = Stat32;
    type Amd64 = Stat64;
}

#[derive(Clone, Copy, Zeroable, NoUninit)]
#[repr(C)]
pub struct Stat32 {
    pub dev: u32,
    pub ino: u32,
    pub mode: u16,
    pub nlink: u16,
    pub uid: u16,
    pub gid: u16,
    pub rdev: u32,
    pub size: u32,
    pub blksize: u32,
    pub blocks: u32,
    pub atime: Timespec32,
    pub mtime: Timespec32,
    pub ctime: Timespec32,
    pub __unused4: u32,
    pub __unused5: u32,
}

#[derive(Clone, Copy, Zeroable, NoUninit)]
#[repr(C)]
pub struct Stat64 {
    pub dev: u64,
    pub ino: u64,
    pub nlink: u64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub _pad0: u32,
    pub rdev: u64,
    pub size: i64,
    pub blksize: i64,
    pub blocks: i64,
    pub atime: Timespec64,
    pub mtime: Timespec64,
    pub ctime: Timespec64,
    pub _unused: [i64; 3],
}

impl TryFrom<Stat> for Stat32 {
    type Error = Error;

    fn try_from(value: Stat) -> Result<Self> {
        Ok(Self {
            dev: u32::try_from(value.dev)?,
            ino: u32::try_from(value.ino)?,
            mode: u16::try_from(value.mode.0)?,
            nlink: u16::try_from(value.nlink)?,
            uid: u16::try_from(value.uid.get())?,
            gid: u16::try_from(value.gid.get())?,
            rdev: u32::try_from(value.rdev)?,
            size: u32::try_from(value.size)?,
            blksize: u32::try_from(value.blksize)?,
            blocks: u32::try_from(value.blocks)?,
            atime: Timespec32::from(value.atime),
            mtime: Timespec32::from(value.mtime),
            ctime: Timespec32::from(value.ctime),
            __unused4: 0,
            __unused5: 0,
        })
    }
}

impl From<Stat> for Stat64 {
    fn from(value: Stat) -> Self {
        Self {
            dev: value.dev,
            ino: value.ino,
            nlink: value.nlink,
            mode: value.mode.0,
            uid: value.uid.get(),
            gid: value.gid.get(),
            _pad0: 0,
            rdev: value.rdev,
            size: value.size,
            blksize: value.blksize,
            blocks: value.blocks,
            atime: Timespec64::from(value.atime),
            mtime: Timespec64::from(value.mtime),
            ctime: Timespec64::from(value.ctime),
            _unused: [0; 3],
        }
    }
}

impl Pointee for Offset {}

impl AbiDependentPointee for Offset {
    type I386 = Offset32;
    type Amd64 = Offset64;
}

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(transparent)]
pub struct Offset32(pub i32);

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(transparent)]
pub struct Offset64(pub i64);

impl From<Offset32> for Offset {
    fn from(value: Offset32) -> Self {
        Self(i64::from(value.0))
    }
}

impl From<Offset64> for Offset {
    fn from(value: Offset64) -> Self {
        Self(value.0)
    }
}

impl Pointee for LongOffset {}

impl PrimitivePointee for LongOffset {}

impl Pointee for WStatus {}

impl PrimitivePointee for WStatus {}

impl Pointee for Stack {}

impl AbiDependentPointee for Stack {
    type I386 = Stack32;
    type Amd64 = Stack64;
}

#[derive(Debug, Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct Stack32 {
    pub sp: u32,
    pub flags: StackFlags,
    pub size: u32,
}

#[derive(Debug, Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct Stack64 {
    pub sp: u64,
    pub flags: StackFlags,
    _pad: u32,
    pub size: u64,
}

impl TryFrom<Stack> for Stack32 {
    type Error = Error;

    fn try_from(value: Stack) -> Result<Self> {
        Ok(Self {
            sp: u32::try_from(value.sp)?,
            flags: value.flags,
            size: u32::try_from(value.size)?,
        })
    }
}

impl From<Stack> for Stack64 {
    fn from(value: Stack) -> Self {
        Self {
            sp: value.sp,
            flags: value.flags,
            _pad: 0,
            size: value.size,
        }
    }
}

impl From<Stack32> for Stack {
    fn from(value: Stack32) -> Self {
        Self {
            sp: u64::from(value.sp),
            flags: value.flags,
            size: u64::from(value.size),
        }
    }
}

impl From<Stack64> for Stack {
    fn from(value: Stack64) -> Self {
        Self {
            sp: value.sp,
            flags: value.flags,
            size: value.size,
        }
    }
}

impl Pointee for Sigset {}

impl AbiDependentPointee for Sigset {
    type I386 = Sigset32;
    type Amd64 = Sigset64;
}

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(transparent)]
pub struct Sigset32([u32; 2]);

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(transparent)]
pub struct Sigset64([u32; 2]);

impl From<Sigset32> for Sigset {
    fn from(value: Sigset32) -> Self {
        Self::from_bits(cast(value))
    }
}

impl From<Sigset64> for Sigset {
    fn from(value: Sigset64) -> Self {
        Self::from_bits(cast(value))
    }
}

impl From<Sigset> for Sigset32 {
    fn from(value: Sigset) -> Self {
        cast(value.to_bits())
    }
}

impl From<Sigset> for Sigset64 {
    fn from(value: Sigset) -> Self {
        cast(value.to_bits())
    }
}

impl Pointee for DirEntry {}

impl WritablePointee for DirEntry {
    fn write(&self, addr: VirtAddr, vm: &VirtualMemory, _abi: Abi) -> Result<usize> {
        let dirent = LinuxDirent64 {
            ino: self.ino,
            off: i64::try_from(self.len())?,
            reclen: u16::try_from(self.len())?,
            ty: self.ty as u8,
            name: [],
            _padding: [0; 5],
        };
        vm.write_bytes(addr, bytes_of(&dirent))?;
        vm.write_bytes(addr + 19u64, self.name.as_ref())?;
        vm.write_bytes(
            addr + 19u64 + u64::from_usize(self.name.as_ref().len()),
            &[0],
        )?;

        Ok(self.len())
    }
}

impl AbiAgnosticPointee for DirEntry {}

impl Pointee for OldDirEntry {}

impl WritablePointee for OldDirEntry {
    fn write(&self, addr: VirtAddr, vm: &VirtualMemory, abi: Abi) -> Result<usize> {
        let len = self.len(abi);

        let dirent = OldLinuxDirent {
            ino: self.0.ino,
            off: u64::from_usize(len),
            reclen: u16::try_from(len)?,
        };
        let base_len = vm.write_with_abi(Pointer::new(addr.as_u64()), dirent, abi)?;
        vm.write_bytes(addr + u64::from_usize(base_len), self.0.name.as_ref())?;
        vm.write_bytes(
            addr + u64::from_usize(base_len + self.0.name.as_ref().len()),
            &[0, self.0.ty as u8],
        )?;
        Ok(len)
    }
}

impl OldDirEntry {
    pub fn len(&self, abi: Abi) -> usize {
        let base_size = match abi {
            Abi::I386 => size_of::<<OldLinuxDirent as AbiDependentPointee>::I386>(),
            Abi::Amd64 => size_of::<<OldLinuxDirent as AbiDependentPointee>::Amd64>(),
        };
        let len = base_size + self.0.name.as_ref().len() + 2;
        len.next_multiple_of(8)
    }
}

impl Pointee for OldLinuxDirent {}

impl AbiDependentPointee for OldLinuxDirent {
    type I386 = OldLinuxDirent32;
    type Amd64 = OldLinuxDirent64;
}

#[derive(Debug, Clone, Copy)]
struct OldLinuxDirent {
    pub ino: u64,
    pub off: u64,
    pub reclen: u16,
}

#[derive(Debug, Clone, Copy, Zeroable, Pod)]
#[repr(C, packed(2))]
struct OldLinuxDirent32 {
    pub ino: u32,
    pub off: u32,
    pub reclen: u16,
}

impl TryFrom<OldLinuxDirent> for OldLinuxDirent32 {
    type Error = Error;

    fn try_from(value: OldLinuxDirent) -> Result<Self> {
        Ok(Self {
            ino: u32::try_from(value.ino)?,
            off: u32::try_from(value.off)?,
            reclen: value.reclen,
        })
    }
}

#[derive(Debug, Clone, Copy, Zeroable, Pod)]
#[repr(C, packed(2))]
struct OldLinuxDirent64 {
    pub ino: u64,
    pub off: u64,
    pub reclen: u16,
}

impl TryFrom<OldLinuxDirent> for OldLinuxDirent64 {
    type Error = Error;

    fn try_from(value: OldLinuxDirent) -> Result<Self> {
        Ok(Self {
            ino: value.ino,
            off: value.off,
            reclen: value.reclen,
        })
    }
}

impl Pointee for Timeval {}

impl AbiDependentPointee for Timeval {
    type I386 = Timeval32;
    type Amd64 = Timeval64;
}

#[derive(Clone, Copy, Zeroable, Pod)]
#[repr(C)]
pub struct Timeval32 {
    tv_sec: u32,
    tv_usec: u32,
}

#[derive(Clone, Copy, Zeroable, Pod)]
#[repr(C)]
pub struct Timeval64 {
    tv_sec: u64,
    tv_usec: u64,
}

impl From<Timeval32> for Timeval {
    fn from(value: Timeval32) -> Self {
        Self {
            tv_sec: value.tv_sec,
            tv_usec: value.tv_usec,
        }
    }
}

impl From<Timeval64> for Timeval {
    fn from(value: Timeval64) -> Self {
        Self {
            tv_sec: value.tv_sec as u32,
            tv_usec: value.tv_usec as u32,
        }
    }
}

impl From<Timeval> for Timeval32 {
    fn from(value: Timeval) -> Self {
        Self {
            tv_sec: value.tv_sec,
            tv_usec: value.tv_usec,
        }
    }
}

impl From<Timeval> for Timeval64 {
    fn from(value: Timeval) -> Self {
        Self {
            tv_sec: u64::from(value.tv_sec),
            tv_usec: u64::from(value.tv_usec),
        }
    }
}

impl Pointee for Time {}

impl AbiDependentPointee for Time {
    type I386 = Time32;
    type Amd64 = Time64;
}

#[derive(Debug, Clone, Copy, Zeroable, Pod)]
#[repr(transparent)]
pub struct Time32(u32);

impl From<Time> for Time32 {
    fn from(value: Time) -> Self {
        Self(value.0)
    }
}

#[derive(Debug, Clone, Copy, Zeroable, Pod)]
#[repr(transparent)]
pub struct Time64(u64);

impl From<Time> for Time64 {
    fn from(value: Time) -> Self {
        Self(u64::from(value.0))
    }
}

impl Pointee for UContext {}

impl AbiDependentPointee for UContext {
    type I386 = UContext32;
    type Amd64 = UContext64;
}

#[derive(Clone, Copy, Zeroable, Pod)]
#[repr(C)]
pub struct UContext32 {
    flags: u32,
    link: Pointer32<UContext32>,
    stack: Stack32,
    mcontext: SigContext32,
    sigmask: Sigset32,
}

impl TryFrom<UContext> for UContext32 {
    type Error = Error;

    fn try_from(value: UContext) -> Result<Self> {
        Ok(Self {
            flags: 0,
            link: Pointer32(0, PhantomData),
            stack: value.stack.try_into()?,
            mcontext: SigContext32 {
                gs: value.mcontext.gs,
                __gsh: 0,
                fs: value.mcontext.fs,
                __fsh: 0,
                es: value.mcontext.es,
                __esh: 0,
                ds: value.mcontext.ds,
                __dsh: 0,
                edi: value.mcontext.rdi as u32,
                esi: value.mcontext.rsi as u32,
                ebp: value.mcontext.rbp as u32,
                esp: value.mcontext.rsp as u32,
                ebx: value.mcontext.rbx as u32,
                edx: value.mcontext.rdx as u32,
                ecx: value.mcontext.rcx as u32,
                eax: value.mcontext.rax as u32,
                trapno: value.mcontext.trapno as u32,
                err: value.mcontext.err as u32,
                eip: value.mcontext.rip as u32,
                cs: value.mcontext.cs,
                __csh: 0,
                eflags: value.mcontext.eflags as u32,
                esp_at_signal: value.mcontext.rsp as u32,
                ss: value.mcontext.ss,
                __ssh: 0,
                fpstate: value.mcontext.fpstate.cast().try_into()?,
                oldmask: value.mcontext.oldmask as u32,
                cr2: value.mcontext.cr2 as u32,
            },
            sigmask: value.sigmask.into(),
        })
    }
}

impl From<UContext32> for UContext {
    fn from(value: UContext32) -> Self {
        Self {
            stack: value.stack.into(),
            mcontext: SigContext {
                r8: 0,
                r9: 0,
                r10: 0,
                r11: 0,
                r12: 0,
                r13: 0,
                r14: 0,
                r15: 0,
                rdi: u64::from(value.mcontext.edi),
                rsi: u64::from(value.mcontext.esi),
                rbp: u64::from(value.mcontext.ebp),
                rbx: u64::from(value.mcontext.ebx),
                rdx: u64::from(value.mcontext.edx),
                rax: u64::from(value.mcontext.eax),
                rcx: u64::from(value.mcontext.ecx),
                rsp: u64::from(value.mcontext.esp),
                rip: u64::from(value.mcontext.eip),
                eflags: u64::from(value.mcontext.eflags),
                cs: value.mcontext.cs,
                ds: value.mcontext.ds,
                es: value.mcontext.es,
                gs: value.mcontext.gs,
                fs: value.mcontext.fs,
                ss: value.mcontext.ss,
                err: u64::from(value.mcontext.err),
                trapno: u64::from(value.mcontext.trapno),
                oldmask: u64::from(value.mcontext.oldmask),
                cr2: u64::from(value.mcontext.cr2),
                fpstate: Pointer::from(value.mcontext.fpstate).cast(),
            },
            sigmask: value.sigmask.into(),
        }
    }
}

#[derive(Clone, Copy, Zeroable, Pod)]
#[repr(C)]
struct SigContext32 {
    gs: u16,
    __gsh: u16,
    fs: u16,
    __fsh: u16,
    es: u16,
    __esh: u16,
    ds: u16,
    __dsh: u16,
    edi: u32,
    esi: u32,
    ebp: u32,
    esp: u32,
    ebx: u32,
    edx: u32,
    ecx: u32,
    eax: u32,
    trapno: u32,
    err: u32,
    eip: u32,
    cs: u16,
    __csh: u16,
    eflags: u32,
    esp_at_signal: u32,
    ss: u16,
    __ssh: u16,
    fpstate: Pointer32<FpState32>,
    oldmask: u32,
    cr2: u32,
}

#[derive(Clone, Copy, Zeroable, Pod)]
#[repr(C)]
pub struct FpState32 {
    cw: u32,
    sw: u32,
    tag: u32,
    ipoff: u32,
    cssel: u32,
    dataoff: u32,
    datasel: u32,
    _st: [FpReg; 8],
    status: u16,
    magic: u16,
    _fxsr_env: [u32; 6],
    mxcsr: u32,
    reserved: u32,
    _fxsr_st: [FpxReg; 8],
    _xmm: [XmmReg; 8],
    padding1: [u32; 44],
    padding2: [u32; 12],
}

#[derive(Clone, Copy, Zeroable, Pod)]
#[repr(C)]
struct FpReg {
    significand: [u16; 4],
    exponent: u16,
}

#[derive(Clone, Copy, Zeroable, Pod)]
#[repr(C)]
struct FpxReg {
    significand: [u16; 4],
    exponent: u16,
    padding: [u16; 3],
}

#[derive(Clone, Copy, Zeroable, Pod)]
#[repr(C)]
struct XmmReg {
    element: [u32; 4],
}

#[derive(Clone, Copy, Zeroable, Pod)]
#[repr(C)]
pub struct UContext64 {
    flags: u64,
    link: Pointer64<UContext64>,
    stack: Stack64,
    mcontext: SigContext64,
    sigmask: Sigset64,
}

impl From<UContext> for UContext64 {
    fn from(value: UContext) -> Self {
        Self {
            flags: 0,
            link: Pointer64(0, PhantomData),
            stack: value.stack.into(),
            mcontext: SigContext64 {
                r8: value.mcontext.r8,
                r9: value.mcontext.r9,
                r10: value.mcontext.r10,
                r11: value.mcontext.r11,
                r12: value.mcontext.r12,
                r13: value.mcontext.r13,
                r14: value.mcontext.r14,
                r15: value.mcontext.r15,
                rdi: value.mcontext.rdi,
                rsi: value.mcontext.rsi,
                rbp: value.mcontext.rbp,
                rbx: value.mcontext.rbx,
                rdx: value.mcontext.rdx,
                rax: value.mcontext.rax,
                rcx: value.mcontext.rcx,
                rsp: value.mcontext.rsp,
                rip: value.mcontext.rip,
                eflags: value.mcontext.eflags,
                cs: value.mcontext.cs,
                gs: value.mcontext.gs,
                fs: value.mcontext.fs,
                ss: value.mcontext.ss,
                err: value.mcontext.err,
                trapno: value.mcontext.trapno,
                oldmask: value.mcontext.oldmask,
                cr2: value.mcontext.cr2,
                fpstate: value.mcontext.fpstate.cast().into(),
                reserved1: [0; 8],
            },
            sigmask: value.sigmask.into(),
        }
    }
}

impl From<UContext64> for UContext {
    fn from(value: UContext64) -> Self {
        Self {
            stack: value.stack.into(),
            mcontext: SigContext {
                r8: value.mcontext.r8,
                r9: value.mcontext.r9,
                r10: value.mcontext.r10,
                r11: value.mcontext.r11,
                r12: value.mcontext.r12,
                r13: value.mcontext.r13,
                r14: value.mcontext.r14,
                r15: value.mcontext.r15,
                rdi: value.mcontext.rdi,
                rsi: value.mcontext.rsi,
                rbp: value.mcontext.rbp,
                rbx: value.mcontext.rbx,
                rdx: value.mcontext.rdx,
                rax: value.mcontext.rax,
                rcx: value.mcontext.rcx,
                rsp: value.mcontext.rsp,
                rip: value.mcontext.rip,
                eflags: value.mcontext.eflags,
                cs: value.mcontext.cs,
                ds: 0x23,
                es: 0x23,
                gs: value.mcontext.gs,
                fs: value.mcontext.fs,
                ss: value.mcontext.ss,
                err: value.mcontext.err,
                trapno: value.mcontext.trapno,
                oldmask: value.mcontext.oldmask,
                cr2: value.mcontext.cr2,
                fpstate: Pointer::from(value.mcontext.fpstate).cast(),
            },
            sigmask: value.sigmask.into(),
        }
    }
}

#[derive(Clone, Copy, Zeroable, Pod)]
#[repr(C)]
struct SigContext64 {
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    rdi: u64,
    rsi: u64,
    rbp: u64,
    rbx: u64,
    rdx: u64,
    rax: u64,
    rcx: u64,
    rsp: u64,
    rip: u64,
    eflags: u64,
    cs: u16,
    gs: u16,
    fs: u16,
    ss: u16,
    err: u64,
    trapno: u64,
    oldmask: u64,
    cr2: u64,
    fpstate: Pointer64<FpState64>,
    reserved1: [u64; 8],
}

#[derive(Clone, Copy, Zeroable, Pod)]
#[repr(C)]
struct FpState64 {
    cwd: u16,
    swd: u16,
    twd: u16,
    fop: u16,
    rip: u64,
    rdp: u64,
    mxcsr: u32,
    mxcsr_mask: u32,
    st_space: [u32; 32],
    xmm_space: [u32; 64],
    reserved2: [u32; 12],
    reserved3: [u32; 12],
}

impl Pointee for RLimit {}

impl AbiDependentPointee for RLimit {
    type I386 = RLimit32;
    type Amd64 = RLimit64;
}

#[derive(Clone, Copy, Zeroable, Pod)]
#[repr(C)]
pub struct RLimit32 {
    rlim_cur: u32,
    rlim_max: u32,
}

#[derive(Clone, Copy, Zeroable, Pod)]
#[repr(C)]
pub struct RLimit64 {
    rlim_cur: u64,
    rlim_max: u64,
}

impl From<RLimit> for RLimit32 {
    fn from(value: RLimit) -> Self {
        Self {
            rlim_cur: value.rlim_cur,
            rlim_max: value.rlim_max,
        }
    }
}

impl From<RLimit> for RLimit64 {
    fn from(value: RLimit) -> Self {
        Self {
            rlim_cur: u64::from(value.rlim_cur),
            rlim_max: u64::from(value.rlim_max),
        }
    }
}

impl Pointee for super::RLimit64 {}

impl PrimitivePointee for super::RLimit64 {}

impl Pointee for SysInfo {}

impl AbiDependentPointee for SysInfo {
    type I386 = SysInfo32;
    type Amd64 = SysInfo64;
}

#[derive(Clone, Copy, Zeroable, Pod)]
#[repr(C)]
pub struct SysInfo32 {
    uptime: i32,
    loads: [u32; 3],
    totalram: u32,
    freeram: u32,
    sharedram: u32,
    bufferram: u32,
    totalswap: u32,
    freeswap: u32,
    procs: u16,
    _padding: u16,
    totalhigh: u32,
    freehigh: u32,
    mem_unit: u32,
}

impl From<SysInfo> for SysInfo32 {
    fn from(value: SysInfo) -> Self {
        Self {
            uptime: value.uptime as _,
            loads: value.loads.map(|load| load as _),
            totalram: value.totalram as _,
            freeram: value.freeram as _,
            sharedram: value.sharedram as _,
            bufferram: value.bufferram as _,
            totalswap: value.totalswap as _,
            freeswap: value.freeswap as _,
            procs: value.procs as _,
            _padding: 0,
            totalhigh: value.totalhigh as _,
            freehigh: value.freehigh as _,
            mem_unit: value.mem_unit as _,
        }
    }
}

#[derive(Clone, Copy, Zeroable, Pod)]
#[repr(C)]
pub struct SysInfo64 {
    uptime: i64,
    loads: [u64; 3],
    totalram: u64,
    freeram: u64,
    sharedram: u64,
    bufferram: u64,
    totalswap: u64,
    freeswap: u64,
    procs: u16,
    _padding1: [u16; 3],
    totalhigh: u64,
    freehigh: u64,
    mem_unit: u32,
    _padding2: u32,
}

impl From<SysInfo> for SysInfo64 {
    fn from(value: SysInfo) -> Self {
        Self {
            uptime: value.uptime,
            loads: value.loads,
            totalram: value.totalram,
            freeram: value.freeram,
            sharedram: value.sharedram,
            bufferram: value.bufferram,
            totalswap: value.totalswap,
            freeswap: value.freeswap,
            procs: value.procs,
            _padding1: [0; 3],
            totalhigh: value.totalhigh,
            freehigh: value.freehigh,
            mem_unit: value.mem_unit,
            _padding2: 0,
        }
    }
}

impl Pointee for PSelectSigsetArg {}

impl AbiDependentPointee for PSelectSigsetArg {
    type I386 = PSelectSigsetArg32;
    type Amd64 = PSelectSigsetArg64;
}

#[derive(Clone, Copy, Zeroable, Pod)]
#[repr(C)]
pub struct PSelectSigsetArg32 {
    ss: Pointer32<Sigset>,
    ss_len: u32,
}

#[derive(Clone, Copy, Zeroable, Pod)]
#[repr(C)]
pub struct PSelectSigsetArg64 {
    ss: Pointer64<Sigset>,
    ss_len: u64,
}

impl From<PSelectSigsetArg32> for PSelectSigsetArg {
    fn from(value: PSelectSigsetArg32) -> Self {
        Self {
            ss: value.ss.into(),
            ss_len: usize_from(value.ss_len),
        }
    }
}

impl From<PSelectSigsetArg64> for PSelectSigsetArg {
    fn from(value: PSelectSigsetArg64) -> Self {
        Self {
            ss: value.ss.into(),
            ss_len: usize_from(value.ss_len),
        }
    }
}

impl Pointee for Uid {}
impl PrimitivePointee for Uid {}

impl Pointee for Gid {}
impl PrimitivePointee for Gid {}

impl Pointee for StatFs {}
impl AbiDependentPointee for StatFs {
    type I386 = StatFs32;
    type Amd64 = StatFs64;
}

#[derive(Clone, Copy, Zeroable, Pod)]
#[repr(C)]
pub struct StatFs32 {
    ty: u32,
    bsize: u32,
    blocks: u32,
    bfree: u32,
    bavail: u32,
    files: u32,
    ffree: u32,
    fsid: [i32; 2],
    namelen: u32,
    frsize: u32,
    flags: u32,
    spare: [u32; 4],
}

impl From<StatFs> for StatFs32 {
    fn from(value: StatFs) -> Self {
        Self {
            ty: value.ty as u32,
            bsize: value.bsize as u32,
            blocks: value.blocks as u32,
            bfree: value.bfree as u32,
            bavail: value.bavail as u32,
            files: value.files as u32,
            ffree: value.ffree as u32,
            fsid: value.fsid,
            namelen: value.namelen as u32,
            frsize: value.frsize as u32,
            flags: value.flags as u32,
            spare: [0; 4],
        }
    }
}

#[derive(Clone, Copy, Zeroable, Pod)]
#[repr(C)]
pub struct StatFs64 {
    ty: i64,
    bsize: i64,
    blocks: i64,
    bfree: i64,
    bavail: i64,
    files: i64,
    ffree: i64,
    fsid: [i32; 2],
    namelen: i64,
    frsize: i64,
    flags: i64,
    spare: [i64; 4],
}

impl From<StatFs> for StatFs64 {
    fn from(value: StatFs) -> Self {
        Self {
            ty: value.ty,
            bsize: value.bsize,
            blocks: value.blocks,
            bfree: value.bfree,
            bavail: value.bavail,
            files: value.files,
            ffree: value.ffree,
            fsid: value.fsid,
            namelen: value.namelen,
            frsize: value.frsize,
            flags: value.flags,
            spare: [0; 4],
        }
    }
}

impl Pointee for Rusage {}
impl AbiDependentPointee for Rusage {
    type I386 = Rusage32;
    type Amd64 = Rusage64;
}

#[derive(Clone, Copy, Zeroable, Pod)]
#[repr(C)]
pub struct Rusage32 {
    utime: Timeval32,
    stime: Timeval32,
    maxrss: u32,
    ixrss: u32,
    idrss: u32,
    isrss: u32,
    minflt: u32,
    majflt: u32,
    nswap: u32,
    inblock: u32,
    oublock: u32,
    msgsnd: u32,
    msgrcv: u32,
    nsignals: u32,
    nvcsw: u32,
    nivcsw: u32,
}

#[derive(Clone, Copy, Zeroable, Pod)]
#[repr(C)]
pub struct Rusage64 {
    utime: Timeval64,
    stime: Timeval64,
    maxrss: u64,
    ixrss: u64,
    idrss: u64,
    isrss: u64,
    minflt: u64,
    majflt: u64,
    nswap: u64,
    inblock: u64,
    oublock: u64,
    msgsnd: u64,
    msgrcv: u64,
    nsignals: u64,
    nvcsw: u64,
    nivcsw: u64,
}

impl From<Rusage> for Rusage32 {
    fn from(value: Rusage) -> Self {
        Self {
            utime: value.utime.into(),
            stime: value.stime.into(),
            maxrss: value.maxrss as u32,
            ixrss: value.ixrss as u32,
            idrss: value.idrss as u32,
            isrss: value.isrss as u32,
            minflt: value.minflt as u32,
            majflt: value.majflt as u32,
            nswap: value.nswap as u32,
            inblock: value.inblock as u32,
            oublock: value.oublock as u32,
            msgsnd: value.msgsnd as u32,
            msgrcv: value.msgrcv as u32,
            nsignals: value.nsignals as u32,
            nvcsw: value.nvcsw as u32,
            nivcsw: value.nivcsw as u32,
        }
    }
}

impl From<Rusage> for Rusage64 {
    fn from(value: Rusage) -> Self {
        Self {
            utime: value.utime.into(),
            stime: value.stime.into(),
            maxrss: value.maxrss,
            ixrss: value.ixrss,
            idrss: value.idrss,
            isrss: value.isrss,
            minflt: value.minflt,
            majflt: value.majflt,
            nswap: value.nswap,
            inblock: value.inblock,
            oublock: value.oublock,
            msgsnd: value.msgsnd,
            msgrcv: value.msgrcv,
            nsignals: value.nsignals,
            nvcsw: value.nvcsw,
            nivcsw: value.nivcsw,
        }
    }
}

impl Pointee for SocketAddr {}
impl PrimitivePointee for SocketAddr {}
