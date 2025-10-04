use core::{
    arch::{asm, x86_64::cmpxchg16b},
    cell::SyncUnsafeCell,
    marker::PhantomData,
    mem::MaybeUninit,
    ops::Index,
    sync::atomic::Ordering,
};

use crate::user::{
    syscall::args::{ExtractableThreadState, RLimit, Resource},
    thread::ThreadGuard,
};

#[derive(Clone)]
pub struct Limits {
    stack: AtomicRLimit,
    core: AtomicRLimit,
    no_file: AtomicRLimit,
    address_space: AtomicRLimit,
}

impl Limits {
    pub const fn default() -> Self {
        Self {
            stack: AtomicRLimit::new(RLimit {
                rlim_cur: 0x80_0000,
                rlim_max: 0x80_0000,
            }),
            core: AtomicRLimit::new(RLimit {
                rlim_cur: RLimit::INFINITY,
                rlim_max: RLimit::INFINITY,
            }),
            no_file: AtomicRLimit::new(RLimit {
                rlim_cur: 1024,
                rlim_max: 65536,
            }),
            address_space: AtomicRLimit::new(RLimit {
                rlim_cur: RLimit::INFINITY,
                rlim_max: RLimit::INFINITY,
            }),
        }
    }
}

impl Index<Resource> for Limits {
    type Output = AtomicRLimit;

    fn index(&self, index: Resource) -> &Self::Output {
        match index {
            Resource::Stack => &self.stack,
            Resource::Core => &self.core,
            Resource::NoFile => &self.no_file,
            Resource::As => &self.address_space,
        }
    }
}

#[repr(align(16))]
pub struct AtomicRLimit(SyncUnsafeCell<RLimit>);

impl AtomicRLimit {
    pub const fn new(value: RLimit) -> Self {
        Self(SyncUnsafeCell::new(value))
    }

    pub fn load(&self) -> RLimit {
        let mut output = MaybeUninit::uninit();
        unsafe {
            asm!(
                "movdqa xmm0, xmmword ptr [{}]",
                "movdqu xmmword ptr [{}], xmm0",
                in(reg) self.0.get(),
                in(reg) output.as_mut_ptr(),
                options(preserves_flags, nostack),
            );
            output.assume_init()
        }
    }

    pub fn store(&self, rlimit: RLimit) {
        unsafe {
            asm!(
                "movdqu xmm0, xmmword ptr [{}]",
                "movdqa xmmword ptr [{}], xmm0",
                in(reg) &raw const rlimit,
                in(reg) self.0.get(),
                options(preserves_flags, nostack),
            );
        }
    }

    pub fn compare_exchange(&self, old: RLimit, new: RLimit) -> Result<RLimit, RLimit> {
        let val = unsafe {
            let old = core::mem::transmute::<RLimit, u128>(old);
            let new = core::mem::transmute::<RLimit, u128>(new);
            let val = cmpxchg16b(
                self.0.get().cast(),
                old,
                new,
                Ordering::Relaxed,
                Ordering::Relaxed,
            );
            core::mem::transmute::<u128, RLimit>(val)
        };
        if val == old { Ok(val) } else { Err(val) }
    }

    pub fn load_current(&self) -> u64 {
        let out;
        unsafe {
            let ptr = &raw const (*self.0.get()).rlim_cur;
            asm!(
                "mov {out}, qword ptr [{ptr}]",
                ptr = in(reg) ptr,
                out = lateout(reg) out,
                options(readonly, preserves_flags, nostack),
            );
        }
        out
    }
}

impl Clone for AtomicRLimit {
    fn clone(&self) -> Self {
        Self::new(self.load())
    }
}

pub struct CurrentLimit<R>(u64, PhantomData<fn(R)>);

impl<R> CurrentLimit<R> {
    pub const fn new(value: u64) -> Self {
        Self(value, PhantomData)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

impl<R> Clone for CurrentLimit<R> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<R> Copy for CurrentLimit<R> {}

impl<R: ConstResource> ExtractableThreadState for CurrentLimit<R> {
    fn extract_from_thread(guard: &ThreadGuard) -> Self {
        Self::new(guard.process().limits[R::RESOURCE].load_current())
    }
}

impl<R: ConstResource> Default for CurrentLimit<R> {
    fn default() -> Self {
        Self::new(Limits::default()[R::RESOURCE].load_current())
    }
}

pub type CurrentStackLimit = CurrentLimit<Stack>;
pub type CurrentNoFileLimit = CurrentLimit<NoFile>;

pub trait ConstResource {
    const RESOURCE: Resource;
}

pub struct Stack;

impl ConstResource for Stack {
    const RESOURCE: Resource = Resource::Stack;
}

pub struct NoFile;

impl ConstResource for NoFile {
    const RESOURCE: Resource = Resource::NoFile;
}
