use core::{
    marker::PhantomData,
    ops::{Index, IndexMut},
};

use super::{
    syscall::args::{ExtractableThreadState, RLimit, Resource},
    thread::ThreadGuard,
};

#[derive(Clone, Copy)]
pub struct Limits {
    stack: RLimit,
    core: RLimit,
    no_file: RLimit,
    address_space: RLimit,
}

impl Limits {
    pub const fn default() -> Self {
        Self {
            stack: RLimit {
                rlim_cur: 0x80_0000,
                rlim_max: 0x80_0000,
            },
            core: RLimit {
                rlim_cur: RLimit::INFINITY,
                rlim_max: RLimit::INFINITY,
            },
            no_file: RLimit {
                rlim_cur: 1024,
                rlim_max: 65536,
            },
            address_space: RLimit {
                rlim_cur: RLimit::INFINITY,
                rlim_max: RLimit::INFINITY,
            },
        }
    }
}

impl Index<Resource> for Limits {
    type Output = RLimit;

    fn index(&self, index: Resource) -> &Self::Output {
        match index {
            Resource::Stack => &self.stack,
            Resource::Core => &self.core,
            Resource::NoFile => &self.no_file,
            Resource::As => &self.address_space,
        }
    }
}

impl IndexMut<Resource> for Limits {
    fn index_mut(&mut self, index: Resource) -> &mut Self::Output {
        match index {
            Resource::Stack => &mut self.stack,
            Resource::Core => &mut self.core,
            Resource::NoFile => &mut self.no_file,
            Resource::As => &mut self.address_space,
        }
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
        Self::new(guard.process().limits.read()[R::RESOURCE].rlim_cur)
    }
}

impl<R: ConstResource> Default for CurrentLimit<R> {
    fn default() -> Self {
        Self::new(Limits::default()[R::RESOURCE].rlim_cur)
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
