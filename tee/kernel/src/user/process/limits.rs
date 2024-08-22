use core::ops::{Index, IndexMut};

use super::syscall::args::{RLimit, Resource};

#[derive(Clone, Copy)]
pub struct Limits {
    no_file: RLimit,
}

impl Limits {
    pub const fn default() -> Self {
        Self {
            no_file: RLimit {
                rlim_cur: 1024,
                rlim_max: 65536,
            },
        }
    }
}

impl Index<Resource> for Limits {
    type Output = RLimit;

    fn index(&self, index: Resource) -> &Self::Output {
        match index {
            Resource::NoFile => &self.no_file,
        }
    }
}

impl IndexMut<Resource> for Limits {
    fn index_mut(&mut self, index: Resource) -> &mut Self::Output {
        match index {
            Resource::NoFile => &mut self.no_file,
        }
    }
}
