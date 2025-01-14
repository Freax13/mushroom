use core::num::NonZeroUsize;

pub mod anon;
pub mod named;

const CAPACITY: usize = 0x10000;
const PIPE_BUF: NonZeroUsize = NonZeroUsize::new(0x1000).unwrap();
