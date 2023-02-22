use super::FileDescriptor;

pub struct ReadHalf {}

impl FileDescriptor for ReadHalf {}

pub struct WriteHalf {}

impl FileDescriptor for WriteHalf {}

pub fn new() -> (ReadHalf, WriteHalf) {
    (ReadHalf {}, WriteHalf {})
}
