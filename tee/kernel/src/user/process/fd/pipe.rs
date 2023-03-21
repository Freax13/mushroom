use super::OpenFileDescription;

pub struct ReadHalf {}

impl OpenFileDescription for ReadHalf {}

pub struct WriteHalf {}

impl OpenFileDescription for WriteHalf {}

pub fn new() -> (ReadHalf, WriteHalf) {
    (ReadHalf {}, WriteHalf {})
}
