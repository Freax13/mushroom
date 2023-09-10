use bytemuck::{CheckedBitPattern, NoUninit};

use crate::Reserved;

#[derive(Debug, Clone, Copy, CheckedBitPattern, NoUninit)]
#[repr(C, align(4096))]
pub struct Message {
    pub auth_tag: [u8; 32],
    pub msg_seqno: u64,
    _reserved1: Reserved<8, false>,
    pub algo: Algo,
    pub content: Content,
}

impl Message {
    pub fn new(auth_tag: [u8; 32], msg_seqno: u64, algo: Algo, content: Content) -> Self {
        Self {
            auth_tag,
            msg_seqno,
            _reserved1: Reserved([0; 8]),
            algo,
            content,
        }
    }
}

#[derive(Debug, Clone, Copy, CheckedBitPattern, NoUninit)]
#[repr(u8)]
pub enum Algo {
    Aes256Gcm = 1,
}

#[derive(Debug, Clone, Copy, CheckedBitPattern)]
#[repr(u8)]
pub enum Content {
    V1(ContentV1) = 1,
}

unsafe impl NoUninit for Content {}

#[derive(Debug, Clone, Copy, CheckedBitPattern, NoUninit)]
#[repr(C, packed)]
pub struct ContentV1 {
    pub hdr_size: u16,
    pub msg_type: u8,
    pub msg_version: u8,
    pub msg_size: u16,
    // FIXME: The firmware doesn't respond with zeros. Find out why.
    _reserved2: Reserved<4, false>,
    pub msg_vmpck: u8,
    // FIXME: The firmware doesn't respond with zeros. Find out why.
    _reserved3: Reserved<3, false>,
    // FIXME: The firmware doesn't respond with zeros. Find out why.
    _reserved4: Reserved<32, false>,
    pub payload: [u8; 4000],
}

impl ContentV1 {
    pub fn new(
        hdr_size: u16,
        msg_type: u8,
        msg_version: u8,
        msg_size: u16,
        msg_vmpck: u8,
        payload: [u8; 4000],
    ) -> Self {
        Self {
            hdr_size,
            msg_type,
            msg_version,
            msg_size,
            _reserved2: Reserved([0; 4]),
            msg_vmpck,
            _reserved3: Reserved([0; 3]),
            _reserved4: Reserved([0; 32]),
            payload,
        }
    }
}

#[cfg(test)]
mod tests {
    use core::mem::{align_of, size_of};

    use super::Message;

    #[test]
    fn test_size() {
        assert_eq!(size_of::<Message>(), 0x1000);
        assert_eq!(align_of::<Message>(), 0x1000);
    }
}
