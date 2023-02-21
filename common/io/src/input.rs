use bytemuck::{bytes_of, Pod, Zeroable};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct Header {
    pub input_len: usize,
    pub hash: [u8; 32],
}

impl Header {
    pub fn new(bytes: &[u8]) -> Self {
        let hash = Sha256::digest(bytes);
        Self {
            input_len: bytes.len(),
            hash: <[u8; 32]>::from(hash),
        }
    }

    pub fn hash(&self) -> [u8; 32] {
        Sha256::digest(bytes_of(self)).into()
    }

    pub fn verify(&self, hash: [u8; 32]) -> bool {
        self.hash() == hash
    }
}
