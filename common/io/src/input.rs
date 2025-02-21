use bytemuck::{CheckedBitPattern, NoUninit, bytes_of};
use sha2::{Digest, Sha256, Sha384};

pub const MAX_HASH_SIZE: usize = 48;

#[derive(Debug, Clone, Copy, CheckedBitPattern, NoUninit, PartialEq, Eq)]
#[repr(C)]
pub struct Header {
    pub input_len: u64,
    pub hash_type: HashType,
    pub hash: [u8; MAX_HASH_SIZE],
    pub next_hash: [u8; 32],
}

impl Header {
    pub fn new(bytes: &[u8], hash_type: HashType, next: &Self) -> Self {
        Self {
            input_len: bytes.len() as u64,
            hash_type,
            hash: hash_type.hash(bytes),
            next_hash: next.hash(),
        }
    }

    pub fn without_hash(bytes: &[u8]) -> Self {
        Self {
            input_len: bytes.len() as u64,
            hash_type: HashType::Sha256,
            hash: [0; MAX_HASH_SIZE],
            next_hash: [0; 32],
        }
    }

    pub const fn end() -> Self {
        Self {
            input_len: !0,
            hash_type: HashType::Sha256,
            hash: [0; MAX_HASH_SIZE],
            next_hash: [0; 32],
        }
    }

    pub fn hash(&self) -> [u8; 32] {
        Sha256::digest(bytes_of(self)).into()
    }

    pub fn verify(&self, hash: [u8; 32]) -> bool {
        self.hash() == hash
    }
}

#[derive(Debug, Clone, Copy, CheckedBitPattern, NoUninit, PartialEq, Eq, Default)]
#[repr(u64)]
pub enum HashType {
    #[default]
    Sha256,
    Sha384,
}

impl HashType {
    pub fn hash(self, data: &[u8]) -> [u8; MAX_HASH_SIZE] {
        let mut hash = [0; MAX_HASH_SIZE];
        match self {
            HashType::Sha256 => hash[..32].copy_from_slice(&Sha256::digest(data)),
            HashType::Sha384 => hash[..48].copy_from_slice(&Sha384::digest(data)),
        }
        hash
    }
}

pub enum Hasher {
    Sha256(Sha256),
    Sha384(Sha384),
}

impl Hasher {
    pub fn new(hash_type: HashType) -> Self {
        match hash_type {
            HashType::Sha256 => Self::Sha256(Sha256::new()),
            HashType::Sha384 => Self::Sha384(Sha384::new()),
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        match self {
            Hasher::Sha256(hasher) => hasher.update(data),
            Hasher::Sha384(hasher) => hasher.update(data),
        }
    }

    pub fn verify(self, hash: [u8; MAX_HASH_SIZE]) {
        let mut bytes = [0; MAX_HASH_SIZE];
        match self {
            Hasher::Sha256(hasher) => bytes[..32].copy_from_slice(&hasher.finalize()),
            Hasher::Sha384(hasher) => bytes[..48].copy_from_slice(&hasher.finalize()),
        }
        assert_eq!(hash, bytes, "input hash doesn't match hash in header");
    }
}
