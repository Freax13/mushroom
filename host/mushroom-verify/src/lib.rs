#![feature(array_chunks)]

use io::input::Header;
use sha2::{Digest, Sha256};

#[cfg(feature = "snp")]
pub mod snp;
#[cfg(feature = "tdx")]
pub mod tdx;

#[derive(Debug)]
pub struct VerificationError(());

#[derive(Clone, Copy)]
pub struct InputHash([u8; 32]);

impl InputHash {
    pub fn new(input: &[u8]) -> Self {
        InputHash(Header::new(input).hash())
    }
}

#[derive(Clone, Copy)]
pub struct OutputHash([u8; 32]);

impl OutputHash {
    pub fn new(output: &[u8]) -> Self {
        Self(Sha256::digest(output).into())
    }
}
