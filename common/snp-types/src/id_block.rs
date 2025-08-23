use core::fmt;

use bytemuck::{AnyBitPattern, CheckedBitPattern, NoUninit};
#[cfg(feature = "p384")]
use p384::ecdsa::VerifyingKey;

pub use crate::attestation::EcdsaP384Sha384Signature;
use crate::guest_policy::GuestPolicy;

#[derive(Debug, Clone, Copy, CheckedBitPattern, NoUninit)]
#[repr(C)]
pub struct IdBlock {
    pub launch_digest: [u8; 48],
    pub family_id: [u8; 16],
    pub image_id: [u8; 16],
    pub version: u32,
    pub guest_svn: u32,
    pub policy: GuestPolicy,
}

#[derive(Debug, Clone, Copy, CheckedBitPattern, NoUninit)]
#[repr(C)]
pub struct IdAuthInfo {
    pub id_key_algo: KeyAlgo,
    pub auth_key_algo: KeyAlgo,
    _reserved1: [u8; 0x40 - 0x8],
    pub id_block_sig: EcdsaP384Sha384Signature,
    pub id_key: PublicKey,
    _reserved2: [u8; 0x680 - 0x644],
    pub id_key_sig: EcdsaP384Sha384Signature,
    pub author_key: PublicKey,
    _reserved: [u8; 0x1000 - 0xc84],
}

impl IdAuthInfo {
    pub fn new(
        id_key_algo: KeyAlgo,
        auth_key_algo: KeyAlgo,
        id_block_sig: EcdsaP384Sha384Signature,
        id_key: PublicKey,
        id_key_sig: EcdsaP384Sha384Signature,
        author_key: PublicKey,
    ) -> Self {
        Self {
            id_key_algo,
            auth_key_algo,
            _reserved1: [0; 0x40 - 0x8],
            id_block_sig,
            id_key,
            _reserved2: [0; 0x680 - 0x644],
            id_key_sig,
            author_key,
            _reserved: [0; 0x1000 - 0xc84],
        }
    }
}

#[derive(Debug, Clone, Copy, CheckedBitPattern, NoUninit, PartialEq, Eq)]
#[repr(u32)]
pub enum KeyAlgo {
    EcdsaP384Sha384 = 1,
}

#[derive(Debug, Clone, Copy, CheckedBitPattern, NoUninit)]
#[repr(C, u32)]
pub enum PublicKey {
    P384(EcdsaP384PublicKey) = 2,
}

impl Default for PublicKey {
    fn default() -> Self {
        Self::P384(EcdsaP384PublicKey::default())
    }
}

#[derive(Clone, Copy, AnyBitPattern, NoUninit)]
#[repr(C)]
pub struct EcdsaP384PublicKey {
    pub qx: [u8; 72],
    pub qy: [u8; 72],
    _padding: [u8; 0x404 - 0x94],
}

impl EcdsaP384PublicKey {
    pub fn new(qx: [u8; 72], qy: [u8; 72]) -> Self {
        Self {
            qx,
            qy,
            _padding: [0; 0x404 - 0x94],
        }
    }
}

impl fmt::Debug for EcdsaP384PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EcdsaP384PublicKey")
            .field("r", &self.qx)
            .field("s", &self.qy)
            .finish()
    }
}

#[cfg(feature = "p384")]
impl From<VerifyingKey> for EcdsaP384PublicKey {
    fn from(value: VerifyingKey) -> Self {
        let point = value.to_encoded_point(false);
        let x = *point.x().unwrap();
        let y = *point.y().unwrap();
        let mut x = <[u8; 48]>::from(x);
        let mut y = <[u8; 48]>::from(y);
        x.reverse();
        y.reverse();
        let mut qx = [0; 72];
        let mut qy = [0; 72];
        qx[0..48].copy_from_slice(&x);
        qy[0..48].copy_from_slice(&y);
        Self::new(qx, qy)
    }
}

impl Default for EcdsaP384PublicKey {
    fn default() -> Self {
        Self::new([0; 72], [0; 72])
    }
}
