#![feature(new_zeroed_alloc)]

use std::num::NonZeroU32;

use anyhow::Result;
use bit_field::BitField;
use kvm::KvmCap;

pub mod insecure;
pub mod snp;

mod kvm;
mod logging;
pub mod profiler;
mod slot;

pub use kvm::KvmHandle;

#[derive(Clone, Copy)]
pub enum Tee {
    Snp,
    Insecure,
}

impl Tee {
    pub fn is_supported(self, kvm: &KvmHandle) -> Result<bool> {
        const KVM_X86_SNP_VM: usize = 3;
        let bit = match self {
            Tee::Snp => KVM_X86_SNP_VM,
            Tee::Insecure => return Ok(true),
        };
        let extension = kvm.check_extension(KvmCap::VM_TYPES)?;
        let bits = extension.map_or(0, NonZeroU32::get);
        Ok(bits.get_bit(bit))
    }
}

pub struct MushroomResult {
    pub output: Vec<u8>,
    pub attestation_report: Option<Vec<u8>>,
}

fn is_efault(err: &anyhow::Error) -> bool {
    err.downcast_ref::<nix::Error>()
        .is_some_and(|&err| err == nix::Error::EFAULT)
}
