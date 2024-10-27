use std::{collections::HashMap, num::NonZeroU32};

use anyhow::{Context, Result};
use bit_field::BitField;
use kvm::KvmCap;
use slot::Slot;
use x86_64::structures::paging::PhysFrame;

#[cfg(feature = "insecure")]
pub mod insecure;
#[cfg(feature = "snp")]
pub mod snp;
#[cfg(feature = "tdx")]
pub mod tdx;

mod kvm;
mod logging;
pub mod profiler;
mod slot;

pub use kvm::KvmHandle;
pub use loader::{HashType, Input};

const TSC_MHZ: u64 = 100;

#[derive(Clone, Copy)]
pub enum Tee {
    #[cfg(feature = "snp")]
    Snp,
    #[cfg(feature = "tdx")]
    Tdx,
    #[cfg(feature = "insecure")]
    Insecure,
}

impl Tee {
    pub fn is_supported(self, kvm: &KvmHandle) -> Result<bool> {
        const KVM_X86_TDX_VM: usize = 2;
        const KVM_X86_SNP_VM: usize = 3;
        let bit: usize = match self {
            #[cfg(feature = "snp")]
            Tee::Snp => KVM_X86_SNP_VM,
            #[cfg(feature = "tdx")]
            Tee::Tdx => KVM_X86_TDX_VM,
            #[cfg(feature = "insecure")]
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

fn find_slot(gpa: PhysFrame, slots: &mut HashMap<u16, Slot>) -> Result<&mut Slot> {
    slots
        .values_mut()
        .find(|slot| {
            let num_frames = u64::try_from(slot.shared_mapping().len().get() / 0x1000).unwrap();
            (slot.gpa()..slot.gpa() + num_frames).contains(&gpa)
        })
        .context("failed to find slot which contains ghcb")
}

fn is_efault(err: &anyhow::Error) -> bool {
    err.downcast_ref::<nix::Error>()
        .is_some_and(|&err| err == nix::Error::EFAULT)
}
