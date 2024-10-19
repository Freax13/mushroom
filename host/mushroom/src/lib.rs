#![feature(new_zeroed_alloc)]

use std::{collections::HashMap, num::NonZeroU32, ptr::NonNull};

use anyhow::{Context, Result};
use bit_field::BitField;
use bytemuck::NoUninit;
use kvm::KvmCap;
use slot::Slot;
use volatile::{
    access::{ReadOnly, Readable},
    VolatilePtr,
};
use x86_64::structures::paging::PhysFrame;

pub mod insecure;
pub mod snp;
pub mod tdx;

mod kvm;
mod logging;
pub mod profiler;
mod slot;

pub use kvm::KvmHandle;

const TSC_MHZ: u64 = 100;

#[derive(Clone, Copy)]
pub enum Tee {
    Snp,
    Tdx,
    Insecure,
}

impl Tee {
    pub fn is_supported(self, kvm: &KvmHandle) -> Result<bool> {
        const KVM_X86_TDX_VM: usize = 2;
        const KVM_X86_SNP_VM: usize = 3;
        let bit = match self {
            Tee::Snp => KVM_X86_SNP_VM,
            Tee::Tdx => KVM_X86_TDX_VM,
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

/// The volatile equivalent of `bytemuck::bytes_of`.
fn volatile_bytes_of<T>(ptr: VolatilePtr<T, impl Readable>) -> VolatilePtr<[u8], ReadOnly>
where
    T: NoUninit,
{
    let data = ptr.as_raw_ptr().as_ptr().cast::<u8>();
    let ptr = core::ptr::slice_from_raw_parts_mut(data, size_of::<T>());
    let ptr = unsafe {
        // SAFETY: We got originially the pointer from a `NonNull` and only
        // casted it to another type and added size metadata.
        NonNull::new_unchecked(ptr)
    };
    unsafe {
        // SAFETY: `ptr` points to a valid `T` and its `NoUninit`
        // implementation promises us that it's safe to view the data as a
        // slice of bytes.
        VolatilePtr::new_read_only(ptr)
    }
}

fn is_efault(err: &anyhow::Error) -> bool {
    err.downcast_ref::<nix::Error>()
        .is_some_and(|&err| err == nix::Error::EFAULT)
}
