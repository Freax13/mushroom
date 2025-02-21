use std::{collections::HashMap, num::NonZeroU32, sync::Once};

use anyhow::{Context, Result};
use bit_field::BitField;
use kvm::KvmCap;
use nix::sys::{
    resource::{Resource, getrlimit, setrlimit},
    signal::{SaFlags, SigAction, SigHandler, SigSet, Signal, sigaction},
};
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

/// The signal used to kick threads out of KVM_RUN.
const SIG_KICK: Signal = Signal::SIGUSR1;

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

fn install_signal_handler() {
    static INSTALL_SIGNAL_HANDLER: Once = Once::new();
    INSTALL_SIGNAL_HANDLER.call_once(|| {
        extern "C" fn handler(_: i32) {
            // Don't do anything.
        }
        unsafe {
            sigaction(
                SIG_KICK,
                &SigAction::new(
                    SigHandler::Handler(handler),
                    SaFlags::empty(),
                    SigSet::empty(),
                ),
            )
            .unwrap();
        };
    });
}

fn raise_file_no_limit() {
    static RAISE_NO_LIMIT: Once = Once::new();
    RAISE_NO_LIMIT.call_once(|| {
        // Set the soft limit to the hard limit. We need this because we
        // allocate a lot of memfds.
        let (_soft, hard) = getrlimit(Resource::RLIMIT_NOFILE).unwrap();
        setrlimit(Resource::RLIMIT_NOFILE, hard, hard).unwrap();
    });
}

#[derive(Debug)]
enum OutputEvent<T = Vec<u8>> {
    Write(Vec<u8>),
    Finish(T),
    Fail(anyhow::Error),
}
