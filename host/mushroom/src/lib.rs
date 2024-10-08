#![feature(new_zeroed_alloc)]

pub mod insecure;
pub mod snp;

mod kvm;
mod logging;
pub mod profiler;
mod slot;

pub struct MushroomResult {
    pub output: Vec<u8>,
    pub attestation_report: Option<Vec<u8>>,
}

fn is_efault(err: &anyhow::Error) -> bool {
    err.downcast_ref::<nix::Error>()
        .is_some_and(|&err| err == nix::Error::EFAULT)
}
