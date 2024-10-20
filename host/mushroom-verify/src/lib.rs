use io::input::Header;
use sha2::{Digest, Sha256};
#[cfg(feature = "snp")]
use snp_types::{attestation::TcbVersion, guest_policy::GuestPolicy};
#[cfg(feature = "tdx")]
use tdx_types::td_quote::TeeTcbSvn;

#[cfg(feature = "snp")]
mod snp;
#[cfg(feature = "tdx")]
mod tdx;

pub struct Configuration(ConfigurationImpl);

enum ConfigurationImpl {
    #[cfg(feature = "snp")]
    Snp(snp::Configuration),
    #[cfg(feature = "tdx")]
    Tdx(tdx::Configuration),
}

impl Configuration {
    #[cfg(feature = "snp")]
    pub fn new_snp(
        supervisor: &[u8],
        kernel: &[u8],
        init: &[u8],
        load_kasan_shadow_mappings: bool,
        policy: GuestPolicy,
        min_tcb: TcbVersion,
    ) -> Self {
        Self(ConfigurationImpl::Snp(snp::Configuration::new(
            supervisor,
            kernel,
            init,
            load_kasan_shadow_mappings,
            policy,
            min_tcb,
        )))
    }

    #[cfg(feature = "tdx")]
    pub fn new_tdx(supervisor: &[u8], kernel: &[u8], init: &[u8], tee_tcb_svn: TeeTcbSvn) -> Self {
        Self(ConfigurationImpl::Tdx(tdx::Configuration::new(
            supervisor,
            kernel,
            init,
            tee_tcb_svn,
        )))
    }

    /// Verify that a input with the given hash is attested to have produced an
    /// output with the given hash.
    pub fn verify(
        &self,
        input_hash: InputHash,
        output_hash: OutputHash,
        attestation_report: &[u8],
    ) -> Result<(), VerificationError> {
        let hash = self.verify_and_extract(input_hash, attestation_report)?;
        if hash != output_hash {
            return Err(VerificationError(()));
        }
        Ok(())
    }

    /// Verify that a input with the given hash is attested to have produced an
    /// output and return its hash.
    pub fn verify_and_extract(
        &self,
        input_hash: InputHash,
        attestation_report: &[u8],
    ) -> Result<OutputHash, VerificationError> {
        match self.0 {
            #[cfg(feature = "snp")]
            ConfigurationImpl::Snp(ref configuration) => {
                configuration.verify_and_extract(input_hash, attestation_report)
            }
            #[cfg(feature = "tdx")]
            ConfigurationImpl::Tdx(ref configuration) => {
                configuration.verify_and_extract(input_hash, attestation_report)
            }
        }
    }
}

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
