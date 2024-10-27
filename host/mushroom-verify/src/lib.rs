use io::input::{Header, MAX_HASH_SIZE};
use sha2::{Digest, Sha256};
#[cfg(feature = "snp")]
use snp_types::{attestation::TcbVersion, guest_policy::GuestPolicy};
#[cfg(feature = "tdx")]
use tdx_types::td_quote::TeeTcbSvn;

pub use loader::{HashType, Input};

#[cfg(feature = "serde")]
mod hex;
#[cfg(feature = "snp")]
mod snp;
#[cfg(feature = "tdx")]
mod tdx;

#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(transparent)
)]
pub struct Configuration(ConfigurationImpl);

#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(tag = "tee", rename_all = "lowercase")
)]
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

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct HashedInput {
    pub input_len: u64,
    pub hash_type: HashType,
    pub hash: [u8; MAX_HASH_SIZE],
}

impl HashedInput {
    pub fn new(input: &Input<impl AsRef<[u8]>>) -> Self {
        let bytes = input.bytes.as_ref();
        Self {
            input_len: bytes.len() as u64,
            hash_type: input.hash_type,
            hash: input.hash_type.hash(bytes),
        }
    }

    pub fn sha256(input_len: u64, hash: [u8; 32]) -> Self {
        let mut bytes = [0; MAX_HASH_SIZE];
        bytes[..32].copy_from_slice(&hash);
        Self {
            input_len,
            hash_type: HashType::Sha256,
            hash: bytes,
        }
    }
}

#[derive(Clone, Copy)]
pub struct InputHash([u8; 32]);

impl InputHash {
    pub fn new<I>(inputs: I) -> Self
    where
        I: IntoIterator<Item = HashedInput>,
        I::IntoIter: DoubleEndedIterator,
    {
        let mut header = Header::end();
        for input in inputs.into_iter().rev() {
            header = Header {
                input_len: input.input_len,
                hash_type: input.hash_type,
                hash: input.hash,
                next_hash: header.hash(),
            };
        }
        InputHash(header.hash())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct OutputHash {
    pub hash: [u8; 32],
    pub len: u64,
}

impl OutputHash {
    pub fn new(output: &[u8]) -> Self {
        Self {
            hash: Sha256::digest(output).into(),
            len: output.len() as u64,
        }
    }
}

impl From<OutputHash> for HashedInput {
    fn from(value: OutputHash) -> Self {
        Self::sha256(value.len, value.hash)
    }
}
