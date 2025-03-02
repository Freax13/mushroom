use std::fmt::{self, Display};

use io::input::{Header, MAX_HASH_SIZE};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub use loader::{HashType, Input};
#[cfg(feature = "snp")]
pub use snp_types::{attestation::TcbVersion, guest_policy::GuestPolicy};
#[cfg(feature = "tdx")]
pub use tdx_types::td_quote::TeeTcbSvn;

#[cfg(feature = "serde")]
mod hex;
#[cfg(feature = "snp")]
// mushroom uses some code in this module. But it shouldn't be considered part
// of the public API.
#[doc(hidden)]
pub mod snp;
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
    ) -> Result<(), Error> {
        let hash = self.verify_and_extract(input_hash, attestation_report)?;

        let OutputHash {
            hash: expected_hash,
            len: expected_len,
        } = output_hash;
        let OutputHash {
            hash: got_hash,
            len: got_len,
        } = hash;

        if expected_len != got_len {
            return Err(Error(ErrorImpl::OutputLength {
                expected: expected_len,
                got: got_len,
            }));
        }
        if expected_hash != got_hash {
            return Err(Error(ErrorImpl::OutputHash {
                expected: expected_hash,
                got: got_hash,
            }));
        }

        Ok(())
    }

    /// Verify that a input with the given hash is attested to have produced an
    /// output and return its hash.
    pub fn verify_and_extract(
        &self,
        input_hash: InputHash,
        attestation_report: &[u8],
    ) -> Result<OutputHash, Error> {
        let res: Result<_, ErrorImpl> = match self.0 {
            #[cfg(feature = "snp")]
            ConfigurationImpl::Snp(ref configuration) => configuration
                .verify_and_extract(input_hash, attestation_report)
                .map_err(Into::into),
            #[cfg(feature = "tdx")]
            ConfigurationImpl::Tdx(ref configuration) => configuration
                .verify_and_extract(input_hash, attestation_report)
                .map_err(Into::into),
        };
        res.map_err(Error)
    }
}

#[derive(Debug, Error)]
#[error(transparent)]
pub struct Error(ErrorImpl);

#[derive(Debug, Error)]
enum ErrorImpl {
    #[cfg(feature = "snp")]
    #[error("failed to verify SEV-SNP attestation report")]
    Snp(#[from] snp::Error),
    #[cfg(feature = "tdx")]
    #[error("failed to verify TD quote")]
    Tdx(#[from] tdx::Error),
    #[error("expected output length to be {expected}, got {got}")]
    OutputLength { expected: u64, got: u64 },
    #[error("expected output hash to be {}, got {}", hex(.expected), hex(.got))]
    OutputHash { expected: [u8; 32], got: [u8; 32] },
}

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

    /// Verify that the hash matches the byte slice.
    pub fn verify(&self, output: &[u8]) -> bool {
        *self == Self::new(output)
    }
}

impl From<OutputHash> for HashedInput {
    fn from(value: OutputHash) -> Self {
        Self::sha256(value.len, value.hash)
    }
}

fn hex(data: &[u8]) -> impl Display + '_ {
    struct Hex<'a>(&'a [u8]);

    impl Display for Hex<'_> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            self.0
                .iter()
                .copied()
                .try_for_each(|b| write!(f, "{b:02x}"))
        }
    }

    Hex(data)
}
