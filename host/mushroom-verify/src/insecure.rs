use bytemuck::{Pod, Zeroable, bytes_of, pod_read_unaligned};
use thiserror::Error;

use crate::{InputHash, OutputHash};

#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Configuration(());

impl Configuration {
    pub fn new() -> Self {
        Self(())
    }

    /// Verify that a input with the given hash is attested to have produced an output and return its hash.
    pub fn verify_and_extract(
        &self,
        attestation_report: &[u8],
    ) -> Result<(InputHash, OutputHash), Error> {
        if attestation_report.len() != size_of::<AttestationReport>() {
            return Err(Error::Size(attestation_report.len()));
        }
        let attestation_report = pod_read_unaligned::<AttestationReport>(attestation_report);

        let input_hash = InputHash::from(attestation_report.input_hash);
        let output_hash = OutputHash {
            hash: attestation_report.output_hash,
            len: u64::from_le(attestation_report.output_len),
        };
        Ok((input_hash, output_hash))
    }
}

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
struct AttestationReport {
    input_hash: [u8; 32],
    output_hash: [u8; 32],
    output_len: u64,
}

pub fn forge_insecure_attestation_report(
    input_hash: InputHash,
    output_hash: OutputHash,
) -> Vec<u8> {
    let report = AttestationReport {
        input_hash: input_hash.0,
        output_hash: output_hash.hash,
        output_len: output_hash.len.to_le(),
    };
    bytes_of(&report).to_vec()
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("expected {expected} bytes, got {0}", expected = size_of::<AttestationReport>())]
    Size(usize),
}

#[cfg(test)]
mod tests {
    use std::process::Output;

    use loader::Input;

    use crate::{
        Configuration, HashedInput, InputHash, OutputHash, forge_insecure_attestation_report,
    };

    #[test]
    fn verify_forged() {
        let input_hash = InputHash::new([HashedInput::new(&Input {
            bytes: [0x12, 0x34, 0x56, 0x78],
            hash_type: loader::HashType::Sha256,
        })]);
        let output_hash = OutputHash::new(&[0x78, 0x56, 0x34, 0x12]);
        let attestation_report = forge_insecure_attestation_report(input_hash, output_hash);
        let configuration = Configuration::new_insecure();
        configuration
            .verify(input_hash, output_hash, &attestation_report)
            .unwrap();
    }
}
