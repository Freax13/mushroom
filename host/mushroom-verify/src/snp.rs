use std::{cmp::Ordering, mem::size_of};

use bytemuck::{NoUninit, bytes_of, checked::try_pod_read_unaligned, pod_read_unaligned};
use ecdsa::RecoveryId;
use loader::{LoadCommand, LoadCommandPayload, generate_base_load_commands};
use p384::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use sha2::{Digest, Sha384};
use snp_types::{
    VmplPermissions,
    attestation::{AttestionReport, EcdsaP384Sha384Signature, TcbVersion},
    guest_policy::GuestPolicy,
    id_block::{IdBlock, PublicKey},
};
use thiserror::Error;
use vcek_kds::Vcek;

use crate::{InputHash, OutputHash, hex};

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub(crate) struct Configuration {
    #[cfg_attr(feature = "serde", serde(with = "crate::hex"))]
    launch_digest: [u8; 48],
    #[cfg_attr(feature = "serde", serde(with = "crate::hex"))]
    id_key_digest: [u8; 48],
    policy: GuestPolicy,
    min_tcb: TcbVersion,
}

impl Configuration {
    pub fn new(
        supervisor: &[u8],
        kernel: &[u8],
        init: &[u8],
        load_kasan_shadow_mappings: bool,
        policy: GuestPolicy,
        min_tcb: TcbVersion,
    ) -> Self {
        let commands =
            generate_base_load_commands(Some(supervisor), kernel, init, load_kasan_shadow_mappings);

        let launch_digest = LaunchDigest::digest(commands);

        let id_block = id_block(launch_digest, policy);
        let (_signature_key, id_key) = create_signature(&id_block);
        let id_key = PublicKey::P384(id_key.into());
        let id_key_digest = Sha384::digest(bytes_of(&id_key));
        let id_key_digest = id_key_digest.into();

        Self {
            launch_digest,
            id_key_digest,
            policy,
            min_tcb,
        }
    }

    /// Verify that a input with the given hash is attested to have produced an output and return its hash.
    pub fn verify_and_extract(
        &self,
        input_hash: InputHash,
        attestation_report: &[u8],
    ) -> Result<OutputHash, Error> {
        // The VCEK is appended to the attestation report. Split the two.
        const REPORT_LEN: usize = size_of::<AttestionReport>();
        if attestation_report.len() < REPORT_LEN {
            return Err(Error::Length {
                got: attestation_report.len(),
            });
        }
        let (attestation_report, vcek) = attestation_report.split_at(REPORT_LEN);

        // Parse the attestation report and the VCEK.
        let report = try_pod_read_unaligned::<AttestionReport>(attestation_report)?;
        let vcek = Vcek::from_bytes(vcek.to_owned())?;

        let AttestionReport::V2(report) = report;

        if report.vmpl != 0 {
            return Err(Error::Vmpl(report.vmpl));
        }
        if report.report_data[40..] != [0; 24] {
            return Err(Error::ReportDataPadding(
                report.report_data[40..].try_into().unwrap(),
            ));
        }
        if report.measurement != self.launch_digest {
            return Err(Error::Measurement {
                expected: self.launch_digest,
                got: report.measurement,
            });
        }
        if report.id_key_digest != self.id_key_digest {
            return Err(Error::IdKeyDigest {
                expected: self.id_key_digest,
                got: report.id_key_digest,
            });
        }
        if report.host_data != input_hash.0 {
            return Err(Error::HostData {
                expected: input_hash.0,
                got: report.host_data,
            });
        }
        if { report.policy } != self.policy {
            return Err(Error::Policy {
                expected: self.policy,
                got: report.policy,
            });
        }
        if report.signature_algo != 1 {
            return Err(Error::SignatureAlgo {
                expected: 1,
                got: report.signature_algo,
            });
        }

        let is_valid_tcb = report
            .launch_tcb
            .partial_cmp(&self.min_tcb)
            .is_some_and(Ordering::is_ge);
        if !is_valid_tcb {
            return Err(Error::Tcb {
                expected: self.min_tcb,
                got: report.launch_tcb,
            });
        }

        // Construct signature.
        let signature = pod_read_unaligned::<EcdsaP384Sha384Signature>(&report.signature);
        let signature = Signature::try_from(signature)?;

        // Verify signature.
        let public_key = vcek.verifying_key();
        public_key.verify(&attestation_report[..=0x29f], &signature)?;

        Ok(OutputHash {
            hash: report.report_data[..32].try_into().unwrap(),
            len: u64::from_le_bytes(report.report_data[32..40].try_into().unwrap()),
        })
    }
}

#[derive(Clone, Copy, NoUninit)]
#[repr(C)]
struct PageInfo {
    /// The value of the current digest (either LD or IMD).
    digest_cur: [u8; 48],
    /// The SHA-384 digest of the measured contents of the region, if any.
    contents: [u8; 48],
    /// Length of this structure in bytes.
    length: u16,
    /// The zero-extended PAGE_TYPE field provided by the hypervisor
    page_type: u8,
    /// Set to the IMI_PAGE flag provided by the hypervisor.
    imi_page: bool,
    /// Must be zero.
    zero: u8,
    /// The VMPL1_PERMS field provided by the hypervisor.
    vmpl1_perms: VmplPermissions,
    /// The VMPL2_PERMS field provided by the hypervisor.
    vmpl2_perms: VmplPermissions,
    /// The VMPL3_PERMS field provided by the hypervisor.
    vmpl3_perms: VmplPermissions,
    /// The 64-bit gPA of the region
    gpa: u64,
}

impl PageInfo {
    fn new(digest_cur: [u8; 48], command: &LoadCommand) -> Option<Self> {
        let contents = match command.payload {
            LoadCommandPayload::Normal(page) => Sha384::digest(page).into(),
            LoadCommandPayload::Vmsa(mut page) => {
                // Zero out GUEST_TSC_SCALE and GUEST_TSC_OFFSET.
                page[0x2f0..=0x2ff].fill(0);
                Sha384::digest(page).into()
            }
            LoadCommandPayload::Zero
            | LoadCommandPayload::Secrets
            | LoadCommandPayload::Cpuid(_) => [0; 48],
            LoadCommandPayload::Shared(_) => return None,
        };

        Some(Self {
            digest_cur,
            contents,
            length: u16::try_from(size_of::<Self>()).unwrap(),
            page_type: command.payload.page_type().unwrap() as u8,
            imi_page: false,
            zero: 0,
            vmpl1_perms: command.vmpl1_perms,
            vmpl2_perms: VmplPermissions::empty(),
            vmpl3_perms: VmplPermissions::empty(),
            gpa: command.physical_address.start_address().as_u64(),
        })
    }
}

pub struct LaunchDigest {
    launch_digest: [u8; 48],
}

impl LaunchDigest {
    pub const fn new() -> Self {
        Self {
            launch_digest: [0; 48],
        }
    }

    pub fn add(&mut self, cmd: &LoadCommand) {
        if let Some(info) = PageInfo::new(self.launch_digest, cmd) {
            self.launch_digest = Sha384::digest(bytes_of(&info)).into();
        }
    }

    pub fn finish(self) -> [u8; 48] {
        self.launch_digest
    }

    pub fn digest(iter: impl IntoIterator<Item = LoadCommand>) -> [u8; 48] {
        let mut digest = Self::new();
        for cmd in iter {
            digest.add(&cmd);
        }
        digest.finish()
    }
}

impl Default for LaunchDigest {
    fn default() -> Self {
        Self::new()
    }
}

pub fn id_block(launch_digest: [u8; 48], policy: GuestPolicy) -> IdBlock {
    IdBlock {
        launch_digest,
        family_id: [0; 16],
        image_id: [0; 16],
        version: 0,
        guest_svn: 0,
        policy,
    }
}

pub fn create_signature(id_block: &IdBlock) -> (Signature, VerifyingKey) {
    // 1. Make up a signature.
    let r = *b"ECDSA is cool! Public Key Recovery rocks!!!!!!!!";
    let s = *b"    https://www.secg.org/sec1-v2.pdf - 4.1.6    ";
    let signature = Signature::from_scalars(r, s).unwrap();

    // 2. Recover a public key that matches the verifies the message with the
    // signature from step 1.
    let msg = bytes_of(id_block);
    let recovery_id = RecoveryId::new(false, false);
    let key = VerifyingKey::recover_from_msg(msg, &signature, recovery_id).unwrap();

    (signature, key)
}

#[derive(Debug, Error)]
pub(crate) enum Error {
    #[error("report is too short: expected at least {} bytes, got {got}", size_of::<AttestionReport>())]
    Length { got: usize },
    #[error("failed to parse report")]
    Bytemuck(#[from] bytemuck::checked::CheckedCastError),
    #[error("failed to parse VCEK")]
    Vcek(#[from] vcek_kds::Error),
    #[error("expected VMPL to be 0, got {0}")]
    Vmpl(u32),
    #[error("expected report data to be padded with zeros, got {}", hex(.0))]
    ReportDataPadding([u8; 24]),
    #[error("expected measurement to be {}, got {}", hex(.expected), hex(.got))]
    Measurement { expected: [u8; 48], got: [u8; 48] },
    #[error("expected id key digest to be {}, got {}", hex(.expected), hex(.got))]
    IdKeyDigest { expected: [u8; 48], got: [u8; 48] },
    #[error("expected host data to be {}, got {}", hex(.expected), hex(.got))]
    HostData { expected: [u8; 32], got: [u8; 32] },
    #[error("expected policy to be {expected:?}, got {got:?}")]
    Policy {
        expected: GuestPolicy,
        got: GuestPolicy,
    },
    #[error("expected signature algorithm to be {expected:?}, got {got:?}")]
    SignatureAlgo { expected: u32, got: u32 },
    #[error("expected TCB version to be {expected:?} or newer, got {got:?}")]
    Tcb {
        expected: TcbVersion,
        got: TcbVersion,
    },
    #[error("failed to verify report signature")]
    Ecdsa(#[from] ecdsa::Error),
}

#[cfg(test)]
mod tests {
    use snp_types::{guest_policy::GuestPolicy, id_block::IdBlock};

    use super::{create_signature, id_block};

    #[test]
    fn public_key_recovery() {
        let id_block = id_block([0xcc; 48], GuestPolicy::new(0, 0));
        create_signature(&id_block);
    }
}
