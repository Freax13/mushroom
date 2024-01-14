use std::{
    fmt::{self, Display},
    mem::size_of,
};

use bytemuck::{bytes_of, checked::try_pod_read_unaligned, pod_read_unaligned, NoUninit};
use io::input::Header;
use loader::{generate_base_load_commands, LoadCommand, LoadCommandPayload};
use openssl::{bn::BigNum, ecdsa::EcdsaSig};
use sha2::{Digest, Sha256, Sha384};
use snp_types::{
    attestation::{AttestionReport, EcdsaP384Sha384Signature, TcbVersion},
    guest_policy::GuestPolicy,
    PageType, VmplPermissions,
};
use vcek_kds::Vcek;

pub struct Configuration {
    launch_digest: [u8; 48],
    policy: GuestPolicy,
}

impl Configuration {
    pub fn new(
        supervisor: &[u8],
        kernel: &[u8],
        init: &[u8],
        load_kasan_shadow_mappings: bool,
        policy: GuestPolicy,
    ) -> Self {
        let commands =
            generate_base_load_commands(Some(supervisor), kernel, init, load_kasan_shadow_mappings);

        let mut launch_digest = [0; 48];

        for command in commands {
            let Some(info) = PageInfo::new(launch_digest, &command) else {
                continue;
            };
            launch_digest = Sha384::digest(bytes_of(&info)).into();
        }

        let info = PageInfo::linux_vmsa(launch_digest);
        launch_digest = Sha384::digest(bytes_of(&info)).into();

        Self {
            launch_digest,
            policy,
        }
    }

    /// Verify that a input the given hash is attested to have produced a output with the given hash.
    ///
    /// The hashes a SHA256 hashes.
    pub fn verify(
        &self,
        input_hash: InputHash,
        output_hash: OutputHash,
        attestation_report: &[u8],
        vcek: &Vcek,
    ) -> Result<(), VerificationError> {
        let report = try_pod_read_unaligned::<AttestionReport>(attestation_report)
            .map_err(|_| VerificationError(()))?;

        let AttestionReport::V2(report) = report;

        macro_rules! verify_eq {
            ($lhs:expr, $rhs:expr) => {
                if $lhs != $rhs {
                    return Err(VerificationError(()));
                }
            };
        }

        verify_eq!(report.vmpl, 0);
        verify_eq!(report.report_data[..32], output_hash.0);
        verify_eq!(report.report_data[32..], [0; 32]);
        verify_eq!(report.measurement, self.launch_digest);
        verify_eq!(report.host_data, input_hash.0);
        verify_eq!({ report.policy }, self.policy);

        verify_eq!(report.signature_algo, 1);

        // Construct signature.
        let signature = &report.signature[..size_of::<EcdsaP384Sha384Signature>()];
        let signature = pod_read_unaligned::<EcdsaP384Sha384Signature>(signature);
        let r = BigNum::from_slice(&signature.r).map_err(|_| VerificationError(()))?;
        let s = BigNum::from_slice(&signature.r).map_err(|_| VerificationError(()))?;
        let sig = EcdsaSig::from_private_components(r, s).map_err(|_| VerificationError(()))?;

        // Verify signature.
        let public_key = vcek
            .as_ref()
            .public_key()
            .map_err(|_| VerificationError(()))?;
        let ec_key = public_key.ec_key().map_err(|_| VerificationError(()))?;
        sig.verify(&attestation_report[..=0x29f], &ec_key)
            .map_err(|_| VerificationError(()))?;

        Ok(())
    }
}

#[derive(Clone, Copy)]
pub struct VcekParameters {
    pub chip_id: ChipId,
    pub tcb: TcbVersion,
}

impl VcekParameters {
    /// Extract the VCEK parameters from an attestation report.
    ///
    /// This information is necessairy to retrieve the VCEK.
    pub fn for_attestaton_report(
        attestation_report: &[u8],
    ) -> Result<VcekParameters, VerificationError> {
        let attestion_report = try_pod_read_unaligned::<AttestionReport>(attestation_report)
            .map_err(|_| VerificationError(()))?;
        let AttestionReport::V2(report) = attestion_report;
        Ok(VcekParameters {
            chip_id: ChipId {
                chip_id: report.chip_id,
            },
            tcb: report.reported_tcb,
        })
    }
}

#[derive(Clone, Copy)]
pub struct ChipId {
    pub chip_id: [u8; 64],
}

impl Display for ChipId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.chip_id.iter() {
            write!(f, "{b:02x}")?;
        }
        Ok(())
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

    fn linux_vmsa(digest_cur: [u8; 48]) -> Self {
        const VMSA_CONTENT: [u8; 48] = [
            0x99, 0xa4, 0xb4, 0x76, 0xdb, 0xe1, 0xea, 0x38, 0xda, 0xe6, 0x7d, 0xbe, 0x6e, 0xac,
            0x70, 0xd9, 0xf0, 0x17, 0xfe, 0xb6, 0x95, 0x4d, 0x6e, 0x9f, 0xe0, 0xa7, 0x05, 0x87,
            0xc9, 0x7e, 0x40, 0x57, 0xce, 0x8e, 0x69, 0xa1, 0x7d, 0xc0, 0x3d, 0x5f, 0xf2, 0xd9,
            0x99, 0xbd, 0x0a, 0x6c, 0x7e, 0x80,
        ];

        Self {
            digest_cur,
            contents: VMSA_CONTENT,
            length: u16::try_from(size_of::<Self>()).unwrap(),
            page_type: PageType::Vmsa as u8,
            imi_page: false,
            vmpl3_perms: VmplPermissions::empty(),
            vmpl2_perms: VmplPermissions::empty(),
            vmpl1_perms: VmplPermissions::empty(),
            zero: 0,
            gpa: 0xffff_ffff_f000,
        }
    }
}
