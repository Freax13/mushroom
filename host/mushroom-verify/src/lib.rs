use std::{
    cmp::Ordering,
    fmt::{self, Display},
    mem::size_of,
};

use bytemuck::{bytes_of, checked::try_pod_read_unaligned, pod_read_unaligned, NoUninit};
use io::input::Header;
use loader::{generate_base_load_commands, LoadCommand, LoadCommandPayload};
use p384::ecdsa::{signature::Verifier, Signature};
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
            min_tcb,
        }
    }

    /// Verify that a input with the given hash is attested to have produced a output with the given hash.
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

        let is_valid_tcb = report
            .launch_tcb
            .partial_cmp(&self.min_tcb)
            .is_some_and(Ordering::is_ge);
        if !is_valid_tcb {
            return Err(VerificationError(()));
        }

        // Construct signature.
        let signature = &report.signature[..size_of::<EcdsaP384Sha384Signature>()];
        let signature = pod_read_unaligned::<EcdsaP384Sha384Signature>(signature);

        let (&r, _) = signature.r.split_first_chunk().unwrap();
        let (&s, _) = signature.s.split_first_chunk().unwrap();
        let mut r = r;
        let mut s = s;
        r.reverse();
        s.reverse();
        let signature = Signature::from_scalars(r, s).map_err(|_| VerificationError(()))?;

        // Verify signature.
        let public_key = vcek.verifying_key();
        public_key
            .verify(&attestation_report[..=0x29f], &signature)
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
            0x8d, 0xed, 0x26, 0x62, 0x7a, 0xe8, 0x93, 0x79, 0x3a, 0x1e, 0x8c, 0x03, 0x50, 0x17,
            0xaa, 0x0a, 0x9c, 0x45, 0x73, 0xeb, 0xbc, 0x25, 0xe3, 0xe6, 0x29, 0xb4, 0x90, 0xc6,
            0xad, 0xd9, 0x8c, 0xdb, 0x20, 0xf4, 0xba, 0xd7, 0xc4, 0x2e, 0x55, 0x27, 0x71, 0x4e,
            0x2b, 0x63, 0xfb, 0xb1, 0xea, 0xd1,
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
