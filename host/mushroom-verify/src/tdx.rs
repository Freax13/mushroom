use std::cmp::Ordering;

use loader::generate_base_load_commands;
use sha2::{Digest, Sha384};
use tdx_types::td_quote::{QeVendorId, Quote, TeeTcbSvn, TeeType, Version};
use x86_64::{structures::paging::PhysFrame, PhysAddr};

use crate::{InputHash, OutputHash, VerificationError};

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Configuration {
    #[cfg_attr(feature = "serde", serde(with = "crate::hex"))]
    mr_td: [u8; 48],
    tee_tcb_svn: TeeTcbSvn,
}

impl Configuration {
    pub fn new(supervisor: &[u8], kernel: &[u8], init: &[u8], tee_tcb_svn: TeeTcbSvn) -> Self {
        let mut hasher = Sha384::new();

        let mut commands =
            generate_base_load_commands(Some(supervisor), kernel, init, false).peekable();

        let mut pages = Vec::new();

        while let Some(first_load_command) = commands
            .by_ref()
            // Only consider private memory.
            .find(|command| command.payload.page_type().is_some())
        {
            let gpa = first_load_command.physical_address;

            pages.push(first_load_command.payload.bytes());

            // Coalesce multiple contigous load commands with the same page type.
            for i in 1.. {
                let following_load_command = commands.next_if(|next_load_segment| {
                    next_load_segment.physical_address > gpa
                        && next_load_segment.physical_address - gpa == i
                        && next_load_segment.payload.page_type().is_some()
                });
                let Some(following_load_command) = following_load_command else {
                    break;
                };
                pages.push(following_load_command.payload.bytes());
            }

            for i in 0..pages.len() {
                let gpa = gpa + i as u64;
                mem_page_add(&mut hasher, gpa);
            }

            for (i, page) in pages.drain(..).enumerate() {
                let gpa = gpa + i as u64;
                for (j, chunk) in page.chunks(256).enumerate() {
                    let gpa = gpa.start_address() + (j * chunk.len()) as u64;
                    mr_extend(&mut hasher, gpa, chunk.try_into().unwrap());
                }
            }
        }

        Self {
            mr_td: hasher.finalize().into(),
            tee_tcb_svn,
        }
    }

    /// Verify that a input with the given hash is attested to have produced an output and return its hash.
    pub fn verify_and_extract(
        &self,
        input_hash: InputHash,
        attestation_report: &[u8],
    ) -> Result<OutputHash, VerificationError> {
        let quote = Quote::parse(attestation_report).map_err(|_| VerificationError(()))?;
        quote
            .verify_signatures()
            .map_err(|_| VerificationError(()))?;

        macro_rules! verify_eq {
            ($lhs:expr, $rhs:expr) => {
                if $lhs != $rhs {
                    return Err(VerificationError(()));
                }
            };
        }
        verify_eq!(quote.header.version, Version::Four);
        verify_eq!(quote.header.tee_type, TeeType::Tdx);
        verify_eq!(quote.header.qe_vendor_id, QeVendorId::INTEL_SGX);

        if !quote
            .body
            .tee_tcb_svn
            .partial_cmp(&self.tee_tcb_svn)
            .is_some_and(Ordering::is_ge)
        {
            return Err(VerificationError(()));
        }
        verify_eq!(quote.body.mr_signer_seam, [0; 48]);
        verify_eq!(quote.body.seam_attributes, [0; 8]);
        verify_eq!(quote.body.td_attributes.0, [0; 8]);
        verify_eq!(quote.body.xfam, [0xe7, 0x1a, 0, 0, 0, 0, 0, 0]);
        verify_eq!(quote.body.mr_td, self.mr_td);
        verify_eq!(quote.body.mr_config_id[..32], input_hash.0);
        verify_eq!(quote.body.mr_config_id[32..], [0; 16]);
        verify_eq!(quote.body.mr_owner, [0; 48]);
        verify_eq!(quote.body.mr_owner_config, [0; 48]);
        verify_eq!(quote.body.rtmrs, [[0; 48]; 4]);
        verify_eq!(quote.body.report_data[40..], [0; 24]);

        // TODO: verify cpu_svn.

        Ok(OutputHash {
            hash: quote.body.report_data[..32].try_into().unwrap(),
            len: u64::from_le_bytes(quote.body.report_data[32..40].try_into().unwrap()),
        })
    }
}

fn mem_page_add(hasher: &mut Sha384, gpa: PhysFrame) {
    hasher.update(b"MEM.PAGE.ADD");
    hasher.update([0; 4]);
    hasher.update(gpa.start_address().as_u64().to_le_bytes());
    hasher.update([0; 104]);
}

fn mr_extend(hasher: &mut Sha384, gpa: PhysAddr, chunk: &[u8; 256]) {
    hasher.update(b"MR.EXTEND");
    hasher.update([0; 7]);
    hasher.update(gpa.as_u64().to_le_bytes());
    hasher.update([0; 104]);
    hasher.update(chunk);
}
