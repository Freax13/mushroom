use std::cmp::Ordering;

use loader::generate_base_load_commands;
use sha2::{Digest, Sha384};
use tdx_types::td_quote::{QeVendorId, Quote, TeeTcbSvn, TeeType, Version};
use thiserror::Error;
use x86_64::{PhysAddr, structures::paging::PhysFrame};

use crate::{InputHash, OutputHash, hex};

#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Configuration {
    #[cfg_attr(feature = "serde", serde(with = "crate::hex"))]
    mr_td: [u8; 48],
    tee_tcb_svn: TeeTcbSvn,
}

impl Configuration {
    pub fn new(supervisor: &[u8], kernel: &[u8], init: &[u8], tee_tcb_svn: TeeTcbSvn) -> Self {
        let mut hasher = Sha384::new();

        let commands = generate_base_load_commands(Some(supervisor), kernel, init, false);
        for command in commands
            // Only consider private memory.
            .filter(|command| command.payload.page_type().is_some())
        {
            let gpa = command.physical_address;

            mem_page_add(&mut hasher, gpa);

            for (i, chunk) in command.payload.bytes().chunks(256).enumerate() {
                let gpa = gpa.start_address() + (i * chunk.len()) as u64;
                mr_extend(&mut hasher, gpa, chunk.try_into().unwrap());
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
        attestation_report: &[u8],
    ) -> Result<(InputHash, OutputHash), Error> {
        let quote = Quote::parse(attestation_report)?;
        quote.verify_signatures()?;

        let Version::Four = quote.header.version;

        if quote.header.tee_type != TeeType::Tdx {
            return Err(Error::Tee {
                expected: TeeType::Tdx,
                got: quote.header.tee_type,
            });
        }
        if quote.header.qe_vendor_id != QeVendorId::INTEL_SGX {
            return Err(Error::QeVendorId {
                expected: QeVendorId::INTEL_SGX,
                got: quote.header.qe_vendor_id,
            });
        }

        if !quote
            .body
            .tee_tcb_svn
            .partial_cmp(&self.tee_tcb_svn)
            .is_some_and(Ordering::is_ge)
        {
            return Err(Error::TeeTcbSvn {
                expected: self.tee_tcb_svn,
                got: quote.body.tee_tcb_svn,
            });
        }

        if quote.body.mr_signer_seam != [0; 48] {
            return Err(Error::MrSignerSeam {
                got: quote.body.mr_signer_seam,
            });
        }
        if quote.body.seam_attributes != [0; 8] {
            return Err(Error::SeamAttributes {
                got: quote.body.seam_attributes,
            });
        }
        if quote.body.td_attributes.0 != [0; 8] {
            return Err(Error::TdAttributes {
                got: quote.body.td_attributes.0,
            });
        }
        if quote.body.xfam != [0xe7, 0x1a, 0, 0, 0, 0, 0, 0] {
            return Err(Error::Xfam {
                expected: [0xe7, 0x1a, 0, 0, 0, 0, 0, 0],
                got: quote.body.xfam,
            });
        }
        if quote.body.mr_td != self.mr_td {
            return Err(Error::MrTd {
                expected: self.mr_td,
                got: quote.body.mr_td,
            });
        }
        if quote.body.mr_config_id[32..] != [0; 16] {
            return Err(Error::MrConfigIdPad {
                got: quote.body.mr_config_id[32..].try_into().unwrap(),
            });
        }
        if quote.body.mr_owner != [0; 48] {
            return Err(Error::MrOwner {
                got: quote.body.mr_owner,
            });
        }
        if quote.body.mr_owner_config != [0; 48] {
            return Err(Error::MrOwnerConfig {
                got: quote.body.mr_owner_config,
            });
        }
        for (i, rtmr) in quote.body.rtmrs.iter().copied().enumerate() {
            if rtmr != [0; 48] {
                return Err(Error::Rtmr {
                    index: i,
                    got: quote.body.mr_owner_config,
                });
            }
        }
        if quote.body.report_data[40..] != [0; 24] {
            return Err(Error::ReportData {
                got: quote.body.report_data[40..].try_into().unwrap(),
            });
        }

        // TODO: verify cpu_svn.

        let input_hash = <[u8; 32]>::try_from(&quote.body.mr_config_id[..32]).unwrap();
        let input_hash = InputHash::from(input_hash);
        let output_hash = OutputHash {
            hash: quote.body.report_data[..32].try_into().unwrap(),
            len: u64::from_le_bytes(quote.body.report_data[32..40].try_into().unwrap()),
        };
        Ok((input_hash, output_hash))
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

#[derive(Debug, Error)]
pub enum Error {
    #[error("failed to parse TD quote")]
    Parse(#[from] tdx_types::td_quote::Error),
    #[error("failed to verify signatures in TD quote")]
    Verify(#[from] tdx_types::td_quote::VerifyError),
    #[error("expected TEE type to be {expected:?}, got {got:?}")]
    Tee { expected: TeeType, got: TeeType },
    #[error("expected QE vendor ID to be {}, got {}", expected.0, got.0)]
    QeVendorId {
        expected: QeVendorId,
        got: QeVendorId,
    },
    #[error("expected TEE TCB SVN to be {expected:?} or newer, got {got:?}")]
    TeeTcbSvn { expected: TeeTcbSvn, got: TeeTcbSvn },
    #[error("expected MRSIGNERSEAM to be all zeros, got {}", hex(.got))]
    MrSignerSeam { got: [u8; 48] },
    #[error("expected SEAMATTRIBUTES to be all zeros, got {}", hex(.got))]
    SeamAttributes { got: [u8; 8] },
    #[error("expected TDATTRIBUTES to be all zeros, got {}", hex(.got))]
    TdAttributes { got: [u8; 8] },
    #[error("expected XFAM to be {}, got {}", hex(.expected), hex(.got))]
    Xfam { expected: [u8; 8], got: [u8; 8] },
    #[error("expected MRTD to be {}, got {}", hex(.expected), hex(.got))]
    MrTd { expected: [u8; 48], got: [u8; 48] },
    #[error("expected MRCONFIGID[32:48] to be all zeros, got {}", hex(.got))]
    MrConfigIdPad { got: [u8; 16] },
    #[error("expected MROWNER to be all zeros, got {}", hex(.got))]
    MrOwner { got: [u8; 48] },
    #[error("expected MROWNERCONFIG to be all zeros, got {}", hex(.got))]
    MrOwnerConfig { got: [u8; 48] },
    #[error("expected RTMR[{index}] to be all zeros, got {}", hex(.got))]
    Rtmr { index: usize, got: [u8; 48] },
    #[error("expected REPORTDATA to be padded with zeros, got {}", hex(.got))]
    ReportData { got: [u8; 24] },
}
