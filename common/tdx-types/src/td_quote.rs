mod raw;

use core::num::TryFromIntError;
use std::sync::LazyLock;

use bytemuck::{
    bytes_of,
    checked::{try_pod_read_unaligned, CheckedCastError},
};
use p256::ecdsa::{
    signature::{DigestVerifier, Verifier},
    DerSignature, Signature, VerifyingKey,
};
use p256::EncodedPoint;
pub use raw::{
    AttestationType, Attributes, Body, EnclaveReportBody, Header, QeVendorId, TeeType, Version,
};
use sha2::{Digest, Sha256};
use thiserror::Error;
use x509_cert::{
    der::{referenced::OwnedToRef, DecodePem, Encode},
    Certificate,
};

pub use crate::report::TeeTcbSvn;

#[derive(Debug)]
pub struct Quote {
    pub header: Header,
    pub body: Body,
    pub signature_data: QuoteSignatureData,
}

impl Quote {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        const HEADER_SIZE: usize = size_of::<Header>();
        const BODY_SIZE: usize = size_of::<Body>();
        let (header, bytes) = bytes
            .split_first_chunk::<HEADER_SIZE>()
            .ok_or(Error::TooShort)?;
        let (body, bytes) = bytes
            .split_first_chunk::<BODY_SIZE>()
            .ok_or(Error::TooShort)?;
        Ok(Self {
            header: try_pod_read_unaligned(header)?,
            body: try_pod_read_unaligned(body)?,
            signature_data: QuoteSignatureData::parse(bytes)?,
        })
    }

    pub fn verify_signatures(&self) -> Result<(), VerifyError> {
        // Extract the QE certification data and the PCK chain.
        let signature_data = &self.signature_data;
        let QeCertificationData::QeReportCertificationData {
            qe_report,
            qe_report_signature,
            qe_authentication_data,
            qe_certification_data,
        } = &signature_data.qe_certification_data
        else {
            return Err(VerifyError::ExpectedQeReportCertificationData);
        };
        let QeCertificationData::PckChain {
            pck_leaf_cert,
            intermediate_ca_cert,
            root_ca_cert: _, // We always use the builtin root CA.
        } = &**qe_certification_data
        else {
            return Err(VerifyError::ExpectedPckChain);
        };

        // Verify signature for the header and body of the Quote using the
        // ECDSA attestation key.
        let mut hasher = Sha256::new();
        hasher.update(bytes_of(&self.header));
        hasher.update(bytes_of(&self.body));
        let signature = Signature::from_bytes(&signature_data.quote_signature.into())?;
        let point = EncodedPoint::from_untagged_bytes(&signature_data.ecdsa_attestation_key.into());
        let verifying_key = VerifyingKey::from_encoded_point(&point)?;
        verifying_key.verify_digest(hasher, &signature)?;

        // Verify the report data of the quoting enclave.
        let mut hasher = Sha256::new();
        hasher.update(self.signature_data.ecdsa_attestation_key);
        hasher.update(qe_authentication_data);
        let digest = hasher.finalize();
        let (hash, zeros) = qe_report.report_data.split_at(32);
        if hash != &*digest || *zeros != [0; 32] {
            return Err(VerifyError::InvalidReportData);
        }

        // Verify the QE report using the PCK leaf.
        let signature = Signature::from_bytes(&((*qe_report_signature).into()))?;
        let public_key = pck_leaf_cert
            .tbs_certificate
            .subject_public_key_info
            .owned_to_ref();
        let verifying_key = VerifyingKey::try_from(public_key)?;
        verifying_key.verify(bytes_of(qe_report), &signature)?;

        // Verify the PCK leaf using the intermediate CA.
        let signature = intermediate_ca_cert
            .signature
            .as_bytes()
            .unwrap_or_default();
        let signature = DerSignature::from_bytes(signature)?;
        let public_key = ROOT_CA
            .tbs_certificate
            .subject_public_key_info
            .owned_to_ref();
        let verifying_key = VerifyingKey::try_from(public_key)?;
        verifying_key.verify(&intermediate_ca_cert.tbs_certificate.to_der()?, &signature)?;

        // Verify the intermediate CA using the root CA.
        let signature = pck_leaf_cert.signature.as_bytes().unwrap_or_default();
        let signature = DerSignature::from_bytes(signature)?;
        let public_key = intermediate_ca_cert
            .tbs_certificate
            .subject_public_key_info
            .owned_to_ref();
        let verifying_key = VerifyingKey::try_from(public_key)?;
        verifying_key.verify(&pck_leaf_cert.tbs_certificate.to_der()?, &signature)?;

        Ok(())
    }
}

#[derive(Debug)]
pub struct QuoteSignatureData {
    pub quote_signature: [u8; 64],
    pub ecdsa_attestation_key: [u8; 64],
    pub qe_certification_data: QeCertificationData,
}

impl QuoteSignatureData {
    fn parse(bytes: &[u8]) -> Result<Self> {
        let (&len, bytes) = bytes.split_first_chunk().ok_or(Error::TooShort)?;
        let len = u32::from_le_bytes(len);
        let len = usize::try_from(len)?;
        let bytes = bytes.get(..len).ok_or(Error::TooShort)?;

        let (&quote_signature, bytes) = bytes.split_first_chunk().ok_or(Error::TooShort)?;
        let (&ecdsa_attestation_key, bytes) = bytes.split_first_chunk().ok_or(Error::TooShort)?;
        let qe_certification_data = QeCertificationData::parse(bytes)?;
        Ok(Self {
            quote_signature,
            ecdsa_attestation_key,
            qe_certification_data,
        })
    }
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum QeCertificationData {
    PckChain {
        pck_leaf_cert: Certificate,
        intermediate_ca_cert: Certificate,
        root_ca_cert: Certificate,
    },
    QeReportCertificationData {
        qe_report: EnclaveReportBody,
        qe_report_signature: [u8; 64],
        qe_authentication_data: Vec<u8>,
        qe_certification_data: Box<Self>,
    },
}

impl QeCertificationData {
    fn parse(bytes: &[u8]) -> Result<Self> {
        let (&certification_data_type, bytes) = bytes.split_first_chunk().ok_or(Error::TooShort)?;
        let certification_data_type = u16::from_le_bytes(certification_data_type);

        let (&size, bytes) = bytes.split_first_chunk().ok_or(Error::TooShort)?;
        let size = u32::from_le_bytes(size);
        let size = usize::try_from(size)?;
        let bytes = bytes.get(..size).ok_or(Error::TooShort)?;

        match certification_data_type {
            5 => {
                // Trim zero bytes at the end.
                let mut bytes = bytes;
                while let Some(new_bytes) = bytes.strip_suffix(b"\0") {
                    bytes = new_bytes;
                }

                let certs = Certificate::load_pem_chain(bytes)?;
                let [pck_leaf_cert, intermediate_ca_cert, root_ca_cert] = certs
                    .try_into()
                    .map_err(|certs: Vec<_>| Error::UnexpectedCertAmount(certs.len()))?;
                Ok(Self::PckChain {
                    pck_leaf_cert,
                    intermediate_ca_cert,
                    root_ca_cert,
                })
            }
            6 => {
                const QE_REPORT_SIZE: usize = size_of::<EnclaveReportBody>();
                let (qe_report, bytes) = bytes
                    .split_first_chunk::<QE_REPORT_SIZE>()
                    .ok_or(Error::TooShort)?;
                let (&qe_report_signature, bytes) =
                    bytes.split_first_chunk().ok_or(Error::TooShort)?;
                let (&qe_authentication_data_length, bytes) =
                    bytes.split_first_chunk().ok_or(Error::TooShort)?;
                let qe_authentication_data_length =
                    u16::from_le_bytes(qe_authentication_data_length);
                let qe_authentication_data_length = usize::from(qe_authentication_data_length);
                if bytes.len() < qe_authentication_data_length {
                    return Err(Error::TooShort);
                }
                let (qe_authentication_data, bytes) = bytes.split_at(qe_authentication_data_length);

                Ok(Self::QeReportCertificationData {
                    qe_report: try_pod_read_unaligned(qe_report)?,
                    qe_report_signature,
                    qe_authentication_data: qe_authentication_data.to_vec(),
                    qe_certification_data: Box::new(Self::parse(bytes)?),
                })
            }
            _ => Err(Error::UnknownCertificationDataType(certification_data_type)),
        }
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("unknown certification data type: {0}")]
    UnknownCertificationDataType(u16),
    #[error("expected three certificates, got {0}")]
    UnexpectedCertAmount(usize),
    #[error("not enough bytes")]
    TooShort,
    #[error(transparent)]
    CheckedCastError(#[from] CheckedCastError),
    #[error(transparent)]
    TryFromIntError(#[from] TryFromIntError),
    #[error(transparent)]
    Der(#[from] x509_cert::der::Error),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, Error)]
pub enum VerifyError {
    #[error(transparent)]
    Ecdsa(#[from] p256::ecdsa::Error),
    #[error(transparent)]
    Spki(#[from] x509_cert::spki::Error),
    #[error(transparent)]
    Der(#[from] x509_cert::der::Error),
    #[error("invalid report data")]
    InvalidReportData,
    #[error("the first certification data isn't a QE report")]
    ExpectedQeReportCertificationData,
    #[error("the second certification data isn't a PCK chain")]
    ExpectedPckChain,
}

static ROOT_CA: LazyLock<Certificate> = LazyLock::new(|| {
    let perm = include_str!("Intel_SGX_Provisioning_Certification_RootCA.pem");
    Certificate::from_pem(perm).unwrap()
});
