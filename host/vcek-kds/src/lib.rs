use std::{
    fmt::{self, Display, Write},
    sync::LazyLock,
};

use p384::ecdsa::VerifyingKey;
use rsa::{pkcs8::DecodePublicKey, pss, signature::Verifier, RsaPublicKey};
use sha2::Sha384;
use snp_types::attestation::TcbVersion;
use thiserror::Error;
use x509_cert::{
    der::{referenced::OwnedToRef, Decode, Encode},
    Certificate,
};

#[cfg(unix)]
mod unix;
#[cfg(not(unix))]
mod unsupported;

#[derive(Debug, Clone, Copy)]
pub enum Product {
    Milan,
    Genoa,
}

impl Product {
    pub fn name(&self) -> &'static str {
        match self {
            Product::Milan => "Milan",
            Product::Genoa => "Genoa",
        }
    }

    pub fn ask(&self) -> Ask {
        static MILAN_ASK: LazyLock<Ask> =
            LazyLock::new(|| Ask::from_der(include_bytes!("Milan.crt")).unwrap());
        match self {
            Product::Milan => MILAN_ASK.clone(),
            Product::Genoa => todo!(),
        }
    }
}

#[derive(Clone)]
pub struct Ask {
    verifying_key: pss::VerifyingKey<Sha384>,
}

impl Ask {
    pub fn from_der(x509_der_bytes: &[u8]) -> Result<Self, Error> {
        let cert = Certificate::from_der(x509_der_bytes)?;
        let mut buf = Vec::new();
        cert.tbs_certificate
            .subject_public_key_info
            .encode_to_vec(&mut buf)
            .unwrap();
        let public_key = RsaPublicKey::from_public_key_der(&buf)?;
        let public_key = pss::VerifyingKey::new(public_key);
        Ok(Self {
            verifying_key: public_key,
        })
    }

    fn verifying_key(&self) -> &pss::VerifyingKey<Sha384> {
        &self.verifying_key
    }
}

pub struct Vcek {
    raw: Vec<u8>,
    verifying_key: VerifyingKey,
}

impl Vcek {
    pub async fn download(parameters: VcekParameters) -> Result<Vcek, Error> {
        let product_name = parameters.product.name();
        let mut hw_id = String::with_capacity(128);
        for b in parameters.chip_id {
            write!(hw_id, "{b:02x}").unwrap();
        }
        let query_parameters = format!(
            "blSPL={}&teeSPL={}&snpSPL={}&ucodeSPL={}",
            parameters.tcb.bootloader(),
            parameters.tcb.tee(),
            parameters.tcb.snp(),
            parameters.tcb.microcode()
        );
        let url =
            format!("https://kdsintf.amd.com/vcek/v1/{product_name}/{hw_id}?{query_parameters}");

        let resp = reqwest::get(url).await?;
        let vcek_cert = resp.bytes().await?;

        Self::from_bytes(vcek_cert.into())
    }

    pub fn from_bytes(vcek_cert: Vec<u8>) -> Result<Vcek, Error> {
        // Parse the VCEK.
        let cert = Certificate::from_der(&vcek_cert)?;

        let products = [Product::Milan];
        let is_valid = products.into_iter().any(|product| {
            let ask = product.ask();

            // Verify the VCEK with the ASK.
            let signature = pss::Signature::try_from(cert.signature.raw_bytes()).unwrap();
            ask.verifying_key()
                .verify(&cert.tbs_certificate.to_der().unwrap(), &signature)
                .is_ok()
        });
        if !is_valid {
            return Err(Error::NoMatchingAsk);
        }

        // Extract the public key from the VCEK.
        let public_key = cert.tbs_certificate.subject_public_key_info.owned_to_ref();
        let verifying_key = VerifyingKey::try_from(public_key).unwrap();

        Ok(Vcek {
            raw: vcek_cert,
            verifying_key,
        })
    }

    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    pub fn raw(&self) -> &[u8] {
        &self.raw
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),
    #[error(transparent)]
    Der(#[from] x509_cert::der::Error),
    #[error(transparent)]
    Spki(#[from] x509_cert::spki::Error),
    #[error(transparent)]
    Ecdsa(#[from] p384::ecdsa::Error),
    #[error("couldn't find matching ASK for VCEK")]
    NoMatchingAsk,
}

#[derive(Debug, Clone, Copy)]
pub struct VcekParameters {
    pub product: Product,
    pub chip_id: [u8; 64],
    pub tcb: TcbVersion,
}

impl VcekParameters {
    #[cfg(target_arch = "x86_64")]
    fn current_product() -> std::io::Result<Product> {
        use std::{arch::x86_64::__cpuid, io::Error};

        // Check that the CPU is an AMD CPU.
        let result = unsafe { __cpuid(0) };
        if result.ebx != 0x6874_7541 || result.ecx != 0x444D_4163 || result.edx != 0x6974_6E65 {
            return Err(Error::new(
                std::io::ErrorKind::Unsupported,
                "unsupported CPU vendor",
            ));
        }

        let result = unsafe { __cpuid(1) };
        match result.eax {
            0x00a00f11 => Ok(Product::Milan),
            _ => Err(Error::new(
                std::io::ErrorKind::Unsupported,
                "unsupported CPU model",
            )),
        }
    }

    #[cfg(not(target_arch = "x86_64"))]
    fn current_product() -> std::io::Result<Product> {
        Err(Error::new(
            ErrorKind::Unsupported,
            "fetching product model is not supported on this platform",
        ))
    }
}

impl Display for VcekParameters {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}-", self.product.name())?;
        for b in self.chip_id {
            write!(f, "{b:02x}")?;
        }
        write!(f, "-{}", self.tcb.bootloader())?;
        write!(f, "-{}", self.tcb.tee())?;
        write!(f, "-{}", self.tcb.snp())?;
        write!(f, "-{}", self.tcb.microcode())
    }
}
