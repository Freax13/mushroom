use std::{fmt::Write, sync::LazyLock};

use p384::ecdsa::VerifyingKey;
use rsa::{pkcs8::DecodePublicKey, pss, signature::Verifier, RsaPublicKey};
use sha2::Sha384;
use thiserror::Error;
use x509_cert::{
    der::{Decode, Encode},
    Certificate,
};

#[derive(Clone, Copy)]
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
    pub async fn download(
        product: Product,
        chip_id: [u8; 64],
        bootloader: u8,
        tee: u8,
        snp: u8,
        microcode: u8,
    ) -> Result<Vcek, Error> {
        let product_name = product.name();
        let mut hw_id = String::with_capacity(128);
        for b in chip_id {
            write!(hw_id, "{b:02x}").unwrap();
        }
        let parameters =
            format!("blSPL={bootloader}&teeSPL={tee}&snpSPL={snp}&ucodeSPL={microcode}");
        let url = format!("https://kdsintf.amd.com/vcek/v1/{product_name}/{hw_id}?{parameters}");

        let resp = reqwest::get(url).await?;
        let vcek_cert = resp.bytes().await?;

        Self::from_bytes(product, vcek_cert.into())
    }

    pub fn from_bytes(product: Product, vcek_cert: Vec<u8>) -> Result<Vcek, Error> {
        let ask = product.ask();

        // Parse the VCEK.
        let cert = Certificate::from_der(&vcek_cert)?;

        // Verify the VCEK with the ASK.
        let signature = pss::Signature::try_from(cert.signature.raw_bytes()).unwrap();
        ask.verifying_key()
            .verify(&cert.tbs_certificate.to_der().unwrap(), &signature)?;

        // Extract the public key from the VCEK.
        let public_key = cert
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key;
        let verifying_key = VerifyingKey::from_sec1_bytes(public_key.as_bytes().unwrap()).unwrap();

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
}
