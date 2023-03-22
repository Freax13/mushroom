use std::fmt::Write;

use openssl::x509::{X509VerifyResult, X509};
use thiserror::Error;

pub async fn vcek_cert(
    product: Product,
    chip_id: [u8; 64],
    bootloader: u8,
    tee: u8,
    snp: u8,
    microcode: u8,
) -> Result<X509, Error> {
    let product_name = product.name();
    let mut hw_id = String::with_capacity(128);
    for b in chip_id {
        write!(hw_id, "{b:02x}").unwrap();
    }
    let parameters = format!("blSPL={bootloader}&teeSPL={tee}&snpSPL={snp}&ucodeSPL={microcode}");
    let url = format!("https://kdsintf.amd.com/vcek/v1/{product_name}/{hw_id}?{parameters}");

    let resp = reqwest::get(url).await?;
    let vcek_cert = resp.bytes().await?;

    let ask = product.ask();

    let vcek_cert = X509::from_der(&vcek_cert)?;

    let result = ask.issued(&vcek_cert);
    if result != X509VerifyResult::OK {
        return Err(Error::X509VerifyResult(result));
    }

    Ok(vcek_cert)
}

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),
    #[error(transparent)]
    X509(#[from] openssl::error::ErrorStack),
    #[error("unexpected verification result: {0}")]
    X509VerifyResult(X509VerifyResult),
}

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

    pub fn ask(&self) -> X509 {
        let ask_ark = match self {
            Product::Milan => include_bytes!("Milan.crt"),
            Product::Genoa => todo!(),
        };

        X509::from_der(ask_ark).unwrap()
    }
}
