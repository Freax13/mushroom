use std::{
    io::ErrorKind,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use mushroom_verify::{Configuration, InputHash, OutputHash, VcekParameters};
use vcek_kds::{Product, Vcek};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let mushroom = Mushroom::parse();
    match mushroom.subcommand {
        MushroomSubcommand::Run(args) => run(args),
        MushroomSubcommand::Verify(args) => verify(args).await,
    }
}

#[derive(Parser)]
#[command(version)]
struct Mushroom {
    #[command(subcommand)]
    subcommand: MushroomSubcommand,
}

#[derive(Subcommand)]
enum MushroomSubcommand {
    /// Run some code.
    Run(RunCommand),
    /// Verify a output and attestation report.
    Verify(VerifyCommand),
}

#[derive(Args)]
struct RunCommand {
    /// Path to the supervisor.
    #[arg(long, value_name = "PATH", env = "SUPERVISOR")]
    supervisor: PathBuf,
    /// Path to the kernel.
    #[arg(long, value_name = "PATH", env = "KERNEL")]
    kernel: PathBuf,
    /// Path to the binary to run.
    #[arg(long, value_name = "PATH", env = "INIT")]
    init: PathBuf,
    /// Path to the input to process.
    #[arg(long, value_name = "PATH")]
    input: PathBuf,
    /// Path to store the output.
    #[arg(long, value_name = "PATH")]
    output: PathBuf,
    /// Path to store the attestation report.
    #[arg(long, value_name = "PATH")]
    attestation_report: PathBuf,
}

fn run(run: RunCommand) -> Result<()> {
    let supervisor = std::fs::read(run.supervisor).context("failed to read supervisor file")?;
    let kernel = std::fs::read(run.kernel).context("failed to read kernel file")?;
    let init = std::fs::read(run.init).context("failed to read init file")?;
    let input = std::fs::read(run.input).context("failed to read input file")?;

    let result = mushroom::main(&supervisor, &kernel, &init, &input)?;

    std::fs::write(run.output, result.output).context("failed to write output")?;
    std::fs::write(run.attestation_report, result.attestation_report)
        .context("failed to write attestation report")?;

    Ok(())
}

#[derive(Args)]
struct VerifyCommand {
    /// Path to the supervisor.
    #[arg(long, value_name = "PATH", env = "SUPERVISOR")]
    supervisor: PathBuf,
    /// Path to the kernel.
    #[arg(long, value_name = "PATH", env = "KERNEL")]
    kernel: PathBuf,
    /// Path to the binary to run.
    #[arg(long, value_name = "PATH", env = "INIT")]
    init: PathBuf,
    /// Path to the input to process.
    #[arg(long, value_name = "PATH")]
    input: PathBuf,
    /// Path to store the output.
    #[arg(long, value_name = "PATH")]
    output: PathBuf,
    /// Path to store the attestation report.
    #[arg(long, value_name = "PATH")]
    attestation_report: PathBuf,
    /// Path to store cached VCEKs.
    #[arg(long, value_name = "PATH")]
    vcek_cache: Option<PathBuf>,
}

async fn verify(run: VerifyCommand) -> Result<()> {
    let supervisor = std::fs::read(run.supervisor).context("failed to read supervisor file")?;
    let kernel = std::fs::read(run.kernel).context("failed to read kernel file")?;
    let init = std::fs::read(run.init).context("failed to read init file")?;
    let input = std::fs::read(run.input).context("failed to read input file")?;
    let output = std::fs::read(run.output).context("failed to read output file")?;
    let attestation_report =
        std::fs::read(run.attestation_report).context("failed to read attestation report")?;

    let input_hash = InputHash::new(&input);
    let output_hash = OutputHash::new(&output);

    // FIXME: use proper error type and use `?` instead of unwrap.
    let product = Product::Milan;
    let params = VcekParameters::for_attestaton_report(&attestation_report).unwrap();

    let mut vcek_cert = None;
    if let Some(cache) = run.vcek_cache.as_ref() {
        vcek_cert = load_vcek_from_cache(cache, product, params).await?;
    }

    let vcek_cert = if let Some(vcek_cert) = vcek_cert {
        vcek_cert
    } else {
        let vcek_cert = vcek_kds::Vcek::download(
            product,
            params.chip_id.chip_id,
            params.tcb.bootloader(),
            params.tcb.tee(),
            params.tcb.snp(),
            params.tcb.microcode(),
        )
        .await?;

        if let Some(cache) = run.vcek_cache.as_ref() {
            save_vcek_to_cache(cache, params, &vcek_cert).await?;
        }

        vcek_cert
    };

    let configuration = Configuration::new(&supervisor, &kernel, &init);
    // FIXME: use proper error type and use `?` instead of unwrap.
    configuration
        .verify(input_hash, output_hash, &attestation_report, &vcek_cert)
        .unwrap();

    println!("Ok");

    Ok(())
}

fn cache_file_name(params: VcekParameters) -> String {
    format!(
        "{}-{}-{}-{}-{}.cert",
        params.chip_id,
        params.tcb.bootloader(),
        params.tcb.tee(),
        params.tcb.snp(),
        params.tcb.microcode(),
    )
}

async fn load_vcek_from_cache(
    cache: &Path,
    product: Product,
    params: VcekParameters,
) -> Result<Option<Vcek>> {
    let cache_name = cache_file_name(params);
    let res = tokio::fs::read(cache.join(cache_name)).await;
    let bytes = match res {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err).context("failed to load VCEK from cache"),
    };
    let vcek = Vcek::from_bytes(product, &bytes).context("failed to deserialize VCEK")?;
    Ok(Some(vcek))
}

async fn save_vcek_to_cache(cache: &Path, params: VcekParameters, vcek: &Vcek) -> Result<()> {
    let cache_name = cache_file_name(params);
    let der = vcek.as_ref().to_der().context("failed to serialize VCEK")?;
    tokio::fs::write(cache.join(cache_name), der)
        .await
        .context("failed to save VCEK")?;
    Ok(())
}
