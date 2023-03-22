use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use mushroom_verify::{Configuration, InputHash, OutputHash, VcekParameters};
use vcek_kds::Product;

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
    /// Path to the binary to run.
    #[arg(long, value_name = "PATH")]
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
    let init = std::fs::read(run.init).context("failed to read init file")?;
    let input = std::fs::read(run.input).context("failed to read input file")?;

    let result = mushroom::main(&init, &input)?;

    std::fs::write(run.output, result.output).context("failed to write output")?;
    std::fs::write(run.attestation_report, result.attestation_report)
        .context("failed to write attestation report")?;

    Ok(())
}

#[derive(Args)]
struct VerifyCommand {
    /// Path to the binary to run.
    #[arg(long, value_name = "PATH")]
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

async fn verify(run: VerifyCommand) -> Result<()> {
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
    let vcek_cert = vcek_kds::vcek_cert(
        product,
        params.chip_id,
        params.tcb.bootloader(),
        params.tcb.tee(),
        params.tcb.snp(),
        params.tcb.microcode(),
    )
    .await?;

    let configuration = Configuration::new(&init);
    // FIXME: use proper error type and use `?` instead of unwrap.
    configuration
        .verify(input_hash, output_hash, &attestation_report, &vcek_cert)
        .unwrap();

    println!("Ok");

    Ok(())
}
