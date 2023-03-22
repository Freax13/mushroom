use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let mushroom = Mushroom::parse();
    match mushroom.subcommand {
        MushroomSubcommand::Run(args) => run(args),
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
    let input = std::fs::read(run.input).context("failed to read init file")?;

    let result = mushroom::main(&init, &input)?;

    std::fs::write(run.output, result.output).context("failed to write output")?;
    std::fs::write(run.attestation_report, result.attestation_report)
        .context("failed to write attestation report")?;

    Ok(())
}
