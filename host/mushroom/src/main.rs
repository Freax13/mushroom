use anyhow::{Context, Result};

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let mut args = std::env::args().skip(1);
    let init = args.next().context("missing init")?;
    let input = args.next().context("missing input")?;
    let output = args.next().context("missing output")?;
    let attestation_report = args.next().context("missing attestation report")?;

    let init = std::fs::read(init).context("failed to read init file")?;
    let input = std::fs::read(input).context("failed to read input file")?;

    let result = mushroom::main(&init, &input)?;

    std::fs::write(output, result.output).context("failed to write output")?;
    std::fs::write(attestation_report, result.attestation_report)
        .context("failed to write attestation report")?;

    Ok(())
}
