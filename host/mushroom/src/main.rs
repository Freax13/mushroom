use anyhow::{Context, Result};

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let mut args = std::env::args().skip(1);
    let init = args.next().context("missing init")?;
    let input = args.next().context("missing input")?;

    let init = std::fs::read(init).context("failed to read init file")?;
    let input = std::fs::read(input).context("failed to read input file")?;

    mushroom::main(&init, &input)
}
