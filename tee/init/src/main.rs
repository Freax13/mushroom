use anyhow::{Context, Result};

fn main() -> Result<()> {
    let pid = std::process::id();
    println!("Hi, my pid is {pid}!");

    if std::env::args().count() == 1 {
        println!("Hello from process 1");

        std::process::Command::new("/bin/init")
            .arg("hello")
            .status()?;
    } else {
        println!("Hello from process 2");

        return Ok(());
    }

    let mut input = std::fs::File::open("/dev/input").context("failed to open input file")?;
    let mut output =
        std::fs::File::create("/dev/output").context("failed to create output file")?;
    std::io::copy(&mut input, &mut output).context("failed to copy")?;
    Ok(())
}
