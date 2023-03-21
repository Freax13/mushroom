use anyhow::{Context, Result};
use nix::unistd::gettid;

fn main() -> Result<()> {
    let pid = std::process::id();
    let tid = gettid();
    println!("Hi, my pid is {pid}, my tid is {tid:?}!");

    for i in 0..4 {
        std::thread::spawn(|| {
            for i in 0..4 {
                let _ = std::thread::spawn(|| {
                    std::thread::spawn(|| {
                        for i in 0..4 {
                            let _ = std::thread::spawn(|| {
                                let pid = std::process::id();
                                let tid = gettid();
                                println!("Hi, my pid is {pid}, my tid is {tid:?}!");
                            });
                        }
                    });
                });
            }
        });
    }

    let mut input = std::fs::File::open("/dev/input").context("failed to open input file")?;
    let mut output =
        std::fs::File::create("/dev/output").context("failed to create output file")?;
    std::io::copy(&mut input, &mut output).context("failed to copy")?;
    Ok(())
}
