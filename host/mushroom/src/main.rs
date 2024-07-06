use std::{
    io::ErrorKind,
    path::{Path, PathBuf},
};

use anyhow::{ensure, Context, Result};
use clap::{Args, Parser, Subcommand};
use mushroom::profiler::ProfileFolder;
use mushroom_verify::{Configuration, InputHash, OutputHash, VcekParameters};
use snp_types::{attestation::TcbVersion, guest_policy::GuestPolicy};
use tracing::warn;
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
struct ConfigArgs {
    /// Path to the supervisor.
    #[arg(
        long,
        value_name = "PATH",
        env = "SUPERVISOR",
        required_unless_present = "insecure"
    )]
    supervisor: Option<PathBuf>,
    /// Path to the kernel.
    #[arg(long, value_name = "PATH", env = "KERNEL")]
    kernel: PathBuf,
    /// Path to the binary to run.
    #[arg(long, value_name = "PATH", env = "INIT")]
    init: PathBuf,
    /// Load KASAN shadow mappings for the kernel.
    #[arg(long, env = "KASAN")]
    kasan: bool,
    #[command(flatten)]
    policy: PolicyArgs,
    /// Whether the run the workload in a non-SNP VM.
    #[arg(long)]
    insecure: bool,
}

#[derive(Args)]
struct IoArgs {
    /// Path to the input to process.
    #[arg(long, value_name = "PATH")]
    input: PathBuf,
    /// Path to store the output.
    #[arg(long, value_name = "PATH")]
    output: PathBuf,
    /// Path to store the attestation report.
    #[arg(long, value_name = "PATH", required_unless_present = "insecure")]
    attestation_report: Option<PathBuf>,
}

#[derive(Args)]
struct PolicyArgs {
    /// Minimum required firmware major version.
    #[arg(long, default_value_t = 1)]
    pub abi_major: u8,
    /// Minimum required firmware minor version.
    #[arg(long, default_value_t = 51)]
    pub abi_minor: u8,
    /// Whether not to allow hyperthreading to be active.
    #[arg(long)]
    pub disallow_smt: bool,
    /// Whether to allow multiple sockets.
    #[arg(long)]
    pub multi_socket: bool,
    /// Whether to allow association of an migration agent.
    #[arg(long)]
    pub allow_migration_agent_association: bool,
    /// Whether to allow debugging.
    #[arg(long)]
    pub allow_debugging: bool,
}

impl PolicyArgs {
    fn policy(&self) -> GuestPolicy {
        GuestPolicy::new(self.abi_major, self.abi_minor)
            .with_allow_smt(!self.disallow_smt)
            .with_allow_migration_agent_association(self.allow_migration_agent_association)
            .with_allow_debugging(self.allow_debugging)
            .with_single_socket_only(!self.multi_socket)
    }
}

#[derive(Args)]
struct RunCommand {
    #[command(flatten)]
    config: ConfigArgs,
    #[command(flatten)]
    io: IoArgs,
    /// Collect profile information into the given folder.
    ///
    /// The collected data can be analyzed with uftrace.
    ///
    /// The kernel has to be compiled with the `profiling` feature enabled. The
    /// supervisor has to be compiled with the `hardened` feature disabled.
    ///
    ///  Profiling is currently incompatible with insecure mode.
    #[arg(long, value_name = "PATH", env = "PROFILE_FOLDER")]
    profile_folder: Option<PathBuf>,
}

fn run(run: RunCommand) -> Result<()> {
    let kernel = std::fs::read(&run.config.kernel).context("failed to read kernel file")?;
    let init = std::fs::read(run.config.init).context("failed to read init file")?;
    let input = std::fs::read(run.io.input).context("failed to read input file")?;

    let result = if !run.config.insecure {
        let supervisor_path = run.config.supervisor.context("missing supervisor path")?;
        let supervisor =
            std::fs::read(supervisor_path).context("failed to read supervisor file")?;

        let profile_folder = run
            .profile_folder
            .map(|profile_folder| ProfileFolder::new(profile_folder, run.config.kernel))
            .transpose()
            .context("failed to create profile folder")?;

        mushroom::main(
            &supervisor,
            &kernel,
            &init,
            run.config.kasan,
            &input,
            run.config.policy.policy(),
            profile_folder,
        )?
    } else {
        if run.io.attestation_report.is_some() {
            warn!("No attestation report will be produced in insecure mode.");
        }
        if run.profile_folder.is_some() {
            warn!("Profiling in insecure mode is currently not supported.");
        }
        mushroom::insecure::main(&kernel, &init, run.config.kasan, &input)?
    };

    std::fs::write(run.io.output, result.output).context("failed to write output")?;
    if let Some((path, attestation_report)) =
        run.io.attestation_report.zip(result.attestation_report)
    {
        std::fs::write(path, attestation_report).context("failed to write attestation report")?;
    }

    Ok(())
}

#[derive(Args)]
struct VerifyCommand {
    #[command(flatten)]
    config: ConfigArgs,
    #[command(flatten)]
    io: IoArgs,
    /// Path to store cached VCEKs.
    #[arg(long, value_name = "PATH")]
    vcek_cache: Option<PathBuf>,
    #[command(flatten)]
    tcb_args: TcbArgs,
}

#[derive(Args)]
struct TcbArgs {
    /// The smallest allowed value for the `bootloader`` field of the launch TCB.
    #[arg(long, default_value_t = 4)]
    bootloader: u8,
    /// The smallest allowed value for the `tee` field of the launch TCB.
    #[arg(long, default_value_t = 0)]
    tee: u8,
    /// The smallest allowed value for the `snp` field of the launch TCB.
    #[arg(long, default_value_t = 21)]
    snp: u8,
    /// The smallest allowed value for the `microcode` field of the launch TCB.
    #[arg(long, default_value_t = 211)]
    microcode: u8,
}

impl TcbArgs {
    fn min_tcb(&self) -> TcbVersion {
        TcbVersion::new(self.bootloader, self.tee, self.snp, self.microcode)
    }
}

async fn verify(run: VerifyCommand) -> Result<()> {
    ensure!(
        !run.config.insecure,
        "Can't verify output produced in insecure mode."
    );

    let supervisor = std::fs::read(run.config.supervisor.context("missing supervisor path")?)
        .context("failed to read supervisor file")?;
    let kernel = std::fs::read(run.config.kernel).context("failed to read kernel file")?;
    let init = std::fs::read(run.config.init).context("failed to read init file")?;
    let input = std::fs::read(run.io.input).context("failed to read input file")?;
    let output = std::fs::read(run.io.output).context("failed to read output file")?;
    let attestation_report = std::fs::read(
        run.io
            .attestation_report
            .context("missing attestion report path")?,
    )
    .context("failed to read attestation report")?;

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

    let configuration = Configuration::new(
        &supervisor,
        &kernel,
        &init,
        run.config.kasan,
        run.config.policy.policy(),
        run.tcb_args.min_tcb(),
    );
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
    let vcek = Vcek::from_bytes(product, bytes).context("failed to deserialize VCEK")?;
    Ok(Some(vcek))
}

async fn save_vcek_to_cache(cache: &Path, params: VcekParameters, vcek: &Vcek) -> Result<()> {
    let cache_name = cache_file_name(params);
    tokio::fs::write(cache.join(cache_name), vcek.raw())
        .await
        .context("failed to save VCEK")?;
    Ok(())
}
