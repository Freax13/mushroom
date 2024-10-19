use std::{
    fmt::{self, Display},
    io::ErrorKind,
    path::{Path, PathBuf},
};

use anyhow::{bail, ensure, Context, Result};
use bytemuck::checked::try_pod_read_unaligned;
use clap::{Args, Parser, Subcommand, ValueEnum};
use mushroom::{profiler::ProfileFolder, KvmHandle, Tee};
use mushroom_verify::{
    snp::{Configuration, VcekParameters},
    tdx, InputHash, OutputHash,
};
use snp_types::{attestation::TcbVersion, guest_policy::GuestPolicy};
use tdx_types::td_quote::{Quote, TeeTcbSvn};
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
    /// Path to the supervisor for SNP.
    #[arg(long,
        value_name = "PATH",
        env = "SUPERVISOR_SNP",
        required_unless_present = "tee",
        required_if_eq_any([("tee", "auto"), ("tee", "snp")]),
    )]
    supervisor_snp: Option<PathBuf>,
    /// Path to the supervisor for TDX.
    #[arg(
        long,
        value_name = "PATH",
        env = "SUPERVISOR_TDX",
        required_unless_present = "tee",
        required_if_eq_any([("tee", "auto"), ("tee", "tdx")]),
    )]
    supervisor_tdx: Option<PathBuf>,
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
    /// TEE used to run the workload.
    #[arg(long = "tee", env = "TEE", default_value_t = TeeWithAuto::Auto)]
    tee: TeeWithAuto,
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
    #[arg(
        long,
        value_name = "PATH",
        required_unless_present = "tee",
        required_if_eq_any([("tee", "auto"), ("tee", "snp"), ("tee", "tdx")]),
    )]
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
    /// Vsock CID used to connect to the quote generation service.
    #[arg(long, value_name = "CID", default_value_t = 2)]
    qgs_cid: u32,
    /// Vsock port used to connect to the quote generation service.
    #[arg(long, value_name = "PORT", default_value_t = 4050)]
    qgs_port: u32,
}

#[derive(ValueEnum, Clone, Copy)]
pub enum TeeWithAuto {
    Snp,
    Tdx,
    Insecure,
    Auto,
}

impl Display for TeeWithAuto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TeeWithAuto::Snp => f.pad("snp"),
            TeeWithAuto::Tdx => f.pad("tdx"),
            TeeWithAuto::Insecure => f.pad("insecure"),
            TeeWithAuto::Auto => f.pad("auto"),
        }
    }
}

fn run(run: RunCommand) -> Result<()> {
    let kernel = std::fs::read(&run.config.kernel).context("failed to read kernel file")?;
    let init = std::fs::read(run.config.init).context("failed to read init file")?;
    let input = std::fs::read(run.io.input).context("failed to read input file")?;

    let kvm_handle = KvmHandle::new()?;

    let tee = match run.config.tee {
        TeeWithAuto::Snp => Tee::Snp,
        TeeWithAuto::Tdx => Tee::Tdx,
        TeeWithAuto::Insecure => Tee::Insecure,
        TeeWithAuto::Auto => {
            if Tee::Snp.is_supported(&kvm_handle)? {
                Tee::Snp
            } else if Tee::Tdx.is_supported(&kvm_handle)? {
                Tee::Tdx
            } else {
                warn!("Neither SNP nor TDX are supported. Falling back to insecure.");
                Tee::Insecure
            }
        }
    };

    let result = match tee {
        Tee::Snp => {
            let supervisor_snp_path = run
                .config
                .supervisor_snp
                .context("missing supervisor path")?;
            let supervisor_snp =
                std::fs::read(supervisor_snp_path).context("failed to read supervisor file")?;

            let profile_folder = run
                .profile_folder
                .map(|profile_folder| ProfileFolder::new(profile_folder, run.config.kernel))
                .transpose()
                .context("failed to create profile folder")?;

            mushroom::snp::main(
                &kvm_handle,
                &supervisor_snp,
                &kernel,
                &init,
                run.config.kasan,
                &input,
                run.config.policy.policy(),
                profile_folder,
            )?
        }
        Tee::Tdx => {
            let supervisor_tdx_path = run
                .config
                .supervisor_tdx
                .context("missing supervisor path")?;
            let supervisor_tdx =
                std::fs::read(supervisor_tdx_path).context("failed to read supervisor file")?;

            let profile_folder = run
                .profile_folder
                .map(|profile_folder| ProfileFolder::new(profile_folder, run.config.kernel))
                .transpose()
                .context("failed to create profile folder")?;

            ensure!(!run.config.kasan, "KASAN is not supported on TDX");

            mushroom::tdx::main(
                &kvm_handle,
                &supervisor_tdx,
                &kernel,
                &init,
                run.config.kasan,
                &input,
                profile_folder,
                run.qgs_cid,
                run.qgs_port,
            )?
        }
        Tee::Insecure => {
            if run.io.attestation_report.is_some() {
                warn!("No attestation report will be produced in insecure mode.");
            }
            if run.profile_folder.is_some() {
                warn!("Profiling in insecure mode is currently not supported.");
            }
            mushroom::insecure::main(&kvm_handle, &kernel, &init, run.config.kasan, &input)?
        }
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
    // SNP:
    /// The smallest allowed value for the `bootloader` field of the launch TCB.
    #[arg(long, default_value_t = 4)]
    bootloader_svn: u8,
    /// The smallest allowed value for the `tee` field of the launch TCB.
    #[arg(long, default_value_t = 0)]
    tee_svn: u8,
    /// The smallest allowed value for the `snp` field of the launch TCB.
    #[arg(long, default_value_t = 22)]
    snp_svn: u8,
    /// The smallest allowed value for the `microcode` field of the launch TCB.
    #[arg(long, default_value_t = 211)]
    microcode_svn: u8,
    // TDX:
    /// TDX module minor SVN.
    #[arg(long, default_value_t = 5)]
    tdx_module_svn_minor: u8,
    /// TDX module major SVN.
    #[arg(long, default_value_t = 1)]
    tdx_module_svn_major: u8,
    /// Microcode SE_SVN at the time the TDX module was loaded.
    #[arg(long, default_value_t = 2)]
    seam_last_patch_svn: u8,
}

impl TcbArgs {
    fn min_tcb(&self) -> TcbVersion {
        TcbVersion::new(
            self.bootloader_svn,
            self.tee_svn,
            self.snp_svn,
            self.microcode_svn,
        )
    }

    fn tee_tcb_svn(&self) -> TeeTcbSvn {
        let mut svns = [0; 16];
        svns[0] = self.tdx_module_svn_minor;
        svns[1] = self.tdx_module_svn_major;
        svns[2] = self.seam_last_patch_svn;
        TeeTcbSvn(svns)
    }
}

async fn verify(run: VerifyCommand) -> Result<()> {
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

    let report = parse_report(run.config.tee, attestation_report)?;
    match report {
        Report::Snp(attestation_report) => {
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

            let supervisor_snp = std::fs::read(
                run.config
                    .supervisor_snp
                    .context("missing supervisor-snp path")?,
            )
            .context("failed to read supervisor-snp file")?;
            let configuration = Configuration::new(
                &supervisor_snp,
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
        }
        Report::Tdx(attestation_report) => {
            let supervisor_tdx = std::fs::read(
                run.config
                    .supervisor_tdx
                    .context("missing supervisor-tdx path")?,
            )
            .context("failed to read supervisor-tdx file")?;
            let configuration = tdx::Configuration::new(
                &supervisor_tdx,
                &kernel,
                &init,
                run.tcb_args.tee_tcb_svn(),
            );
            configuration
                .verify(input_hash, output_hash, &attestation_report)
                .unwrap();
        }
    }

    println!("Ok");

    Ok(())
}

enum Report {
    Snp(Vec<u8>),
    Tdx(Vec<u8>),
}

fn parse_report(tee: TeeWithAuto, attestation_report: Vec<u8>) -> Result<Report> {
    match tee {
        TeeWithAuto::Snp => Ok(Report::Snp(attestation_report)),
        TeeWithAuto::Tdx => Ok(Report::Tdx(attestation_report)),
        TeeWithAuto::Insecure => bail!("Can't verify output produced in insecure mode."),
        TeeWithAuto::Auto => {
            if try_pod_read_unaligned::<snp_types::attestation::AttestionReport>(
                &attestation_report,
            )
            .is_ok()
            {
                return Ok(Report::Snp(attestation_report));
            }
            if Quote::parse(&attestation_report).is_ok() {
                return Ok(Report::Tdx(attestation_report));
            }
            bail!("Can't determine attestation report type.")
        }
    }
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
