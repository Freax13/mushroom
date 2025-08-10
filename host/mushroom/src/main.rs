use std::{
    fmt::{self, Display},
    io::ErrorKind,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail, ensure};
use bytemuck::checked::try_pod_read_unaligned;
use clap::{Args, Parser, Subcommand, ValueEnum};
use loader::{HashType, Input};
use mushroom::{KvmHandle, MushroomResult, Tee, profiler::ProfileFolder};
use mushroom_verify::{Configuration, HashedInput};
use mushroom_verify::{InputHash, OutputHash};
#[cfg(feature = "snp")]
use snp_types::{attestation::TcbVersion, guest_policy::GuestPolicy};
#[cfg(feature = "tdx")]
use tdx_types::td_quote::{Quote, TeeTcbSvn};
use tracing::warn;
#[cfg(feature = "snp")]
use vcek_kds::{Vcek, VcekParameters};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let mushroom = Mushroom::parse();
    match mushroom.subcommand {
        MushroomSubcommand::Run(args) => run(args).await,
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
        default_value = option_env!("DEFAULT_PATH_SUPERVISOR_SNP"),
        required_unless_present = "tee",
        required_if_eq_any([("tee", "auto"), ("tee", "snp")]),
    )]
    #[cfg(feature = "snp")]
    supervisor_snp: Option<PathBuf>,
    /// Path to the supervisor for TDX.
    #[arg(
        long,
        value_name = "PATH",
        env = "SUPERVISOR_TDX",
        default_value = option_env!("DEFAULT_PATH_SUPERVISOR_TDX"),
        required_unless_present = "tee",
        required_if_eq_any([("tee", "auto"), ("tee", "tdx")]),
    )]
    #[cfg(feature = "tdx")]
    supervisor_tdx: Option<PathBuf>,
    /// Path to the kernel.
    #[arg(
        long,
        value_name = "PATH",
        env = "KERNEL",
        default_value = option_env!("DEFAULT_PATH_KERNEL"),
    )]
    kernel: PathBuf,
    /// Path to the binary to run.
    #[arg(long, value_name = "PATH", env = "INIT")]
    init: PathBuf,
    /// Load KASAN shadow mappings for the kernel.
    #[arg(long, env = "KASAN")]
    kasan: bool,
    #[cfg(feature = "snp")]
    #[command(flatten)]
    policy: PolicyArgs,
    /// TEE used to run the workload.
    #[arg(long = "tee", env = "TEE", default_value_t = TeeWithAuto::Auto)]
    tee: TeeWithAuto,
}

#[derive(Args)]
struct IoArgs {
    /// Paths to the inputs to process.
    ///
    /// By default the inputs are hashed using sha256. A different hash can be
    /// specified by prepending `<HASH-TYPE>:` (e.g. `sha384:`) to the path.
    #[arg(long, value_name = "PATH")]
    input: Vec<PathBuf>,
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

impl IoArgs {
    fn inputs(&self) -> Result<Vec<Input<Vec<u8>>>> {
        let mut inputs = Vec::with_capacity(self.input.len());
        for input in self.input.iter() {
            let mut input: &Path = input;

            let mut hash_type = HashType::Sha256;
            if let Ok(path) = input.strip_prefix("sha256:") {
                hash_type = HashType::Sha256;
                input = path;
            } else if let Ok(path) = input.strip_prefix("sha384:") {
                hash_type = HashType::Sha384;
                input = path;
            }

            let bytes = std::fs::read(input)
                .with_context(|| format!("failed to read input file {}", input.display()))?;
            inputs.push(Input { bytes, hash_type });
        }
        Ok(inputs)
    }
}

#[cfg(feature = "snp")]
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

#[cfg(feature = "snp")]
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
    #[cfg(feature = "tdx")]
    #[arg(long, value_name = "CID", default_value_t = 2)]
    qgs_cid: u32,
    /// Vsock port used to connect to the quote generation service.
    #[arg(long, value_name = "PORT", default_value_t = 4050)]
    #[cfg(feature = "tdx")]
    qgs_port: u32,
}

#[derive(ValueEnum, Clone, Copy)]
pub enum TeeWithAuto {
    #[cfg(feature = "snp")]
    Snp,
    #[cfg(feature = "tdx")]
    Tdx,
    #[cfg(feature = "insecure")]
    Insecure,
    Auto,
}

impl Display for TeeWithAuto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(feature = "snp")]
            TeeWithAuto::Snp => f.pad("snp"),
            #[cfg(feature = "tdx")]
            TeeWithAuto::Tdx => f.pad("tdx"),
            #[cfg(feature = "insecure")]
            TeeWithAuto::Insecure => f.pad("insecure"),
            TeeWithAuto::Auto => f.pad("auto"),
        }
    }
}

async fn run(run: RunCommand) -> Result<()> {
    let kernel = std::fs::read(&run.config.kernel).context("failed to read kernel file")?;
    let init = std::fs::read(run.config.init).context("failed to read init file")?;
    let inputs = run.io.inputs()?;

    let kvm_handle = KvmHandle::new()?;

    let tee: Tee = match run.config.tee {
        #[cfg(feature = "snp")]
        TeeWithAuto::Snp => Tee::Snp,
        #[cfg(feature = "tdx")]
        TeeWithAuto::Tdx => Tee::Tdx,
        #[cfg(feature = "insecure")]
        TeeWithAuto::Insecure => Tee::Insecure,
        TeeWithAuto::Auto => match () {
            #[cfg(feature = "snp")]
            () if Tee::Snp.is_supported(&kvm_handle)? => Tee::Snp,
            #[cfg(feature = "tdx")]
            () if Tee::Tdx.is_supported(&kvm_handle)? => Tee::Tdx,
            #[cfg(feature = "insecure")]
            _ => {
                warn!("No TEE is supported by the host. Falling back to insecure.");
                Tee::Insecure
            }
            #[cfg(not(feature = "insecure"))]
            _ => bail!("Couldn't determine TEE"),
        },
    };

    let result: MushroomResult = match tee {
        #[cfg(feature = "snp")]
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

            let parameters = VcekParameters::current_parameters()?;
            let vcek_cert = if let Some(vcek_cert) = load_vcek_from_cache(parameters).await? {
                vcek_cert
            } else {
                let vcek_cert = Vcek::download(parameters).await?;
                save_vcek_to_cache(parameters, &vcek_cert).await?;
                vcek_cert
            };

            mushroom::snp::main(
                &kvm_handle,
                &supervisor_snp,
                &kernel,
                &init,
                run.config.kasan,
                &inputs,
                run.config.policy.policy(),
                vcek_cert,
                profile_folder,
            )?
        }
        #[cfg(feature = "tdx")]
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
                &inputs,
                profile_folder,
                run.qgs_cid,
                run.qgs_port,
            )?
        }
        #[cfg(feature = "insecure")]
        Tee::Insecure => {
            if run.io.attestation_report.is_some() {
                warn!("No attestation report will be produced in insecure mode.");
            }
            if run.profile_folder.is_some() {
                warn!("Profiling in insecure mode is currently not supported.");
            }
            mushroom::insecure::main(&kvm_handle, &kernel, &init, run.config.kasan, &inputs)?
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
    #[command(flatten)]
    tcb_args: TcbArgs,
}

#[derive(Args)]
struct TcbArgs {
    // SNP:
    /// The smallest allowed value for the `bootloader` field of the launch TCB.
    #[cfg(feature = "snp")]
    #[arg(long, default_value_t = 4)]
    bootloader_svn: u8,
    /// The smallest allowed value for the `tee` field of the launch TCB.
    #[cfg(feature = "snp")]
    #[arg(long, default_value_t = 0)]
    tee_svn: u8,
    /// The smallest allowed value for the `snp` field of the launch TCB.
    #[cfg(feature = "snp")]
    #[arg(long, default_value_t = 22)]
    snp_svn: u8,
    /// The smallest allowed value for the `microcode` field of the launch TCB.
    #[cfg(feature = "snp")]
    #[arg(long, default_value_t = 213)]
    microcode_svn: u8,
    // TDX:
    /// TDX module minor SVN.
    #[cfg(feature = "tdx")]
    #[arg(long, default_value_t = 5)]
    tdx_module_svn_minor: u8,
    /// TDX module major SVN.
    #[cfg(feature = "tdx")]
    #[arg(long, default_value_t = 1)]
    tdx_module_svn_major: u8,
    /// Microcode SE_SVN at the time the TDX module was loaded.
    #[cfg(feature = "tdx")]
    #[arg(long, default_value_t = 2)]
    seam_last_patch_svn: u8,
}

impl TcbArgs {
    #[cfg(feature = "snp")]
    fn min_tcb(&self) -> TcbVersion {
        TcbVersion::new(
            self.bootloader_svn,
            self.tee_svn,
            self.snp_svn,
            self.microcode_svn,
        )
    }

    #[cfg(feature = "tdx")]
    fn tee_tcb_svn(&self) -> TeeTcbSvn {
        TeeTcbSvn::new(
            self.tdx_module_svn_minor,
            self.tdx_module_svn_major,
            self.seam_last_patch_svn,
        )
    }
}

async fn verify(run: VerifyCommand) -> Result<()> {
    let kernel = std::fs::read(run.config.kernel).context("failed to read kernel file")?;
    let init = std::fs::read(run.config.init).context("failed to read init file")?;
    let inputs = run.io.inputs()?;
    let output = std::fs::read(run.io.output).context("failed to read output file")?;
    let attestation_report = std::fs::read(
        run.io
            .attestation_report
            .context("missing attestion report path")?,
    )
    .context("failed to read attestation report")?;

    let input_hash = InputHash::new(inputs.into_iter().map(|input| HashedInput::new(&input)));
    let output_hash = OutputHash::new(&output);

    let report = determine_report_type(run.config.tee, &attestation_report)?;
    let configuration: Configuration = match report {
        #[cfg(feature = "snp")]
        ReportType::Snp => {
            let supervisor_snp = std::fs::read(
                run.config
                    .supervisor_snp
                    .context("missing supervisor-snp path")?,
            )
            .context("failed to read supervisor-snp file")?;
            Configuration::new_snp(
                &supervisor_snp,
                &kernel,
                &init,
                run.config.kasan,
                run.config.policy.policy(),
                run.tcb_args.min_tcb(),
            )
        }
        #[cfg(feature = "tdx")]
        ReportType::Tdx => {
            let supervisor_tdx = std::fs::read(
                run.config
                    .supervisor_tdx
                    .context("missing supervisor-tdx path")?,
            )
            .context("failed to read supervisor-tdx file")?;
            Configuration::new_tdx(&supervisor_tdx, &kernel, &init, run.tcb_args.tee_tcb_svn())
        }
    };

    configuration.verify(input_hash, output_hash, &attestation_report)?;

    println!("Ok");

    Ok(())
}

enum ReportType {
    #[cfg(feature = "snp")]
    Snp,
    #[cfg(feature = "tdx")]
    Tdx,
}

fn determine_report_type(tee: TeeWithAuto, attestation_report: &[u8]) -> Result<ReportType> {
    match tee {
        #[cfg(feature = "snp")]
        TeeWithAuto::Snp => Ok(ReportType::Snp),
        #[cfg(feature = "tdx")]
        TeeWithAuto::Tdx => Ok(ReportType::Tdx),
        #[cfg(feature = "insecure")]
        TeeWithAuto::Insecure => bail!("Can't verify output produced in insecure mode."),
        TeeWithAuto::Auto => {
            #[cfg(feature = "snp")]
            {
                use snp_types::attestation::AttestionReport;
                if attestation_report
                    .get(..size_of::<AttestionReport>())
                    .is_some_and(|report| try_pod_read_unaligned::<AttestionReport>(report).is_ok())
                {
                    return Ok(ReportType::Snp);
                }
            }
            #[cfg(feature = "tdx")]
            if Quote::parse(attestation_report).is_ok() {
                return Ok(ReportType::Tdx);
            }
            bail!("Can't determine attestation report type.")
        }
    }
}

#[cfg(feature = "snp")]
fn cache_file_name(params: VcekParameters) -> String {
    format!("{params}.cert")
}

#[cfg(feature = "snp")]
async fn load_vcek_from_cache(params: VcekParameters) -> Result<Option<Vcek>> {
    use tracing::debug;

    let dirs = xdg::BaseDirectories::with_prefix("mushroom");
    let Some(file) = dirs.find_cache_file(cache_file_name(params)) else {
        debug!(%params, "cache miss");
        return Ok(None);
    };
    debug!(%params, "cache hit");
    let res = tokio::fs::read(file).await;
    let bytes = match res {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err).context("failed to load VCEK from cache"),
    };
    let vcek = Vcek::from_bytes(bytes).context("failed to deserialize VCEK")?;
    Ok(Some(vcek))
}

#[cfg(feature = "snp")]
async fn save_vcek_to_cache(params: VcekParameters, vcek: &Vcek) -> Result<()> {
    let dirs = xdg::BaseDirectories::with_prefix("mushroom");
    let file = dirs.place_cache_file(cache_file_name(params))?;
    tokio::fs::write(file, vcek.raw())
        .await
        .context("failed to save VCEK")?;
    Ok(())
}
