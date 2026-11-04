//! `tee-runner` — host CLI for running attestable wasm service modules.
//!
//! * `measure` — print the capability manifest and module measurement
//! * `run`     — handle a single JSON request, print the JSON response
//! * `serve`   — handle length-prefixed JSON frames over TCP
//! * `verify`  — verify an attestation document against a trust root

mod server;

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use runner_core::{measure_module, Limits, Runner};
use tee_attest::{Attestor, Expectations, MockAttestor, TrustRoot};

#[derive(Parser)]
#[command(
    name = "tee-runner",
    about = "Run attestable wasm service modules in a sandbox"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Print the capability manifest and measurement of a module.
    Measure {
        /// Path to the wasm service module.
        module: PathBuf,
    },
    /// Handle a single JSON request and print the JSON response.
    Run {
        /// Path to the wasm service module.
        module: PathBuf,
        /// JSON request file (`-` for stdin).
        #[arg(short, long, default_value = "-")]
        request: PathBuf,
        /// Per-request wall-clock budget in milliseconds (epoch interruption).
        #[arg(long, default_value_t = 500)]
        cpu_ms: u64,
        /// Deterministic fuel (instruction) budget per request.
        #[arg(long, default_value_t = 50_000_000)]
        fuel: u64,
        /// Guest linear-memory limit in MiB.
        #[arg(long, default_value_t = 32)]
        mem_mib: usize,
        /// Use a mock Ed25519 attestation backend; prints the trust root
        /// (`mock-attest-root: <hex>`) to stderr. For local/QEMU testing only.
        #[arg(long)]
        mock_attest: bool,
    },
    /// Serve length-prefixed JSON frames over TCP.
    ///
    /// Each frame is a u32 big-endian length followed by a JSON request.
    /// Responses are wrapped as {"ok":true,"response":...} or
    /// {"ok":false,"error":...}.
    Serve {
        /// Path to the wasm service module.
        module: PathBuf,
        /// Listen address.
        #[arg(long, default_value = "127.0.0.1:7000")]
        listen: String,
        /// Per-request wall-clock budget in milliseconds (epoch interruption).
        #[arg(long, default_value_t = 500)]
        cpu_ms: u64,
        /// Deterministic fuel (instruction) budget per request.
        #[arg(long, default_value_t = 50_000_000)]
        fuel: u64,
        /// Guest linear-memory limit in MiB.
        #[arg(long, default_value_t = 32)]
        mem_mib: usize,
        /// Use a mock Ed25519 attestation backend; prints the trust root
        /// (`mock-attest-root: <hex>`) to stderr. For local/QEMU testing only.
        #[arg(long)]
        mock_attest: bool,
    },
    /// Verify an attestation document against a trust root (reference client).
    Verify {
        /// Trust root public key, hex-encoded (32 bytes for the mock root).
        #[arg(long)]
        root: String,
        /// Attestation document, hex-encoded.
        #[arg(long)]
        doc: String,
        /// Expected freshness nonce, hex-encoded.
        #[arg(long)]
        nonce: Option<String>,
        /// Expected user_data (module measurement), hex-encoded.
        #[arg(long)]
        user_data: Option<String>,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Commands::Measure { module } => cmd_measure(&module),
        Commands::Run {
            module,
            request,
            cpu_ms,
            fuel,
            mem_mib,
            mock_attest,
        } => cmd_run(&module, &request, cpu_ms, fuel, mem_mib, mock_attest),
        Commands::Serve {
            module,
            listen,
            cpu_ms,
            fuel,
            mem_mib,
            mock_attest,
        } => cmd_serve(&module, &listen, cpu_ms, fuel, mem_mib, mock_attest),
        Commands::Verify {
            root,
            doc,
            nonce,
            user_data,
        } => cmd_verify(&root, &doc, nonce.as_deref(), user_data.as_deref()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

fn limits(cpu_ms: u64, fuel: u64, mem_mib: usize) -> Limits {
    Limits {
        max_cpu: Duration::from_millis(cpu_ms),
        max_fuel: fuel,
        max_memory_bytes: mem_mib * 1024 * 1024,
        ..Limits::default()
    }
}

fn read_module(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(path).with_context(|| format!("reading module {}", path.display()))
}

/// Builds the attestation backend for `--mock-attest`.
///
/// The mock's PCR0 binds the runner binary itself (sha256 of the executable),
/// so mock documents carry an inspectable, honest-looking PCR set. The trust
/// root is printed to stderr for relying parties (tests, manual flows).
fn build_attestor(mock_attest: bool) -> Result<Option<Arc<dyn Attestor>>> {
    if !mock_attest {
        return Ok(None);
    }
    use sha2::{Digest, Sha256};
    let exe = std::env::current_exe().context("resolving runner binary path")?;
    let exe_bytes = std::fs::read(&exe).with_context(|| format!("reading {}", exe.display()))?;
    let mut pcrs = std::collections::BTreeMap::new();
    pcrs.insert("0".to_string(), hex::encode(Sha256::digest(&exe_bytes)));
    let (backend, root) = MockAttestor::generate("tee-runner-mock", pcrs);
    eprintln!("mock-attest-root: {}", root.to_hex());
    Ok(Some(Arc::new(backend)))
}

fn cmd_measure(module: &Path) -> Result<()> {
    let bytes = read_module(module)?;
    let (manifest, measurement) = measure_module(&bytes)?;
    let caps: Vec<&str> = manifest.iter().map(|c| c.as_str()).collect();
    let caps = if caps.is_empty() {
        "(none)".to_string()
    } else {
        caps.join(",")
    };
    println!("capabilities: {caps}");
    println!("measurement: {}", runner_core::to_hex(&measurement));
    Ok(())
}

fn cmd_run(
    module: &Path,
    request: &Path,
    cpu_ms: u64,
    fuel: u64,
    mem_mib: usize,
    mock_attest: bool,
) -> Result<()> {
    let bytes = read_module(module)?;
    let attestor = build_attestor(mock_attest)?;
    let mut runner = Runner::build(&bytes, limits(cpu_ms, fuel, mem_mib), attestor)?;

    let raw = read_request(request)?;
    let request: serde_json::Value =
        serde_json::from_slice(&raw).context("request is not valid JSON")?;

    let outcome = runner.call_handle(request);
    print_logs(&mut runner);
    match outcome {
        Ok(resp) => {
            println!("{}", serde_json::to_string(&resp)?);
            Ok(())
        }
        Err(err) => Err(anyhow::anyhow!(err)),
    }
}

fn read_request(path: &Path) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    if path.as_os_str() == "-" {
        std::io::stdin()
            .read_to_end(&mut buf)
            .context("reading request from stdin")?;
    } else {
        buf = std::fs::read(path)
            .with_context(|| format!("reading request file {}", path.display()))?;
    }
    Ok(buf)
}

fn print_logs(runner: &mut Runner) {
    for entry in runner.take_logs() {
        eprintln!("log[{}] {}", entry.level, entry.message);
    }
}

fn cmd_serve(
    module: &Path,
    listen: &str,
    cpu_ms: u64,
    fuel: u64,
    mem_mib: usize,
    mock_attest: bool,
) -> Result<()> {
    let bytes = read_module(module)?;
    let attestor = build_attestor(mock_attest)?;
    let mut runner = Runner::build(&bytes, limits(cpu_ms, fuel, mem_mib), attestor)?;
    eprintln!("module measurement: {}", runner.measurement_hex());
    server::serve(&mut runner, listen)
}

fn cmd_verify(root: &str, doc: &str, nonce: Option<&str>, user_data: Option<&str>) -> Result<()> {
    let root = TrustRoot::from_hex(root)?;
    let document = hex::decode(doc.trim()).context("doc is not valid hex")?;
    let mut expectations = Expectations::new();
    if let Some(nonce) = nonce {
        expectations =
            expectations.with_nonce(&hex::decode(nonce.trim()).context("nonce is not valid hex")?);
    }
    if let Some(user_data) = user_data {
        expectations = expectations
            .with_user_data(&hex::decode(user_data.trim()).context("user_data is not valid hex")?);
    }
    let payload = tee_attest::verify(&root, &document, &expectations)?;
    println!("{}", serde_json::to_string_pretty(&payload)?);
    Ok(())
}
