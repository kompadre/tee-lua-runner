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
use tee_crypto::ChannelServer;

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
        /// Provision the TEE envelope-unwrap key (X25519 secret, hex32) for
        /// `gate.unwrap`; prints `tee-pk: <hex>` to stderr.
        #[arg(long)]
        tee_key: Option<String>,
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
        /// Wrap frames in the end-to-end channel (HPKE to a per-process
        /// channel key bound into the mock attestation's `public_key`);
        /// prints `channel-pk: <hex>` to stderr.
        #[arg(long)]
        channel: bool,
        /// Fetch attestation documents from an NSM stand-in at this address
        /// (`HOST:PORT` or `vsock:CID:PORT`) instead of signing in-process.
        /// The stand-in prints the trust root. Mutually exclusive with
        /// `--mock-attest`.
        #[arg(long)]
        nsm: Option<String>,
        /// Provision the TEE envelope-unwrap key (X25519 secret, hex32) for
        /// `gate.unwrap`; prints `tee-pk: <hex>` to stderr.
        #[arg(long)]
        tee_key: Option<String>,
    },
    /// Host-side NSM stand-in daemon: the "firmware" that signs attestation
    /// documents on request (same operation API as the real `/dev/nsm`;
    /// Stage 7 swaps this for the ioctl backend).
    NsmStandin {
        /// Listen address: `HOST:PORT` or `vsock:PORT`.
        #[arg(long)]
        listen: String,
        /// Stable Ed25519 root seed (hex32); generated (and NOT printed)
        /// when absent — the *trust root* line is what clients need.
        #[arg(long)]
        seed_hex: Option<String>,
        /// Value for pcr[0] (hex) to embed in documents.
        #[arg(long)]
        pcr0: Option<String>,
        /// module_id for documents (default `nsm-standin`).
        #[arg(long)]
        module_id: Option<String>,
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
            tee_key,
        } => cmd_run(
            &module,
            &request,
            ExecOpts {
                cpu_ms,
                fuel,
                mem_mib,
                mock_attest,
                tee_key,
            },
        ),
        Commands::Serve {
            module,
            listen,
            cpu_ms,
            fuel,
            mem_mib,
            mock_attest,
            channel,
            nsm,
            tee_key,
        } => cmd_serve(
            &module,
            &listen,
            channel,
            nsm,
            ExecOpts {
                cpu_ms,
                fuel,
                mem_mib,
                mock_attest,
                tee_key,
            },
        ),
        Commands::NsmStandin {
            listen,
            seed_hex,
            pcr0,
            module_id,
        } => cmd_nsm_standin(listen, seed_hex, pcr0, module_id),
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

/// Per-invocation execution knobs shared by `run` and `serve`.
struct ExecOpts {
    cpu_ms: u64,
    fuel: u64,
    mem_mib: usize,
    mock_attest: bool,
    tee_key: Option<String>,
}

fn read_module(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(path).with_context(|| format!("reading module {}", path.display()))
}

/// Parses `--tee-key` and prints the derived public key (stderr, first in
/// the documented print order: tee-pk, root, channel-pk, measurement).
fn provision_tee_key(tee_key: Option<&str>) -> Result<Option<[u8; 32]>> {
    let Some(hex_key) = tee_key else {
        return Ok(None);
    };
    let bytes: [u8; 32] = hex::decode(hex_key.trim())
        .context("tee-key is not valid hex")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("tee-key must be exactly 32 bytes"))?;
    eprintln!("tee-pk: {}", hex::encode(tee_crypto::x25519_public(&bytes)));
    Ok(Some(bytes))
}

fn runner_config(
    opts: &ExecOpts,
    attestor: Option<Arc<dyn Attestor>>,
) -> runner_core::RunnerConfig {
    let mut config = runner_core::RunnerConfig::new(limits(opts.cpu_ms, opts.fuel, opts.mem_mib));
    if let Some(attestor) = attestor {
        config = config.with_attestor(attestor);
    }
    config
}

/// Builds the attestation backend for `--mock-attest`.
///
/// The mock's PCR0 binds the runner binary itself (sha256 of the executable),
/// so mock documents carry an inspectable, honest-looking PCR set. When a
/// channel key is present (serve `--channel`), its hex public key is bound
/// into the document's `public_key` field — clients verify the channel key
/// against the attestation. The trust root is printed to stderr for relying
/// parties (tests, manual flows).
fn build_attestor(
    mock_attest: bool,
    channel_pk: Option<&str>,
) -> Result<Option<Arc<dyn Attestor>>> {
    if !mock_attest {
        return Ok(None);
    }
    use sha2::{Digest, Sha256};
    let exe = std::env::current_exe().context("resolving runner binary path")?;
    let exe_bytes = std::fs::read(&exe).with_context(|| format!("reading {}", exe.display()))?;
    let mut pcrs = std::collections::BTreeMap::new();
    pcrs.insert("0".to_string(), hex::encode(Sha256::digest(&exe_bytes)));
    let (backend, root) = MockAttestor::generate("tee-runner-mock", pcrs);
    let backend = match channel_pk {
        Some(pk) => backend.with_public_key(pk),
        None => backend,
    };
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

fn cmd_run(module: &Path, request: &Path, opts: ExecOpts) -> Result<()> {
    let bytes = read_module(module)?;
    let tee_key = provision_tee_key(opts.tee_key.as_deref())?;
    let attestor = build_attestor(opts.mock_attest, None)?;
    let mut config = runner_config(&opts, attestor);
    if let Some(tee_key) = tee_key {
        config = config.with_tee_key(tee_key);
    }
    let mut runner = Runner::build(&bytes, config)?;

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
    channel: bool,
    nsm: Option<String>,
    opts: ExecOpts,
) -> Result<()> {
    if nsm.is_some() && opts.mock_attest {
        anyhow::bail!("--nsm and --mock-attest are mutually exclusive");
    }
    let bytes = read_module(module)?;

    // Stderr print order (documented): tee-pk, root (mock only), channel-pk,
    // measurement. With --nsm the trust root is printed by the stand-in.
    let tee_key = provision_tee_key(opts.tee_key.as_deref())?;

    // Channel key: bound into whichever attestation backend is active.
    let channel = if channel {
        let (server, pk) = ChannelServer::generate();
        Some((server, hex::encode(pk)))
    } else {
        None
    };
    let channel_pk = channel.as_ref().map(|(_, pk)| pk.as_str());
    let attestor = match &nsm {
        Some(addr) => {
            let backend = tee_attest::NsmRemoteAttestor::new(addr, channel_pk.map(String::from))
                .map_err(|err| anyhow::anyhow!(err))?;
            Some(Arc::new(backend) as Arc<dyn Attestor>)
        }
        None => build_attestor(opts.mock_attest, channel_pk)?,
    };
    if let Some((_, pk)) = &channel {
        eprintln!("channel-pk: {pk}");
    }

    let mut config = runner_config(&opts, attestor);
    if let Some(tee_key) = tee_key {
        config = config.with_tee_key(tee_key);
    }
    let mut runner = Runner::build(&bytes, config)?;
    eprintln!("module measurement: {}", runner.measurement_hex());
    server::serve(&mut runner, listen, channel.map(|(server, _)| server))
}

/// The host-side stand-in "firmware": signs documents on request over the
/// NSM operation API (same request/response fields Stage 7 moves to the
/// `/dev/nsm` ioctl). Holds the mock root seed; per-request `public_key`
/// binding uses a fresh-from-seed backend so the root stays stable.
fn cmd_nsm_standin(
    listen: String,
    seed_hex: Option<String>,
    pcr0: Option<String>,
    module_id: Option<String>,
) -> Result<()> {
    use rand::RngCore;
    use tee_proto::transport::{Addr, Listener};

    let seed: [u8; 32] = match seed_hex {
        Some(hex_str) => hex::decode(hex_str.trim())
            .context("seed is not valid hex")?
            .try_into()
            .map_err(|_| anyhow::anyhow!("seed must be exactly 32 bytes"))?,
        None => {
            let mut seed = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut seed);
            seed
        }
    };
    let module_id = module_id.unwrap_or_else(|| "nsm-standin".to_string());
    let pcrs: std::collections::BTreeMap<String, String> = pcr0
        .map(|value| std::collections::BTreeMap::from([("0".to_string(), value)]))
        .unwrap_or_default();

    // Clients need the *trust root*, never the seed.
    let (_, root) = MockAttestor::from_seed(module_id.clone(), pcrs.clone(), seed);
    eprintln!("nsm-standin trust root: {}", root.to_hex());

    let addr: Addr = listen.parse::<Addr>().map_err(|err| anyhow::anyhow!(err))?;
    let listener = Listener::bind(&addr).with_context(|| format!("binding {listen}"))?;
    println!("nsm-standin listening on {}", listener.local_label()?);

    loop {
        let mut stream = match listener.accept() {
            Ok(stream) => stream,
            Err(err) => {
                eprintln!("accept failed: {err}");
                continue;
            }
        };
        if let Err(err) = handle_nsm_conn(&mut stream, seed, &module_id, &pcrs) {
            eprintln!("nsm connection error: {err:#}");
        }
    }
}

fn handle_nsm_conn(
    stream: &mut tee_proto::transport::Stream,
    seed: [u8; 32],
    module_id: &str,
    pcrs: &std::collections::BTreeMap<String, String>,
) -> Result<()> {
    let Some(request_bytes) = tee_proto::framing::read_frame(stream)? else {
        return Ok(());
    };
    let response = match serde_json::from_slice::<tee_attest::NsmRequest>(&request_bytes) {
        Ok(request) => {
            let outcome = (|| -> Result<Vec<u8>, String> {
                let decode = |value: Option<&str>, what: &str| -> Result<Vec<u8>, String> {
                    match value {
                        Some(hex_str) => {
                            hex::decode(hex_str).map_err(|err| format!("invalid {what} hex: {err}"))
                        }
                        None => Ok(Vec::new()),
                    }
                };
                let nonce = decode(request.nonce.as_deref(), "nonce")?;
                let user_data = decode(request.user_data.as_deref(), "user_data")?;
                let (backend, _) =
                    MockAttestor::from_seed(module_id.to_string(), pcrs.clone(), seed);
                let backend = match request.public_key {
                    Some(public_key) => backend.with_public_key(public_key),
                    None => backend,
                };
                backend
                    .attest(&nonce, &user_data)
                    .map_err(|err| err.to_string())
            })();
            match outcome {
                Ok(document) => tee_attest::NsmResponse {
                    document: Some(hex::encode(document)),
                    error: None,
                },
                Err(err) => tee_attest::NsmResponse {
                    document: None,
                    error: Some(err),
                },
            }
        }
        Err(err) => tee_attest::NsmResponse {
            document: None,
            error: Some(format!("bad request: {err}")),
        },
    };
    tee_proto::framing::write_frame(stream, &serde_json::to_vec(&response)?)?;
    Ok(())
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
