//! `tee-runner` — host CLI for running attestable wasm service modules.
//!
//! * `measure` — print the capability manifest and module measurement
//! * `run`     — handle a single JSON request, print the JSON response
//! * `serve`   — handle length-prefixed JSON frames over TCP

mod server;

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use runner_core::{measure_module, Limits, Runner};

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
        } => cmd_run(&module, &request, cpu_ms, fuel, mem_mib),
        Commands::Serve {
            module,
            listen,
            cpu_ms,
            fuel,
            mem_mib,
        } => cmd_serve(&module, &listen, cpu_ms, fuel, mem_mib),
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

fn cmd_run(module: &Path, request: &Path, cpu_ms: u64, fuel: u64, mem_mib: usize) -> Result<()> {
    let bytes = read_module(module)?;
    let mut runner = Runner::new(&bytes, limits(cpu_ms, fuel, mem_mib))?;

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

fn cmd_serve(module: &Path, listen: &str, cpu_ms: u64, fuel: u64, mem_mib: usize) -> Result<()> {
    let bytes = read_module(module)?;
    let mut runner = Runner::new(&bytes, limits(cpu_ms, fuel, mem_mib))?;
    eprintln!("module measurement: {}", runner.measurement_hex());
    server::serve(&mut runner, listen)
}
