//! `tee-runner` — host CLI for running attestable Lua service scripts.
//!
//! * `measure` — print the capability manifest and script measurement
//! * `run`     — handle a single JSON request, print the JSON response
//! * `serve`   — handle length-prefixed JSON frames over TCP

mod server;

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use runner_core::{parse_manifest, script_measurement, to_hex, Limits, Runner};

#[derive(Parser)]
#[command(
    name = "tee-runner",
    about = "Run attestable Lua service scripts in a sandbox"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Print the capability manifest and measurement of a script.
    Measure {
        /// Path to the Lua script.
        script: PathBuf,
    },
    /// Handle a single JSON request and print the JSON response.
    Run {
        /// Path to the Lua script.
        script: PathBuf,
        /// JSON request file (`-` for stdin).
        #[arg(short, long, default_value = "-")]
        request: PathBuf,
        /// Per-request wall-clock budget in milliseconds.
        #[arg(long, default_value_t = 500)]
        cpu_ms: u64,
        /// Lua memory limit in MiB.
        #[arg(long, default_value_t = 32)]
        mem_mib: usize,
    },
    /// Serve length-prefixed JSON frames over TCP.
    ///
    /// Each frame is a u32 big-endian length followed by a JSON request.
    /// Responses are wrapped as {"ok":true,"response":...} or
    /// {"ok":false,"error":...}.
    Serve {
        /// Path to the Lua script.
        script: PathBuf,
        /// Listen address.
        #[arg(long, default_value = "127.0.0.1:7000")]
        listen: String,
        /// Per-request wall-clock budget in milliseconds.
        #[arg(long, default_value_t = 500)]
        cpu_ms: u64,
        /// Lua memory limit in MiB.
        #[arg(long, default_value_t = 32)]
        mem_mib: usize,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Commands::Measure { script } => cmd_measure(&script),
        Commands::Run {
            script,
            request,
            cpu_ms,
            mem_mib,
        } => cmd_run(&script, &request, cpu_ms, mem_mib),
        Commands::Serve {
            script,
            listen,
            cpu_ms,
            mem_mib,
        } => cmd_serve(&script, &listen, cpu_ms, mem_mib),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

fn limits(cpu_ms: u64, mem_mib: usize) -> Limits {
    Limits {
        max_cpu: Duration::from_millis(cpu_ms),
        max_memory_bytes: mem_mib * 1024 * 1024,
        ..Limits::default()
    }
}

fn read_source(script: &Path) -> Result<String> {
    std::fs::read_to_string(script).with_context(|| format!("reading script {}", script.display()))
}

fn cmd_measure(script: &Path) -> Result<()> {
    let source = read_source(script)?;
    let manifest = parse_manifest(&source)?;
    let caps: Vec<&str> = manifest.iter().map(|c| c.as_str()).collect();
    let caps = if caps.is_empty() {
        "(none)".to_string()
    } else {
        caps.join(",")
    };
    println!("capabilities: {caps}");
    println!(
        "measurement: {}",
        to_hex(&script_measurement(&source, &manifest))
    );
    Ok(())
}

fn cmd_run(script: &Path, request: &Path, cpu_ms: u64, mem_mib: usize) -> Result<()> {
    let source = read_source(script)?;
    let mut runner = Runner::new(&source, limits(cpu_ms, mem_mib))?;

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

fn cmd_serve(script: &Path, listen: &str, cpu_ms: u64, mem_mib: usize) -> Result<()> {
    let source = read_source(script)?;
    let mut runner = Runner::new(&source, limits(cpu_ms, mem_mib))?;
    eprintln!("script measurement: {}", runner.measurement_hex());
    server::serve(&mut runner, listen)
}
