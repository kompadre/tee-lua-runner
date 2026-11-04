//! `tpass` — pass-like client for the attestable throttle/gate service.
//!
//! Flow for anything networked: plaintext attestation challenge (freshness
//! nonce, root + pinned measurement verification) → channel key from the
//! *verified* document → channel-wrapped protocol requests. Entries at rest
//! are `E_TEE(E_local(secret))`; only unlocked local keys read plaintext.

mod commands;
mod config;
mod keystore;
mod remote;

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Result;
use clap::{Parser, Subcommand};

use commands::Ctx;

#[derive(Parser)]
#[command(
    name = "tpass",
    about = "Pass-like client for the attestable throttle/gate service"
)]
struct Cli {
    /// Store directory (keystore, config, entries).
    #[arg(long, global = true)]
    store: Option<PathBuf>,
    /// Read the passphrase from this file (first line) instead of prompting.
    #[arg(long, global = true)]
    passphrase_file: Option<PathBuf>,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create the store: identity, sealed keystore, public half, config.
    Init {
        /// Enclave address (host:port of `tee-runner serve`).
        #[arg(long)]
        server: Option<String>,
        /// Hex trust root for attestation verification.
        #[arg(long)]
        root: Option<String>,
        /// Pinned module measurement (hex).
        #[arg(long)]
        measurement: Option<String>,
        /// Pinned TEE envelope key (hex, X25519 public).
        #[arg(long)]
        tee_pk: Option<String>,
    },
    /// Fetch and verify the attestation document; print its payload.
    Attest {
        /// Enclave address (falls back to config).
        #[arg(long)]
        server: Option<String>,
        /// Hex trust root (falls back to config).
        #[arg(long)]
        root: Option<String>,
        /// Expected measurement (hex); enforced when present.
        #[arg(long)]
        measurement: Option<String>,
        /// Pinned TEE envelope key (hex).
        #[arg(long)]
        tee_pk: Option<String>,
        /// Expected enclave-image PCR0 (hex, from the measurements
        /// manifest); enforced when present, falls back to config.
        #[arg(long)]
        pcr0: Option<String>,
        /// Save pins to the config (root, server, TOFU measurement,
        /// attested envelope key, PCR0, discovered channel mode).
        #[arg(long)]
        save: bool,
    },
    /// Generate a random password and insert it.
    Generate {
        /// Entry name.
        name: String,
        /// Password length (8..=128).
        #[arg(long, default_value_t = 24)]
        length: usize,
    },
    /// Insert a secret read from stdin (pass convention).
    Insert {
        /// Entry name.
        name: String,
    },
    /// Fetch and print an entry's plaintext.
    Show {
        /// Entry name.
        name: String,
    },
    /// List entry names.
    List,
    /// Delete a local entry.
    Rm {
        /// Entry name.
        name: String,
    },
    /// Blacklist this identity at the enclave (PoP-gated).
    Revoke,
    /// Print the service's audit ring (decisions, never secrets).
    Audit,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let store = cli.store.unwrap_or_else(default_store);
    let ctx = Ctx {
        store,
        passphrase_file: cli.passphrase_file,
    };
    match cli.command {
        Commands::Init {
            server,
            root,
            measurement,
            tee_pk,
        } => commands::init(&ctx, server, root, measurement, tee_pk),
        Commands::Attest {
            server,
            root,
            measurement,
            tee_pk,
            pcr0,
            save,
        } => commands::attest(&ctx, server, root, measurement, tee_pk, pcr0, save),
        Commands::Generate { name, length } => commands::generate(&ctx, &name, length),
        Commands::Insert { name } => commands::insert(&ctx, &name),
        Commands::Show { name } => commands::show(&ctx, &name),
        Commands::List => commands::list(&ctx),
        Commands::Rm { name } => commands::rm(&ctx, &name),
        Commands::Revoke => commands::revoke(&ctx),
        Commands::Audit => commands::audit(&ctx),
    }
}

fn default_store() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".tpass")
}
