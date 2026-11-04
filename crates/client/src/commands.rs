//! `tpass` command implementations.

use std::io::Read;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use rand::Rng;
use tee_crypto::{seal_secret, LocalIdentity, PublicIdentity};
use tee_proto::{fetch_pop_message, revoke_pop_message, Request, Response};
use zeroize::Zeroizing;

use crate::config::{self, Config};
use crate::keystore;
use crate::remote::Session;

/// Resolved invocation context (global flags).
pub struct Ctx {
    pub store: PathBuf,
    pub passphrase_file: Option<PathBuf>,
}

impl Ctx {
    fn config(&self) -> Result<Config> {
        Config::load(&self.store)
    }

    fn passphrase(&self, confirm: bool) -> Result<Zeroizing<String>> {
        keystore::read_passphrase(self.passphrase_file.as_deref(), confirm)
    }

    /// The pinned TEE envelope key (clients seal entries to it).
    fn tee_pk(&self) -> Result<[u8; 32]> {
        let config = self.config()?;
        let hex_key = config
            .tee_pk_hex
            .as_deref()
            .context("tee-pk not configured (`tpass attest --tee-pk <hex> --save`)")?;
        tee_proto::decode_pk32(hex_key).context("configured tee-pk is not a 32-byte hex key")
    }

    /// Connects and completes the attestation bootstrap using config pins.
    fn attested_session(&self) -> Result<(Session, Config)> {
        let config = self.config()?;
        let server = config
            .server
            .as_deref()
            .context("server not configured (`tpass init --server` or `attest --save`)")?;
        let root = config
            .root_hex
            .as_deref()
            .context("trust root not configured (`tpass attest --root <hex> --save`)")?;
        let expected = match &config.measurement_hex {
            Some(hex_str) => {
                Some(hex::decode(hex_str).context("configured measurement is not hex")?)
            }
            None => None,
        };
        let mut session = Session::connect(server)?;
        session.attest(root, expected.as_deref())?;
        Ok((session, config))
    }

    fn unlock(&self) -> Result<LocalIdentity> {
        let passphrase = self.passphrase(false)?;
        keystore::unlock(&self.store, passphrase.as_bytes())
    }

    fn public(&self) -> Result<PublicIdentity> {
        keystore::load_public(&self.store)
    }
}

/// Turns a refused/odd protocol response into a user-facing error.
fn refused(response: Response) -> anyhow::Error {
    match response {
        Response::Error {
            code,
            message,
            retry_after_ms,
        } => {
            let mut text = format!("server refused [{}]: {message}", code.as_str());
            if let Some(ms) = retry_after_ms {
                text.push_str(&format!(" (retry in {ms} ms)"));
            }
            anyhow::anyhow!(text)
        }
        other => anyhow::anyhow!("unexpected server response: {other:?}"),
    }
}

// ------------------------------------------------------------------ commands

/// Initializes a fresh store: identity, sealed keystore, public half, config.
pub fn init(
    ctx: &Ctx,
    server: Option<String>,
    root: Option<String>,
    measurement: Option<String>,
    tee_pk: Option<String>,
) -> Result<()> {
    if ctx.store.join(config::KEYSTORE_FILE).exists() {
        bail!("store already initialized at {}", ctx.store.display());
    }
    let identity = LocalIdentity::generate();
    let passphrase = ctx.passphrase(true)?;
    keystore::create(&ctx.store, passphrase.as_bytes(), &identity)?;
    Config {
        server,
        root_hex: root,
        measurement_hex: measurement,
        tee_pk_hex: tee_pk,
        channel: false,
    }
    .save(&ctx.store)?;
    println!("initialized store at {}", ctx.store.display());
    println!("identity key id: {}", identity.public().key_id());
    Ok(())
}

pub fn attest(
    ctx: &Ctx,
    server: Option<String>,
    root: Option<String>,
    measurement: Option<String>,
    tee_pk: Option<String>,
    save: bool,
) -> Result<()> {
    let mut config = ctx.config()?;
    let server = server
        .or(config.server.clone())
        .context("--server (or a configured server) is required")?;
    let root = root
        .or(config.root_hex.clone())
        .context("--root (or a configured trust root) is required")?;
    let measurement_hex = measurement.or(config.measurement_hex.clone());
    let expected = match &measurement_hex {
        Some(hex_str) => Some(hex::decode(hex_str).context("measurement is not hex")?),
        None => None,
    };

    let mut session = Session::connect(&server)?;
    let payload = session.attest(&root, expected.as_deref())?;

    println!("attestation verified");
    println!("  module_id:  {}", payload.module_id);
    println!("  digest:     {}", payload.digest);
    println!("  algorithm:  {}", payload.algorithm);
    println!("  timestamp:  {}", payload.timestamp);
    println!(
        "  measurement: {}",
        payload.user_data.as_deref().unwrap_or("<none>")
    );
    println!(
        "  channel key: {}",
        payload
            .public_key
            .as_deref()
            .unwrap_or("<none> (plain mode)")
    );
    for (index, pcr) in &payload.pcrs {
        println!("  pcr[{index}]: {pcr}");
    }

    if save {
        config.server = Some(server);
        config.root_hex = Some(root);
        if config.measurement_hex.is_none() {
            if let Some(measured) = &payload.user_data {
                config.measurement_hex = Some(measured.clone());
                println!("pinned measurement (trust on first use): {measured}");
            }
        }
        if let Some(pk) = tee_pk {
            config.tee_pk_hex = Some(pk);
        }
        config.channel = payload.public_key.is_some();
        config.save(&ctx.store)?;
        println!("config saved: {}", Config::path(&ctx.store).display());
    }
    Ok(())
}

pub fn insert(ctx: &Ctx, name: &str) -> Result<()> {
    let mut value = Vec::new();
    std::io::stdin()
        .read_to_end(&mut value)
        .context("reading the secret from stdin")?;
    // Pass convention: strip one trailing newline.
    if value.last() == Some(&b'\n') {
        value.pop();
        if value.last() == Some(&b'\r') {
            value.pop();
        }
    }
    insert_value(ctx, name, &value)
}

pub fn generate(ctx: &Ctx, name: &str, length: usize) -> Result<()> {
    if !(8..=128).contains(&length) {
        bail!("length must be 8..=128");
    }
    insert_value(ctx, name, generate_password(length).as_bytes())
}

fn insert_value(ctx: &Ctx, name: &str, value: &[u8]) -> Result<()> {
    if value.is_empty() {
        bail!("refusing to insert an empty value");
    }
    let path = config::entry_path(&ctx.store, name)?;
    let tee_pk = ctx.tee_pk()?;
    let public = ctx.public()?;
    let blob = seal_secret(&tee_pk, &public.encryption, value)?;
    std::fs::write(&path, blob).with_context(|| format!("writing {}", path.display()))?;
    println!("inserted {name}");
    Ok(())
}

pub fn show(ctx: &Ctx, name: &str) -> Result<()> {
    let path = config::entry_path(&ctx.store, name)?;
    let outer = std::fs::read(&path)
        .with_context(|| format!("reading {} (no such entry?)", path.display()))?;

    // Unlock first: fail fast before touching the network.
    let identity = ctx.unlock()?;
    let public = identity.public();
    let pop = identity.sign(&fetch_pop_message(
        &public.signing,
        &public.encryption,
        &outer,
    ));
    let request = Request::Fetch {
        sign_pk: hex::encode(public.signing),
        enc_pk: hex::encode(public.encryption),
        envelope: hex::encode(&outer),
        pop: hex::encode(pop),
    };

    let (mut session, _config) = ctx.attested_session()?;
    match session.request(&request)? {
        Response::Fetch { inner } => {
            let inner = hex::decode(&inner).context("inner blob is not hex")?;
            let secret = identity
                .open_inner(&inner)
                .map_err(|err| anyhow::anyhow!("local decrypt failed: {err}"))?;
            let secret = String::from_utf8(secret).context("secret is not valid UTF-8")?;
            println!("{secret}");
            Ok(())
        }
        other => Err(refused(other)),
    }
}

pub fn list(ctx: &Ctx) -> Result<()> {
    for name in config::list_entries(&ctx.store)? {
        println!("{name}");
    }
    Ok(())
}

pub fn rm(ctx: &Ctx, name: &str) -> Result<()> {
    let path = config::entry_path(&ctx.store, name)?;
    std::fs::remove_file(&path)
        .with_context(|| format!("removing {} (no such entry?)", path.display()))?;
    println!("removed {name}");
    Ok(())
}

pub fn revoke(ctx: &Ctx) -> Result<()> {
    let identity = ctx.unlock()?;
    let public = identity.public();
    let pop = identity.sign(&revoke_pop_message(&public.signing, &public.encryption));
    let request = Request::Revoke {
        sign_pk: hex::encode(public.signing),
        enc_pk: hex::encode(public.encryption),
        pop: hex::encode(pop),
    };

    let (mut session, _config) = ctx.attested_session()?;
    match session.request(&request)? {
        Response::Revoke => {
            println!("identity revoked: {}", hex::encode(public.signing));
            println!("existing entries are now unusable; remove them with `tpass rm`");
            Ok(())
        }
        other => Err(refused(other)),
    }
}

pub fn audit(ctx: &Ctx) -> Result<()> {
    let (mut session, _config) = ctx.attested_session()?;
    match session.request(&Request::Audit)? {
        Response::Audit { entries } => {
            if entries.is_empty() {
                println!("(audit ring is empty)");
                return Ok(());
            }
            for entry in entries {
                println!(
                    "#{} ts={} {} {} owner={}",
                    entry.seq, entry.ts, entry.action, entry.outcome, entry.owner
                );
            }
            Ok(())
        }
        other => Err(refused(other)),
    }
}

/// Random password over a human-usable alphabet (no ambiguous 0/O/1/l/I).
fn generate_password(length: usize) -> String {
    const CHARSET: &[u8] = b"abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*-_=+";
    let mut rng = rand::rngs::OsRng;
    (0..length)
        .map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_password_length_and_alphabet() {
        let value = generate_password(24);
        assert_eq!(value.len(), 24);
        assert!(value.chars().all(|c| {
            b"abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*-_=+"
                .contains(&(c as u8))
        }));
        // Randomness sanity: two draws differ (1 in 2^190 chance of collision).
        assert_ne!(generate_password(24), generate_password(24));
    }
}
