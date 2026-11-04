//! Store layout and configuration pins for `tpass`.
//!
//! ```text
//! <store>/
//!   keystore     sealed LocalIdentity seed (see keystore.rs)
//!   public.json  the public half (insert/generate need no passphrase)
//!   config.json  operator pins: server, root, measurement, tee_pk, channel
//!   *.entry      sealed password entries (E_TEE(E_local(secret)))
//! ```

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

pub const KEYSTORE_FILE: &str = "keystore";
pub const PUBLIC_FILE: &str = "public.json";
pub const CONFIG_FILE: &str = "config.json";
pub const ENTRY_SUFFIX: &str = ".entry";

/// Operator-pinned trust material and connection settings.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    /// `host:port` of `tee-runner serve`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    /// Hex trust root (attestation verification key).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_hex: Option<String>,
    /// Pinned module measurement (hex, user_data). May start absent and get
    /// trust-on-first-use pinned by `tpass attest --save`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub measurement_hex: Option<String>,
    /// Pinned TEE envelope key (hex, X25519 public). Carried in config until
    /// the attestation payload can carry both enclave keys (Stage 6).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tee_pk_hex: Option<String>,
    /// Whether the server runs in channel mode (discovered from the verified
    /// document's `public_key` field, saved by `attest --save`).
    #[serde(default)]
    pub channel: bool,
}

impl Config {
    pub fn path(store: &Path) -> PathBuf {
        store.join(CONFIG_FILE)
    }

    /// Loads the config; a missing file yields defaults (fresh store).
    pub fn load(store: &Path) -> Result<Self> {
        let path = Self::path(store);
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        serde_json::from_str(&raw).with_context(|| format!("parsing {}", path.display()))
    }

    pub fn save(&self, store: &Path) -> Result<()> {
        std::fs::create_dir_all(store)
            .with_context(|| format!("creating store {}", store.display()))?;
        let path = Self::path(store);
        let raw = serde_json::to_string_pretty(self)?;
        std::fs::write(&path, raw).with_context(|| format!("writing {}", path.display()))
    }
}

/// Validates an entry name and resolves it inside the store. Rejects path
/// traversal and anything outside `[A-Za-z0-9._-]`.
pub fn entry_path(store: &Path, name: &str) -> Result<PathBuf> {
    if name.is_empty() || name.len() > 128 {
        anyhow::bail!("entry name must be 1..=128 characters");
    }
    if name == "." || name == ".." {
        anyhow::bail!("entry name may not be `.` or `..`");
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        anyhow::bail!("entry names may contain only letters, digits, '-', '_', '.'");
    }
    Ok(store.join(format!("{name}{ENTRY_SUFFIX}")))
}

/// Lists entry names (sorted), stripping the `.entry` suffix.
pub fn list_entries(store: &Path) -> Result<Vec<String>> {
    if !store.exists() {
        return Ok(Vec::new());
    }
    let mut names = Vec::new();
    for entry in std::fs::read_dir(store)? {
        let entry = entry?;
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            continue;
        };
        if let Some(stem) = name.strip_suffix(ENTRY_SUFFIX) {
            names.push(stem.to_string());
        }
    }
    names.sort();
    Ok(names)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_roundtrip_and_defaults() {
        let store = std::env::temp_dir().join(format!("tpass-cfg-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&store);

        // Missing file → defaults.
        assert_eq!(Config::load(&store).unwrap(), Config::default());

        let config = Config {
            server: Some("127.0.0.1:7000".into()),
            root_hex: Some("ab".repeat(32)),
            measurement_hex: None,
            tee_pk_hex: Some("cd".repeat(32)),
            channel: true,
        };
        config.save(&store).unwrap();
        assert_eq!(Config::load(&store).unwrap(), config);

        let _ = std::fs::remove_dir_all(&store);
    }

    #[test]
    fn entry_names_are_path_traversal_safe() {
        let store = Path::new("/store");
        assert_eq!(
            entry_path(store, "mail-google").unwrap(),
            Path::new("/store/mail-google.entry")
        );
        for bad in ["", "..", ".", "a/b", "..%2f", "a b", &"n".repeat(129)] {
            assert!(entry_path(store, bad).is_err(), "must reject {bad:?}");
        }
        // Flat, dot-prefixed names are fine (they cannot traverse).
        assert!(entry_path(store, ".config").is_ok());
    }

    #[test]
    fn list_handles_missing_and_extracts_names() {
        let store = std::env::temp_dir().join(format!("tpass-list-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&store);
        assert!(list_entries(&store).unwrap().is_empty());

        std::fs::create_dir_all(&store).unwrap();
        std::fs::write(store.join("beta.entry"), b"x").unwrap();
        std::fs::write(store.join("alpha.entry"), b"y").unwrap();
        std::fs::write(store.join("config.json"), b"{}").unwrap();
        assert_eq!(list_entries(&store).unwrap(), vec!["alpha", "beta"]);

        let _ = std::fs::remove_dir_all(&store);
    }
}
