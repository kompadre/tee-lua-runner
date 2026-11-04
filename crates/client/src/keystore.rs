//! Passphrase-protected keystore (at-rest format decision: SESSION 5).
//!
//! ```text
//! TPASSKEY1 ‖ m,t,p (3×u32 LE) ‖ salt(16) ‖ nonce(12) ‖ sealed(80)
//! ```
//!
//! * key = **Argon2id**(passphrase, salt, params) → 32 B
//!   (params recorded in-file so old keystores stay unlockable after default
//!   changes; defaults m=19456 KiB, t=2, p=1 from `argon2::Params::new`)
//! * payload = `LocalIdentity::to_seed()` (64 B) sealed with
//!   ChaCha20Poly1305 (sealed = 64 + 16 tag = 80 B)
//! * the public half is stored beside it (`public.json`) so insert/generate
//!   need no passphrase at all
//!
//! Everything passphrase/derived/seed-related is `Zeroizing` (AGENTS note:
//! zeroize became official at Stage 3 for key material).

use std::path::Path;

use anyhow::{bail, Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use rand::RngCore;
use tee_crypto::LocalIdentity;
use zeroize::Zeroizing;

use crate::config::{KEYSTORE_FILE, PUBLIC_FILE};

const MAGIC: &[u8; 9] = b"TPASSKEY1";
/// Argon2id defaults: m = 19456 KiB, t = 2, p = 1.
const DEFAULT_M_COST: u32 = 19_456;
const DEFAULT_T_COST: u32 = 2;
const DEFAULT_P_COST: u32 = 1;
const KEY_LEN: usize = 32;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const SEED_LEN: usize = 64;
const TAG_LEN: usize = 16;
const SEALED_LEN: usize = SEED_LEN + TAG_LEN;

fn derive_key(passphrase: &[u8], salt: &[u8], m: u32, t: u32, p: u32) -> Result<[u8; KEY_LEN]> {
    let params = Params::new(m, t, p, Some(KEY_LEN))
        .map_err(|err| anyhow::anyhow!("argon2 params: {err}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; KEY_LEN];
    argon2
        .hash_password_into(passphrase, salt, &mut key)
        .map_err(|err| anyhow::anyhow!("argon2: {err}"))?;
    Ok(key)
}

/// Creates the sealed keystore and the public half in `store`.
pub fn create(store: &Path, passphrase: &[u8], identity: &LocalIdentity) -> Result<()> {
    std::fs::create_dir_all(store)
        .with_context(|| format!("creating store {}", store.display()))?;

    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    rand::rngs::OsRng.fill_bytes(&mut nonce);

    let key = Zeroizing::new(derive_key(
        passphrase,
        &salt,
        DEFAULT_M_COST,
        DEFAULT_T_COST,
        DEFAULT_P_COST,
    )?);
    let seed = identity.to_seed();
    let sealed = ChaCha20Poly1305::new(Key::from_slice(&*key))
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &seed[..],
                aad: MAGIC,
            },
        )
        .map_err(|err| anyhow::anyhow!("keystore encryption failed: {err}"))?;
    debug_assert_eq!(sealed.len(), SEALED_LEN);

    let mut file = Vec::with_capacity(MAGIC.len() + 12 + SALT_LEN + NONCE_LEN + SEALED_LEN);
    file.extend_from_slice(MAGIC);
    file.extend_from_slice(&DEFAULT_M_COST.to_le_bytes());
    file.extend_from_slice(&DEFAULT_T_COST.to_le_bytes());
    file.extend_from_slice(&DEFAULT_P_COST.to_le_bytes());
    file.extend_from_slice(&salt);
    file.extend_from_slice(&nonce);
    file.extend_from_slice(&sealed);
    std::fs::write(store.join(KEYSTORE_FILE), file)
        .with_context(|| format!("writing {}", store.join(KEYSTORE_FILE).display()))?;

    let public = serde_json::to_string_pretty(&identity.public())?;
    std::fs::write(store.join(PUBLIC_FILE), public)
        .with_context(|| format!("writing {}", store.join(PUBLIC_FILE).display()))?;
    Ok(())
}

/// Unlocks the keystore with the passphrase (wrong passphrase and tampering
/// both surface as a decrypt failure).
pub fn unlock(store: &Path, passphrase: &[u8]) -> Result<LocalIdentity> {
    let path = store.join(KEYSTORE_FILE);
    let raw = std::fs::read(&path)
        .with_context(|| format!("reading {} (run `tpass init` first)", path.display()))?;
    if raw.len() != MAGIC.len() + 12 + SALT_LEN + NONCE_LEN + SEALED_LEN
        || &raw[..MAGIC.len()] != MAGIC
    {
        bail!("keystore is malformed or has an unknown format");
    }
    let m = u32::from_le_bytes(raw[9..13].try_into().expect("checked length"));
    let t = u32::from_le_bytes(raw[13..17].try_into().expect("checked length"));
    let p = u32::from_le_bytes(raw[17..21].try_into().expect("checked length"));
    let salt = &raw[21..21 + SALT_LEN];
    let nonce = &raw[21 + SALT_LEN..21 + SALT_LEN + NONCE_LEN];
    let sealed = &raw[21 + SALT_LEN + NONCE_LEN..];

    let key = Zeroizing::new(derive_key(passphrase, salt, m, t, p)?);
    let seed = ChaCha20Poly1305::new(Key::from_slice(&*key))
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: sealed,
                aad: MAGIC,
            },
        )
        .map_err(|_| anyhow::anyhow!("wrong passphrase (or corrupted keystore)"))?;
    let seed: [u8; SEED_LEN] = seed
        .try_into()
        .map_err(|_| anyhow::anyhow!("keystore plaintext has an unexpected length"))?;
    Ok(LocalIdentity::from_seed(Zeroizing::new(seed)))
}

/// Loads the public half (no passphrase; used by insert/generate).
pub fn load_public(store: &Path) -> Result<tee_crypto::PublicIdentity> {
    let path = store.join(PUBLIC_FILE);
    let raw = std::fs::read_to_string(&path)
        .with_context(|| format!("reading {} (run `tpass init` first)", path.display()))?;
    serde_json::from_str(&raw).with_context(|| format!("parsing {}", path.display()))
}

/// Read a passphrase from a file (first line) or prompt without echo.
/// `confirm` asks twice (init only).
pub fn read_passphrase(passphrase_file: Option<&Path>, confirm: bool) -> Result<Zeroizing<String>> {
    if let Some(path) = passphrase_file {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading passphrase file {}", path.display()))?;
        let line = raw.strip_suffix('\n').unwrap_or(&raw);
        let line = line.strip_suffix('\r').unwrap_or(line);
        return Ok(Zeroizing::new(line.to_string()));
    }
    if confirm {
        let first = Zeroizing::new(rpassword::prompt_password("Passphrase: ")?);
        let second = Zeroizing::new(rpassword::prompt_password("Confirm passphrase: ")?);
        if *first != *second {
            bail!("passphrases do not match");
        }
        return Ok(first);
    }
    Ok(Zeroizing::new(rpassword::prompt_password("Passphrase: ")?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn temp_store(tag: &str) -> PathBuf {
        let store = std::env::temp_dir().join(format!("tpass-ks-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&store);
        store
    }

    #[test]
    fn create_unlock_roundtrip_and_wrong_passphrase() {
        let store = temp_store("roundtrip");
        let identity = LocalIdentity::from_seed(Zeroizing::new([9u8; 64]));
        create(&store, b"correct horse battery", &identity).unwrap();

        let unlocked = unlock(&store, b"correct horse battery").unwrap();
        assert_eq!(unlocked.public(), identity.public());
        assert!(store.join("keystore").exists());
        assert!(store.join("public.json").exists());

        // Wrong passphrase → decrypt failure with a clear message.
        let err = unlock(&store, b"wrong pass").unwrap_err().to_string();
        assert!(err.contains("wrong passphrase"), "{err}");

        let _ = std::fs::remove_dir_all(&store);
    }

    #[test]
    fn tampered_and_malformed_keystores_are_rejected() {
        let store = temp_store("tamper");
        let identity = LocalIdentity::generate();
        create(&store, b"pass", &identity).unwrap();

        // Flip a sealed byte → AEAD failure.
        let path = store.join("keystore");
        let mut raw = std::fs::read(&path).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 0xff;
        std::fs::write(&path, &raw).unwrap();
        let err = unlock(&store, b"pass").unwrap_err().to_string();
        assert!(err.contains("wrong passphrase"), "{err}");

        // Wrong magic → format error (not a passphrase error).
        let mut raw = std::fs::read(&path).unwrap();
        raw[0] = b'X';
        std::fs::write(&path, &raw).unwrap();
        let err = unlock(&store, b"pass").unwrap_err().to_string();
        assert!(err.contains("malformed"), "{err}");

        let _ = std::fs::remove_dir_all(&store);
    }

    #[test]
    fn unlock_without_store_is_actionable() {
        let store = temp_store("missing");
        let err = unlock(&store, b"pass").unwrap_err().to_string();
        assert!(err.contains("tpass init"), "{err}");
    }
}
