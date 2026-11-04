//! In-process stand-in for the runner's host functions, used when the guest
//! crate is built for native targets (unit tests, workspace builds).
//!
//! Mirrors the wasm-side envelopes *and error codes* exactly — service tests
//! assert on `HostError::code` values that the real runner produces, so the
//! native path stays an honest stand-in. Only the mock TEE key differs: the
//! native `gate.unwrap` uses [`MOCK_TEE_KEY`], never real key material.

use std::cell::RefCell;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

use crate::host::HostError;

thread_local! {
    static STATE: RefCell<HashMap<String, Value>> = RefCell::new(HashMap::new());
}

const MAX_STATE_KEY: usize = 256;
const MAX_STATE_VALUE: usize = 64 * 1024;
const MAX_RANDOM_BYTES: usize = 4096;

/// Mock TEE envelope-unwrap key for native tests (X25519 scalar).
/// The public key is `tee_crypto::x25519_public(&MOCK_TEE_KEY)`.
pub const MOCK_TEE_KEY: [u8; 32] = [42; 32];

/// Message-only host error (no code) — parity with the runner's plain
/// `host_err` envelopes.
fn err(message: impl Into<String>) -> HostError {
    HostError {
        message: message.into(),
        code: None,
    }
}

/// Coded host error — parity with the runner's `host_err_code` envelopes.
fn err_code(message: impl Into<String>, code: &str) -> HostError {
    HostError {
        message: message.into(),
        code: Some(code.to_string()),
    }
}

fn key_str(args: &Value) -> Result<&str, HostError> {
    let key = args
        .get("key")
        .and_then(Value::as_str)
        .ok_or_else(|| err("state: missing or invalid `key`"))?;
    if key.is_empty() || key.len() > MAX_STATE_KEY {
        return Err(err(format!(
            "state: invalid key length (1..={MAX_STATE_KEY} bytes)"
        )));
    }
    Ok(key)
}

fn hex_field(args: &Value, field: &str) -> Result<Vec<u8>, HostError> {
    let raw = args
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| err(format!("missing `{field}`")))?;
    hex::decode(raw).map_err(|e| err(format!("invalid hex in `{field}`: {e}")))
}

pub(crate) fn invoke(module: &str, field: &str, args: &Value) -> Result<Value, HostError> {
    match (module, field) {
        ("log", "log") => {
            let level = args
                .get("level")
                .and_then(Value::as_str)
                .ok_or_else(|| err("log: missing `level`"))?;
            if !matches!(level, "debug" | "info" | "warn" | "error") {
                return Err(err(format!(
                    "log: unknown level `{level}` (use debug/info/warn/error)"
                )));
            }
            Ok(Value::Null)
        }
        ("state", "get") => {
            let key = key_str(args)?;
            Ok(STATE.with(|state| state.borrow().get(key).cloned().unwrap_or(Value::Null)))
        }
        ("state", "set") => {
            let key = key_str(args)?.to_string();
            let value = args
                .get("value")
                .cloned()
                .ok_or_else(|| err("state.set: missing `value`"))?;
            let size = serde_json::to_string(&value).map(|s| s.len()).unwrap_or(0);
            if size > MAX_STATE_VALUE {
                return Err(err(format!(
                    "state.set: value too large ({size} bytes, limit {MAX_STATE_VALUE})"
                )));
            }
            STATE.with(|state| {
                state.borrow_mut().insert(key, value);
            });
            Ok(Value::Null)
        }
        ("state", "delete") => {
            let key = key_str(args)?.to_string();
            STATE.with(|state| {
                state.borrow_mut().remove(&key);
            });
            Ok(Value::Null)
        }
        ("state", "keys") => {
            let mut keys: Vec<String> = STATE.with(|state| {
                let state = state.borrow();
                state.keys().cloned().collect()
            });
            keys.sort();
            Ok(Value::Array(keys.into_iter().map(Value::String).collect()))
        }
        ("clock", "unix_seconds") => {
            let secs = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            Ok(json!(secs))
        }
        ("random", "bytes") => {
            let n = args
                .get("n")
                .and_then(Value::as_u64)
                .ok_or_else(|| err("random.bytes: missing `n`"))?;
            if n == 0 || n > MAX_RANDOM_BYTES as u64 {
                return Err(err(format!(
                    "random.bytes: n must be 1..={MAX_RANDOM_BYTES}"
                )));
            }
            use rand::RngCore;
            let mut buf = vec![0u8; n as usize];
            rand::rngs::OsRng.fill_bytes(&mut buf);
            Ok(Value::String(hex::encode(buf)))
        }
        ("crypto", "sha256") => {
            use sha2::{Digest, Sha256};
            let data = hex_field(args, "data_hex")?;
            Ok(Value::String(hex::encode(Sha256::digest(&data))))
        }
        ("crypto", "hmac_sha256") => {
            use hmac::{Hmac, Mac};
            use sha2::Sha256;
            let key = hex_field(args, "key_hex")?;
            let data = hex_field(args, "data_hex")?;
            let mut mac =
                Hmac::<Sha256>::new_from_slice(&key).map_err(|e| err(format!("hmac: {e}")))?;
            mac.update(&data);
            Ok(Value::String(hex::encode(mac.finalize().into_bytes())))
        }
        ("crypto", "hkdf_sha256") => {
            use sha2::Sha256;
            let ikm = hex_field(args, "ikm_hex")?;
            let salt = hex_field(args, "salt_hex")?;
            let info = hex_field(args, "info_hex")?;
            let len = args
                .get("len")
                .and_then(Value::as_u64)
                .ok_or_else(|| err("crypto.hkdf_sha256: missing `len`"))?;
            if len == 0 || len > 255 * 32 {
                return Err(err("crypto.hkdf_sha256: len must be 1..=8160"));
            }
            let hk = hkdf::Hkdf::<Sha256>::new(Some(&salt), &ikm);
            let mut okm = vec![0u8; len as usize];
            hk.expand(&info, &mut okm)
                .map_err(|e| err(format!("crypto.hkdf_sha256: {e}")))?;
            Ok(Value::String(hex::encode(okm)))
        }
        ("crypto", "ct_eq") => {
            let a = hex_field(args, "a_hex")?;
            let b = hex_field(args, "b_hex")?;
            if a.len() != b.len() {
                return Ok(json!(false));
            }
            let mut diff = 0u8;
            for (x, y) in a.iter().zip(b.iter()) {
                diff |= x ^ y;
            }
            Ok(json!(diff == 0))
        }
        ("crypto", "ed25519_verify") => {
            let pk = <[u8; 32]>::try_from(
                hex::decode(
                    args.get("pk_hex")
                        .and_then(Value::as_str)
                        .ok_or_else(|| err("crypto.ed25519_verify: missing `pk_hex`"))?,
                )
                .unwrap_or_default()
                .as_slice(),
            )
            .map_err(|_| err("crypto.ed25519_verify: invalid `pk_hex`"))?;
            let sig = <[u8; 64]>::try_from(
                hex::decode(
                    args.get("sig_hex")
                        .and_then(Value::as_str)
                        .ok_or_else(|| err("crypto.ed25519_verify: missing `sig_hex`"))?,
                )
                .unwrap_or_default()
                .as_slice(),
            )
            .map_err(|_| err("crypto.ed25519_verify: invalid `sig_hex`"))?;
            let message = hex::decode(
                args.get("msg_hex")
                    .and_then(Value::as_str)
                    .ok_or_else(|| err("crypto.ed25519_verify: missing `msg_hex`"))?,
            )
            .map_err(|_| err("crypto.ed25519_verify: invalid `msg_hex`"))?;
            let verifying = ed25519_dalek::VerifyingKey::from_bytes(&pk)
                .map_err(|_| err("crypto.ed25519_verify: invalid public key"))?;
            let signature = ed25519_dalek::Signature::from_bytes(&sig);
            Ok(json!(verifying.verify_strict(&message, &signature).is_ok()))
        }
        ("attest", "attest") => Err(err("tee.attest: no attestation backend configured")),
        ("gate", "unwrap") => {
            // Parity with runner-core's `gate_unwrap_envelope`, including
            // message text and stable codes.
            let outer_hex = args
                .get("outer_hex")
                .and_then(Value::as_str)
                .ok_or_else(|| err_code("gate.unwrap: missing `outer_hex`", "bad_request"))?;
            let owner_hex = args
                .get("owner_hex")
                .and_then(Value::as_str)
                .ok_or_else(|| err_code("gate.unwrap: missing `owner_hex`", "bad_request"))?;
            let outer = hex::decode(outer_hex)
                .map_err(|_| err_code("gate.unwrap: invalid hex in `outer_hex`", "bad_request"))?;
            let owner = <[u8; 32]>::try_from(hex::decode(owner_hex).unwrap_or_default().as_slice())
                .map_err(|_| {
                    err_code("gate.unwrap: `owner_hex` must be 32 bytes", "bad_request")
                })?;
            match tee_crypto::tee_unwrap(&MOCK_TEE_KEY, &outer, &owner) {
                Ok(inner) => Ok(Value::String(hex::encode(inner))),
                Err(tee_crypto::CryptoError::WrongOwner) => Err(err_code(
                    "gate.unwrap: envelope addressed to a different owner",
                    "wrong_owner",
                )),
                Err(tee_crypto::CryptoError::OpenFailed) => Err(err_code(
                    "gate.unwrap: envelope did not decrypt",
                    "decrypt_failed",
                )),
                Err(tee_crypto::CryptoError::Malformed(_, detail)) => Err(err_code(
                    format!("gate.unwrap: malformed envelope: {detail}"),
                    "malformed",
                )),
                Err(other) => Err(err_code(format!("gate.unwrap: {other}"), "decrypt_failed")),
            }
        }
        _ => Err(err(format!("unknown host function {module}.{field}"))),
    }
}
