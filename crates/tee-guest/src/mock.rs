//! In-process stand-in for the runner's host functions, used when the guest
//! crate is built for native targets (unit tests, workspace builds).
//!
//! Mirrors the wasm-side envelopes: `Ok(value)` on success, `Err(message)` on
//! a host-reported error, with the same messages the real runner produces.

use std::cell::RefCell;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

thread_local! {
    static STATE: RefCell<HashMap<String, Value>> = RefCell::new(HashMap::new());
}

const MAX_STATE_KEY: usize = 256;
const MAX_STATE_VALUE: usize = 64 * 1024;
const MAX_RANDOM_BYTES: usize = 4096;

fn key_str(args: &Value) -> Result<&str, String> {
    let key = args
        .get("key")
        .and_then(Value::as_str)
        .ok_or_else(|| "state: missing or invalid `key`".to_string())?;
    if key.is_empty() || key.len() > MAX_STATE_KEY {
        return Err(format!(
            "state: invalid key length (1..={MAX_STATE_KEY} bytes)"
        ));
    }
    Ok(key)
}

fn hex_field(args: &Value, field: &str) -> Result<Vec<u8>, String> {
    let raw = args
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing `{field}`"))?;
    hex::decode(raw).map_err(|e| format!("invalid hex in `{field}`: {e}"))
}

pub(crate) fn invoke(module: &str, field: &str, args: &Value) -> Result<Value, String> {
    match (module, field) {
        ("log", "log") => {
            let level = args
                .get("level")
                .and_then(Value::as_str)
                .ok_or_else(|| "log: missing `level`".to_string())?;
            if !matches!(level, "debug" | "info" | "warn" | "error") {
                return Err(format!(
                    "log: unknown level `{level}` (use debug/info/warn/error)"
                ));
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
                .ok_or_else(|| "state.set: missing `value`".to_string())?;
            let size = serde_json::to_string(&value).map(|s| s.len()).unwrap_or(0);
            if size > MAX_STATE_VALUE {
                return Err(format!(
                    "state.set: value too large ({size} bytes, limit {MAX_STATE_VALUE})"
                ));
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
                .ok_or_else(|| "random.bytes: missing `n`".to_string())?;
            if n == 0 || n > MAX_RANDOM_BYTES as u64 {
                return Err(format!("random.bytes: n must be 1..={MAX_RANDOM_BYTES}"));
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
            let mut mac = Hmac::<Sha256>::new_from_slice(&key).map_err(|e| format!("hmac: {e}"))?;
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
                .ok_or_else(|| "crypto.hkdf_sha256: missing `len`".to_string())?;
            if len == 0 || len > 255 * 32 {
                return Err("crypto.hkdf_sha256: len must be 1..=8160".to_string());
            }
            let hk = hkdf::Hkdf::<Sha256>::new(Some(&salt), &ikm);
            let mut okm = vec![0u8; len as usize];
            hk.expand(&info, &mut okm)
                .map_err(|e| format!("crypto.hkdf_sha256: {e}"))?;
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
        ("attest", "attest") => Err("tee.attest: no attestation backend configured".to_string()),
        _ => Err(format!("unknown host function {module}.{field}")),
    }
}
