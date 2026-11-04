//! Typed wrappers over host capability calls.
//!
//! Binary values cross the boundary as lowercase hex inside JSON envelopes.
//!
//! On wasm32 each wrapper calls its own import directly — no central dispatch
//! table — so `wasm-ld --gc-sections` removes every capability the module
//! does not actually use, keeping the (hashed) import section an honest
//! capability manifest. On other targets (native unit tests, workspace
//! builds) calls are served by [`crate::mock`].
//!
//! Errors are [`HostError`]s: `message` for humans, optional stable `code`
//! for service-side protocol mapping (e.g. `gate.unwrap`'s `wrong_owner`).
//! Both `From<HostError> for String` and `From<String> for HostError` exist
//! so wrappers and services convert with `?` in either direction.

use serde_json::{json, Value};

/// Host-reported failure (see module docs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostError {
    pub message: String,
    pub code: Option<String>,
}

impl HostError {
    fn msg(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            code: None,
        }
    }
}

impl std::fmt::Display for HostError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl From<HostError> for String {
    fn from(err: HostError) -> Self {
        err.message
    }
}

impl From<String> for HostError {
    fn from(message: String) -> Self {
        Self {
            message,
            code: None,
        }
    }
}

#[cfg(target_arch = "wasm32")]
type RawFn = unsafe extern "C" fn(i32, i32) -> i64;

#[cfg(target_arch = "wasm32")]
mod raw {
    #[link(wasm_import_module = "log")]
    extern "C" {
        #[link_name = "log"]
        pub fn log(ptr: i32, len: i32) -> i64;
    }
    #[link(wasm_import_module = "state")]
    extern "C" {
        #[link_name = "get"]
        pub fn state_get(ptr: i32, len: i32) -> i64;
        #[link_name = "set"]
        pub fn state_set(ptr: i32, len: i32) -> i64;
        #[link_name = "delete"]
        pub fn state_delete(ptr: i32, len: i32) -> i64;
        #[link_name = "keys"]
        pub fn state_keys(ptr: i32, len: i32) -> i64;
    }
    #[link(wasm_import_module = "clock")]
    extern "C" {
        #[link_name = "unix_seconds"]
        pub fn unix_seconds(ptr: i32, len: i32) -> i64;
    }
    #[link(wasm_import_module = "random")]
    extern "C" {
        #[link_name = "bytes"]
        pub fn bytes(ptr: i32, len: i32) -> i64;
    }
    #[link(wasm_import_module = "crypto")]
    extern "C" {
        #[link_name = "sha256"]
        pub fn sha256(ptr: i32, len: i32) -> i64;
        #[link_name = "hmac_sha256"]
        pub fn hmac_sha256(ptr: i32, len: i32) -> i64;
        #[link_name = "hkdf_sha256"]
        pub fn hkdf_sha256(ptr: i32, len: i32) -> i64;
        #[link_name = "ct_eq"]
        pub fn ct_eq(ptr: i32, len: i32) -> i64;
        #[link_name = "ed25519_verify"]
        pub fn ed25519_verify(ptr: i32, len: i32) -> i64;
    }
    #[link(wasm_import_module = "attest")]
    extern "C" {
        #[link_name = "attest"]
        pub fn attest(ptr: i32, len: i32) -> i64;
    }
    #[link(wasm_import_module = "gate")]
    extern "C" {
        #[link_name = "unwrap"]
        pub fn unwrap(ptr: i32, len: i32) -> i64;
    }
}

/// Dispatches one host call: direct import on wasm32, mock elsewhere.
macro_rules! host_call {
    ($raw:path, $module:expr, $field:expr, $args:expr) => {{
        let args = $args;
        #[cfg(target_arch = "wasm32")]
        let result = invoke_wasm($raw, &args);
        #[cfg(not(target_arch = "wasm32"))]
        let result = crate::mock::invoke($module, $field, &args);
        result
    }};
}

#[cfg(target_arch = "wasm32")]
fn invoke_wasm(raw: RawFn, args: &Value) -> Result<Value, HostError> {
    let input = serde_json::to_vec(args)
        .map_err(|e| HostError::msg(format!("host call serialization: {e}")))?;
    let in_ptr = crate::abi::alloc(input.len() as i32);
    if in_ptr <= 0 {
        return Err(HostError::msg("guest allocation failed"));
    }
    // SAFETY: `in_ptr` came from this instance's own `alloc` and `input`
    // fits in i32 (requests are size-capped well below 2 GiB).
    unsafe {
        std::ptr::copy_nonoverlapping(input.as_ptr(), in_ptr as *mut u8, input.len());
    }
    let packed = unsafe { raw(in_ptr, input.len() as i32) };
    let (out_ptr, out_len) = crate::abi::unpack(packed).map_err(HostError::msg)?;
    let out_ptr =
        i32::try_from(out_ptr).map_err(|_| HostError::msg("host output pointer too large"))?;
    let out_len = i32::try_from(out_len).map_err(|_| HostError::msg("host output too large"))?;
    let out = crate::abi::read_slice(out_ptr, out_len).map_err(HostError::msg)?;
    let envelope: Value = serde_json::from_slice(out)
        .map_err(|e| HostError::msg(format!("host returned invalid JSON: {e}")))?;
    match envelope.get("ok") {
        Some(Value::Bool(true)) => Ok(envelope.get("value").cloned().unwrap_or(Value::Null)),
        _ => Err(HostError {
            message: envelope
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("host error")
                .to_string(),
            code: envelope
                .get("code")
                .and_then(Value::as_str)
                .map(String::from),
        }),
    }
}

fn hex_value(value: &Value, what: &str) -> Result<Vec<u8>, HostError> {
    let raw = value
        .as_str()
        .ok_or_else(|| HostError::msg(format!("{what} returned a non-string")))?;
    hex::decode(raw).map_err(|e| HostError::msg(format!("{what} returned invalid hex: {e}")))
}

// ---------------------------------------------------------- typed wrappers

pub fn log(level: &str, message: &str) -> Result<(), HostError> {
    host_call!(
        raw::log,
        "log",
        "log",
        json!({ "level": level, "message": message })
    )?;
    Ok(())
}

pub fn state_get(key: &str) -> Result<Value, HostError> {
    host_call!(raw::state_get, "state", "get", json!({ "key": key }))
}

pub fn state_set(key: &str, value: &Value) -> Result<(), HostError> {
    host_call!(
        raw::state_set,
        "state",
        "set",
        json!({ "key": key, "value": value })
    )?;
    Ok(())
}

pub fn state_delete(key: &str) -> Result<(), HostError> {
    host_call!(raw::state_delete, "state", "delete", json!({ "key": key }))?;
    Ok(())
}

pub fn state_keys() -> Result<Vec<String>, HostError> {
    let value = host_call!(raw::state_keys, "state", "keys", json!({}))?;
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(String::from))
                .collect()
        })
        .ok_or_else(|| HostError::msg("state.keys returned a non-array"))
}

pub fn clock_unix() -> Result<i64, HostError> {
    host_call!(raw::unix_seconds, "clock", "unix_seconds", json!({}))?
        .as_i64()
        .ok_or_else(|| HostError::msg("clock.unix_seconds returned a non-integer"))
}

pub fn random_bytes(n: usize) -> Result<Vec<u8>, HostError> {
    let value = host_call!(raw::bytes, "random", "bytes", json!({ "n": n }))?;
    hex_value(&value, "random.bytes")
}

pub fn crypto_sha256(data: &[u8]) -> Result<Vec<u8>, HostError> {
    let value = host_call!(
        raw::sha256,
        "crypto",
        "sha256",
        json!({ "data_hex": hex::encode(data) })
    )?;
    hex_value(&value, "crypto.sha256")
}

pub fn crypto_hmac_sha256(key: &[u8], data: &[u8]) -> Result<Vec<u8>, HostError> {
    let value = host_call!(
        raw::hmac_sha256,
        "crypto",
        "hmac_sha256",
        json!({ "key_hex": hex::encode(key), "data_hex": hex::encode(data) })
    )?;
    hex_value(&value, "crypto.hmac_sha256")
}

pub fn crypto_hkdf_sha256(
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    len: usize,
) -> Result<Vec<u8>, HostError> {
    let value = host_call!(
        raw::hkdf_sha256,
        "crypto",
        "hkdf_sha256",
        json!({
            "ikm_hex": hex::encode(ikm),
            "salt_hex": hex::encode(salt),
            "info_hex": hex::encode(info),
            "len": len,
        })
    )?;
    hex_value(&value, "crypto.hkdf_sha256")
}

pub fn crypto_ct_eq(a: &[u8], b: &[u8]) -> Result<bool, HostError> {
    let value = host_call!(
        raw::ct_eq,
        "crypto",
        "ct_eq",
        json!({ "a_hex": hex::encode(a), "b_hex": hex::encode(b) })
    )?;
    value
        .as_bool()
        .ok_or_else(|| HostError::msg("crypto.ct_eq returned a non-boolean"))
}

/// Ed25519 proof-of-possession verification: `Ok(false)` = valid key but bad
/// signature; `Err` = structurally invalid input (caller bug).
pub fn crypto_ed25519_verify(
    pk: &[u8; 32],
    message: &[u8],
    signature: &[u8; 64],
) -> Result<bool, HostError> {
    let value = host_call!(
        raw::ed25519_verify,
        "crypto",
        "ed25519_verify",
        json!({
            "pk_hex": hex::encode(pk),
            "msg_hex": hex::encode(message),
            "sig_hex": hex::encode(signature),
        })
    )?;
    value
        .as_bool()
        .ok_or_else(|| HostError::msg("crypto.ed25519_verify returned a non-boolean"))
}

pub fn attest(nonce: &[u8]) -> Result<Vec<u8>, HostError> {
    let value = host_call!(
        raw::attest,
        "attest",
        "attest",
        json!({ "nonce_hex": hex::encode(nonce) })
    )?;
    hex_value(&value, "tee.attest")
}

/// Blind-gatekeeper unwrap: returns the inner blob's hex (still sealed to
/// the owner's local key). On failure the `HostError::code` carries the
/// stable code (`wrong_owner`, `decrypt_failed`, `malformed`,
/// `not_provisioned`, `bad_request`) for protocol mapping.
pub fn gate_unwrap(outer: &[u8], owner_pk: &[u8; 32]) -> Result<Value, HostError> {
    host_call!(
        raw::unwrap,
        "gate",
        "unwrap",
        json!({ "outer_hex": hex::encode(outer), "owner_hex": hex::encode(owner_pk) })
    )
}
