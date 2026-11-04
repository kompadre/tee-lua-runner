//! Typed wrappers over host capability calls.
//!
//! Binary values cross the boundary as lowercase hex inside JSON envelopes.
//!
//! On wasm32 each wrapper calls its own import directly — no central dispatch
//! table — so `wasm-ld --gc-sections` removes every capability the module
//! does not actually use, keeping the (hashed) import section an honest
//! capability manifest. On other targets (native unit tests, workspace
//! builds) calls are served by [`crate::mock`].

use serde_json::{json, Value};

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
    }
    #[link(wasm_import_module = "attest")]
    extern "C" {
        #[link_name = "attest"]
        pub fn attest(ptr: i32, len: i32) -> i64;
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
fn invoke_wasm(raw: RawFn, args: &Value) -> Result<Value, String> {
    let input = serde_json::to_vec(args).map_err(|e| format!("host call serialization: {e}"))?;
    let in_ptr = crate::abi::alloc(input.len() as i32);
    if in_ptr <= 0 {
        return Err("guest allocation failed".to_string());
    }
    // SAFETY: `in_ptr` came from this instance's own `alloc` and `input`
    // fits in i32 (requests are size-capped well below 2 GiB).
    unsafe {
        std::ptr::copy_nonoverlapping(input.as_ptr(), in_ptr as *mut u8, input.len());
    }
    let packed = unsafe { raw(in_ptr, input.len() as i32) };
    let (out_ptr, out_len) = crate::abi::unpack(packed)?;
    let out_ptr =
        i32::try_from(out_ptr).map_err(|_| "host output pointer too large".to_string())?;
    let out_len = i32::try_from(out_len).map_err(|_| "host output too large".to_string())?;
    let out = crate::abi::read_slice(out_ptr, out_len)?;
    let envelope: Value =
        serde_json::from_slice(out).map_err(|e| format!("host returned invalid JSON: {e}"))?;
    match envelope.get("ok") {
        Some(Value::Bool(true)) => Ok(envelope.get("value").cloned().unwrap_or(Value::Null)),
        _ => Err(envelope
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("host error")
            .to_string()),
    }
}

fn hex_value(value: &Value, what: &str) -> Result<Vec<u8>, String> {
    let raw = value
        .as_str()
        .ok_or_else(|| format!("{what} returned a non-string"))?;
    hex::decode(raw).map_err(|e| format!("{what} returned invalid hex: {e}"))
}

// ---------------------------------------------------------- typed wrappers

pub fn log(level: &str, message: &str) -> Result<(), String> {
    host_call!(
        raw::log,
        "log",
        "log",
        json!({ "level": level, "message": message })
    )?;
    Ok(())
}

pub fn state_get(key: &str) -> Result<Value, String> {
    host_call!(raw::state_get, "state", "get", json!({ "key": key }))
}

pub fn state_set(key: &str, value: &Value) -> Result<(), String> {
    host_call!(
        raw::state_set,
        "state",
        "set",
        json!({ "key": key, "value": value })
    )?;
    Ok(())
}

pub fn state_delete(key: &str) -> Result<(), String> {
    host_call!(raw::state_delete, "state", "delete", json!({ "key": key }))?;
    Ok(())
}

pub fn state_keys() -> Result<Vec<String>, String> {
    let value = host_call!(raw::state_keys, "state", "keys", json!({}))?;
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(String::from))
                .collect()
        })
        .ok_or_else(|| "state.keys returned a non-array".to_string())
}

pub fn clock_unix() -> Result<i64, String> {
    host_call!(raw::unix_seconds, "clock", "unix_seconds", json!({}))?
        .as_i64()
        .ok_or_else(|| "clock.unix_seconds returned a non-integer".to_string())
}

pub fn random_bytes(n: usize) -> Result<Vec<u8>, String> {
    let value = host_call!(raw::bytes, "random", "bytes", json!({ "n": n }))?;
    hex_value(&value, "random.bytes")
}

pub fn crypto_sha256(data: &[u8]) -> Result<Vec<u8>, String> {
    let value = host_call!(
        raw::sha256,
        "crypto",
        "sha256",
        json!({ "data_hex": hex::encode(data) })
    )?;
    hex_value(&value, "crypto.sha256")
}

pub fn crypto_hmac_sha256(key: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
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
) -> Result<Vec<u8>, String> {
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

pub fn crypto_ct_eq(a: &[u8], b: &[u8]) -> Result<bool, String> {
    let value = host_call!(
        raw::ct_eq,
        "crypto",
        "ct_eq",
        json!({ "a_hex": hex::encode(a), "b_hex": hex::encode(b) })
    )?;
    value
        .as_bool()
        .ok_or_else(|| "crypto.ct_eq returned a non-boolean".to_string())
}

pub fn attest(nonce: &[u8]) -> Result<Vec<u8>, String> {
    let value = host_call!(
        raw::attest,
        "attest",
        "attest",
        json!({ "nonce_hex": hex::encode(nonce) })
    )?;
    hex_value(&value, "tee.attest")
}
