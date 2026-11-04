//! Example service modules. Exactly one is compiled into an artifact via the
//! `svc-*` features (see the `compile_error!` guards in `lib.rs`).

use serde_json::Value;

/// Entry point: routes to the compiled-in service.
pub fn dispatch(req: &Value) -> Result<Value, String> {
    #[cfg(feature = "svc-echo")]
    {
        return echo(req);
    }
    #[cfg(feature = "svc-counter")]
    {
        return counter(req);
    }
    #[cfg(feature = "svc-hasher")]
    {
        return hasher(req);
    }
    #[cfg(feature = "svc-attest")]
    {
        return attest_doc(req);
    }
    #[cfg(feature = "svc-throttle")]
    {
        return crate::throttle::handle(req);
    }
    #[cfg(not(any(
        feature = "svc-echo",
        feature = "svc-counter",
        feature = "svc-hasher",
        feature = "svc-attest",
        feature = "svc-throttle"
    )))]
    {
        let _ = req;
        Err("no service compiled into this module".to_string())
    }
}

/// Echoes the request back. No capabilities required.
#[cfg(feature = "svc-echo")]
fn echo(req: &Value) -> Result<Value, String> {
    use serde_json::json;
    Ok(json!({ "echo": req }))
}

/// Rolling counter: demonstrates state + clock + log capabilities.
#[cfg(feature = "svc-counter")]
fn counter(req: &Value) -> Result<Value, String> {
    use serde_json::json;
    let method = req.get("method").and_then(Value::as_str).unwrap_or("");
    let key = req.get("key").and_then(Value::as_str).unwrap_or("default");
    match method {
        "incr" => {
            let current = crate::host::state_get(key)?.as_i64().unwrap_or(0);
            let value = current + 1;
            crate::host::state_set(key, &json!(value))?;
            crate::host::log("info", &format!("incremented {key}"))?;
            let at = crate::host::clock_unix()?;
            Ok(json!({ "key": key, "value": value, "at": at }))
        }
        "get" => {
            let value = crate::host::state_get(key)?.as_i64().unwrap_or(0);
            Ok(json!({ "key": key, "value": value }))
        }
        "reset" => {
            crate::host::state_delete(key)?;
            crate::host::log("info", &format!("reset {key}"))?;
            Ok(json!({ "ok": true }))
        }
        other => Err(format!("unknown method: {other}")),
    }
}

/// Hashing service: SHA-256 digests and random tokens
/// (crypto + random capabilities).
#[cfg(feature = "svc-hasher")]
fn hasher(req: &Value) -> Result<Value, String> {
    use serde_json::json;
    match req.get("method").and_then(Value::as_str).unwrap_or("") {
        "sha256" => {
            let data = req.get("data").and_then(Value::as_str).unwrap_or("");
            let digest = crate::host::crypto_sha256(data.as_bytes())?;
            Ok(json!({ "digest": hex::encode(&digest) }))
        }
        "token" => {
            let token = crate::host::random_bytes(16)?;
            Ok(json!({ "token": hex::encode(&token) }))
        }
        "equal" => {
            let a = req.get("a").and_then(Value::as_str).unwrap_or("");
            let b = req.get("b").and_then(Value::as_str).unwrap_or("");
            let equal = crate::host::crypto_ct_eq(a.as_bytes(), b.as_bytes())?;
            Ok(json!({ "equal": equal }))
        }
        other => Err(format!("unknown method: {other}")),
    }
}

/// Attestation service (attest capability): returns a document produced by
/// the runner's configured backend for the requested nonce.
#[cfg(feature = "svc-attest")]
fn attest_doc(req: &Value) -> Result<Value, String> {
    use serde_json::json;
    match req.get("method").and_then(Value::as_str).unwrap_or("") {
        "doc" => {
            let nonce_hex = req
                .get("nonce_hex")
                .and_then(Value::as_str)
                .ok_or_else(|| "attest: missing `nonce_hex`".to_string())?;
            let nonce = hex::decode(nonce_hex)
                .map_err(|err| format!("attest: invalid hex nonce: {err}"))?;
            let doc = crate::host::attest(&nonce)?;
            Ok(json!({ "doc_hex": hex::encode(&doc) }))
        }
        other => Err(format!("unknown method: {other}")),
    }
}

#[cfg(all(test, feature = "svc-counter"))]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn counter_increments_and_reads_back() {
        let first = dispatch(&json!({ "method": "incr", "key": "a" })).unwrap();
        assert_eq!(first["value"], json!(1));
        let second = dispatch(&json!({ "method": "incr", "key": "a" })).unwrap();
        assert_eq!(second["value"], json!(2));
        let read = dispatch(&json!({ "method": "get", "key": "a" })).unwrap();
        assert_eq!(read["value"], json!(2));
        dispatch(&json!({ "method": "reset", "key": "a" })).unwrap();
        let read = dispatch(&json!({ "method": "get", "key": "a" })).unwrap();
        assert_eq!(read["value"], json!(0));
    }

    #[test]
    fn unknown_method_is_an_error() {
        let err = dispatch(&json!({ "method": "nope" })).unwrap_err();
        assert!(err.contains("unknown method"), "unexpected: {err}");
    }
}
