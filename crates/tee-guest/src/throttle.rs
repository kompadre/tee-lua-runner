//! The gate/throttle service — the reference workload (Stage 4).
//!
//! Flow per fetch: validate → PoP (binds *both* identity keys to *this*
//! envelope) → blacklist check → rolling window → `gate.unwrap` → audit.
//! The policy constants below are the attestable surface: their values are
//! part of this module's measured bytes.
//!
//! Clock semantics (Q1 v1 decision): `now = max(host_time, last_seen)` —
//! clock *rollback* fails closed (buckets only tighten). Forward-jump
//! resistance requires attested time and is carried forward (TODO Q1').
//! Persistence (Q2 v1): host in-memory state; restarts reset buckets and
//! blacklist (TODO Q2').

use serde_json::{json, Value};
use tee_proto::{
    decode_pk32, fetch_pop_message, revoke_pop_message, AuditEntry, ErrorCode, Request, Response,
};

use crate::host::{self, HostError};

// ------------------------------------------------------------------ policy
// (auditable: these bytes are covered by the module measurement)

/// Rolling window length, seconds.
pub const WINDOW_SECS: i64 = 60;
/// Max fetches per identity per window.
pub const MAX_FETCHES: usize = 5;
/// Max tracked identities before least-recent eviction.
pub const MAX_OWNERS: usize = 512;
/// Blacklist capacity; revocations beyond it are refused (fail closed).
pub const MAX_REVOKES: usize = 256;
/// Audit ring capacity (oldest entries drop out).
pub const AUDIT_CAPACITY: usize = 256;

const META_KEY: &str = "_meta";
const AUDIT_KEY: &str = "audit";
const AUDIT_SEQ_KEY: &str = "_audit_seq";
const BUCKET_PREFIX: &str = "t:";
const REVOKE_PREFIX: &str = "b:";

fn bucket_key(sign_hex: &str) -> String {
    format!("{BUCKET_PREFIX}{sign_hex}")
}

fn revoke_key(sign_hex: &str) -> String {
    format!("{REVOKE_PREFIX}{sign_hex}")
}

/// Runner entry point. Protocol-level failures come back as `ok` responses
/// carrying `Response::Error` (typed codes + optional retry hint); `Err` is
/// reserved for internal breakage (response serialization).
pub fn handle(req: &Value) -> Result<Value, String> {
    let response = match serde_json::from_value::<Request>(req.clone()) {
        Ok(Request::Fetch {
            sign_pk,
            enc_pk,
            envelope,
            pop,
        }) => fetch(&sign_pk, &enc_pk, &envelope, &pop),
        Ok(Request::Revoke {
            sign_pk,
            enc_pk,
            pop,
        }) => revoke(&sign_pk, &enc_pk, &pop),
        Ok(Request::Audit) => audit(),
        Err(err) => err_response(
            ErrorCode::BadRequest,
            format!("malformed request: {err}"),
            None,
        ),
    };
    serde_json::to_value(&response).map_err(|err| format!("response serialization: {err}"))
}

fn err_response(
    code: ErrorCode,
    message: impl Into<String>,
    retry_after_ms: Option<u64>,
) -> Response {
    Response::Error {
        code,
        message: message.into(),
        retry_after_ms,
    }
}

/// Host failure → protocol-internal error.
fn internal(failure: impl std::fmt::Display) -> Response {
    err_response(ErrorCode::Internal, failure.to_string(), None)
}

// ------------------------------------------------------------------- clock

/// Host time with a monotonic floor: `now = max(real_now, last_seen)`, so a
/// rollback can only *tighten* windows (fail closed).
fn now_with_floor() -> Result<i64, HostError> {
    let real_now = host::clock_unix()?;
    let last_seen = host::state_get(META_KEY)?
        .get("last_seen")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let now = real_now.max(last_seen);
    host::state_set(META_KEY, &json!({ "last_seen": now }))?;
    Ok(now)
}

// ------------------------------------------------------------------ audit

/// Best-effort audit write: never fail a fetch because the ring could not be
/// written; surface via `log` instead (ring contains key ids + outcomes
/// only — never envelopes, inners, or secrets).
fn audit_record(ts: i64, owner: &str, action: &str, outcome: &str) {
    let result: Result<(), HostError> = (|| {
        let seq = host::state_get(AUDIT_SEQ_KEY)?.as_u64().unwrap_or(0) + 1;
        host::state_set(AUDIT_SEQ_KEY, &json!(seq))?;
        let mut entries: Vec<AuditEntry> =
            serde_json::from_value(host::state_get(AUDIT_KEY)?).unwrap_or_default();
        entries.push(AuditEntry {
            seq,
            ts,
            owner: owner.to_string(),
            action: action.to_string(),
            outcome: outcome.to_string(),
        });
        while entries.len() > AUDIT_CAPACITY {
            entries.remove(0);
        }
        let value = serde_json::to_value(&entries).map_err(|err| HostError {
            message: format!("audit serialization: {err}"),
            code: None,
        })?;
        host::state_set(AUDIT_KEY, &value)
    })();
    if let Err(failure) = result {
        let _ = host::log("warn", &format!("audit write failed: {failure}"));
    }
}

// ------------------------------------------------------------------ policy

fn is_revoked(sign_hex: &str) -> Result<bool, HostError> {
    Ok(!host::state_get(&revoke_key(sign_hex))?.is_null())
}

fn load_bucket(key: &str) -> Result<Vec<i64>, HostError> {
    let value = host::state_get(key)?;
    Ok(value
        .as_array()
        .map(|items| items.iter().filter_map(Value::as_i64).collect())
        .unwrap_or_default())
}

/// Admission control: before adding a new identity's bucket, evict the
/// identity with the oldest latest-timestamp; refuse if nothing can go.
fn ensure_owner_slot(sign_hex: &str) -> Result<(), ErrorCode> {
    let existing = host::state_get(&bucket_key(sign_hex)).map_err(|_| ErrorCode::Internal)?;
    if !existing.is_null() {
        return Ok(());
    }
    let keys = host::state_keys().map_err(|_| ErrorCode::Internal)?;
    let owners: Vec<String> = keys
        .into_iter()
        .filter(|key| key.starts_with(BUCKET_PREFIX))
        .collect();
    if owners.len() < MAX_OWNERS {
        return Ok(());
    }
    let mut oldest: Option<(String, i64)> = None;
    for owner_key in &owners {
        let bucket = load_bucket(owner_key).map_err(|_| ErrorCode::Internal)?;
        let latest = bucket.last().copied().unwrap_or(0);
        if oldest
            .as_ref()
            .is_none_or(|(_, earliest)| latest < *earliest)
        {
            oldest = Some((owner_key.clone(), latest));
        }
    }
    match oldest {
        Some((victim, _)) => {
            host::state_delete(&victim).map_err(|_| ErrorCode::Internal)?;
            Ok(())
        }
        None => Err(ErrorCode::ThrottleStateFull),
    }
}

/// Maps `gate.unwrap`'s stable host code to a protocol code.
fn gate_outcome(failure: &HostError) -> ErrorCode {
    match failure.code.as_deref() {
        Some("wrong_owner") => ErrorCode::WrongOwner,
        Some("decrypt_failed") | Some("malformed") => ErrorCode::BadEnvelope,
        Some("bad_request") | Some("not_provisioned") | Some(_) | None => ErrorCode::Internal,
    }
}

// ----------------------------------------------------------------- handlers

fn fetch(sign_pk: &str, enc_pk: &str, envelope: &str, pop: &str) -> Response {
    let (Some(sign), Some(enc)) = (decode_pk32(sign_pk), decode_pk32(enc_pk)) else {
        return err_response(
            ErrorCode::BadRequest,
            "sign_pk/enc_pk must be 32-byte hex",
            None,
        );
    };
    let Ok(envelope_bytes) = hex::decode(envelope) else {
        return err_response(ErrorCode::BadRequest, "envelope must be hex", None);
    };
    let Some(signature): Option<[u8; 64]> = hex::decode(pop)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
    else {
        return err_response(ErrorCode::BadPop, "pop must be 64-byte hex", None);
    };

    let now = match now_with_floor() {
        Ok(now) => now,
        Err(failure) => return internal(failure),
    };

    // 1. Proof of possession: domain-separated message binds the identity's
    //    signing key, the envelope-recipient key, and this exact envelope.
    let message = fetch_pop_message(&sign, &enc, &envelope_bytes);
    match host::crypto_ed25519_verify(&sign, &message, &signature) {
        Ok(true) => {}
        Ok(false) => {
            audit_record(now, sign_pk, "fetch", ErrorCode::BadPop.as_str());
            return err_response(ErrorCode::BadPop, "proof of possession failed", None);
        }
        Err(failure) => return internal(failure),
    }

    // 2. Blacklist: a revoked identity is refused outright, PoP or not.
    match is_revoked(sign_pk) {
        Ok(true) => {
            audit_record(now, sign_pk, "fetch", ErrorCode::Blacklisted.as_str());
            return err_response(
                ErrorCode::Blacklisted,
                "identity has been revoked (blacklisted)",
                None,
            );
        }
        Ok(false) => {}
        Err(failure) => return internal(failure),
    }

    // 3. Rolling window per identity.
    let bucket_key = bucket_key(sign_pk);
    let mut bucket = match load_bucket(&bucket_key) {
        Ok(bucket) => bucket,
        Err(failure) => return internal(failure),
    };
    bucket.retain(|&ts| ts >= now - WINDOW_SECS);
    if bucket.len() >= MAX_FETCHES {
        let oldest = bucket.first().copied().unwrap_or(now);
        let retry_ms = (oldest + WINDOW_SECS - now).max(0) * 1000;
        audit_record(now, sign_pk, "fetch", ErrorCode::Throttled.as_str());
        return err_response(
            ErrorCode::Throttled,
            format!("rate limit: at most {MAX_FETCHES} fetches per {WINDOW_SECS}s"),
            Some(retry_ms as u64),
        );
    }

    // 4. Admission control for new identities (bounded owner set).
    if let Err(code) = ensure_owner_slot(sign_pk) {
        audit_record(now, sign_pk, "fetch", code.as_str());
        return err_response(code, "throttle state is full", None);
    }
    bucket.push(now);
    if let Err(failure) = host::state_set(&bucket_key, &json!(bucket)) {
        return internal(failure);
    }

    // 5. The actual gatekeeper operation — never sees plaintext.
    match host::gate_unwrap(&envelope_bytes, &enc) {
        Ok(inner) => {
            audit_record(now, sign_pk, "fetch", "ok");
            let Some(inner) = inner.as_str() else {
                return internal("gate.unwrap returned a non-string inner blob");
            };
            Response::Fetch {
                inner: inner.to_string(),
            }
        }
        Err(failure) => {
            let code = gate_outcome(&failure);
            audit_record(now, sign_pk, "fetch", code.as_str());
            err_response(code, failure.message, None)
        }
    }
}

fn revoke(sign_pk: &str, enc_pk: &str, pop: &str) -> Response {
    let (Some(sign), Some(enc)) = (decode_pk32(sign_pk), decode_pk32(enc_pk)) else {
        return err_response(
            ErrorCode::BadRequest,
            "sign_pk/enc_pk must be 32-byte hex",
            None,
        );
    };
    let Some(signature): Option<[u8; 64]> = hex::decode(pop)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
    else {
        return err_response(ErrorCode::BadPop, "pop must be 64-byte hex", None);
    };

    let now = match now_with_floor() {
        Ok(now) => now,
        Err(failure) => return internal(failure),
    };

    let message = revoke_pop_message(&sign, &enc);
    match host::crypto_ed25519_verify(&sign, &message, &signature) {
        Ok(true) => {}
        Ok(false) => {
            audit_record(now, sign_pk, "revoke", ErrorCode::BadPop.as_str());
            return err_response(ErrorCode::BadPop, "proof of possession failed", None);
        }
        Err(failure) => return internal(failure),
    }

    // Idempotent: revoking twice is fine (and skips the capacity check).
    let already = match is_revoked(sign_pk) {
        Ok(already) => already,
        Err(failure) => return internal(failure),
    };
    if !already {
        let count = match host::state_keys() {
            Ok(keys) => keys.iter().filter(|k| k.starts_with(REVOKE_PREFIX)).count(),
            Err(failure) => return internal(failure),
        };
        if count >= MAX_REVOKES {
            audit_record(now, sign_pk, "revoke", ErrorCode::RevokeListFull.as_str());
            return err_response(
                ErrorCode::RevokeListFull,
                "blacklist is full; revocation refused",
                None,
            );
        }
    }

    if let Err(failure) = host::state_set(&revoke_key(sign_pk), &json!(now)) {
        return internal(failure);
    }
    // Free the throttle slot; a revoked identity never needs one again.
    if let Err(failure) = host::state_delete(&bucket_key(sign_pk)) {
        return internal(failure);
    }
    audit_record(now, sign_pk, "revoke", "ok");
    Response::Revoke
}

fn audit() -> Response {
    match host::state_get(AUDIT_KEY) {
        Ok(value) => match serde_json::from_value(value) {
            Ok(entries) => Response::Audit { entries },
            Err(err) => err_response(ErrorCode::Internal, format!("audit decode: {err}"), None),
        },
        Err(failure) => internal(failure),
    }
}

#[cfg(all(test, feature = "svc-throttle"))]
mod tests {
    use super::*;
    use tee_crypto::{open_local, seal_secret, x25519_public, LocalIdentity};
    use zeroize::Zeroizing;

    fn identity(seed: u32) -> LocalIdentity {
        let mut bytes = [0u8; 64];
        for chunk in bytes.chunks_mut(2) {
            chunk[0] = (seed & 0xff) as u8;
            chunk[1] = ((seed >> 8) & 0xff) as u8;
        }
        LocalIdentity::from_seed(Zeroizing::new(bytes))
    }

    fn tee_pk() -> [u8; 32] {
        x25519_public(&crate::mock::MOCK_TEE_KEY)
    }

    fn sealed_for(identity: &LocalIdentity, secret: &[u8]) -> String {
        let public = identity.public();
        hex::encode(
            seal_secret(&tee_pk(), &public.encryption, secret)
                .expect("envelope seals under the mock TEE key"),
        )
    }

    fn fetch_request(identity: &LocalIdentity, envelope_hex: &str) -> Value {
        let public = identity.public();
        let envelope_bytes = hex::decode(envelope_hex).unwrap();
        let message = fetch_pop_message(&public.signing, &public.encryption, &envelope_bytes);
        let pop = identity.sign(&message);
        json!({
            "op": "fetch",
            "sign_pk": hex::encode(public.signing),
            "enc_pk": hex::encode(public.encryption),
            "envelope": envelope_hex,
            "pop": hex::encode(pop),
        })
    }

    fn revoke_request(identity: &LocalIdentity) -> Value {
        let public = identity.public();
        let message = revoke_pop_message(&public.signing, &public.encryption);
        let pop = identity.sign(&message);
        json!({
            "op": "revoke",
            "sign_pk": hex::encode(public.signing),
            "enc_pk": hex::encode(public.encryption),
            "pop": hex::encode(pop),
        })
    }

    fn expect_ok(resp: &Value) {
        assert_ne!(resp["result"], json!("error"), "unexpected error: {resp}");
    }

    fn expect_error(resp: &Value, code: &str) {
        assert_eq!(resp["result"], json!("error"), "{resp}");
        assert_eq!(resp["code"], json!(code), "{resp}");
    }

    #[test]
    fn fetch_unwraps_through_the_gate() {
        let owner = identity(1);
        let envelope = sealed_for(&owner, b"the-secret");
        let resp = handle(&fetch_request(&owner, &envelope)).unwrap();
        expect_ok(&resp);
        assert_eq!(resp["result"], json!("fetch"), "{resp}");

        // The inner blob opens with the owner's local key (client side).
        let inner_hex = resp["inner"].as_str().unwrap();
        let inner = hex::decode(inner_hex).unwrap();
        let seed = owner.to_seed();
        let owner_sk: [u8; 32] = seed[32..].try_into().expect("seed layout");
        assert_eq!(open_local(&owner_sk, &inner).unwrap(), b"the-secret");
    }

    #[test]
    fn wrong_owner_envelope_is_refused_by_the_gate() {
        let owner = identity(2);
        let attacker = identity(3);
        // A valid PoP for the attacker, but the envelope belongs to `owner`.
        let envelope = sealed_for(&owner, b"secret");
        let resp = handle(&fetch_request(&attacker, &envelope)).unwrap();
        // PoP binds identity to THIS envelope: signed over owner's envelope
        // by the attacker's key would verify only if the attacker signed it —
        // fetch_request signs with the attacker's key over the owner's
        // envelope, so the PoP *verifies* (both keys are the attacker's) and
        // the gate rejects on recipient mismatch:
        expect_error(&resp, "wrong_owner");
    }

    #[test]
    fn forged_pop_is_rejected() {
        let owner = identity(4);
        let other = identity(5);
        let envelope = sealed_for(&owner, b"secret");
        let mut request = fetch_request(&owner, &envelope);
        // Re-sign with the wrong identity: PoP no longer matches sign_pk.
        let public = other.public();
        let envelope_bytes = hex::decode(request["envelope"].as_str().unwrap()).unwrap();
        let message = fetch_pop_message(&public.signing, &public.encryption, &envelope_bytes);
        request["pop"] = json!(hex::encode(other.sign(&message)));
        let resp = handle(&request).unwrap();
        expect_error(&resp, "bad_pop");
    }

    #[test]
    fn rolling_window_throttles_per_identity() {
        let owner = identity(6);
        let envelope = sealed_for(&owner, b"secret");
        let request = fetch_request(&owner, &envelope);

        for _ in 0..MAX_FETCHES {
            expect_ok(&handle(&request).unwrap());
        }
        let resp = handle(&request).unwrap();
        expect_error(&resp, "throttled");
        assert!(resp["retry_after_ms"].as_u64().unwrap() > 0, "{resp}");

        // A different identity has its own bucket: unaffected.
        let other = identity(7);
        let other_envelope = sealed_for(&other, b"secret2");
        expect_ok(&handle(&fetch_request(&other, &other_envelope)).unwrap());
    }

    #[test]
    fn revocation_is_idempotent_and_blocks_fetches() {
        let owner = identity(8);
        let envelope = sealed_for(&owner, b"secret");

        let resp = handle(&revoke_request(&owner)).unwrap();
        expect_ok(&resp);
        assert_eq!(resp["result"], json!("revoke"), "{resp}");

        // Even with a perfect PoP, a revoked identity is refused.
        let resp = handle(&fetch_request(&owner, &envelope)).unwrap();
        expect_error(&resp, "blacklisted");

        // Idempotent.
        let resp = handle(&revoke_request(&owner)).unwrap();
        expect_ok(&resp);
        assert_eq!(resp["result"], json!("revoke"), "{resp}");
    }

    #[test]
    fn audit_ring_records_decisions_without_secrets() {
        let owner = identity(9);
        let envelope = sealed_for(&owner, b"super-secret-value");
        // Exhaust the window exactly, then trip it once: the ring should see
        // both `ok` and `throttled` outcomes for this owner.
        for _ in 0..MAX_FETCHES {
            expect_ok(&handle(&fetch_request(&owner, &envelope)).unwrap());
        }
        let throttled = handle(&fetch_request(&owner, &envelope)).unwrap();
        expect_error(&throttled, "throttled");

        let resp = handle(&json!({ "op": "audit" })).unwrap();
        expect_ok(&resp);
        let entries = resp["entries"].as_array().unwrap();
        let mine: Vec<_> = entries
            .iter()
            .filter(|e| e["owner"] == json!(hex::encode(owner.public().signing)))
            .collect();
        assert!(mine.iter().any(|e| e["outcome"] == json!("ok")), "{mine:?}");
        assert!(
            mine.iter().any(|e| e["outcome"] == json!("throttled")),
            "{mine:?}"
        );

        // No secrets anywhere in the serialized ring.
        let blob = serde_json::to_string(entries).unwrap();
        assert!(!blob.contains(&envelope), "envelope leaked into audit");
        assert!(!blob.contains("super-secret-value"), "secret leaked");
        assert!(!blob.contains("inner"), "inner blob leaked");
    }

    #[test]
    fn malformed_requests_get_bad_request() {
        let resp = handle(&json!({ "op": "fetch", "sign_pk": "zz" })).unwrap();
        expect_error(&resp, "bad_request");

        let resp = handle(&json!({ "op": "unknown" })).unwrap();
        expect_error(&resp, "bad_request");
    }

    #[test]
    fn owner_buckets_are_evicted_beyond_the_cap() {
        // Fill the owner set with brand-new identities (unique seeds 100+).
        for seed in 100..(100 + MAX_OWNERS as u32) {
            let owner = identity(seed);
            let envelope = sealed_for(&owner, b"s");
            expect_ok(&handle(&fetch_request(&owner, &envelope)).unwrap());
        }
        let count_owners = || -> usize {
            let keys = host::state_keys().unwrap();
            keys.iter().filter(|k| k.starts_with(BUCKET_PREFIX)).count()
        };
        // Leftovers from other tests sharing this worker's state are fine;
        // the invariant is: the cap holds and admission control acted.
        assert!(count_owners() <= MAX_OWNERS, "owner cap must hold");

        // One more NEW identity: admission evicts the least-recent owner.
        let newest = identity(99);
        let envelope = sealed_for(&newest, b"s");
        expect_ok(&handle(&fetch_request(&newest, &envelope)).unwrap());
        assert!(count_owners() <= MAX_OWNERS, "eviction must keep the cap");
        // The newest owner's bucket exists.
        let newest_hex = hex::encode(newest.public().signing);
        assert!(
            !host::state_get(&bucket_key(&newest_hex)).unwrap().is_null(),
            "newest bucket must exist"
        );
    }
}
