//! Protocol contract tests: serde shapes and PoP message stability.

use tee_proto::{
    decode_pk32, fetch_pop_message, revoke_pop_message, AuditEntry, ErrorCode, Request, Response,
    FETCH_POP_DOMAIN, REVOKE_POP_DOMAIN,
};

#[test]
fn request_serde_shapes() {
    let fetch = Request::Fetch {
        sign_pk: "aa".repeat(32),
        enc_pk: "bb".repeat(32),
        envelope: "cc".repeat(10),
        pop: "dd".repeat(64),
    };
    let json = serde_json::to_string(&fetch).unwrap();
    assert!(json.contains(r#""op":"fetch""#), "{json}");
    let back: Request = serde_json::from_str(&json).unwrap();
    assert_eq!(back, fetch);

    let revoke = Request::Revoke {
        sign_pk: "aa".repeat(32),
        enc_pk: "bb".repeat(32),
        pop: "dd".repeat(64),
    };
    let json = serde_json::to_string(&revoke).unwrap();
    assert!(json.contains(r#""op":"revoke""#), "{json}");

    let json = serde_json::to_string(&Request::Audit).unwrap();
    assert_eq!(json, r#"{"op":"audit"}"#);
}

#[test]
fn response_serde_shapes() {
    let err = Response::Error {
        code: ErrorCode::Throttled,
        message: "wait".into(),
        retry_after_ms: Some(1500),
    };
    let json = serde_json::to_string(&err).unwrap();
    assert!(json.contains(r#""result":"error""#), "{json}");
    assert!(json.contains(r#""code":"throttled""#), "{json}");
    assert!(json.contains(r#""retry_after_ms":1500"#), "{json}");
    let back: Response = serde_json::from_str(&json).unwrap();
    assert_eq!(back, err);

    // retry_after_ms is omitted entirely when absent.
    let err = Response::Error {
        code: ErrorCode::BadPop,
        message: "no".into(),
        retry_after_ms: None,
    };
    let json = serde_json::to_string(&err).unwrap();
    assert!(!json.contains("retry_after_ms"), "{json}");

    let fetch = Response::Fetch {
        inner: "deadbeef".into(),
    };
    let json = serde_json::to_string(&fetch).unwrap();
    assert!(json.contains(r#""result":"fetch""#), "{json}");
    assert!(json.contains(r#""inner":"deadbeef""#), "{json}");

    let json = serde_json::to_string(&Response::Revoke).unwrap();
    assert_eq!(json, r#"{"result":"revoke"}"#);
}

/// The PoP messages are the client↔service byte contract: pin them.
#[test]
fn pop_messages_are_stable() {
    use sha2::{Digest, Sha256};

    let sign_pk = [0x11u8; 32];
    let enc_pk = [0x22u8; 32];
    let envelope = b"envelope-bytes";

    // fetch = domain ‖ sign_pk ‖ enc_pk ‖ sha256(envelope)
    let mut expected = FETCH_POP_DOMAIN.to_vec();
    expected.extend_from_slice(&sign_pk);
    expected.extend_from_slice(&enc_pk);
    expected.extend_from_slice(&Sha256::digest(envelope));
    assert_eq!(fetch_pop_message(&sign_pk, &enc_pk, envelope), expected);

    // revoke = domain ‖ sign_pk ‖ enc_pk
    let mut expected = REVOKE_POP_DOMAIN.to_vec();
    expected.extend_from_slice(&sign_pk);
    expected.extend_from_slice(&enc_pk);
    assert_eq!(revoke_pop_message(&sign_pk, &enc_pk), expected);

    // Layout invariants the service relies on.
    let fetch = fetch_pop_message(&sign_pk, &enc_pk, envelope);
    assert_eq!(fetch.len(), FETCH_POP_DOMAIN.len() + 32 + 32 + 32);
    assert_eq!(&fetch[..FETCH_POP_DOMAIN.len()], FETCH_POP_DOMAIN);
    assert_eq!(
        &fetch[FETCH_POP_DOMAIN.len()..FETCH_POP_DOMAIN.len() + 32],
        sign_pk
    );

    // The two domains must not collide (cross-protocol attack).
    assert_ne!(FETCH_POP_DOMAIN, REVOKE_POP_DOMAIN);
}

#[test]
fn audit_entry_contains_no_extra_fields() {
    let entry = AuditEntry {
        seq: 7,
        ts: 1_700_000_000,
        owner: "aa".repeat(32),
        action: "fetch".into(),
        outcome: "ok".into(),
    };
    let value = serde_json::to_value(&entry).unwrap();
    let obj = value.as_object().unwrap();
    assert_eq!(obj.len(), 5, "no extra fields allowed: {obj:?}");
    for key in ["seq", "ts", "owner", "action", "outcome"] {
        assert!(obj.contains_key(key), "missing field {key}");
    }
}

#[test]
fn attest_request_response_shapes() {
    let request = Request::Attest {
        nonce_hex: "0011aabb".into(),
    };
    let json = serde_json::to_string(&request).unwrap();
    assert_eq!(json, r#"{"op":"attest","nonce_hex":"0011aabb"}"#);
    let back: Request = serde_json::from_str(&json).unwrap();
    assert_eq!(back, request);

    let response = Response::Attest {
        doc_hex: "cafe".into(),
    };
    let json = serde_json::to_string(&response).unwrap();
    assert_eq!(json, r#"{"result":"attest","doc_hex":"cafe"}"#);
    let back: Response = serde_json::from_str(&json).unwrap();
    assert_eq!(back, response);
}

#[test]
fn decode_pk32_validates_lengths() {
    assert!(decode_pk32(&"ab".repeat(32)).is_some());
    assert!(decode_pk32("abcd").is_none());
    assert!(decode_pk32("zz").is_none());
}
