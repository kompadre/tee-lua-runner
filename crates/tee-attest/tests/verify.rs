//! Verification tests for the mock attestation backend.

use std::collections::BTreeMap;

use tee_attest::{Attestor, Expectations, MockAttestor, TrustRoot, VerifyError};

fn pcrs() -> BTreeMap<String, String> {
    BTreeMap::from([("0".to_string(), "ab".repeat(32))])
}

fn fixture() -> (MockAttestor, TrustRoot) {
    MockAttestor::from_seed("test-module", pcrs(), [7u8; 32])
}

#[test]
fn roundtrip_verifies_with_expectations() {
    let (mock, root) = fixture();
    let nonce = b"challenge-1";
    let user_data = vec![9u8; 32];

    let document = mock.attest(nonce, &user_data).unwrap();
    let payload = tee_attest::verify(
        &root,
        &document,
        &Expectations::new()
            .with_nonce(nonce)
            .with_user_data(&user_data),
    )
    .unwrap();

    assert_eq!(payload.module_id, "test-module");
    assert_eq!(payload.digest, "SHA256");
    assert_eq!(payload.algorithm, "EdDSA");
    assert_eq!(payload.pcrs, pcrs());
    assert_eq!(payload.nonce.as_deref(), Some(hex::encode(nonce).as_str()));
    assert_eq!(
        payload.user_data.as_deref(),
        Some(hex::encode(&user_data).as_str())
    );
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(payload.timestamp <= now && now - payload.timestamp < 60);
}

#[test]
fn verification_without_expectations_succeeds() {
    let (mock, root) = fixture();
    let document = mock.attest(b"n", &[1u8; 32]).unwrap();
    assert!(tee_attest::verify(&root, &document, &Expectations::default()).is_ok());
}

#[test]
fn every_tampered_byte_fails_verification() {
    let (mock, root) = fixture();
    let document = mock.attest(b"challenge", &[3u8; 32]).unwrap();

    for index in 0..document.len() {
        let mut tampered = document.clone();
        tampered[index] ^= 0xff;
        let result = tee_attest::verify(&root, &tampered, &Expectations::default());
        assert!(
            result.is_err(),
            "flip at byte {index} must not verify (got {result:?})"
        );
    }
}

#[test]
fn wrong_root_fails_signature_check() {
    let (mock, _root) = fixture();
    let (_other_mock, other_root) = MockAttestor::from_seed("test-module", pcrs(), [8u8; 32]);
    let document = mock.attest(b"n", &[1u8; 32]).unwrap();

    let err = tee_attest::verify(&other_root, &document, &Expectations::default()).unwrap_err();
    assert!(matches!(err, VerifyError::SignatureInvalid), "got {err:?}");
}

#[test]
fn nonce_mismatch_and_missing_nonce_are_rejected() {
    let (mock, root) = fixture();

    // Signed nonce differs from the expectation.
    let document = mock.attest(b"real-nonce", &[1u8; 32]).unwrap();
    let err = tee_attest::verify(
        &root,
        &document,
        &Expectations::new().with_nonce(b"other-nonce"),
    )
    .unwrap_err();
    assert!(matches!(err, VerifyError::NonceMismatch), "got {err:?}");

    // Document without a nonce, but an expectation demands one.
    let document = mock.attest(b"", &[1u8; 32]).unwrap();
    let err = tee_attest::verify(
        &root,
        &document,
        &Expectations::new().with_nonce(b"anything"),
    )
    .unwrap_err();
    assert!(matches!(err, VerifyError::NonceMismatch), "got {err:?}");
}

#[test]
fn user_data_mismatch_is_rejected() {
    let (mock, root) = fixture();
    let document = mock.attest(b"n", &[1u8; 32]).unwrap();
    let err = tee_attest::verify(
        &root,
        &document,
        &Expectations::new().with_user_data(&[2u8; 32]),
    )
    .unwrap_err();
    assert!(matches!(err, VerifyError::UserDataMismatch), "got {err:?}");
}

#[test]
fn trust_root_hex_roundtrip_and_validation() {
    let (_mock, root) = fixture();
    let parsed = TrustRoot::from_hex(&root.to_hex()).unwrap();
    assert_eq!(root, parsed);

    assert!(matches!(
        TrustRoot::from_hex("zz"),
        Err(VerifyError::InvalidTrustRoot(_))
    ));
    assert!(matches!(
        TrustRoot::from_hex("abcd"), // not 32 bytes
        Err(VerifyError::InvalidTrustRoot(_))
    ));
}

#[test]
fn seed_is_deterministic() {
    let (_a, root_a) = MockAttestor::from_seed("m", pcrs(), [7u8; 32]);
    let (_b, root_b) = MockAttestor::from_seed("m", pcrs(), [7u8; 32]);
    assert_eq!(root_a.to_hex(), root_b.to_hex());

    let (_c, root_c) = MockAttestor::from_seed("m", pcrs(), [9u8; 32]);
    assert_ne!(root_a.to_hex(), root_c.to_hex());
}

#[test]
fn garbled_input_is_a_decode_error() {
    let (_mock, root) = fixture();
    let err = tee_attest::verify(&root, b"not a cbor doc", &Expectations::default()).unwrap_err();
    assert!(matches!(err, VerifyError::Decode(_)), "got {err:?}");
}

/// The document must have the literal COSE_Sign1 shape:
/// `[protected bstr, {}, payload bstr, signature bstr]` — byte strings, not
/// arrays of integers (serde's default `&[u8]` encoding).
#[test]
fn document_has_cose_sign1_shape() {
    let (mock, root) = fixture();
    let document = mock.attest(b"n", &[1u8; 32]).unwrap();

    let value: ciborium::Value = ciborium::from_reader(&document[..]).unwrap();
    let ciborium::Value::Array(items) = value else {
        panic!("document is not a CBOR array");
    };
    assert_eq!(items.len(), 4);
    assert!(
        matches!(&items[0], ciborium::Value::Bytes(_)),
        "protected must be a byte string, got {:?}",
        items[0]
    );
    assert!(
        matches!(&items[1], ciborium::Value::Map(m) if m.is_empty()),
        "unprotected must be an empty map, got {:?}",
        items[1]
    );
    assert!(
        matches!(&items[2], ciborium::Value::Bytes(_)),
        "payload must be a byte string, got {:?}",
        items[2]
    );
    assert!(
        matches!(&items[3], ciborium::Value::Bytes(b) if b.len() == 64),
        "signature must be a 64-byte byte string, got {:?}",
        items[3]
    );
    // And the payload must decode as the Nitro-mirroring schema.
    let payload: tee_attest::AttestationPayload = match &items[2] {
        ciborium::Value::Bytes(bytes) => {
            ciborium::from_reader(bytes.as_slice()).expect("payload schema")
        }
        _ => unreachable!(),
    };
    assert_eq!(payload.module_id, "test-module");
    // Still verifies end-to-end after the shape check.
    assert!(tee_attest::verify(&root, &document, &Expectations::default()).is_ok());
}
