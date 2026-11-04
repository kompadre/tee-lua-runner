//! Minimal COSE_Sign1 (RFC 9814) codec: CBOR structure + Ed25519 signatures.
//!
//! Scope is deliberately small: single-signer Sign1 documents with an
//! `{"alg": "EdDSA"}` protected header and an empty unprotected header —
//! enough to be structurally faithful for mock/QEMU attestation and to keep
//! Stage 7 (real NSM documents + AWS chain) a backend swap, not a rewrite.
//!
//! Note: byte strings must be built via [`ciborium::Value::Bytes`] — plain
//! `&[u8]` in a serde tuple serializes as a CBOR *array of integers* (which
//! is self-consistent for roundtrips but not COSE).

use std::collections::BTreeMap;

use ciborium::Value;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::Serialize;

use crate::verify::VerifyError;

/// Signature algorithm used by the mock attestation documents.
pub(crate) const ALG_EDDSA: &str = "EdDSA";

/// COSE alg label for ES384 as produced by the real NSM (`-35`).
pub(crate) const ALG_ES384: &str = "-35";

/// Reads the protected-header `alg` value as a comparable string:
/// text algorithms come through verbatim (`"EdDSA"`), numeric COSE
/// identifiers are rendered as their signed decimal (`"-35"`). Missing
/// or malformed headers map to the missing-label string so dispatch
/// rejects them uniformly.
pub(crate) fn alg(protected: &[u8]) -> Result<String, VerifyError> {
    let header: ciborium::Value = ciborium::from_reader(protected)
        .map_err(|err| VerifyError::Decode(format!("protected header: {err}")))?;
    let ciborium::Value::Map(entries) = header else {
        return Err(VerifyError::Decode(
            "protected header is not a CBOR map".into(),
        ));
    };
    for (key, value) in &entries {
        let is_alg = match key {
            ciborium::Value::Text(label) => label == "alg",
            ciborium::Value::Integer(label) => i128::from(*label) == 1,
            _ => false,
        };
        if !is_alg {
            continue;
        }
        return Ok(match value {
            ciborium::Value::Text(label) => label.clone(),
            ciborium::Value::Integer(id) => i128::from(*id).to_string(),
            other => format!("{other:?}"),
        });
    }
    Ok("<missing>".to_string())
}

fn to_cbor<T: Serialize>(value: &T) -> Vec<u8> {
    let mut bytes = Vec::new();
    // Serializing into a Vec<u8> can only fail on allocation failure.
    ciborium::into_writer(value, &mut bytes).expect("serialization into Vec<u8> cannot fail");
    bytes
}

/// COSE Sig_structure for Sign1:
/// `["Signature1", protected, external_aad, payload]`.
pub(crate) fn sig_structure(protected: &[u8], payload: &[u8]) -> Vec<u8> {
    to_cbor(&Value::Array(vec![
        Value::Text("Signature1".to_string()),
        Value::Bytes(protected.to_vec()),
        Value::Bytes(Vec::new()), // external_aad
        Value::Bytes(payload.to_vec()),
    ]))
}

/// Signs `payload` into a COSE_Sign1 document: CBOR array
/// `[protected bstr, unprotected map, payload bstr, signature bstr]`.
pub(crate) fn sign(signing_key: &SigningKey, payload: &[u8]) -> Vec<u8> {
    let mut header = BTreeMap::new();
    header.insert("alg", ALG_EDDSA);
    let protected = to_cbor(&header);
    let signature = signing_key.sign(&sig_structure(&protected, payload));
    to_cbor(&Value::Array(vec![
        Value::Bytes(protected),
        Value::Map(Vec::new()), // unprotected: always empty
        Value::Bytes(payload.to_vec()),
        Value::Bytes(signature.to_bytes().to_vec()),
    ]))
}

fn expect_bytes(value: Value, what: &str) -> Result<Vec<u8>, VerifyError> {
    match value {
        Value::Bytes(bytes) => Ok(bytes),
        other => Err(VerifyError::Decode(format!(
            "{what} is not a CBOR byte string: {other:?}"
        ))),
    }
}

/// `(protected, payload, signature)` of a COSE_Sign1 document.
pub(crate) type Sign1Parts = (Vec<u8>, Vec<u8>, Vec<u8>);

/// Parses a COSE_Sign1 document into `(protected, payload, signature)`.
/// Rejects anything that is not the canonical Sign1 shape.
pub(crate) fn parse(document: &[u8]) -> Result<Sign1Parts, VerifyError> {
    let value: Value =
        ciborium::from_reader(document).map_err(|err| VerifyError::Decode(err.to_string()))?;
    let Value::Array(items) = value else {
        return Err(VerifyError::Decode("document is not a CBOR array".into()));
    };
    if items.len() != 4 {
        return Err(VerifyError::Decode(format!(
            "COSE_Sign1 must have 4 elements, found {}",
            items.len()
        )));
    }
    let mut items = items.into_iter();
    let protected = expect_bytes(items.next().expect("checked length 4"), "protected header")?;
    // Unprotected header must be an empty map.
    match items.next().expect("checked length 4") {
        Value::Map(map) if map.is_empty() => {}
        other => {
            return Err(VerifyError::Decode(format!(
                "unprotected header must be an empty map, found {other:?}"
            )))
        }
    }
    let payload = expect_bytes(items.next().expect("checked length 4"), "payload")?;
    let signature = expect_bytes(items.next().expect("checked length 4"), "signature")?;
    Ok((protected, payload, signature))
}

/// Verifies the COSE_Sign1 signature over `(protected, payload)` and the
/// algorithm allowlist in the protected header.
pub(crate) fn verify_signature(
    verifying_key: &VerifyingKey,
    protected: &[u8],
    payload: &[u8],
    signature: &[u8],
) -> Result<(), VerifyError> {
    let header: BTreeMap<String, String> = ciborium::from_reader(protected)
        .map_err(|err| VerifyError::Decode(format!("protected header: {err}")))?;
    let alg = header
        .get("alg")
        .ok_or_else(|| VerifyError::UnsupportedAlgorithm("<missing>".to_string()))?;
    if alg != ALG_EDDSA {
        return Err(VerifyError::UnsupportedAlgorithm(alg.clone()));
    }
    let sig: [u8; 64] = signature
        .try_into()
        .map_err(|_| VerifyError::SignatureInvalid)?;
    verifying_key
        .verify_strict(
            &sig_structure(protected, payload),
            &Signature::from_bytes(&sig),
        )
        .map_err(|_| VerifyError::SignatureInvalid)
}
