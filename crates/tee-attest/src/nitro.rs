//! Verification of **real** Nitro attestation documents (Stage 7).
//!
//! A real document is the same COSE_Sign1 envelope the mock produces, but:
//! the protected header is `{"alg": -35}` (COSE `ES384`, ECDSA P-384/SHA-384)
//! and the payload is the NSM's CBOR `AttestationDoc`, which embeds an X.509
//! chain: `cabundle = [root, intermediate, …]` (root first, per the NSM API
//! docs) with the end-entity `certificate` in its own field.
//!
//! Trust model (mirrors AWS's published validation process):
//! 1. `cabundle[0]` must hash (SHA-256) to the **pinned** AWS Nitro root
//!    fingerprint — no configurable root, the value is compiled in.
//! 2. Every subsequent certificate must be signed by the previous one
//!    (`ecdsa-with-SHA384` only) and be time-valid at verification time.
//! 3. The leaf's public key must verify the COSE signature (ES384, fixed
//!    `r‖s` encoding) over the standard `Signature1` structure.
//! 4. Payload fields and [`Expectations`](crate::verify::Expectations) are
//!    checked exactly as on the mock path.
//!
//! Verification time is a parameter ([`verify_nitro`]) because AWS issues
//! short-lived CA certificates (hours–days): the fixture document from 2025
//! only verifies against its own timestamp. Production callers pass
//! `SystemTime::now()` via [`crate::verify::verify`].

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use aws_nitro_enclaves_nsm_api::api::AttestationDoc;
use p384::ecdsa::signature::Verifier as _;
use p384::ecdsa::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use x509_parser::oid_registry::OID_SIG_ECDSA_WITH_SHA384;
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::cose;
use crate::verify::{AttestationPayload, Expectations, VerifyError};

/// COSE algorithm identifier for ES384 (IANA `COSE Algorithms`, RFC 8152).
const ALG_ES384: i64 = -35;

/// SHA-256 of the AWS Nitro Enclaves Root G1 certificate (DER), as published
/// by AWS (`docs.aws.amazon.com/enclaves/latest/user/verify-root.html`,
/// fingerprint `64:1A:03:21:…:8F:79:BB:5B`) and cross-checked against the
/// root certificate shipped in the `AWS_NitroEnclaves_Root-G1.zip` bundle.
const AWS_NITRO_ROOT_SHA256: [u8; 32] = [
    0x64, 0x1a, 0x03, 0x21, 0xa3, 0xe2, 0x44, 0xef, 0xe4, 0x56, 0x46, 0x31, 0x95, 0xd6, 0x06, 0x31,
    0x7e, 0xd7, 0xcd, 0xcc, 0x3c, 0x17, 0x56, 0xe0, 0x98, 0x93, 0xf3, 0xc6, 0x8f, 0x79, 0xbb, 0x5b,
];

/// Verifies a real Nitro document: ES384 signature over an AWS-rooted chain,
/// then payload/expectations checks identical to the mock path.
///
/// `now` bounds certificate validity windows (production: wall clock;
/// tests: the document's own timestamp).
pub(crate) fn verify_nitro(
    protected: &[u8],
    payload_bytes: &[u8],
    signature: &[u8],
    expectations: &Expectations,
    now: SystemTime,
) -> Result<AttestationPayload, VerifyError> {
    check_alg_header(protected)?;

    let doc = AttestationDoc::from_binary(payload_bytes)
        .map_err(|err| VerifyError::PayloadDecode(format!("nitro attestation doc: {err:?}")))?;

    let leaf_key = verify_chain(&doc, now)?;
    verify_cose_signature(&leaf_key, protected, payload_bytes, signature)?;

    let payload = map_payload(doc);
    super::verify::check_expectations(&payload, expectations)?;
    Ok(payload)
}

/// Requires the protected header to carry `{1: -35}` (alg = ES384).
fn check_alg_header(protected: &[u8]) -> Result<(), VerifyError> {
    let header: ciborium::Value = ciborium::from_reader(protected)
        .map_err(|err| VerifyError::Decode(format!("protected header: {err}")))?;
    let ciborium::Value::Map(entries) = header else {
        return Err(VerifyError::Decode(
            "protected header is not a CBOR map".into(),
        ));
    };
    let alg = entries.iter().find_map(|(key, value)| match key {
        ciborium::Value::Integer(label) if i128::from(*label) == 1 => Some(value),
        _ => None,
    });
    match alg {
        Some(ciborium::Value::Integer(id)) if i128::from(*id) == ALG_ES384 as i128 => Ok(()),
        Some(other) => Err(VerifyError::UnsupportedAlgorithm(format!("{other:?}"))),
        None => Err(VerifyError::UnsupportedAlgorithm("<missing>".into())),
    }
}

/// Walks `cabundle[0..] ‖ [certificate]`, pinning the root by fingerprint,
/// verifying each certificate against its predecessor (`ecdsa-with-SHA384`,
/// validity window vs `now`), and returns the leaf's public key.
fn verify_chain(doc: &AttestationDoc, now: SystemTime) -> Result<VerifyingKey, VerifyError> {
    let mut certs: Vec<&[u8]> = doc.cabundle.iter().map(|c| c.as_ref()).collect();
    if certs.is_empty() {
        return Err(VerifyError::CertificateChain(
            "document carries an empty CA bundle".into(),
        ));
    }
    certs.push(doc.certificate.as_ref());

    let root = certs[0];
    let fingerprint = Sha256::digest(root);
    if fingerprint.as_slice() != AWS_NITRO_ROOT_SHA256 {
        return Err(VerifyError::CertificateChain(format!(
            "root fingerprint mismatch: got {}",
            hex::encode(fingerprint)
        )));
    }

    let now_secs = now
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let mut parent_key: Option<VerifyingKey> = None;
    let mut leaf_key: Option<VerifyingKey> = None;
    for (index, cert_der) in certs.iter().enumerate() {
        let cert = X509Certificate::from_der(cert_der)
            .map_err(|err| VerifyError::CertificateChain(format!("cert {index}: {err}")))?
            .1;

        // Signature algorithm allowlist: the Nitro PKI signs every
        // certificate with ECDSA P-384/SHA-384.
        if cert.signature_algorithm.oid() != &OID_SIG_ECDSA_WITH_SHA384 {
            return Err(VerifyError::CertificateChain(format!(
                "cert {index}: unexpected signature algorithm {}",
                cert.signature_algorithm.oid()
            )));
        }

        // Validity window (all chain members, root included — mirrors AWS's
        // guidance and keeps expired roots from verifying forever).
        let not_before = cert.validity.not_before.timestamp();
        let not_after = cert.validity.not_after.timestamp();
        if now_secs < not_before || now_secs > not_after {
            return Err(VerifyError::CertificateChain(format!(
                "cert {index} not valid at {now_secs} (valid {not_before}..={not_after})"
            )));
        }

        let key = verifying_key(&cert)?;
        match &parent_key {
            // Root: pinned by fingerprint above; its self-signature is not
            // consulted (the pin *is* the trust anchor).
            None => parent_key = Some(key),
            Some(parent) => {
                let tbs = tbs_bytes(cert_der)?;
                let sig =
                    Signature::from_der(cert.signature_value.data.as_ref()).map_err(|err| {
                        VerifyError::CertificateChain(format!("cert {index}: sig encoding: {err}"))
                    })?;
                parent.verify(tbs, &sig).map_err(|err| {
                    VerifyError::CertificateChain(format!("cert {index}: signature: {err}"))
                })?;
                parent_key = Some(key);
            }
        }
        leaf_key = Some(key);
    }

    leaf_key.ok_or_else(|| VerifyError::CertificateChain("no certificates".into()))
}

/// Extracts the leaf (last certificate) SPKI as a P-384 verifying key.
fn verifying_key(cert: &X509Certificate<'_>) -> Result<VerifyingKey, VerifyError> {
    VerifyingKey::from_sec1_bytes(cert.public_key().subject_public_key.data.as_ref())
        .map_err(|err| VerifyError::CertificateChain(format!("public key: {err}")))
}

/// Verifies the COSE_Sign1 signature (ES384, fixed `r‖s` encoding — COSE
/// does not use DER here) with the leaf key over the `Signature1` structure.
fn verify_cose_signature(
    key: &VerifyingKey,
    protected: &[u8],
    payload: &[u8],
    signature: &[u8],
) -> Result<(), VerifyError> {
    let sig = Signature::from_slice(signature)
        .map_err(|err| VerifyError::UnsupportedAlgorithm(format!("ES384 signature: {err}")))?;
    let structure = cose::sig_structure(protected, payload);
    key.verify(&structure, &sig)
        .map_err(|_| VerifyError::SignatureInvalid)
}

/// Minimal DER reader: returns the first element (the TBS `SEQUENCE`) of the
/// outer certificate SEQUENCE. `x509-parser` keeps those bytes crate-private,
/// and the walk is short enough to audit directly.
fn tbs_bytes(cert_der: &[u8]) -> Result<&[u8], VerifyError> {
    let bad = |what: &str| VerifyError::CertificateChain(format!("DER: {what}"));
    let mut pos = 0usize;
    // Outer SEQUENCE.
    if cert_der.get(pos) != Some(&0x30) {
        return Err(bad("certificate is not a SEQUENCE"));
    }
    pos += 1;
    let _outer_len = der_len(cert_der, &mut pos)?;
    // First inner element: the TBS SEQUENCE, tag through end of value.
    let start = pos;
    if cert_der.get(pos) != Some(&0x30) {
        return Err(bad("tbsCertificate is not a SEQUENCE"));
    }
    pos += 1;
    let inner_len = der_len(cert_der, &mut pos)?;
    let end = pos
        .checked_add(inner_len)
        .ok_or_else(|| bad("length overflow"))?;
    cert_der.get(start..end).ok_or_else(|| bad("truncated"))
}

/// Reads a DER length at `pos` (definite form; short or long) and advances.
fn der_len(bytes: &[u8], pos: &mut usize) -> Result<usize, VerifyError> {
    let bad = |what: &str| VerifyError::CertificateChain(format!("DER: {what}"));
    let first = *bytes.get(*pos).ok_or_else(|| bad("length missing"))?;
    *pos += 1;
    if first < 0x80 {
        return Ok(first as usize);
    }
    let count = (first & 0x7f) as usize;
    if count == 0 || count > 4 {
        return Err(bad("unsupported length form"));
    }
    let mut len = 0usize;
    for _ in 0..count {
        let byte = *bytes.get(*pos).ok_or_else(|| bad("length truncated"))?;
        *pos += 1;
        len = (len << 8) | byte as usize;
    }
    Ok(len)
}

/// Maps the NSM document into the shared client-facing payload schema.
/// - `pcrs`: hex strings keyed by index; all-zero registers are dropped
///   (they mean "not present", matching AWS's own verifier).
/// - `timestamp`: NSM milliseconds → seconds, the schema's unit.
/// - `public_key`/`nonce`/`user_data`: raw bytes → hex, as on the mock path.
fn map_payload(doc: AttestationDoc) -> AttestationPayload {
    let digest = match doc.digest {
        aws_nitro_enclaves_nsm_api::api::Digest::SHA256 => "SHA256",
        aws_nitro_enclaves_nsm_api::api::Digest::SHA384 => "SHA384",
        aws_nitro_enclaves_nsm_api::api::Digest::SHA512 => "SHA512",
    };
    let pcrs = doc
        .pcrs
        .into_iter()
        .filter(|(_, value)| !value.iter().all(|byte| *byte == 0))
        .map(|(index, value)| (index.to_string(), hex::encode(value.as_ref())))
        .collect::<BTreeMap<String, String>>();
    AttestationPayload {
        module_id: doc.module_id,
        digest: digest.to_string(),
        pcrs,
        timestamp: doc.timestamp / 1000,
        nonce: doc.nonce.map(|bytes| hex::encode(bytes.as_ref())),
        user_data: doc.user_data.map(|bytes| hex::encode(bytes.as_ref())),
        public_key: doc.public_key.map(|bytes| hex::encode(bytes.as_ref())),
        algorithm: "ES384".to_string(),
    }
}
