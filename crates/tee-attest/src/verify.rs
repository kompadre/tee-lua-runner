//! Client-side attestation document verification.
//!
//! Reaching [`verify`]'s returned payload means: the document is a
//! well-formed COSE_Sign1 signed by the trust root's Ed25519 key (strict
//! verification), and every provided [`Expectations`] entry matched the
//! *signed* content. Callers then inspect PCR values/payload fields.

use std::collections::BTreeMap;
use std::fmt;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use crate::cose;

/// Errors raised while verifying an attestation document.
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    /// The bytes are not a decodable COSE_Sign1 structure.
    #[error("document is not a decodable COSE_Sign1 structure: {0}")]
    Decode(String),
    /// The protected header names an algorithm outside the allowlist.
    #[error("unsupported signature algorithm `{0}`")]
    UnsupportedAlgorithm(String),
    /// The signature does not verify under the trust root.
    #[error("signature verification failed")]
    SignatureInvalid,
    /// The signed payload bytes are not the expected CBOR schema.
    #[error("attestation payload is not decodable: {0}")]
    PayloadDecode(String),
    /// A nonce expectation was set but the signed content differs/omits it.
    #[error("expected nonce missing or mismatched")]
    NonceMismatch,
    /// A user_data expectation was set but the signed content differs/omits it.
    #[error("expected user_data missing or mismatched")]
    UserDataMismatch,
    /// A PCR0 expectation was set but the signed content differs/omits it.
    #[error("expected PCR0 missing or mismatched: {0}")]
    PcrMismatch(&'static str),
    /// The provided trust root is unusable.
    #[error("invalid trust root: {0}")]
    InvalidTrustRoot(String),
    /// The X.509 chain behind a real Nitro document failed validation
    /// (root fingerprint, per-certificate signature, algorithm, or validity).
    #[error("certificate chain validation failed: {0}")]
    CertificateChain(String),
}

/// Attestation payload schema — mirrors the Nitro attestation document
/// fields (CBOR; binary values hex-encoded, as in Nitro documents).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationPayload {
    pub module_id: String,
    pub digest: String,
    pub pcrs: BTreeMap<String, String>,
    pub timestamp: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_data: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    pub algorithm: String,
}

impl AttestationPayload {
    /// The attested envelope-unwrap public key (32 bytes, hex) carried as
    /// the `tee_pk` suffix of `user_data` (`measurement ‖ tee_pk`), or
    /// `None` for the legacy bare-measurement layout or a malformed value.
    ///
    /// Trust: only meaningful after [`verify`] succeeded *and* the caller's
    /// measurement expectation matched — the suffix is signed content
    /// produced by the measured runner, which generated or accepted the key
    /// it reports.
    pub fn tee_pk(&self) -> Option<[u8; 32]> {
        let user_data = self.user_data.as_deref()?;
        if user_data.len() != 128 {
            // Not `measurement ‖ tee_pk` (64 bytes hex-encoded).
            return None;
        }
        let suffix = &user_data[64..];
        hex::decode(suffix).ok()?.try_into().ok()
    }
}

/// Trust anchor for verification.
///
/// * [`TrustRoot::from_hex`] — Stage 2 mock root: a raw Ed25519 key (the
///   stand-in prints it; QEMU/dev flows pin it out of band).
/// * [`TrustRoot::aws_nitro`] — the real Nitro PKI: the AWS Nitro Enclaves
///   Root G1 fingerprint is *compiled in* (Stage 7), so nothing is pinned
///   out of band — `--root aws-nitro` on the CLI/config selects it.
///
/// Dispatch happens on the *document's* algorithm: ES384 documents always
/// verify against the pinned AWS root regardless of the configured value;
/// EdDSA (mock) documents require a mock root here.
#[derive(Clone, PartialEq, Eq)]
pub enum TrustRoot {
    /// Mock/QEMU root: an Ed25519 verification key.
    Mock(ed25519_dalek::VerifyingKey),
    /// Real Nitro PKI (pinned AWS root, no key material).
    Nitro,
}

impl TrustRoot {
    /// Parses a hex-encoded (32-byte) Ed25519 public key (mock root).
    pub fn from_hex(hex_str: &str) -> Result<Self, VerifyError> {
        let bytes: [u8; 32] = hex::decode(hex_str.trim())
            .map_err(|err| VerifyError::InvalidTrustRoot(format!("hex: {err}")))?
            .try_into()
            .map_err(|_| VerifyError::InvalidTrustRoot("expected 32 bytes".to_string()))?;
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&bytes)
            .map_err(|err| VerifyError::InvalidTrustRoot(err.to_string()))?;
        Ok(Self::Mock(verifying_key))
    }

    /// Accepts either the `aws-nitro` keyword (real Nitro PKI) or a hex
    /// mock root — the single entry point for CLI/config values.
    pub fn parse(value: &str) -> Result<Self, VerifyError> {
        let trimmed = value.trim();
        if trimmed.eq_ignore_ascii_case("aws-nitro") {
            return Ok(Self::Nitro);
        }
        Self::from_hex(trimmed)
    }

    /// The real Nitro root (pinned AWS certificate fingerprint).
    pub fn aws_nitro() -> Self {
        Self::Nitro
    }

    /// Hex-encoded Ed25519 public key (mock roots only).
    pub fn to_hex(&self) -> String {
        match self {
            Self::Mock(key) => hex::encode(key.to_bytes()),
            Self::Nitro => "aws-nitro".to_string(),
        }
    }

    pub(crate) fn from_verifying_key(verifying_key: ed25519_dalek::VerifyingKey) -> Self {
        Self::Mock(verifying_key)
    }
}

impl fmt::Debug for TrustRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TrustRoot({})", self.to_hex())
    }
}

/// What the relying party expects from a document. All set entries must
/// match the signed payload; unset entries are not checked.
#[derive(Debug, Clone, Default)]
pub struct Expectations {
    pub nonce: Option<Vec<u8>>,
    pub user_data: Option<Vec<u8>>,
    /// Required PCR0 (hex, as rendered in the payload) — the enclave-image
    /// measurement from the releases manifest.
    pub pcr0: Option<String>,
}

impl Expectations {
    pub fn new() -> Self {
        Self::default()
    }

    /// Require this freshness nonce (as produced by the caller's challenge).
    pub fn with_nonce(mut self, nonce: &[u8]) -> Self {
        self.nonce = Some(nonce.to_vec());
        self
    }

    /// Require this module measurement inside the signed `user_data`.
    ///
    /// Since Stage 7 the runner composes `user_data = measurement ‖ tee_pk`
    /// (64 bytes) when an envelope-unwrap key is provisioned, so this
    /// matches a strict *prefix* with an optional single 32-byte suffix —
    /// never arbitrary extension. The suffix, when present, is the attested
    /// envelope key: extract it with [`AttestationPayload::tee_pk`].
    pub fn with_user_data(mut self, user_data: &[u8]) -> Self {
        self.user_data = Some(user_data.to_vec());
        self
    }

    /// Require PCR0 to equal this hex value (measurements manifest).
    /// Anchors the *hardware* measurement of the enclave image — unlike the
    /// self-reported `user_data`, a tampered runner cannot forge it.
    pub fn with_pcr0(mut self, pcr0: &str) -> Self {
        self.pcr0 = Some(pcr0.trim().to_ascii_lowercase());
        self
    }
}

/// Verifies a document against a trust root and expectations.
///
/// Dispatches on the protected-header algorithm:
/// - `"EdDSA"` — mock/QEMU document, signature checked under `root`.
/// - ES384 (`-35`) — **real Nitro document**: verified against the pinned
///   AWS Nitro root (see [`crate::nitro`]); `root` is not consulted, but the
///   freshness/`user_data` expectations still apply.
///
/// Certificate validity is checked against the current wall clock; use
/// [`verify_at`] to pin time (test vectors with expired CA certificates).
pub fn verify(
    root: &TrustRoot,
    document: &[u8],
    expectations: &Expectations,
) -> Result<AttestationPayload, VerifyError> {
    verify_at(root, document, expectations, SystemTime::now())
}

/// [`verify`] with an explicit verification time for certificate validity.
pub fn verify_at(
    root: &TrustRoot,
    document: &[u8],
    expectations: &Expectations,
    now: SystemTime,
) -> Result<AttestationPayload, VerifyError> {
    let (protected, payload_bytes, signature) = cose::parse(document)?;
    let payload = if cose::alg(&protected)? == cose::ALG_ES384 {
        // Real Nitro document: trust anchors to the compiled-in AWS root;
        // the configured root is irrelevant (an ES384 signature cannot be
        // validated against a mock key anyway).
        crate::nitro::verify_nitro(&protected, &payload_bytes, &signature, expectations, now)?
    } else {
        let TrustRoot::Mock(verifying_key) = root else {
            return Err(VerifyError::InvalidTrustRoot(
                "document is a mock (EdDSA) attestation but the configured trust \
                 root is `aws-nitro` — verify against the stand-in's root instead"
                    .into(),
            ));
        };
        cose::verify_signature(verifying_key, &protected, &payload_bytes, &signature)?;
        let payload: AttestationPayload = ciborium::from_reader(&payload_bytes[..])
            .map_err(|err| VerifyError::PayloadDecode(err.to_string()))?;
        check_expectations(&payload, expectations)?;
        payload
    };
    Ok(payload)
}

/// Checks nonce/`user_data` expectations against the *signed* payload.
/// Shared by the mock and real-Nitro verification paths.
///
/// `user_data` uses prefix semantics with a length bound (see
/// [`Expectations::with_user_data`]): the signed value must start with the
/// expected measurement and be either exactly that long or exactly 32 bytes
/// longer (the attested `tee_pk` suffix).
pub(crate) fn check_expectations(
    payload: &AttestationPayload,
    expectations: &Expectations,
) -> Result<(), VerifyError> {
    if let Some(expected) = &expectations.nonce {
        let want = hex::encode(expected);
        if payload.nonce.as_deref() != Some(want.as_str()) {
            return Err(VerifyError::NonceMismatch);
        }
    }
    if let Some(expected) = &expectations.user_data {
        let want = hex::encode(expected);
        // Valid layouts: `measurement` (legacy) or `measurement ‖ tee_pk`.
        let valid = match payload.user_data.as_deref() {
            Some(got) => {
                got.starts_with(&want) && (got.len() == want.len() || got.len() == want.len() + 64)
            }
            None => false,
        };
        if !valid {
            return Err(VerifyError::UserDataMismatch);
        }
    }
    if let Some(expected) = &expectations.pcr0 {
        let got = payload
            .pcrs
            .get("0")
            .map(|value| value.to_ascii_lowercase());
        if got.as_deref() != Some(expected.as_str()) {
            return Err(VerifyError::PcrMismatch(
                "PCR0 does not match the pinned measurements manifest value",
            ));
        }
    }
    Ok(())
}
