//! Client-side attestation document verification.
//!
//! Reaching [`verify`]'s returned payload means: the document is a
//! well-formed COSE_Sign1 signed by the trust root's Ed25519 key (strict
//! verification), and every provided [`Expectations`] entry matched the
//! *signed* content. Callers then inspect PCR values/payload fields.

use std::collections::BTreeMap;
use std::fmt;

use ed25519_dalek::VerifyingKey;
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
    /// The provided trust root is unusable.
    #[error("invalid trust root: {0}")]
    InvalidTrustRoot(String),
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

/// Trust anchor for verification. Stage 2: a raw Ed25519 key (mock root).
/// Stage 7 adds the AWS Nitro certificate chain behind the same entry point.
#[derive(Clone, PartialEq, Eq)]
pub struct TrustRoot {
    verifying_key: VerifyingKey,
}

impl TrustRoot {
    /// Parses a hex-encoded (32-byte) Ed25519 public key.
    pub fn from_hex(hex_str: &str) -> Result<Self, VerifyError> {
        let bytes: [u8; 32] = hex::decode(hex_str.trim())
            .map_err(|err| VerifyError::InvalidTrustRoot(format!("hex: {err}")))?
            .try_into()
            .map_err(|_| VerifyError::InvalidTrustRoot("expected 32 bytes".to_string()))?;
        let verifying_key = VerifyingKey::from_bytes(&bytes)
            .map_err(|err| VerifyError::InvalidTrustRoot(err.to_string()))?;
        Ok(Self { verifying_key })
    }

    /// Hex-encoded Ed25519 public key.
    pub fn to_hex(&self) -> String {
        hex::encode(self.verifying_key.to_bytes())
    }

    pub(crate) fn from_verifying_key(verifying_key: VerifyingKey) -> Self {
        Self { verifying_key }
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

    /// Require this user_data (for the runner: the module measurement).
    pub fn with_user_data(mut self, user_data: &[u8]) -> Self {
        self.user_data = Some(user_data.to_vec());
        self
    }
}

/// Verifies a document against a trust root and expectations.
pub fn verify(
    root: &TrustRoot,
    document: &[u8],
    expectations: &Expectations,
) -> Result<AttestationPayload, VerifyError> {
    let (protected, payload_bytes, signature) = cose::parse(document)?;
    cose::verify_signature(&root.verifying_key, &protected, &payload_bytes, &signature)?;
    let payload: AttestationPayload = ciborium::from_reader(&payload_bytes[..])
        .map_err(|err| VerifyError::PayloadDecode(err.to_string()))?;

    if let Some(expected) = &expectations.nonce {
        let want = hex::encode(expected);
        if payload.nonce.as_deref() != Some(want.as_str()) {
            return Err(VerifyError::NonceMismatch);
        }
    }
    if let Some(expected) = &expectations.user_data {
        let want = hex::encode(expected);
        if payload.user_data.as_deref() != Some(want.as_str()) {
            return Err(VerifyError::UserDataMismatch);
        }
    }
    Ok(payload)
}
