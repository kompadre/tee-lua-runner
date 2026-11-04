//! Wire protocol for the gate/throttle service (Stage 4/5).
//!
//! JSON payloads ride *inside* the Stage 3 channel (Q3 decision: binary
//! records outside, JSON payloads inside). The proof-of-possession message
//! builders are **the** shared contract: the client signs exactly what the
//! service rebuilds — byte-for-byte, domain-separated. [`framing`] is the
//! shared u32-length codec used by both the runner server and `tpass`.

pub mod framing;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Domain separation for fetch PoPs.
pub const FETCH_POP_DOMAIN: &[u8] = b"tpass/fetch/v1";
/// Domain separation for revocation PoPs.
pub const REVOKE_POP_DOMAIN: &[u8] = b"tpass/revoke/v1";

/// Client → service requests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    /// Unwrap an envelope. `sign_pk` (Ed25519) is the identity, `enc_pk`
    /// (X25519) is the envelope recipient the TEE checks against; `pop`
    /// proves possession of `sign_pk` over *these exact fields*.
    Fetch {
        sign_pk: String,
        enc_pk: String,
        envelope: String,
        pop: String,
    },
    /// Blacklist this identity outright (compromised key). PoP required so
    /// identities cannot be revoked by third parties.
    Revoke {
        sign_pk: String,
        enc_pk: String,
        pop: String,
    },
    /// Recent audit-ring entries (key id + decisions; never secrets).
    Audit,
    /// Attestation challenge (freshness nonce). The one operation allowed
    /// as plaintext in channel mode — the channel key can only be trusted
    /// after this round trip verifies.
    Attest {
        /// Hex nonce, 1..=64 bytes.
        nonce_hex: String,
    },
}

/// Service → client responses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum Response {
    /// The still-`E_local`-sealed inner blob (client decrypts locally).
    Fetch { inner: String },
    /// Revocation accepted.
    Revoke,
    /// Audit ring snapshot.
    Audit { entries: Vec<AuditEntry> },
    /// Attestation document (COSE_Sign1 bytes, hex) for the challenge.
    Attest { doc_hex: String },
    /// Protocol-level failure.
    Error {
        code: ErrorCode,
        message: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        retry_after_ms: Option<u64>,
    },
}

/// Protocol error codes (stable strings in JSON).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// Rolling window exhausted; `retry_after_ms` says when to come back.
    Throttled,
    /// Identity blacklisted (hard refuse, PoP or not).
    Blacklisted,
    /// Proof of possession failed or mismatched.
    BadPop,
    /// The envelope did not open / was malformed.
    BadEnvelope,
    /// The envelope is addressed to a different owner key.
    WrongOwner,
    /// Throttle bucket capacity exhausted (admission control).
    ThrottleStateFull,
    /// Blacklist capacity exhausted (refuses further revocations).
    RevokeListFull,
    /// Malformed request fields.
    BadRequest,
    /// Unexpected internal failure.
    Internal,
}

impl ErrorCode {
    /// Snake-case string used in audit records.
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::Throttled => "throttled",
            ErrorCode::Blacklisted => "blacklisted",
            ErrorCode::BadPop => "bad_pop",
            ErrorCode::BadEnvelope => "bad_envelope",
            ErrorCode::WrongOwner => "wrong_owner",
            ErrorCode::ThrottleStateFull => "throttle_state_full",
            ErrorCode::RevokeListFull => "revoke_list_full",
            ErrorCode::BadRequest => "bad_request",
            ErrorCode::Internal => "internal",
        }
    }
}

/// One audit-ring record. Contains the identity's public key and the
/// decision only — **never** envelopes, inner blobs, or any secret
/// (AGENTS: never log secrets).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Monotonic sequence number.
    pub seq: u64,
    /// Host timestamp (seconds; monotonic-floor semantics — Session 5).
    pub ts: i64,
    /// Identity Ed25519 public key (hex) — public information.
    pub owner: String,
    /// `"fetch"` or `"revoke"`.
    pub action: String,
    /// `"ok"` or an [`ErrorCode`] string.
    pub outcome: String,
}

/// The exact message signed for a fetch:
/// `domain ‖ sign_pk ‖ enc_pk ‖ sha256(envelope)`.
///
/// Binding both public keys prevents an attacker from substituting their own
/// signing key while claiming someone else's envelope-recipient key (the
/// identity = both keys together, Stage 3).
pub fn fetch_pop_message(sign_pk: &[u8; 32], enc_pk: &[u8; 32], envelope: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(FETCH_POP_DOMAIN.len() + 32 + 32 + 32);
    msg.extend_from_slice(FETCH_POP_DOMAIN);
    msg.extend_from_slice(sign_pk);
    msg.extend_from_slice(enc_pk);
    msg.extend_from_slice(&Sha256::digest(envelope));
    msg
}

/// The exact message signed for a revocation:
/// `domain ‖ sign_pk ‖ enc_pk`.
pub fn revoke_pop_message(sign_pk: &[u8; 32], enc_pk: &[u8; 32]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(REVOKE_POP_DOMAIN.len() + 64);
    msg.extend_from_slice(REVOKE_POP_DOMAIN);
    msg.extend_from_slice(sign_pk);
    msg.extend_from_slice(enc_pk);
    msg
}

/// Parses a 32-byte hex public key.
pub fn decode_pk32(hex_str: &str) -> Option<[u8; 32]> {
    hex::decode(hex_str.trim()).ok()?.try_into().ok()
}
