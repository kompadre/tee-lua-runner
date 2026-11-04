//! Identities, HPKE envelopes and the client↔enclave channel (Stage 3).
//!
//! Crypto posture:
//! * HPKE per RFC 9180, single suite
//!   DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / ChaCha20Poly1305:
//!   **base mode** for envelopes and channel requests, **auth mode** for
//!   channel responses (the enclave proves possession of its attested
//!   channel key — otherwise any wire observer could forge responses, since
//!   HPKE-to-a-public-key alone authenticates nobody). Pinned against the
//!   RFC's Appendix A.2 test vectors.
//! * Blind gatekeeper: `seal_secret` builds `E_TEE(E_local(secret))`. The
//!   TEE unwraps only the outer layer, checks the inner envelope's recipient
//!   against the owner key the client claims, and returns the inner blob —
//!   plaintext never enters the TEE (AGENTS invariant 7).

pub mod channel;
pub mod envelope;
mod hpke;
pub mod identity;

pub use channel::{ChannelClient, ChannelServer, OpenedRequest, PendingRequest};
pub use envelope::{
    inner_recipient, open_local, open_tee, seal_local, seal_secret, seal_tee, tee_unwrap,
};
pub use identity::{LocalIdentity, PublicIdentity};

/// Errors raised by this crate.
///
/// Decryption failures are deliberately collapsed into a single opaque
/// [`CryptoError::OpenFailed`] — callers must not be able to distinguish
/// "wrong key" from "tampered ciphertext" (no padding/oracle semantics).
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    /// AEAD open failed (wrong key, tampering, or non-authorizing context).
    #[error("HPKE decryption failed")]
    OpenFailed,
    /// Non-contributory (all-zero) X25519 output — RFC 7748 mandates abort.
    #[error("non-contributory Diffie-Hellman output")]
    NonContributory,
    /// Malformed envelope/channel structure.
    #[error("malformed {0}: {1}")]
    Malformed(&'static str, String),
    /// Inner envelope is not addressed to this key.
    #[error("inner envelope is not addressed to this key")]
    WrongRecipient,
    /// Inner envelope is addressed to a different owner than claimed.
    #[error("inner envelope is addressed to a different owner")]
    WrongOwner,
    /// Codec failure (CBOR encode/decode).
    #[error("codec error: {0}")]
    Codec(String),
}
