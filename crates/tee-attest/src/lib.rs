//! Attestation backends and document verification.
//!
//! * [`Attestor`] — the trait the runner depends on (`nonce` + `user_data` →
//!   document bytes). `user_data` is where the runner binds the guest module
//!   measurement.
//! * [`NullAttestor`] — refuses; the safe default when no backend is wired.
//! * [`MockAttestor`] — Stage 2/6 stand-in producing COSE_Sign1 documents
//!   signed by an Ed25519 test root, structurally mirroring Nitro attestation
//!   payloads (module_id, digest, pcrs, timestamp, nonce, user_data).
//! * [`verify`] — client-side verification against a pluggable [`TrustRoot`]
//!   with explicit [`Expectations`] (freshness nonce, measurement binding).
//!
//! Stage 7 swaps the mock backend for the real `/dev/nsm` NSM and the trust
//! root for the AWS Nitro certificate chain; the document shape and the
//! verification entry point stay the same.

mod cose;
mod mock;
mod nsm;
mod verify;

pub use mock::MockAttestor;
pub use nsm::{NsmRemoteAttestor, NsmRequest, NsmResponse};
pub use verify::{verify, AttestationPayload, Expectations, TrustRoot, VerifyError};

/// Errors produced by an attestation backend.
#[derive(Debug, thiserror::Error)]
pub enum AttestError {
    /// The backend refused or failed to produce a document.
    #[error("attestation backend failure: {0}")]
    Backend(String),
    /// No attestation backend is available in this build/environment.
    #[error("attestation is not supported by this backend")]
    Unsupported,
}

/// Produces attestation documents that bind `user_data` (for the runner:
/// the module measurement, see `runner_core::measure`).
///
/// `nonce` is caller-supplied and included in the document so relying parties
/// can prove freshness.
pub trait Attestor: Send + Sync {
    fn attest(&self, nonce: &[u8], user_data: &[u8]) -> Result<Vec<u8>, AttestError>;
}

/// Backend that refuses to attest. Used until a mock (Stage 2) or real NSM
/// backend (Stage 7) is configured, so scripts get a clear error instead of a
/// silently fake document.
pub struct NullAttestor;

impl Attestor for NullAttestor {
    fn attest(&self, _nonce: &[u8], _user_data: &[u8]) -> Result<Vec<u8>, AttestError> {
        Err(AttestError::Unsupported)
    }
}
