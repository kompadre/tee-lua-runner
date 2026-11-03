//! Attestation backends for the TEE runner.
//!
//! The runner only depends on the [`Attestor`] trait; concrete backends
//! (mock for local/QEMU runs, real `/dev/nsm` for AWS Nitro) are wired in
//! at Stage 2.

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
/// the script measurement, see `runner_core::measure`).
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
