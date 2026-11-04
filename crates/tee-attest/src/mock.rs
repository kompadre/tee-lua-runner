//! COSE_Sign1 mock attestation backend (Stages 2 and 6).
//!
//! Produces documents that structurally mirror Nitro attestation payloads
//! (`module_id`, `digest`, `pcrs`, `timestamp`, `nonce`, `user_data`) signed
//! by an Ed25519 test root. These are **not** Nitro documents: trust them
//! only in local/QEMU testing. Stage 7 swaps this for the real `/dev/nsm`
//! backend while keeping the document shape and `verify` entry point.

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use rand::RngCore;

use crate::cose;
use crate::verify::{AttestationPayload, TrustRoot};
use crate::AttestError;

const MOCK_DIGEST: &str = "SHA256";
const MOCK_ALGORITHM: &str = "EdDSA";

/// Test-root-backed attestation backend. The signing key never leaves the
/// backend; callers only ever see [`TrustRoot`]'s public key.
pub struct MockAttestor {
    signing_key: SigningKey,
    module_id: String,
    pcrs: BTreeMap<String, String>,
}

// Redacted: must not expose key material through Debug.
impl std::fmt::Debug for MockAttestor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MockAttestor")
            .field("module_id", &self.module_id)
            .field("pcrs", &self.pcrs)
            .finish_non_exhaustive()
    }
}

impl MockAttestor {
    /// Generates a fresh Ed25519 test root; returns `(backend, trust root)`.
    pub fn generate(
        module_id: impl Into<String>,
        pcrs: BTreeMap<String, String>,
    ) -> (Self, TrustRoot) {
        let mut seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        Self::from_seed(module_id, pcrs, seed)
    }

    /// Deterministic construction for tests and fixtures.
    pub fn from_seed(
        module_id: impl Into<String>,
        pcrs: BTreeMap<String, String>,
        seed: [u8; 32],
    ) -> (Self, TrustRoot) {
        let signing_key = SigningKey::from_bytes(&seed);
        let trust_root = TrustRoot::from_verifying_key(signing_key.verifying_key());
        (
            Self {
                signing_key,
                module_id: module_id.into(),
                pcrs,
            },
            trust_root,
        )
    }
}

impl crate::Attestor for MockAttestor {
    fn attest(&self, nonce: &[u8], user_data: &[u8]) -> Result<Vec<u8>, AttestError> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .map_err(|err| AttestError::Backend(format!("clock before unix epoch: {err}")))?;
        let payload = AttestationPayload {
            module_id: self.module_id.clone(),
            digest: MOCK_DIGEST.to_string(),
            pcrs: self.pcrs.clone(),
            timestamp,
            nonce: (!nonce.is_empty()).then(|| hex::encode(nonce)),
            user_data: (!user_data.is_empty()).then(|| hex::encode(user_data)),
            public_key: None,
            algorithm: MOCK_ALGORITHM.to_string(),
        };
        let mut payload_bytes = Vec::new();
        ciborium::into_writer(&payload, &mut payload_bytes)
            .map_err(|err| AttestError::Backend(format!("payload encoding: {err}")))?;
        Ok(cose::sign(&self.signing_key, &payload_bytes))
    }
}
