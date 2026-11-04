//! Local identities: an Ed25519 signing key + an X25519 encryption key.
//!
//! * The **signing** key owns the identity (proof-of-possession challenges,
//!   Stage 4's throttle binding).
//! * The **encryption** key is the envelope recipient (`E_local`) — its bytes
//!   are the "local public key" the client claims to the blind gatekeeper.
//!
//! Secret material zeroizes on drop (`StaticSecret` via x25519-dalek's
//! `zeroize` feature, `SigningKey` via dalek's own zeroize); `Debug` is
//! redacted (AGENTS conventions).

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

const POP_DOMAIN: &[u8] = b"tee-lua-runner/pop/v1";
const KEY_ID_DOMAIN: &[u8] = b"tee-lua-runner/local-id/v1";

/// Public half of a local identity (safe to publish / send to the TEE).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicIdentity {
    /// Ed25519 public key (identity + proof-of-possession).
    pub signing: [u8; 32],
    /// X25519 public key (envelope recipient, `E_local`).
    pub encryption: [u8; 32],
}

impl PublicIdentity {
    /// Stable identifier for logs, throttle buckets and audit records:
    /// `sha256(domain ‖ signing ‖ encryption)` as hex.
    pub fn key_id(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(KEY_ID_DOMAIN);
        hasher.update(self.signing);
        hasher.update(self.encryption);
        hex::encode(hasher.finalize())
    }
}

/// A local identity: key material + operations.
pub struct LocalIdentity {
    signing: SigningKey,
    encryption: StaticSecret,
}

// Redacted: must not expose key material through Debug.
impl std::fmt::Debug for LocalIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalIdentity")
            .field("key_id", &self.public().key_id())
            .finish_non_exhaustive()
    }
}

impl LocalIdentity {
    /// Generates a fresh identity from the OS CSPRNG.
    pub fn generate() -> Self {
        let mut seed = Zeroizing::new([0u8; 64]);
        rand::rngs::OsRng.fill_bytes(&mut *seed);
        Self::from_seed(seed)
    }

    /// Reconstructs an identity from a 64-byte seed
    /// (Ed25519 seed ‖ X25519 scalar). The seed is zeroized on drop here;
    /// callers must not retain unprotected copies.
    pub fn from_seed(seed: Zeroizing<[u8; 64]>) -> Self {
        let ed_bytes: [u8; 32] = seed[..32].try_into().expect("seed is 64 bytes");
        let x_bytes: [u8; 32] = seed[32..].try_into().expect("seed is 64 bytes");
        Self {
            signing: SigningKey::from_bytes(&ed_bytes),
            encryption: StaticSecret::from(x_bytes),
        }
    }

    /// Exports the identity as a 64-byte seed (zeroizing). Stage 5 wraps
    /// this in the passphrase-protected keystore.
    pub fn to_seed(&self) -> Zeroizing<[u8; 64]> {
        let mut seed = Zeroizing::new([0u8; 64]);
        seed[..32].copy_from_slice(&self.signing.to_bytes());
        seed[32..].copy_from_slice(&self.encryption.to_bytes());
        seed
    }

    /// The public half of this identity.
    pub fn public(&self) -> PublicIdentity {
        PublicIdentity {
            signing: self.signing.verifying_key().to_bytes(),
            encryption: PublicKey::from(&self.encryption).to_bytes(),
        }
    }

    /// Signatures over arbitrary messages (payload-level auth, Stage 4+).
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing.sign(message).to_bytes()
    }

    /// Domain-separated proof-of-possession over a challenge.
    pub fn sign_challenge(&self, challenge: &[u8]) -> [u8; 64] {
        self.sign(&[POP_DOMAIN, challenge].concat())
    }

    /// Verifies a proof-of-possession produced by [`Self::sign_challenge`].
    pub fn verify_challenge(signing_pk: &[u8; 32], challenge: &[u8], signature: &[u8; 64]) -> bool {
        let Ok(verifying) = VerifyingKey::from_bytes(signing_pk) else {
            return false;
        };
        let sig = Signature::from_bytes(signature);
        verifying
            .verify_strict(&[POP_DOMAIN, challenge].concat(), &sig)
            .is_ok()
    }

    /// Opens a gate-returned inner envelope (`E_local`) with this identity's
    /// encryption secret — the client half of the blind-gatekeeper flow.
    /// The secret never leaves this function.
    pub fn open_inner(&self, inner: &[u8]) -> Result<Vec<u8>, crate::CryptoError> {
        crate::envelope::open_local(self.encryption.as_bytes(), inner)
    }
}
