use sha2::{Digest, Sha256};

use crate::capability::Manifest;

/// Domain separation tag for guest module measurements.
pub const MEASUREMENT_DOMAIN: &[u8] = b"tee-runner/module/v1";

/// SHA-256 over the domain tag, the module bytes and the canonical capability
/// manifest (derived from the module's import section).
///
/// The module bytes are hashed verbatim — they are exactly what executes —
/// and the manifest is included so the attestation payload is self-describing
/// without requiring clients to parse wasm themselves.
pub fn script_measurement(source: &[u8], manifest: &Manifest) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(MEASUREMENT_DOMAIN);
    hasher.update([0u8]);
    hasher.update((source.len() as u64).to_le_bytes());
    hasher.update(source);
    hasher.update([0u8]);
    hasher.update(manifest.canonical().as_bytes());
    hasher.finalize().into()
}

/// Lowercase hex encoding.
pub fn to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}
