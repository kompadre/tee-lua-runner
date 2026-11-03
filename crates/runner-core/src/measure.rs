use sha2::{Digest, Sha256};

use crate::capability::Manifest;

/// Domain separation tag for script measurements.
pub const MEASUREMENT_DOMAIN: &[u8] = b"tee-lua-runner/script/v1";

/// SHA-256 over the domain tag, the script bytes and the capability manifest.
///
/// Stable across runs and machines: any change to the script bytes or to the
/// set of granted capabilities changes the measurement. Capability order does
/// not (the manifest is canonicalized before hashing).
pub fn script_measurement(source: &str, manifest: &Manifest) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(MEASUREMENT_DOMAIN);
    hasher.update([0u8]);
    hasher.update((source.len() as u64).to_le_bytes());
    hasher.update(source.as_bytes());
    hasher.update([0u8]);
    hasher.update(manifest.canonical().as_bytes());
    hasher.finalize().into()
}

/// Lowercase hex encoding.
pub fn to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}
