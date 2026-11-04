//! RFC 9180 HPKE — base and auth modes for one fixed suite.
//!
//! Suite: DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / ChaCha20Poly1305
//! (kem_id 0x0020, kdf_id 0x0001, aead_id 0x0003). Every construction here
//! follows the RFC's pseudocode verbatim; `#[cfg(test)]` helpers with
//! injectable ephemeral seeds exist solely to pin Appendix A.2 vectors.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::CryptoError;

pub(crate) const KEM_ID: u16 = 0x0020; // DHKEM(X25519, HKDF-SHA256)
pub(crate) const KDF_ID: u16 = 0x0001; // HKDF-SHA256
pub(crate) const AEAD_ID: u16 = 0x0003; // ChaCha20Poly1305
const MODE_BASE: u8 = 0;
const MODE_AUTH: u8 = 2;
const NSECRET: usize = 32;
const NK: usize = 32;
const NN: usize = 12;
const NH: usize = 32;

fn kem_suite_id() -> [u8; 5] {
    let mut id = [0u8; 5];
    id[..3].copy_from_slice(b"KEM");
    id[3..].copy_from_slice(&KEM_ID.to_be_bytes());
    id
}

fn hpke_suite_id() -> [u8; 10] {
    let mut id = [0u8; 10];
    id[..4].copy_from_slice(b"HPKE");
    id[4..6].copy_from_slice(&KEM_ID.to_be_bytes());
    id[6..8].copy_from_slice(&KDF_ID.to_be_bytes());
    id[8..].copy_from_slice(&AEAD_ID.to_be_bytes());
    id
}

/// HKDF-Extract(salt, "HPKE-v1" ‖ suite_id ‖ label ‖ ikm).
fn labeled_extract(suite_id: &[u8], salt: &[u8], label: &str, ikm: &[u8]) -> [u8; NH] {
    // An empty salt is equivalent to Nh zero bytes for HMAC (RFC 5869 §2.2).
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(salt)
        .expect("HMAC-SHA256 accepts keys of any length");
    mac.update(b"HPKE-v1");
    mac.update(suite_id);
    mac.update(label.as_bytes());
    mac.update(ikm);
    mac.finalize().into_bytes().into()
}

/// HKDF-Expand(prk, I2OSP(L,2) ‖ "HPKE-v1" ‖ suite_id ‖ label ‖ info, L).
fn labeled_expand(
    suite_id: &[u8],
    prk: &[u8],
    label: &str,
    info: &[u8],
    len: usize,
) -> Result<Vec<u8>, CryptoError> {
    if len > 255 * NH {
        return Err(CryptoError::Malformed(
            "hpke",
            format!("expand length {len} exceeds 255*Nh"),
        ));
    }
    let mut labeled_info = Vec::with_capacity(2 + 7 + suite_id.len() + label.len() + info.len());
    labeled_info.extend_from_slice(&(len as u16).to_be_bytes());
    labeled_info.extend_from_slice(b"HPKE-v1");
    labeled_info.extend_from_slice(suite_id);
    labeled_info.extend_from_slice(label.as_bytes());
    labeled_info.extend_from_slice(info);

    let mut out = Vec::with_capacity(len + NH);
    let mut t: Vec<u8> = Vec::new();
    let mut counter: u8 = 1;
    while out.len() < len {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(prk)
            .expect("HMAC-SHA256 accepts keys of any length");
        mac.update(&t);
        mac.update(&labeled_info);
        mac.update(&[counter]);
        t = mac.finalize().into_bytes().to_vec();
        out.extend_from_slice(&t);
        counter = counter
            .checked_add(1)
            .ok_or_else(|| CryptoError::Malformed("hpke", "expand counter overflow".into()))?;
    }
    out.truncate(len);
    Ok(out)
}

fn to_array<const N: usize>(bytes: Vec<u8>) -> Result<[u8; N], CryptoError> {
    bytes
        .try_into()
        .map_err(|_| CryptoError::Malformed("hpke", format!("expected {} bytes", N)))
}

pub(crate) fn public_of(sk: &[u8; 32]) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(*sk)).to_bytes()
}

/// DH(sk, pk) with the RFC 7748 all-zero check (RFC 9180 §7.1.4).
fn dh(sk: &[u8; 32], pk: &[u8; 32]) -> Result<[u8; NSECRET], CryptoError> {
    let shared = StaticSecret::from(*sk).diffie_hellman(&PublicKey::from(*pk));
    if !shared.was_contributory() {
        return Err(CryptoError::NonContributory);
    }
    to_array(shared.as_bytes().to_vec())
}

/// DeriveKeyPair for X25519 (RFC 9180 §7.1.3).
pub(crate) fn derive_key_pair(ikm: &[u8]) -> Result<([u8; 32], [u8; 32]), CryptoError> {
    let suite = kem_suite_id();
    let dkp_prk = labeled_extract(&suite, &[], "dkp_prk", ikm);
    let sk = to_array::<32>(labeled_expand(&suite, &dkp_prk, "sk", &[], NSECRET)?)?;
    Ok((sk, public_of(&sk)))
}

/// ExtractAndExpand (RFC 9180 §4.1).
fn extract_and_expand(dh_out: &[u8], kem_context: &[u8]) -> Result<[u8; NSECRET], CryptoError> {
    let suite = kem_suite_id();
    let eae_prk = labeled_extract(&suite, &[], "eae_prk", dh_out);
    to_array(labeled_expand(
        &suite,
        &eae_prk,
        "shared_secret",
        kem_context,
        NSECRET,
    )?)
}

fn random_seed() -> [u8; 32] {
    let mut seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    seed
}

// ------------------------------------------------------------------ base mode

fn encap_base(pk_r: &[u8; 32], ikm_e: &[u8; 32]) -> Result<([u8; 32], [u8; 32]), CryptoError> {
    let (sk_e, pk_e) = derive_key_pair(ikm_e)?;
    let dh_out = dh(&sk_e, pk_r)?;
    let mut kem_context = Vec::with_capacity(64);
    kem_context.extend_from_slice(&pk_e);
    kem_context.extend_from_slice(pk_r);
    Ok((pk_e, extract_and_expand(&dh_out, &kem_context)?))
}

fn decap_base(enc: &[u8; 32], sk_r: &[u8; 32]) -> Result<[u8; 32], CryptoError> {
    let dh_out = dh(sk_r, enc)?;
    let mut kem_context = Vec::with_capacity(64);
    kem_context.extend_from_slice(enc);
    kem_context.extend_from_slice(&public_of(sk_r));
    extract_and_expand(&dh_out, &kem_context)
}

// ------------------------------------------------------------------ auth mode

fn encap_auth(
    pk_r: &[u8; 32],
    sk_s: &[u8; 32],
    ikm_e: &[u8; 32],
) -> Result<([u8; 32], [u8; 32]), CryptoError> {
    let (sk_e, pk_e) = derive_key_pair(ikm_e)?;
    let mut dh_out = Vec::with_capacity(64);
    dh_out.extend_from_slice(&dh(&sk_e, pk_r)?);
    dh_out.extend_from_slice(&dh(sk_s, pk_r)?);
    let mut kem_context = Vec::with_capacity(96);
    kem_context.extend_from_slice(&pk_e);
    kem_context.extend_from_slice(pk_r);
    kem_context.extend_from_slice(&public_of(sk_s));
    Ok((pk_e, extract_and_expand(&dh_out, &kem_context)?))
}

fn decap_auth(enc: &[u8; 32], sk_r: &[u8; 32], pk_s: &[u8; 32]) -> Result<[u8; 32], CryptoError> {
    let mut dh_out = Vec::with_capacity(64);
    dh_out.extend_from_slice(&dh(sk_r, enc)?);
    dh_out.extend_from_slice(&dh(sk_r, pk_s)?);
    let mut kem_context = Vec::with_capacity(96);
    kem_context.extend_from_slice(enc);
    kem_context.extend_from_slice(&public_of(sk_r));
    kem_context.extend_from_slice(pk_s);
    extract_and_expand(&dh_out, &kem_context)
}

// --------------------------------------------------------------- key schedule

struct Schedule {
    key: [u8; NK],
    base_nonce: [u8; NN],
}

fn key_schedule(
    mode: u8,
    shared_secret: &[u8; NSECRET],
    info: &[u8],
) -> Result<Schedule, CryptoError> {
    let suite = hpke_suite_id();
    let psk_id_hash = labeled_extract(&suite, &[], "psk_id_hash", &[]);
    let info_hash = labeled_extract(&suite, &[], "info_hash", info);
    let mut key_schedule_context = Vec::with_capacity(1 + 2 * NH);
    key_schedule_context.push(mode);
    key_schedule_context.extend_from_slice(&psk_id_hash);
    key_schedule_context.extend_from_slice(&info_hash);

    let secret = labeled_extract(&suite, shared_secret, "secret", &[]);
    let key = to_array(labeled_expand(
        &suite,
        &secret,
        "key",
        &key_schedule_context,
        NK,
    )?)?;
    let base_nonce = to_array(labeled_expand(
        &suite,
        &secret,
        "base_nonce",
        &key_schedule_context,
        NN,
    )?)?;
    Ok(Schedule { key, base_nonce })
}

/// ComputeNonce(seq) = base_nonce XOR I2OSP(seq, Nn).
fn nonce_for(base_nonce: &[u8; NN], seq: u64) -> [u8; NN] {
    let mut nonce = *base_nonce;
    let seq_be = seq.to_be_bytes();
    for (i, byte) in seq_be.iter().enumerate() {
        nonce[NN - 8 + i] ^= byte;
    }
    nonce
}

fn aead_seal(schedule: &Schedule, seq: u64, aad: &[u8], pt: &[u8]) -> Result<Vec<u8>, CryptoError> {
    ChaCha20Poly1305::new(Key::from_slice(&schedule.key))
        .encrypt(
            Nonce::from_slice(&nonce_for(&schedule.base_nonce, seq)),
            Payload { msg: pt, aad },
        )
        .map_err(|_| CryptoError::Malformed("hpke", "aead encryption failed".into()))
}

fn aead_open(schedule: &Schedule, seq: u64, aad: &[u8], ct: &[u8]) -> Result<Vec<u8>, CryptoError> {
    ChaCha20Poly1305::new(Key::from_slice(&schedule.key))
        .decrypt(
            Nonce::from_slice(&nonce_for(&schedule.base_nonce, seq)),
            Payload { msg: ct, aad },
        )
        .map_err(|_| CryptoError::OpenFailed)
}

// ------------------------------------------------------ single-shot public API

/// HPKE single-shot Seal (base mode, seq 0).
pub(crate) fn seal_base(
    pk_r: &[u8; 32],
    info: &[u8],
    aad: &[u8],
    pt: &[u8],
) -> Result<([u8; 32], Vec<u8>), CryptoError> {
    let (enc, shared) = encap_base(pk_r, &random_seed())?;
    let schedule = key_schedule(MODE_BASE, &shared, info)?;
    Ok((enc, aead_seal(&schedule, 0, aad, pt)?))
}

/// HPKE single-shot Open (base mode, seq 0).
pub(crate) fn open_base(
    enc: &[u8; 32],
    sk_r: &[u8; 32],
    info: &[u8],
    aad: &[u8],
    ct: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let shared = decap_base(enc, sk_r)?;
    let schedule = key_schedule(MODE_BASE, &shared, info)?;
    aead_open(&schedule, 0, aad, ct)
}

/// HPKE single-shot Seal, auth mode: the sender proves possession of
/// `sk_s` (mode 2, RFC 9180 §5.1.3) — used for channel responses so the
/// client can authenticate the enclave via its attested channel key.
pub(crate) fn seal_auth(
    pk_r: &[u8; 32],
    sk_s: &[u8; 32],
    info: &[u8],
    aad: &[u8],
    pt: &[u8],
) -> Result<([u8; 32], Vec<u8>), CryptoError> {
    let (enc, shared) = encap_auth(pk_r, sk_s, &random_seed())?;
    let schedule = key_schedule(MODE_AUTH, &shared, info)?;
    Ok((enc, aead_seal(&schedule, 0, aad, pt)?))
}

/// HPKE single-shot Open, auth mode: verifies the sender held `pk_s`.
pub(crate) fn open_auth(
    enc: &[u8; 32],
    sk_r: &[u8; 32],
    pk_s: &[u8; 32],
    info: &[u8],
    aad: &[u8],
    ct: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let shared = decap_auth(enc, sk_r, pk_s)?;
    let schedule = key_schedule(MODE_AUTH, &shared, info)?;
    aead_open(&schedule, 0, aad, ct)
}

// Test-only: injectable seeds and sequence numbers for RFC vectors.
#[cfg(test)]
pub(crate) mod vectors {
    use super::*;

    pub(crate) fn seal_base_with(
        pk_r: &[u8; 32],
        ikm_e: &[u8; 32],
        info: &[u8],
        aad: &[u8],
        pt: &[u8],
        seq: u64,
    ) -> Result<([u8; 32], Vec<u8>), CryptoError> {
        let (enc, shared) = encap_base(pk_r, ikm_e)?;
        let schedule = key_schedule(MODE_BASE, &shared, info)?;
        Ok((enc, aead_seal(&schedule, seq, aad, pt)?))
    }

    pub(crate) fn open_base_at(
        enc: &[u8; 32],
        sk_r: &[u8; 32],
        info: &[u8],
        aad: &[u8],
        ct: &[u8],
        seq: u64,
    ) -> Result<Vec<u8>, CryptoError> {
        let shared = decap_base(enc, sk_r)?;
        let schedule = key_schedule(MODE_BASE, &shared, info)?;
        aead_open(&schedule, seq, aad, ct)
    }

    pub(crate) fn seal_auth_with(
        pk_r: &[u8; 32],
        sk_s: &[u8; 32],
        ikm_e: &[u8; 32],
        info: &[u8],
        aad: &[u8],
        pt: &[u8],
        seq: u64,
    ) -> Result<([u8; 32], Vec<u8>), CryptoError> {
        let (enc, shared) = encap_auth(pk_r, sk_s, ikm_e)?;
        let schedule = key_schedule(MODE_AUTH, &shared, info)?;
        Ok((enc, aead_seal(&schedule, seq, aad, pt)?))
    }

    pub(crate) fn open_auth_at(
        enc: &[u8; 32],
        sk_r: &[u8; 32],
        pk_s: &[u8; 32],
        info: &[u8],
        aad: &[u8],
        ct: &[u8],
        seq: u64,
    ) -> Result<Vec<u8>, CryptoError> {
        let shared = decap_auth(enc, sk_r, pk_s)?;
        let schedule = key_schedule(MODE_AUTH, &shared, info)?;
        aead_open(&schedule, seq, aad, ct)
    }

    /// `(key, base_nonce, exporter_secret)`
    pub(crate) type ScheduleParts = ([u8; NK], [u8; NN], [u8; NH]);

    pub(crate) fn key_schedule_parts(
        mode: u8,
        shared_secret: &[u8; NSECRET],
        info: &[u8],
    ) -> Result<ScheduleParts, CryptoError> {
        let suite = hpke_suite_id();
        let psk_id_hash = labeled_extract(&suite, &[], "psk_id_hash", &[]);
        let info_hash = labeled_extract(&suite, &[], "info_hash", info);
        let mut ctx = Vec::new();
        ctx.push(mode);
        ctx.extend_from_slice(&psk_id_hash);
        ctx.extend_from_slice(&info_hash);
        let secret = labeled_extract(&suite, shared_secret, "secret", &[]);
        let key = to_array(labeled_expand(&suite, &secret, "key", &ctx, NK)?)?;
        let base_nonce = to_array(labeled_expand(&suite, &secret, "base_nonce", &ctx, NN)?)?;
        let exporter = to_array(labeled_expand(&suite, &secret, "exp", &ctx, NH)?)?;
        Ok((key, base_nonce, exporter))
    }

    pub(crate) fn shared_from_encap(
        pk_r: &[u8; 32],
        ikm_e: &[u8; 32],
    ) -> Result<([u8; 32], [u8; 32]), CryptoError> {
        encap_base(pk_r, ikm_e)
    }

    pub(crate) fn auth_shared_from_encap(
        pk_r: &[u8; 32],
        sk_s: &[u8; 32],
        ikm_e: &[u8; 32],
    ) -> Result<([u8; 32], [u8; 32]), CryptoError> {
        encap_auth(pk_r, sk_s, ikm_e)
    }

    pub(crate) fn nonce_for_pub(base_nonce: &[u8; NN], seq: u64) -> [u8; NN] {
        nonce_for(base_nonce, seq)
    }

    pub(crate) fn hpke_suite_id_pub() -> [u8; 10] {
        hpke_suite_id()
    }

    pub(crate) fn mode_base_pub() -> u8 {
        MODE_BASE
    }

    pub(crate) fn labeled_extract_pub(
        suite: &[u8],
        salt: &[u8],
        label: &str,
        ikm: &[u8],
    ) -> [u8; NH] {
        labeled_extract(suite, salt, label, ikm)
    }
}

/// Official test vectors: RFC 9180 Appendix A.2 (base) and A.2.3 (auth).
#[cfg(test)]
mod rfc9180_tests {
    use super::vectors::*;
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        hex::decode(s).expect("valid hex vector")
    }

    fn key32(s: &str) -> [u8; 32] {
        unhex(s).try_into().expect("32-byte vector")
    }

    fn nonce12(s: &str) -> [u8; 12] {
        unhex(s).try_into().expect("12-byte vector")
    }

    const INFO: &str = "4f6465206f6e2061204772656369616e2055726e"; // "Ode on a Grecian Urn"
    const PT: &str = "4265617574792069732074727574682c20747275746820626561757479"; // "Beauty is truth, truth beauty"

    // ---------------------------------------------------------- A.2.1 base

    #[test]
    fn a2_derive_key_pairs() {
        let (sk, pk) = derive_key_pair(&unhex(
            "909a9b35d3dc4713a5e72a4da274b55d3d3821a37e5d099e74a647db583a904b",
        ))
        .unwrap();
        assert_eq!(
            hex::encode(sk),
            "f4ec9b33b792c372c1d2c2063507b684ef925b8c75a42dbcbf57d63ccd381600"
        );
        assert_eq!(
            hex::encode(pk),
            "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a"
        );

        let (sk, pk) = derive_key_pair(&unhex(
            "1ac01f181fdf9f352797655161c58b75c656a6cc2716dcb66372da835542e1df",
        ))
        .unwrap();
        assert_eq!(
            hex::encode(sk),
            "8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb"
        );
        assert_eq!(
            hex::encode(pk),
            "4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a"
        );
    }

    #[test]
    fn a2_base_encap_key_schedule_and_nonce() {
        let info = unhex(INFO);
        let pk_r = key32("4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a");
        let ikm_e = key32("909a9b35d3dc4713a5e72a4da274b55d3d3821a37e5d099e74a647db583a904b");

        let (enc, shared) = shared_from_encap(&pk_r, &ikm_e).unwrap();
        assert_eq!(
            hex::encode(enc),
            "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a"
        );
        assert_eq!(
            hex::encode(shared),
            "0bbe78490412b4bbea4812666f7916932b828bba79942424abb65244930d69a7"
        );

        // key_schedule_context = mode ‖ psk_id_hash ‖ info_hash
        let suite = hpke_suite_id_pub();
        let psk_id_hash = labeled_extract_pub(&suite, &[], "psk_id_hash", &[]);
        let info_hash = labeled_extract_pub(&suite, &[], "info_hash", &info);
        let mut ctx = vec![mode_base_pub()];
        ctx.extend_from_slice(&psk_id_hash);
        ctx.extend_from_slice(&info_hash);
        assert_eq!(
            hex::encode(&ctx),
            "00431df6cd95e11ff49d7013563baf7f11588c75a6611ee2a4404a49306ae4cfc5b69c5718a60cc5876c358d3f7fc31ddb598503f67be58ea1e798c0bb19eb9796"
        );

        // `secret` = LabeledExtract(shared_secret, "secret", psk="")
        let secret = labeled_extract_pub(&suite, &shared, "secret", &[]);
        assert_eq!(
            hex::encode(secret),
            "5b9cd775e64b437a2335cf499361b2e0d5e444d5cb41a8a53336d8fe402282c6"
        );

        let (key, base_nonce, exporter) =
            key_schedule_parts(mode_base_pub(), &shared, &info).unwrap();
        assert_eq!(
            hex::encode(key),
            "ad2744de8e17f4ebba575b3f5f5a8fa1f69c2a07f6e7500bc60ca6e3e3ec1c91"
        );
        assert_eq!(hex::encode(base_nonce), "5c4d98150661b848853b547f");
        assert_eq!(
            hex::encode(exporter),
            "a3b010d4994890e2c6968a36f64470d3c824c8f5029942feb11e7a74b2921922"
        );

        // ComputeNonce(seq) = base_nonce XOR I2OSP(seq, 12)
        let base = nonce12("5c4d98150661b848853b547f");
        for (seq, expected) in [
            (0u64, "5c4d98150661b848853b547f"),
            (1, "5c4d98150661b848853b547e"),
            (2, "5c4d98150661b848853b547d"),
            (4, "5c4d98150661b848853b547b"),
            (255, "5c4d98150661b848853b5480"),
            (256, "5c4d98150661b848853b557f"),
        ] {
            assert_eq!(
                hex::encode(nonce_for_pub(&base, seq)),
                expected,
                "seq {seq}"
            );
        }
    }

    #[test]
    fn a2_base_seal_vectors_and_roundtrip() {
        let info = unhex(INFO);
        let pk_r = key32("4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a");
        let sk_r = key32("8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb");
        let ikm_e = key32("909a9b35d3dc4713a5e72a4da274b55d3d3821a37e5d099e74a647db583a904b");
        let pt = unhex(PT);

        for (seq, aad_hex, ct_hex) in [
            (
                0u64,
                "436f756e742d30",
                "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28",
            ),
            (
                1,
                "436f756e742d31",
                "6b53c051e4199c518de79594e1c4ab18b96f081549d45ce015be002090bb119e85285337cc95ba5f59992dc98c",
            ),
            (
                256,
                "436f756e742d323536",
                "7a4a13e9ef23978e2c520fd4d2e757514ae160cd0cd05e556ef692370ca53076214c0c40d4c728d6ed9e727a5b",
            ),
        ] {
            let aad = unhex(aad_hex);
            let (enc, ct) =
                seal_base_with(&pk_r, &ikm_e, &info, &aad, &pt, seq).unwrap();
            assert_eq!(hex::encode(&ct), ct_hex, "seq {seq} ciphertext");
            // And the vector ciphertext decrypts under the receiver key.
            let dec = open_base_at(&enc, &sk_r, &info, &aad, &unhex(ct_hex), seq).unwrap();
            assert_eq!(dec, pt, "seq {seq} roundtrip");
        }
    }

    // ---------------------------------------------------------- A.2.3 auth

    #[test]
    fn a2_auth_encap_key_schedule_and_seal() {
        let info = unhex(INFO);
        let pk_r = key32("1a478716d63cb2e16786ee93004486dc151e988b34b475043d3e0175bdb01c44");
        let sk_r = key32("3ca22a6d1cda1bb9480949ec5329d3bf0b080ca4c45879c95eddb55c70b80b82");
        let pk_s = key32("f0f4f9e96c54aeed3f323de8534fffd7e0577e4ce269896716bcb95643c8712b");
        let sk_s = key32("2def0cb58ffcf83d1062dd085c8aceca7f4c0c3fd05912d847b61f3e54121f05");
        let ikm_e = key32("938d3daa5a8904540bc24f48ae90eed3f4f7f11839560597b55e7c9598c996c0");
        let pt = unhex(PT);
        let aad = unhex("436f756e742d30");

        let (enc, shared) = auth_shared_from_encap(&pk_r, &sk_s, &ikm_e).unwrap();
        assert_eq!(
            hex::encode(enc),
            "f7674cc8cd7baa5872d1f33dbaffe3314239f6197ddf5ded1746760bfc847e0e"
        );
        assert_eq!(
            hex::encode(shared),
            "d2d67828c8bc9fa661cf15a31b3ebf1febe0cafef7abfaaca580aaf6d471e3eb"
        );

        let (key, base_nonce, exporter) = key_schedule_parts(2, &shared, &info).unwrap(); // mode_auth = 2
        assert_eq!(
            hex::encode(key),
            "b071fd1136680600eb447a845a967d35e9db20749cdf9ce098bcc4deef4b1356"
        );
        assert_eq!(hex::encode(base_nonce), "d20577dff16d7cea2c4bf780");
        assert_eq!(
            hex::encode(exporter),
            "be2d93b82071318cdb88510037cf504344151f2f9b9da8ab48974d40a2251dd7"
        );

        // Seal matches the vector, and the recipient opens it under (skR, pkS).
        let (enc2, ct) = seal_auth_with(&pk_r, &sk_s, &ikm_e, &info, &aad, &pt, 0).unwrap();
        assert_eq!(enc2, enc);
        assert_eq!(
            hex::encode(&ct),
            "ab1a13c9d4f01a87ec3440dbd756e2677bd2ecf9df0ce7ed73869b98e00c09be111cb9fdf077347aeb88e61bdf"
        );
        let dec = open_auth_at(&enc, &sk_r, &pk_s, &info, &aad, &ct, 0).unwrap();
        assert_eq!(dec, pt);

        // Auth property: without the sender's static keypair the response
        // does not open (this is what stops wire-level response forgery).
        let wrong_pk_s = key32(
            &hex::encode(pk_s)
                .chars()
                .rev()
                .collect::<String>()
                .repeat(2)[..64],
        ); // arbitrary other key
        assert!(matches!(
            open_auth_at(&enc, &sk_r, &wrong_pk_s, &info, &aad, &ct, 0),
            Err(CryptoError::OpenFailed)
        ));
    }
}
