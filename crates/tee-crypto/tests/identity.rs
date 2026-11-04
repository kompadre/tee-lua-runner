//! Identity tests: seed roundtrips, public derivation, proof-of-possession.

use tee_crypto::{LocalIdentity, PublicIdentity};
use zeroize::Zeroizing;

#[test]
fn seed_roundtrip_and_determinism() {
    let seed = Zeroizing::new([7u8; 64]);
    let a = LocalIdentity::from_seed(seed.clone());
    let b = LocalIdentity::from_seed(seed);
    assert_eq!(a.public(), b.public());
    assert_eq!(a.to_seed().as_ref(), &[7u8; 64]);

    let c = LocalIdentity::from_seed(Zeroizing::new([8u8; 64]));
    assert_ne!(a.public(), c.public());
}

#[test]
fn generate_produces_distinct_identities() {
    let a = LocalIdentity::generate();
    let b = LocalIdentity::generate();
    assert_ne!(a.public(), b.public());
}

#[test]
fn key_id_is_stable_and_distinct() {
    let a = LocalIdentity::from_seed(Zeroizing::new([1u8; 64])).public();
    let a2 = LocalIdentity::from_seed(Zeroizing::new([1u8; 64])).public();
    let b = LocalIdentity::from_seed(Zeroizing::new([2u8; 64])).public();
    assert_eq!(a.key_id(), a2.key_id());
    assert_ne!(a.key_id(), b.key_id());
    assert_eq!(a.key_id().len(), 64); // sha256 hex
}

#[test]
fn proof_of_possession_roundtrip_and_domain_binding() {
    let identity = LocalIdentity::from_seed(Zeroizing::new([3u8; 64]));
    let public = identity.public();
    let challenge = b"nonce-from-the-throttle-service";

    let sig = identity.sign_challenge(challenge);
    assert!(LocalIdentity::verify_challenge(
        &public.signing,
        challenge,
        &sig
    ));

    // Wrong challenge fails.
    assert!(!LocalIdentity::verify_challenge(
        &public.signing,
        b"other-challenge",
        &sig
    ));

    // A raw signature over the challenge (without the domain separator) must
    // NOT verify as a PoP.
    let raw = identity.sign(challenge);
    assert!(!LocalIdentity::verify_challenge(
        &public.signing,
        challenge,
        &raw
    ));

    // Tampered signature fails.
    let mut tampered = sig;
    tampered[0] ^= 0xff;
    assert!(!LocalIdentity::verify_challenge(
        &public.signing,
        challenge,
        &tampered
    ));
}

#[test]
fn public_identity_serde_roundtrip() {
    let public = LocalIdentity::generate().public();
    let json = serde_json::to_string(&public).unwrap();
    let back: PublicIdentity = serde_json::from_str(&json).unwrap();
    assert_eq!(public, back);
}
