//! Envelope tests: the blind-gatekeeper flow, owner binding, tampering.

use tee_crypto::{
    inner_recipient, open_local, open_tee, seal_local, seal_secret, seal_tee, tee_unwrap,
    CryptoError,
};

fn keypair(seed: u8) -> ([u8; 32], [u8; 32]) {
    let sk = x25519_dalek::StaticSecret::from([seed; 32]);
    let pk = x25519_dalek::PublicKey::from(&sk).to_bytes();
    (sk.to_bytes(), pk)
}

#[test]
fn local_roundtrip() {
    let (sk, pk) = keypair(1);
    let blob = seal_local(&pk, b"password-entry").unwrap();
    assert_eq!(open_local(&sk, &blob).unwrap(), b"password-entry");
    assert_eq!(inner_recipient(&blob).unwrap(), pk);
}

#[test]
fn wrong_local_key_is_rejected() {
    let (_sk_a, pk_a) = keypair(1);
    let (sk_b, _pk_b) = keypair(2);
    let blob = seal_local(&pk_a, b"secret").unwrap();
    // Header check: not addressed to B at all.
    assert!(matches!(
        open_local(&sk_b, &blob),
        Err(CryptoError::WrongRecipient)
    ));
}

#[test]
fn recipient_swap_binds_in_aad() {
    let (sk_a, pk_a) = keypair(1);
    let (sk_b, pk_b) = keypair(2);
    let mut blob = seal_local(&pk_a, b"secret").unwrap();
    blob[4..4 + 32].copy_from_slice(&pk_b); // swap recipient header to B

    // B passes the header check, but the AAD binds the recipient: the HPKE
    // open fails (a swap cannot redirect an envelope).
    assert!(matches!(
        open_local(&sk_b, &blob),
        Err(CryptoError::OpenFailed)
    ));
    // And A now fails the header check.
    assert!(matches!(
        open_local(&sk_a, &blob),
        Err(CryptoError::WrongRecipient)
    ));
}

#[test]
fn full_blind_gatekeeper_flow() {
    let (tee_sk, tee_pk) = keypair(10);
    let (owner_sk, owner_pk) = keypair(20);
    let secret = b"S3CR3T-passphrase-entry";

    // Store: E_TEE(E_local(secret))
    let stored = seal_secret(&tee_pk, &owner_pk, secret).unwrap();

    // Plaintext never appears in the stored blob (defense in depth).
    assert!(!stored.windows(secret.len()).any(|w| w == secret));

    // TEE side: unwrap outer, check owner, return inner — no plaintext seen.
    let claimed = tee_unwrap(&tee_sk, &stored, &owner_pk).unwrap();
    assert_eq!(inner_recipient(&claimed).unwrap(), owner_pk);

    // Client side: open inner with the local key.
    assert_eq!(open_local(&owner_sk, &claimed).unwrap(), secret);
}

#[test]
fn gatekeeper_rejects_wrong_owner_and_wrong_tee_key() {
    let (tee_sk, tee_pk) = keypair(10);
    let (owner_sk, owner_pk) = keypair(20);
    let (_other_sk, other_pk) = keypair(30);
    let stored = seal_secret(&tee_pk, &owner_pk, b"secret").unwrap();

    // Claiming someone else's key fails the owner check.
    assert!(matches!(
        tee_unwrap(&tee_sk, &stored, &other_pk),
        Err(CryptoError::WrongOwner)
    ));

    // A different TEE key cannot even open the outer envelope
    // (the AAD binds the TEE public key).
    let (wrong_tee_sk, _wrong_tee_pk) = keypair(11);
    assert!(matches!(
        open_tee(&wrong_tee_sk, &stored),
        Err(CryptoError::OpenFailed)
    ));

    // After a successful unwrap, only the true owner opens the inner blob.
    let claimed = tee_unwrap(&tee_sk, &stored, &owner_pk).unwrap();
    let (intruder_sk, _intruder_pk) = keypair(40);
    assert!(matches!(
        open_local(&intruder_sk, &claimed),
        Err(CryptoError::WrongRecipient)
    ));
    assert_eq!(open_local(&owner_sk, &claimed).unwrap(), b"secret");
}

#[test]
fn every_tampered_byte_of_stored_blob_fails_the_chain() {
    let (tee_sk, tee_pk) = keypair(10);
    let (owner_sk, owner_pk) = keypair(20);
    let stored = seal_secret(&tee_pk, &owner_pk, b"S3CR3T").unwrap();

    for index in 0..stored.len() {
        let mut tampered = stored.clone();
        tampered[index] ^= 0xff;
        let outcome = tee_unwrap(&tee_sk, &tampered, &owner_pk)
            .and_then(|inner| open_local(&owner_sk, &inner));
        assert!(
            outcome.is_err(),
            "flip at byte {index} must break the chain (got {outcome:?})"
        );
    }
}

#[test]
fn malformed_structures_are_rejected() {
    let (sk, pk) = keypair(1);
    let outer = seal_tee(&pk, b"x").unwrap();
    assert!(matches!(
        open_tee(&sk, &outer[..3]),
        Err(CryptoError::Malformed(..))
    ));
    assert!(matches!(
        inner_recipient(b"TLI1short"),
        Err(CryptoError::Malformed(..))
    ));
    let mut blob = seal_local(&pk, b"x").unwrap();
    blob[..4].copy_from_slice(b"XXXX");
    assert!(matches!(
        open_local(&sk, &blob),
        Err(CryptoError::Malformed(..))
    ));
}
