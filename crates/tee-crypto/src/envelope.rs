//! Blind-gatekeeper envelopes: `E_local` (inner) and `E_TEE` (outer).
//!
//! Layouts (all binary, fixed fields):
//!
//! ```text
//! inner = "TLI1" ‖ recipient_x25519_pk(32) ‖ enc(32) ‖ ct
//! outer = "TLO1" ‖ enc(32) ‖ ct
//! ```
//!
//! * The inner envelope's recipient is visible by design: the TEE must read
//!   it to enforce "inner recipient == owner key the client claims"
//!   *without* being able to open the inner ciphertext itself.
//! * `seal_secret(tee_pk, owner_pk, secret)` = outer(inner): the TEE unwraps
//!   the outer layer only (`tee_unwrap`), checks the recipient, and returns
//!   the inner blob — plaintext never enters the TEE.
//! * HPKE info strings and AADs bind context: inner AAD covers
//!   magic‖recipient (recipient swaps fail at the *client's* open), outer
//!   AAD covers magic‖tee_pk.

use crate::hpke;
use crate::CryptoError;

const INNER_MAGIC: [u8; 4] = *b"TLI1";
const OUTER_MAGIC: [u8; 4] = *b"TLO1";
const LOCAL_INFO: &[u8] = b"tee-lua-runner/envelope/local/v1";
const TEE_INFO: &[u8] = b"tee-lua-runner/envelope/tee/v1";
const PK_LEN: usize = 32;
const ENC_LEN: usize = 32;
const TAG_LEN: usize = 16;
const MIN_INNER: usize = 4 + PK_LEN + ENC_LEN + TAG_LEN;
const MIN_OUTER: usize = 4 + ENC_LEN + TAG_LEN;

fn local_aad(recipient: &[u8; PK_LEN]) -> Vec<u8> {
    [&INNER_MAGIC[..], recipient.as_slice()].concat()
}

fn tee_aad(tee_pk: &[u8; PK_LEN]) -> Vec<u8> {
    [&OUTER_MAGIC[..], tee_pk.as_slice()].concat()
}

/// Seals `plaintext` to the local identity's X25519 key (inner envelope).
pub fn seal_local(recipient_pk: &[u8; PK_LEN], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let (enc, ct) = hpke::seal_base(
        recipient_pk,
        LOCAL_INFO,
        &local_aad(recipient_pk),
        plaintext,
    )?;
    let mut out = Vec::with_capacity(MIN_INNER + ct.len());
    out.extend_from_slice(&INNER_MAGIC);
    out.extend_from_slice(recipient_pk);
    out.extend_from_slice(&enc);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Opens an inner envelope with the local identity's X25519 secret.
pub fn open_local(recipient_sk: &[u8; PK_LEN], inner: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if inner.len() < MIN_INNER {
        return Err(CryptoError::Malformed(
            "inner envelope",
            format!("{} bytes < {MIN_INNER}", inner.len()),
        ));
    }
    if inner[..4] != INNER_MAGIC {
        return Err(CryptoError::Malformed(
            "inner envelope",
            "bad magic".to_string(),
        ));
    }
    let recipient: [u8; PK_LEN] = inner[4..4 + PK_LEN].try_into().expect("checked length");
    let expected = hpke::public_of(recipient_sk);
    if recipient != expected {
        return Err(CryptoError::WrongRecipient);
    }
    let enc: [u8; ENC_LEN] = inner[4 + PK_LEN..4 + PK_LEN + ENC_LEN]
        .try_into()
        .expect("checked length");
    let ct = &inner[4 + PK_LEN + ENC_LEN..];
    hpke::open_base(&enc, recipient_sk, LOCAL_INFO, &local_aad(&recipient), ct)
}

/// Reads the inner envelope's recipient without any key material — this is
/// the blind gatekeeper's owner check input.
pub fn inner_recipient(inner: &[u8]) -> Result<[u8; PK_LEN], CryptoError> {
    if inner.len() < MIN_INNER {
        return Err(CryptoError::Malformed(
            "inner envelope",
            format!("{} bytes < {MIN_INNER}", inner.len()),
        ));
    }
    if inner[..4] != INNER_MAGIC {
        return Err(CryptoError::Malformed(
            "inner envelope",
            "bad magic".to_string(),
        ));
    }
    inner[4..4 + PK_LEN]
        .try_into()
        .map_err(|_| CryptoError::Malformed("inner envelope", "recipient".to_string()))
}

/// Seals `payload` to the TEE's X25519 key (outer envelope).
pub fn seal_tee(tee_pk: &[u8; PK_LEN], payload: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let (enc, ct) = hpke::seal_base(tee_pk, TEE_INFO, &tee_aad(tee_pk), payload)?;
    let mut out = Vec::with_capacity(MIN_OUTER + ct.len());
    out.extend_from_slice(&OUTER_MAGIC);
    out.extend_from_slice(&enc);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Opens an outer envelope with the TEE's X25519 secret (runs *inside* the
/// TEE at Stage 4).
pub fn open_tee(tee_sk: &[u8; PK_LEN], outer: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if outer.len() < MIN_OUTER {
        return Err(CryptoError::Malformed(
            "outer envelope",
            format!("{} bytes < {MIN_OUTER}", outer.len()),
        ));
    }
    if outer[..4] != OUTER_MAGIC {
        return Err(CryptoError::Malformed(
            "outer envelope",
            "bad magic".to_string(),
        ));
    }
    let tee_pk = hpke::public_of(tee_sk);
    let enc: [u8; ENC_LEN] = outer[4..4 + ENC_LEN].try_into().expect("checked length");
    let ct = &outer[4 + ENC_LEN..];
    hpke::open_base(&enc, tee_sk, TEE_INFO, &tee_aad(&tee_pk), ct)
}

/// Builds the full stored blob: `E_TEE(E_local(secret))`.
pub fn seal_secret(
    tee_pk: &[u8; PK_LEN],
    owner_pk: &[u8; PK_LEN],
    secret: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let inner = seal_local(owner_pk, secret)?;
    seal_tee(tee_pk, &inner)
}

/// The blind gatekeeper's unwrap: opens the outer envelope, verifies the
/// inner envelope is addressed to `claimed_owner_pk`, returns the inner blob.
/// Never sees plaintext; never persists anything.
pub fn tee_unwrap(
    tee_sk: &[u8; PK_LEN],
    outer: &[u8],
    claimed_owner_pk: &[u8; PK_LEN],
) -> Result<Vec<u8>, CryptoError> {
    let inner = open_tee(tee_sk, outer)?;
    let recipient = inner_recipient(&inner)?;
    if &recipient != claimed_owner_pk {
        return Err(CryptoError::WrongOwner);
    }
    Ok(inner)
}
