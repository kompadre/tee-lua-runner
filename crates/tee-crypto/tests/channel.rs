//! Channel tests: roundtrips, server authentication (auth mode), bindings,
//! exhaustive tamper scans.

use sha2::{Digest, Sha256};
use tee_crypto::{ChannelClient, ChannelServer, CryptoError};

fn server() -> (ChannelServer, [u8; 32]) {
    ChannelServer::from_seed([9u8; 32])
}

#[test]
fn request_response_roundtrip() {
    let (server, server_pk) = server();
    let client = ChannelClient::new(server_pk);

    let (wire, pending) = client.seal_request(br#"{"method":"get"}"#).unwrap();
    let opened = server.open_request(&wire).unwrap();
    assert_eq!(opened.request, br#"{"method":"get"}"#);
    // Both sides agree on the transcript hash of the exact wire bytes.
    let expected_hash: [u8; 32] = Sha256::digest(wire.as_slice()).into();
    assert_eq!(opened.request_hash, expected_hash);

    let response = br#"{"ok":true,"response":42}"#;
    let response_wire = server
        .seal_response(
            &opened.response_pk,
            &opened.nonce,
            &opened.request_hash,
            response,
        )
        .unwrap();
    let opened_response = client.open_response(&pending, &response_wire).unwrap();
    assert_eq!(opened_response, response);
}

#[test]
fn responses_are_server_authenticated() {
    let (server, server_pk) = server();
    let client = ChannelClient::new(server_pk);

    let (wire, pending) = client.seal_request(b"req").unwrap();
    let opened = server.open_request(&wire).unwrap();

    // An attacker who observed the wire (nonce + req_hash are visible) and
    // holds only the server's PUBLIC key cannot forge an acceptable
    // response: auth mode requires the server's static secret — the one
    // bound into the attestation document.
    let (rogue, _rogue_pk) = ChannelServer::from_seed([66u8; 32]);
    let forged = rogue
        .seal_response(
            &opened.response_pk,
            &opened.nonce,
            &opened.request_hash,
            b"evil",
        )
        .unwrap();
    assert!(matches!(
        client.open_response(&pending, &forged),
        Err(CryptoError::OpenFailed)
    ));
}

#[test]
fn wrong_server_key_cannot_open_requests() {
    let (server, _server_pk) = server();
    let (_other_server, other_pk) = ChannelServer::from_seed([7u8; 32]);
    let client = ChannelClient::new(other_pk);

    let (wire, _pending) = client.seal_request(b"req").unwrap();
    assert!(matches!(
        server.open_request(&wire),
        Err(CryptoError::OpenFailed)
    ));
}

#[test]
fn transcript_bindings_are_enforced() {
    let (server, server_pk) = server();
    let client = ChannelClient::new(server_pk);
    let (wire, pending) = client.seal_request(b"req").unwrap();
    let opened = server.open_request(&wire).unwrap();

    // Wrong request hash (e.g. replaying a response meant for another request).
    let wrong_hash = [0u8; 32];
    let response = server
        .seal_response(&opened.response_pk, &opened.nonce, &wrong_hash, b"resp")
        .unwrap();
    assert!(matches!(
        client.open_response(&pending, &response),
        Err(CryptoError::Malformed(_, ref m)) if m.contains("request hash")
    ));

    // Wrong nonce echo.
    let response = server
        .seal_response(
            &opened.response_pk,
            &[7u8; 16],
            &opened.request_hash,
            b"resp",
        )
        .unwrap();
    assert!(matches!(
        client.open_response(&pending, &response),
        Err(CryptoError::Malformed(_, ref m)) if m.contains("nonce")
    ));
}

#[test]
fn every_tampered_request_byte_is_rejected_by_the_server() {
    let (server, server_pk) = server();
    let client = ChannelClient::new(server_pk);
    let (wire, _pending) = client.seal_request(b"req").unwrap();

    for index in 0..wire.len() {
        let mut tampered = wire.clone();
        tampered[index] ^= 0xff;
        assert!(
            server.open_request(&tampered).is_err(),
            "flip at byte {index} must be rejected"
        );
    }
}

#[test]
fn every_tampered_response_byte_is_rejected_by_the_client() {
    let (server, server_pk) = server();
    let client = ChannelClient::new(server_pk);
    let (wire, pending) = client.seal_request(b"req").unwrap();
    let opened = server.open_request(&wire).unwrap();
    let response = server
        .seal_response(
            &opened.response_pk,
            &opened.nonce,
            &opened.request_hash,
            b"resp",
        )
        .unwrap();

    for index in 0..response.len() {
        let mut tampered = response.clone();
        tampered[index] ^= 0xff;
        assert!(
            client.open_response(&pending, &tampered).is_err(),
            "flip at byte {index} must be rejected"
        );
    }
}
