//! Client↔enclave end-to-end channel (one-shot request/response).
//!
//! * **Requests** are HPKE base-mode sealed to the enclave's *attested*
//!   channel key (server-confidentiality; only the enclave can read them).
//! * **Responses** are HPKE *auth mode* sealed by the enclave: the client
//!   verifies them under the same attested key, so a wire observer cannot
//!   forge responses (HPKE-to-a-public-key authenticates nobody — auth mode
//!   makes the enclave prove possession of the attested secret).
//! * Transcript binding: the response carries the request's nonce (freshness
//!   echo) and `sha256(request wire bytes)`, both mixed into the HPKE info.
//! * Client authentication is payload-level (PoP), Stage 4 — channel v1 is
//!   server-authenticated only.
//!
//! Wire format: CBOR (`ciborium`), length-prefixed by the transport.

use rand::RngCore;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::hpke;
use crate::CryptoError;

const CHANNEL_VERSION: u8 = 1;
const NONCE_LEN: usize = 16;
const REQUEST_INFO: &[u8] = b"tee-lua-runner/channel/request/v1";
const RESPONSE_INFO: &[u8] = b"tee-lua-runner/channel/response/v1";

fn cbor_encode<T: Serialize>(value: &T) -> Result<Vec<u8>, CryptoError> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes).map_err(|e| CryptoError::Codec(e.to_string()))?;
    Ok(bytes)
}

fn cbor_decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, CryptoError> {
    ciborium::from_reader(bytes).map_err(|e| CryptoError::Codec(e.to_string()))
}

#[derive(Serialize, Deserialize)]
struct RequestWire {
    v: u8,
    nonce: Vec<u8>,
    enc: Vec<u8>,
    ct: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct RequestPayload {
    nonce: Vec<u8>,
    request: Vec<u8>,
    response_pk: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct ResponseWire {
    v: u8,
    nonce: Vec<u8>,
    req_hash: Vec<u8>,
    enc: Vec<u8>,
    ct: Vec<u8>,
}

/// What the enclave side opens from a channel request.
#[derive(Debug)]
pub struct OpenedRequest {
    /// Inner request bytes (the transport-level JSON payload).
    pub request: Vec<u8>,
    /// Client's per-request response key (X25519).
    pub response_pk: [u8; 32],
    /// Freshness nonce echoed in the response.
    pub nonce: [u8; NONCE_LEN],
    /// `sha256` of the request wire bytes (response transcript binding).
    pub request_hash: [u8; 32],
}

/// Per-request secrets the client must hold until the response arrives.
pub struct PendingRequest {
    response_sk: StaticSecret,
    nonce: [u8; NONCE_LEN],
    request_hash: [u8; 32],
}

// Redacted: must not expose key material through Debug.
impl std::fmt::Debug for PendingRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingRequest")
            .field("nonce", &hex::encode(self.nonce))
            .field("request_hash", &hex::encode(self.request_hash))
            .finish_non_exhaustive()
    }
}

/// Enclave-side channel endpoint (holds the static channel key — the one
/// bound into the attestation document's `public_key` field).
pub struct ChannelServer {
    sk: StaticSecret,
}

impl std::fmt::Debug for ChannelServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChannelServer")
            .field("public_key", &hex::encode(self.public_key()))
            .finish()
    }
}

impl ChannelServer {
    /// Generates a fresh channel keypair; returns `(server, public_key)`.
    pub fn generate() -> (Self, [u8; 32]) {
        let mut seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        Self::from_seed(seed)
    }

    /// Deterministic construction for tests/fixtures.
    pub fn from_seed(seed: [u8; 32]) -> (Self, [u8; 32]) {
        let sk = StaticSecret::from(seed);
        let pk = PublicKey::from(&sk).to_bytes();
        (Self { sk }, pk)
    }

    /// The attested channel public key.
    pub fn public_key(&self) -> [u8; 32] {
        PublicKey::from(&self.sk).to_bytes()
    }

    /// Opens a channel request message.
    pub fn open_request(&self, message: &[u8]) -> Result<OpenedRequest, CryptoError> {
        let wire: RequestWire = cbor_decode(message)?;
        if wire.v != CHANNEL_VERSION {
            return Err(CryptoError::Malformed(
                "channel request",
                format!("unsupported version {}", wire.v),
            ));
        }
        let nonce: [u8; NONCE_LEN] = wire
            .nonce
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::Malformed("channel request", "nonce".into()))?;
        let enc: [u8; 32] = wire
            .enc
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::Malformed("channel request", "enc".into()))?;

        let mut info = REQUEST_INFO.to_vec();
        info.extend_from_slice(&nonce);
        let payload_bytes = hpke::open_base(&enc, &self.sk.to_bytes(), &info, &[], &wire.ct)?;
        let payload: RequestPayload = cbor_decode(&payload_bytes)?;

        // The nonce inside the sealed payload must match the cleartext one
        // (prevents splicing a fresh header onto an old sealed payload).
        if payload.nonce.as_slice() != nonce {
            return Err(CryptoError::Malformed(
                "channel request",
                "nonce mismatch between header and payload".into(),
            ));
        }
        let response_pk: [u8; 32] = payload
            .response_pk
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::Malformed("channel request", "response_pk".into()))?;
        let request_hash = Sha256::digest(message).into();

        Ok(OpenedRequest {
            request: payload.request,
            response_pk,
            nonce,
            request_hash,
        })
    }

    /// Seals a response (auth mode: proves possession of the channel key)
    /// bound to the request's nonce and wire hash.
    pub fn seal_response(
        &self,
        response_pk: &[u8; 32],
        nonce: &[u8; NONCE_LEN],
        request_hash: &[u8; 32],
        response: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let mut info = RESPONSE_INFO.to_vec();
        info.extend_from_slice(nonce);
        info.extend_from_slice(request_hash);
        let (enc, ct) = hpke::seal_auth(response_pk, &self.sk.to_bytes(), &info, &[], response)?;
        cbor_encode(&ResponseWire {
            v: CHANNEL_VERSION,
            nonce: nonce.to_vec(),
            req_hash: request_hash.to_vec(),
            enc: enc.to_vec(),
            ct,
        })
    }
}

/// Client-side channel endpoint.
pub struct ChannelClient {
    server_pk: [u8; 32],
}

impl ChannelClient {
    /// `server_pk` must come from a *verified* attestation document's
    /// `public_key` field — that binding is the whole point of the channel.
    pub fn new(server_pk: [u8; 32]) -> Self {
        Self { server_pk }
    }

    /// Seals `request` for the enclave; returns the wire message and the
    /// pending state needed to open the matching response.
    pub fn seal_request(&self, request: &[u8]) -> Result<(Vec<u8>, PendingRequest), CryptoError> {
        let mut nonce = [0u8; NONCE_LEN];
        rand::rngs::OsRng.fill_bytes(&mut nonce);

        let response_sk = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let response_pk = PublicKey::from(&response_sk).to_bytes();

        let payload = cbor_encode(&RequestPayload {
            nonce: nonce.to_vec(),
            request: request.to_vec(),
            response_pk: response_pk.to_vec(),
        })?;

        let mut info = REQUEST_INFO.to_vec();
        info.extend_from_slice(&nonce);
        let (enc, ct) = hpke::seal_base(&self.server_pk, &info, &[], &payload)?;

        let wire = cbor_encode(&RequestWire {
            v: CHANNEL_VERSION,
            nonce: nonce.to_vec(),
            enc: enc.to_vec(),
            ct,
        })?;

        let pending = PendingRequest {
            response_sk,
            nonce,
            request_hash: Sha256::digest(&wire).into(),
        };
        Ok((wire, pending))
    }

    /// Opens a response against the pending request: checks the nonce echo,
    /// the request-hash transcript binding, and — decisively — that it was
    /// sealed under the attested server key (auth mode).
    pub fn open_response(
        &self,
        pending: &PendingRequest,
        message: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let wire: ResponseWire = cbor_decode(message)?;
        if wire.v != CHANNEL_VERSION {
            return Err(CryptoError::Malformed(
                "channel response",
                format!("unsupported version {}", wire.v),
            ));
        }
        if wire.nonce.as_slice() != pending.nonce {
            return Err(CryptoError::Malformed(
                "channel response",
                "nonce echo mismatch".into(),
            ));
        }
        if wire.req_hash.as_slice() != pending.request_hash {
            return Err(CryptoError::Malformed(
                "channel response",
                "request hash mismatch".into(),
            ));
        }
        let enc: [u8; 32] = wire
            .enc
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::Malformed("channel response", "enc".into()))?;

        let mut info = RESPONSE_INFO.to_vec();
        info.extend_from_slice(&pending.nonce);
        info.extend_from_slice(&pending.request_hash);
        hpke::open_auth(
            &enc,
            &pending.response_sk.to_bytes(),
            &self.server_pk,
            &info,
            &[],
            &wire.ct,
        )
    }
}
