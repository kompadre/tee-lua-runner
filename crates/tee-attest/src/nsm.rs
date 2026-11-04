//! NSM-shaped attestation backend: the **same operation API** the real
//! Nitro NSM provides (`GetAttestationDoc`), with two interchangeable
//! backends behind [`crate::Attestor`]:
//!
//! * [`NsmDeviceAttestor`] (Stage 7): local `/dev/nsm` ioctl inside a real
//!   Nitro enclave, via `aws-nitro-enclaves-nsm-api`. Produces genuine
//!   Nitro documents (verified through the AWS certificate chain).
//! * [`NsmRemoteAttestor`] (Stage 6): dials a stand-in daemon over
//!   TCP/vsock; documents are Stage 2 COSE_Sign1 (mock-signed).
//!
//! The `public_key` field mirrors the real NSM request: the enclave passes
//! its channel key, which the NSM binds into the signed document — exactly
//! the flow the client already verifies.

use std::str::FromStr;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tee_proto::framing::{read_frame, write_frame};
use tee_proto::transport::{Addr, Stream};

use crate::AttestError;

/// Mirrors `GetAttestationDoc`'s request (binary fields as hex for this
/// JSON-over-stream transport; the Stage 7 ioctl uses raw bytes).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NsmRequest {
    /// Freshness nonce (hex), 0..=128 bytes like the real NSM.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    /// Caller-provided binding data (hex), up to 512 bytes like the real NSM.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_data: Option<String>,
    /// Public key (hex) to embed in the document (channel key).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    /// Digest algorithm selection (reserved for Stage 7 parity).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
}

/// The NSM operation result: an opaque signed document (hex) or an error.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NsmResponse {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub document: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Attestor that performs the NSM operation against a remote stand-in,
/// dialing per request (attestation is rare; statelessness beats a
/// connection pool here).
pub struct NsmRemoteAttestor {
    addr: Addr,
    public_key: Option<String>,
}

impl NsmRemoteAttestor {
    /// `addr`: `HOST:PORT` or `vsock:CID:PORT`. `public_key_hex`: the
    /// enclave channel key to bind into every document (the NSM's
    /// `public_key` request field).
    pub fn new(addr: &str, public_key_hex: Option<String>) -> Result<Self, String> {
        let addr = Addr::from_str(addr).map_err(|err| err.to_string())?;
        Ok(Self {
            addr,
            public_key: public_key_hex,
        })
    }
}

impl crate::Attestor for NsmRemoteAttestor {
    fn attest(&self, nonce: &[u8], user_data: &[u8]) -> Result<Vec<u8>, AttestError> {
        let fail = |msg: String| AttestError::Backend(format!("nsm[{}]: {msg}", self.addr));

        let mut stream = Stream::dial(&self.addr).map_err(|err| fail(format!("dial: {err}")))?;
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .map_err(|err| fail(format!("set timeout: {err}")))?;
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .map_err(|err| fail(format!("set timeout: {err}")))?;

        let request = NsmRequest {
            nonce: Some(hex::encode(nonce)),
            user_data: Some(hex::encode(user_data)),
            public_key: self.public_key.clone(),
            digest: None,
        };
        let payload =
            serde_json::to_vec(&request).map_err(|err| fail(format!("encode request: {err}")))?;
        write_frame(&mut stream, &payload).map_err(|err| fail(format!("send: {err}")))?;

        let Some(response_bytes) =
            read_frame(&mut stream).map_err(|err| fail(format!("receive: {err}")))?
        else {
            return Err(fail("stand-in closed the connection".into()));
        };
        let response: NsmResponse = serde_json::from_slice(&response_bytes)
            .map_err(|err| fail(format!("decode response: {err}")))?;
        if let Some(error) = response.error {
            return Err(fail(error));
        }
        let Some(document) = response.document else {
            return Err(fail("empty document".into()));
        };
        hex::decode(document).map_err(|err| fail(format!("document not hex: {err}")))
    }
}

/// Attestor backed by the local `/dev/nsm` device (real Nitro enclave).
///
/// Wraps `aws-nitro-enclaves-nsm-api`'s ioctl driver: `nsm_init()` opens
/// the device once, each `attest` issues `GetAttestationDoc` with the
/// request fields, and the response is the genuine Nitro document (CBOR
/// attestation payload under ES384 + AWS certificate chain — verified by
/// [`crate::verify`]'s dispatch, not here).
///
/// Outside an enclave `/dev/nsm` does not exist and construction fails
/// with the device error, so accidental host use is loud, not silent.
pub struct NsmDeviceAttestor {
    fd: i32,
    public_key: Option<String>,
}

// The fd is a plain device descriptor; sharing it across threads is fine
// (requests are serialized by the ioctl itself).
unsafe impl Send for NsmDeviceAttestor {}
unsafe impl Sync for NsmDeviceAttestor {}

impl NsmDeviceAttestor {
    /// `public_key_hex`: the enclave channel key to bind into every
    /// document (the NSM's `public_key` request field), as hex.
    pub fn new(public_key_hex: Option<String>) -> Result<Self, String> {
        let fd = aws_nitro_enclaves_nsm_api::driver::nsm_init();
        if fd < 0 {
            return Err("cannot open /dev/nsm (not running inside a Nitro enclave? \
                 use `--nsm HOST:PORT` for the stand-in backend)"
                .to_string());
        }
        Ok(Self {
            fd,
            public_key: public_key_hex,
        })
    }
}

impl Drop for NsmDeviceAttestor {
    fn drop(&mut self) {
        aws_nitro_enclaves_nsm_api::driver::nsm_exit(self.fd);
    }
}

impl crate::Attestor for NsmDeviceAttestor {
    fn attest(&self, nonce: &[u8], user_data: &[u8]) -> Result<Vec<u8>, AttestError> {
        use aws_nitro_enclaves_nsm_api::api::{Request, Response};
        use serde_bytes::ByteBuf;

        let fail = |msg: String| AttestError::Backend(format!("nsm[/dev/nsm]: {msg}"));

        // The real NSM takes the public key as raw bytes; we keep hex
        // strings at this layer (same as the remote backend), so decode.
        let public_key = match &self.public_key {
            Some(hex_str) => {
                Some(hex::decode(hex_str).map_err(|err| fail(format!("public_key hex: {err}")))?)
            }
            None => None,
        };

        let request = Request::Attestation {
            user_data: Some(ByteBuf::from(user_data.to_vec())),
            nonce: Some(ByteBuf::from(nonce.to_vec())),
            public_key: public_key.map(ByteBuf::from),
        };
        match aws_nitro_enclaves_nsm_api::driver::nsm_process_request(self.fd, request) {
            Response::Attestation { document } => Ok(document),
            Response::Error(code) => Err(fail(format!("NSM error: {code:?}"))),
            other => Err(fail(format!("unexpected response: {other:?}"))),
        }
    }
}
