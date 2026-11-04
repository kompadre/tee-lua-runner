//! NSM-shaped attestation backend: the **same operation API** the real
//! Nitro NSM provides (`GetAttestationDoc`), split so Stage 7 only swaps
//! transport + document format:
//!
//! * Stage 6 (here): `NsmRemoteAttestor` dials a stand-in daemon over
//!   TCP/vsock; documents are Stage 2 COSE_Sign1 (mock-signed).
//! * Stage 7: the same request fields go over the `/dev/nsm` ioctl ABI
//!   (`aws-nitro-enclaves-nsm-api`); the response carries the Nitro
//!   document and verification gains the AWS certificate-chain root.
//!
//! The `public_key` field mirrors the real NSM request: the enclave passes
//! its channel key, which the stand-in binds into the signed document —
//! exactly the flow the client already verifies.

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
