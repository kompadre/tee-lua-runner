//! Server session: plaintext attestation challenge → verified channel →
//! channel-wrapped protocol requests.
//!
//! The challenge is the bootstrap: the channel key arrives only inside a
//! *verified* document (signature + freshness nonce + optional pinned
//! measurement), so nothing was trusted from the transport itself.

use std::net::TcpStream;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use rand::RngCore;
use serde_json::{json, Value as Json};
use tee_attest::{AttestationPayload, Expectations, TrustRoot};
use tee_crypto::ChannelClient;
use tee_proto::framing::{read_frame, write_frame};
use tee_proto::{Request, Response};

pub struct Session {
    stream: TcpStream,
    channel: Option<ChannelClient>,
}

impl Session {
    pub fn connect(server: &str) -> Result<Self> {
        let stream =
            TcpStream::connect(server).with_context(|| format!("connecting to {server}"))?;
        stream.set_read_timeout(Some(Duration::from_secs(15)))?;
        stream.set_write_timeout(Some(Duration::from_secs(15)))?;
        Ok(Self {
            stream,
            channel: None,
        })
    }

    /// Freshness challenge → verified attestation payload. On success the
    /// session holds the channel key (when the document binds one).
    pub fn attest(
        &mut self,
        root_hex: &str,
        expected_measurement: Option<&[u8]>,
    ) -> Result<AttestationPayload> {
        let mut nonce = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let response = self.plain_roundtrip(&Request::Attest {
            nonce_hex: hex::encode(nonce),
        })?;

        let Response::Attest { doc_hex } = response else {
            bail!("server returned {response:?} instead of an attestation");
        };
        let document = hex::decode(&doc_hex).context("attestation document is not hex")?;

        let mut expectations = Expectations::new().with_nonce(&nonce);
        if let Some(measurement) = expected_measurement {
            expectations = expectations.with_user_data(measurement);
        }
        let root = TrustRoot::from_hex(root_hex)?;
        let payload = tee_attest::verify(&root, &document, &expectations)
            .context("attestation verification failed")?;

        self.channel = payload
            .public_key
            .as_deref()
            .and_then(tee_proto::decode_pk32)
            .map(ChannelClient::new);
        Ok(payload)
    }

    /// Channel-wrapped protocol request (requires a prior successful
    /// [`Self::attest`], and a document that binds a channel key).
    pub fn request(&mut self, request: &Request) -> Result<Response> {
        let Some(channel) = &self.channel else {
            bail!("session is not attested (or the document binds no channel key)");
        };
        let payload = serde_json::to_vec(request)?;
        let (message, pending) = channel.seal_request(&payload)?;
        write_frame(&mut self.stream, &message)?;

        let Some(response_bytes) = read_frame(&mut self.stream)? else {
            bail!("server closed the connection");
        };
        let envelope = channel
            .open_response(&pending, &response_bytes)
            .context("channel response failed to open (channel key rotated? re-run attest)")?;
        parse_envelope(&envelope)
    }

    fn plain_roundtrip(&mut self, request: &Request) -> Result<Response> {
        let payload = serde_json::to_vec(request)?;
        write_frame(&mut self.stream, &payload)?;
        let Some(bytes) = read_frame(&mut self.stream)? else {
            bail!("server closed the connection");
        };
        parse_envelope(&bytes)
    }
}

/// Parses the runner's envelope: `{ok,response}` or `{ok:false,error}`.
fn parse_envelope(bytes: &[u8]) -> Result<Response> {
    let envelope: Json = serde_json::from_slice(bytes).context("server returned invalid JSON")?;
    if envelope.get("ok") != Some(&json!(true)) {
        let message = envelope
            .get("error")
            .and_then(Json::as_str)
            .unwrap_or("unknown server error");
        bail!("server error: {message}");
    }
    serde_json::from_value(envelope.get("response").cloned().unwrap_or(Json::Null))
        .context("unexpected response shape")
}
