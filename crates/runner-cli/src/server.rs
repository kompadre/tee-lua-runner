//! TCP transport for `tee-runner serve`.
//!
//! Framing: u32 big-endian length followed by that many bytes of payload.
//!
//! * **Plain mode** (default): payloads are JSON requests; responses are
//!   wrapped as `{"ok":true,"response":...}` / `{"ok":false,"error":...}`.
//! * **Channel mode** (`--channel`): payloads are binary CBOR channel
//!   messages (tee-crypto) — requests are HPKE-sealed to the enclave's
//!   channel key and responses are auth-mode sealed back, so the transport
//!   never sees plaintext requests. A rejected channel message is a
//!   transport error and closes the connection; once a request is open,
//!   errors travel in-band as usual.

use std::net::{TcpListener, TcpStream};

use anyhow::{Context, Result};
use serde_json::{json, Value as Json};
use tee_crypto::ChannelServer;
use tee_proto::framing;

use runner_core::Runner;

/// Replay window for channel nonces (oldest evicted beyond this).
const MAX_NONCES: usize = 4096;

/// One wire nonce may be consumed at most once per serve process: a replayed
/// channel message opens (HPKE is stateless) but never executes. Bounded
/// window — beyond [`MAX_NONCES`] the oldest nonces drop out (documented v1
/// freshness bound).
struct NonceCache {
    seen: std::collections::HashSet<[u8; 16]>,
    order: std::collections::VecDeque<[u8; 16]>,
}

impl NonceCache {
    fn new() -> Self {
        Self {
            seen: std::collections::HashSet::new(),
            order: std::collections::VecDeque::new(),
        }
    }

    /// Returns false if the nonce was already consumed (replay).
    fn consume(&mut self, nonce: [u8; 16]) -> bool {
        if !self.seen.insert(nonce) {
            return false;
        }
        self.order.push_back(nonce);
        if self.order.len() > MAX_NONCES {
            if let Some(oldest) = self.order.pop_front() {
                self.seen.remove(&oldest);
            }
        }
        true
    }
}

pub fn serve(runner: &mut Runner, listen: &str, channel: Option<ChannelServer>) -> Result<()> {
    let listener = TcpListener::bind(listen).with_context(|| format!("binding {listen}"))?;
    let addr = listener.local_addr()?;
    println!("listening on {addr}");
    // Stage 1 simplification: requests are handled sequentially, one at a time.
    let mut nonces = NonceCache::new();
    for stream in listener.incoming() {
        let mut stream = match stream {
            Ok(stream) => stream,
            Err(err) => {
                eprintln!("accept failed: {err}");
                continue;
            }
        };
        if let Err(err) = handle_conn(runner, channel.as_ref(), &mut nonces, &mut stream) {
            eprintln!("connection closed with error: {err:#}");
        }
        for entry in runner.take_logs() {
            eprintln!("log[{}] {}", entry.level, entry.message);
        }
    }
    Ok(())
}

fn handle_conn(
    runner: &mut Runner,
    channel: Option<&ChannelServer>,
    nonces: &mut NonceCache,
    stream: &mut TcpStream,
) -> Result<()> {
    loop {
        let frame = match read_frame(stream)? {
            Some(frame) => frame,
            None => return Ok(()), // clean EOF
        };
        let reply: Vec<u8> = match channel {
            Some(server) => {
                if looks_like_json(&frame) {
                    // Plaintext is allowed ONLY for the attestation
                    // challenge: the channel key cannot be trusted before
                    // the client has seen a verified document.
                    let request: tee_proto::Request =
                        serde_json::from_slice(&frame).map_err(|err| {
                            anyhow::anyhow!("plaintext frame is not a valid request: {err}")
                        })?;
                    if !matches!(request, tee_proto::Request::Attest { .. }) {
                        anyhow::bail!(
                            "channel mode: only attestation requests may be sent in plaintext"
                        );
                    }
                    reply_plain(runner, &frame)?
                } else {
                    reply_channel(runner, server, nonces, &frame)?
                }
            }
            None => reply_plain(runner, &frame)?,
        };
        write_frame(stream, &reply)?;
    }
}

fn reply_envelope(runner: &mut Runner, request: &Json) -> Json {
    match runner.call_handle(request.clone()) {
        Ok(resp) => json!({ "ok": true, "response": resp }),
        Err(err) => json!({ "ok": false, "error": err.to_string() }),
    }
}

fn reply_plain(runner: &mut Runner, frame: &[u8]) -> Result<Vec<u8>> {
    let request: Json = serde_json::from_slice(frame).context("frame is not valid JSON")?;
    Ok(serde_json::to_vec(&reply_envelope(runner, &request))?)
}

fn reply_channel(
    runner: &mut Runner,
    server: &ChannelServer,
    nonces: &mut NonceCache,
    frame: &[u8],
) -> Result<Vec<u8>> {
    let opened = server
        .open_request(frame)
        .map_err(|err| anyhow::anyhow!("channel request rejected: {err}"))?;
    // Replay guard: one wire nonce, one execution (cross-connection too —
    // the cache lives for the whole serve process).
    if !nonces.consume(opened.nonce) {
        anyhow::bail!("channel request replayed (nonce already seen)");
    }
    // Once the channel message is open, errors go back in-band through the
    // authenticated response path (we hold the response keys).
    let envelope = match serde_json::from_slice::<Json>(&opened.request) {
        Ok(request) => reply_envelope(runner, &request),
        Err(err) => json!({ "ok": false, "error": format!("request is not valid JSON: {err}") }),
    };
    let response_bytes = serde_json::to_vec(&envelope)?;
    server
        .seal_response(
            &opened.response_pk,
            &opened.nonce,
            &opened.request_hash,
            &response_bytes,
        )
        .map_err(|err| anyhow::anyhow!("sealing channel response: {err}"))
}

/// First non-whitespace byte is `{` → plaintext JSON rather than CBOR.
fn looks_like_json(frame: &[u8]) -> bool {
    frame
        .iter()
        .find(|byte| !byte.is_ascii_whitespace())
        .is_some_and(|byte| *byte == b'{')
}

fn read_frame(stream: &mut TcpStream) -> Result<Option<Vec<u8>>> {
    Ok(framing::read_frame(stream)?)
}

fn write_frame(stream: &mut TcpStream, payload: &[u8]) -> Result<()> {
    Ok(framing::write_frame(stream, payload)?)
}
