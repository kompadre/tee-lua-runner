//! TCP transport for `tee-runner serve`.
//!
//! Framing: u32 big-endian length followed by that many bytes of JSON.
//! One request per frame; responses are wrapped as
//! `{"ok":true,"response":...}` or `{"ok":false,"error":...}` so errors are
//! visible in-band on a long-lived connection. Malformed frames are transport
//! errors and close the connection.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

use anyhow::{Context, Result};
use serde_json::Value as Json;

use runner_core::Runner;

/// Largest accepted frame payload.
const MAX_FRAME: usize = 4 * 1024 * 1024;

pub fn serve(runner: &mut Runner, listen: &str) -> Result<()> {
    let listener = TcpListener::bind(listen).with_context(|| format!("binding {listen}"))?;
    let addr = listener.local_addr()?;
    println!("listening on {addr}");
    // Stage 1 simplification: requests are handled sequentially, one at a time.
    for stream in listener.incoming() {
        let mut stream = match stream {
            Ok(stream) => stream,
            Err(err) => {
                eprintln!("accept failed: {err}");
                continue;
            }
        };
        if let Err(err) = handle_conn(runner, &mut stream) {
            eprintln!("connection closed with error: {err:#}");
        }
        for entry in runner.take_logs() {
            eprintln!("log[{}] {}", entry.level, entry.message);
        }
    }
    Ok(())
}

fn handle_conn(runner: &mut Runner, stream: &mut TcpStream) -> Result<()> {
    loop {
        let request = match read_frame(stream)? {
            Some(frame) => frame,
            None => return Ok(()), // clean EOF
        };
        let reply = match runner.call_handle(request) {
            Ok(resp) => serde_json::json!({ "ok": true, "response": resp }),
            Err(err) => serde_json::json!({ "ok": false, "error": err.to_string() }),
        };
        write_frame(stream, &reply)?;
    }
}

fn read_frame(stream: &mut TcpStream) -> Result<Option<Json>> {
    let mut len_buf = [0u8; 4];
    match stream.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(err.into()),
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > MAX_FRAME {
        anyhow::bail!("invalid frame length {len} (max {MAX_FRAME})");
    }
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload)?;
    let value = serde_json::from_slice(&payload).context("frame is not valid JSON")?;
    Ok(Some(value))
}

fn write_frame(stream: &mut TcpStream, value: &Json) -> Result<()> {
    let payload = serde_json::to_vec(value)?;
    stream.write_all(&(payload.len() as u32).to_be_bytes())?;
    stream.write_all(&payload)?;
    stream.flush()?;
    Ok(())
}
