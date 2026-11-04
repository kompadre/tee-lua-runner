//! Shared length-prefixed frame codec: u32 big-endian length + payload.
//!
//! One source for the runner server (`tee-runner serve`) and the `tpass`
//! client — keep transport semantics identical on both sides.

use std::io::{Read, Write};

/// Largest accepted frame payload.
pub const MAX_FRAME: usize = 4 * 1024 * 1024;

/// Reads one frame; `Ok(None)` on a clean EOF at a frame boundary.
pub fn read_frame(reader: &mut impl Read) -> std::io::Result<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(err),
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > MAX_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid frame length {len} (max {MAX_FRAME})"),
        ));
    }
    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload)?;
    Ok(Some(payload))
}

/// Writes one frame and flushes.
pub fn write_frame(writer: &mut impl Write, payload: &[u8]) -> std::io::Result<()> {
    writer.write_all(&(payload.len() as u32).to_be_bytes())?;
    writer.write_all(payload)?;
    writer.flush()?;
    Ok(())
}
