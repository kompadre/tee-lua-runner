//! The guest side of the runner ABI (wasm32 only).
//!
//! * `alloc(size) -> ptr` — reserve bytes in this instance's linear memory.
//!   The runner creates a fresh instance per request, so allocations live for
//!   the duration of the request only (a deliberate leak; the memory dies
//!   with the instance).
//! * `handle(req_ptr, req_len) -> i64` — packed `(len << 32) | ptr` of a JSON
//!   envelope: `{"ok":true,"response":...}` or `{"ok":false,"error":"..."}`.
//!   A negative return is a catastrophic guest failure.

use serde_json::Value;

/// Host-written output of a capability call lives in guest memory too; this
/// is the current linear-memory size for bounds checks.
fn memory_bytes() -> usize {
    let pages = std::arch::wasm32::memory_size(0);
    pages * 65536
}

pub(crate) fn read_slice<'a>(ptr: i32, len: i32) -> Result<&'a [u8], String> {
    if ptr < 0 || len < 0 {
        return Err("negative pointer/length from host".to_string());
    }
    let start = ptr as usize;
    let end = start
        .checked_add(len as usize)
        .ok_or_else(|| "length overflow from host".to_string())?;
    if end > memory_bytes() {
        return Err("host returned out-of-bounds output".to_string());
    }
    // SAFETY: bounds checked against the live linear memory above.
    Ok(unsafe { std::slice::from_raw_parts(start as *const u8, end - start) })
}

#[no_mangle]
pub extern "C" fn alloc(size: i32) -> i32 {
    if size <= 0 {
        return 0;
    }
    let mut buf = vec![0u8; size as usize].into_boxed_slice();
    let ptr = buf.as_mut_ptr() as i32;
    std::mem::forget(buf);
    ptr
}

pub(crate) const fn pack(ptr: u32, len: u32) -> i64 {
    (ptr as i64) | ((len as i64) << 32)
}

pub(crate) fn unpack(value: i64) -> Result<(u32, u32), String> {
    if value < 0 {
        return Err("guest internal error".to_string());
    }
    let raw = value as u64;
    Ok((raw as u32, (raw >> 32) as u32))
}

#[no_mangle]
pub extern "C" fn handle(req_ptr: i32, req_len: i32) -> i64 {
    let envelope = match read_slice(req_ptr, req_len)
        .map_err(|err| err)
        .and_then(|bytes| {
            serde_json::from_slice::<Value>(bytes)
                .map_err(|err| format!("request is not valid JSON: {err}"))
        })
        .and_then(|req| crate::services::dispatch(&req))
    {
        Ok(response) => serde_json::json!({ "ok": true, "response": response }),
        Err(err) => serde_json::json!({ "ok": false, "error": err }),
    };
    let bytes = match serde_json::to_vec(&envelope) {
        Ok(bytes) => bytes,
        Err(err) => {
            format!(r#"{{"ok":false,"error":"envelope serialization failed: {err}"}}"#).into_bytes()
        }
    };
    let dst = alloc(bytes.len() as i32);
    if dst <= 0 {
        return -1;
    }
    // SAFETY: `dst` came from `alloc` and the size fits this instance.
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), dst as *mut u8, bytes.len());
    }
    pack(dst as u32, bytes.len() as u32)
}
