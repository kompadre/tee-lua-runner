use std::time::Duration;

/// Resource limits enforced per request.
///
/// * `max_fuel` — deterministic instruction budget; exhaustion traps and is
///   uncatchable by guest code by construction.
/// * `max_cpu` — wall-clock budget enforced with Wasmtime epoch interruption
///   (also uncatchable); on a loaded host it is conservative.
/// * `max_memory_bytes` — hard cap on the guest's linear memory
///   (`StoreLimits`), enforced exactly (no growth overshoot).
#[derive(Debug, Clone)]
pub struct Limits {
    /// Wall-clock budget for one request (epoch interruption).
    pub max_cpu: Duration,
    /// Deterministic fuel budget for one request.
    pub max_fuel: u64,
    /// Cap on guest linear memory.
    pub max_memory_bytes: usize,
    /// Cap on the serialized request size.
    pub max_request_bytes: usize,
    /// Cap on the serialized response size.
    pub max_response_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_cpu: Duration::from_millis(500),
            // Generous for policy-scale work; epoch interruption is the
            // wall-clock backstop. Calibrate with real service guests later.
            max_fuel: 50_000_000,
            max_memory_bytes: 32 * 1024 * 1024,
            max_request_bytes: 1024 * 1024,
            max_response_bytes: 1024 * 1024,
        }
    }
}
