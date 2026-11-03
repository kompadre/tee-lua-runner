use std::time::Duration;

/// Resource limits enforced per load/request.
///
/// CPU is a wall-clock budget: on a loaded host it is conservative, and the
/// hook re-arms at stride 1 when the budget trips so a script cannot `pcall`
/// swallow the error and keep spinning.
#[derive(Debug, Clone)]
pub struct Limits {
    /// Wall-clock budget for one load/request.
    pub max_cpu: Duration,
    /// Cap on Lua memory usage (checked at the instruction hook).
    pub max_memory_bytes: usize,
    /// Cap on the serialized request size.
    pub max_request_bytes: usize,
    /// Cap on the serialized response size.
    pub max_response_bytes: usize,
    /// Instruction stride of the resource-limit hook.
    pub hook_stride: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_cpu: Duration::from_millis(500),
            max_memory_bytes: 32 * 1024 * 1024,
            max_request_bytes: 1024 * 1024,
            max_response_bytes: 1024 * 1024,
            hook_stride: 1000,
        }
    }
}
