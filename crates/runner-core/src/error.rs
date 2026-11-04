use thiserror::Error;

/// Errors produced by the runner core.
#[derive(Debug, Error)]
pub enum RunnerError {
    /// The module's import section references unknown capabilities or has the
    /// wrong host signatures.
    #[error("invalid capability manifest: {0}")]
    InvalidManifest(String),

    /// A required export (`memory`, `alloc`, `handle`) is missing or mistyped.
    #[error("invalid module: missing export `{0}`")]
    MissingExport(String),

    /// The module is not valid wasm, or failed to compile/validate.
    #[error("module failed to load: {0}")]
    ScriptLoad(String),

    /// The guest reported a failure envelope (or trapped in user logic).
    #[error("script error: {0}")]
    Script(String),

    /// A resource limit tripped while running the module.
    #[error("resource limit exceeded: {0}")]
    LimitExceeded(#[from] Limit),

    /// The serialized request exceeds [`crate::Limits::max_request_bytes`].
    #[error("request too large: {size} bytes (limit {max} bytes)")]
    RequestTooLarge { size: usize, max: usize },

    /// The guest's output exceeds [`crate::Limits::max_response_bytes`].
    #[error("response too large: {size} bytes (limit {max} bytes)")]
    ResponseTooLarge { size: usize, max: usize },

    /// An internal failure (engine setup, memory plumbing).
    #[error("internal error: {0}")]
    Internal(String),
}

/// Resource limits that can trip while the guest runs.
#[derive(Debug, Clone, Error)]
pub enum Limit {
    /// Wall-clock budget for one request was exhausted (epoch interruption).
    #[error("CPU time limit exceeded (limit {0} ms)")]
    Cpu(u64),
    /// Deterministic fuel (instruction) budget was exhausted.
    #[error("fuel limit exceeded (limit {0} instructions)")]
    Fuel(u64),
    /// The guest's linear memory exceeded the configured cap.
    #[error("memory limit exceeded (limit {max} bytes)")]
    Memory { max: usize },
}
