use thiserror::Error;

/// Errors produced by the runner core.
#[derive(Debug, Error)]
pub enum RunnerError {
    /// The `@capability` manifest is invalid.
    #[error("invalid capability manifest: {0}")]
    InvalidManifest(String),

    /// The script failed to compile or run at load time.
    #[error("script failed to load: {0}")]
    ScriptLoad(String),

    /// The script does not define a global `handle` function.
    #[error("script does not define a global `handle` function")]
    NoHandler,

    /// The script raised an error while handling a request.
    #[error("script error: {0}")]
    Script(String),

    /// A resource limit tripped while running the script.
    #[error("resource limit exceeded: {0}")]
    LimitExceeded(#[from] Limit),

    /// The serialized request exceeds [`crate::Limits::max_request_bytes`].
    #[error("request too large: {size} bytes (limit {max} bytes)")]
    RequestTooLarge { size: usize, max: usize },

    /// The serialized response exceeds [`crate::Limits::max_response_bytes`].
    #[error("response too large: {size} bytes (limit {max} bytes)")]
    ResponseTooLarge { size: usize, max: usize },

    /// An internal error surfaced from the Lua bridge.
    #[error("lua error: {0}")]
    Lua(#[from] mlua::Error),
}

/// Resource limits that can trip while the script runs.
#[derive(Debug, Clone, Error)]
pub enum Limit {
    /// Wall-clock budget for one load/request was exhausted.
    #[error("CPU time limit exceeded (limit {0} ms)")]
    Cpu(u64),
    /// Lua memory usage exceeded the configured cap.
    #[error("memory limit exceeded (used {used} bytes, limit {max} bytes)")]
    Memory { used: usize, max: usize },
}
