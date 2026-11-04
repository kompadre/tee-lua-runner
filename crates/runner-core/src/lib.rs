//! Guest module runner core for TEE service scripts.
//!
//! * [`capability`] — the capability manifest derived from a module's imports
//! * [`measure`] — SHA-256 module measurement bound into attestation documents
//! * [`limits`] — per-request fuel/wall-clock/memory limits
//! * [`engine`] — the Wasmtime engine: validation, linking, request loop

pub mod capability;
pub mod engine;
pub mod error;
pub mod limits;
pub mod measure;

pub use capability::{Capability, Manifest};
pub use engine::{measure_module, LogEntry, Runner};
pub use error::{Limit, RunnerError};
pub use limits::Limits;
pub use measure::{script_measurement, to_hex, MEASUREMENT_DOMAIN};
