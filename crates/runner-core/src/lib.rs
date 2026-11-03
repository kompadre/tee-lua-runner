//! Lua runner core for TEE service scripts.
//!
//! * [`capability`] — the `@capability` manifest scripts declare in their header
//! * [`measure`] — SHA-256 script measurement bound into attestation documents
//! * [`limits`] — per-request CPU/memory limits
//! * [`sandbox`] — the Lua sandbox and request loop

pub mod capability;
pub mod error;
pub mod limits;
pub mod measure;
pub mod sandbox;

pub use capability::{parse_manifest, Capability, Manifest};
pub use error::{Limit, RunnerError};
pub use limits::Limits;
pub use measure::{script_measurement, to_hex, MEASUREMENT_DOMAIN};
pub use sandbox::{LogEntry, Runner};
