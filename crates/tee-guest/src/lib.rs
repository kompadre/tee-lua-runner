//! Guest SDK and example service modules for the tee runner.
//!
//! A guest module must export `memory`, `alloc(i32)->i32` and
//! `handle(i32,i32)->i64` (see `abi`) and declares its capabilities by
//! importing them from the `host` module wrappers below.
//!
//! Build (one service per artifact):
//!
//! ```sh
//! cargo build -p tee-guest --release --target wasm32-unknown-unknown \
//!     --no-default-features --features svc-counter
//! ```

// Exactly one service feature per artifact (10 pairwise guards for 5
// features; exhaustively listing pairs keeps mistakes loud).
#[cfg(all(feature = "svc-echo", feature = "svc-counter"))]
compile_error!("only one service feature may be enabled at a time");
#[cfg(all(feature = "svc-echo", feature = "svc-hasher"))]
compile_error!("only one service feature may be enabled at a time");
#[cfg(all(feature = "svc-echo", feature = "svc-attest"))]
compile_error!("only one service feature may be enabled at a time");
#[cfg(all(feature = "svc-echo", feature = "svc-throttle"))]
compile_error!("only one service feature may be enabled at a time");
#[cfg(all(feature = "svc-counter", feature = "svc-hasher"))]
compile_error!("only one service feature may be enabled at a time");
#[cfg(all(feature = "svc-counter", feature = "svc-attest"))]
compile_error!("only one service feature may be enabled at a time");
#[cfg(all(feature = "svc-counter", feature = "svc-throttle"))]
compile_error!("only one service feature may be enabled at a time");
#[cfg(all(feature = "svc-hasher", feature = "svc-attest"))]
compile_error!("only one service feature may be enabled at a time");
#[cfg(all(feature = "svc-hasher", feature = "svc-throttle"))]
compile_error!("only one service feature may be enabled at a time");
#[cfg(all(feature = "svc-attest", feature = "svc-throttle"))]
compile_error!("only one service feature may be enabled at a time");

pub mod host;
pub mod services;

#[cfg(not(target_arch = "wasm32"))]
mod mock;

#[cfg(target_arch = "wasm32")]
mod abi;

/// The gate/throttle service — the reference workload (Stage 4).
#[cfg(feature = "svc-throttle")]
pub mod throttle;
