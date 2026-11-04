//! Integration tests against hand-written wasm fixtures (wat).

use std::time::{Duration, Instant};

use runner_core::{
    measure_module, script_measurement, Capability, Limit, Limits, Manifest, Runner, RunnerError,
};
use serde_json::json;

/// A minimal echo guest: `handle` wraps the request as
/// `{"ok":true,"response":<request>}` (prefix is 22 bytes, overhead 23).
const ECHO: &str = r#"(module
  (memory (export "memory") 1)
  (data (i32.const 0) "{\"ok\":true,\"response\":")
  (global $bump (mut i32) (i32.const 64))
  (func (export "alloc") (param $n i32) (result i32)
    (local $p i32)
    (local.set $p (global.get $bump))
    (global.set $bump (i32.add (global.get $bump) (local.get $n)))
    (local.get $p))
  (func (export "handle") (param $in i32) (param $n i32) (result i64)
    (local $out i32)
    (local.set $out (global.get $bump))
    (global.set $bump (i32.add (global.get $bump) (i32.add (local.get $n) (i32.const 23))))
    (memory.copy (local.get $out) (i32.const 0) (i32.const 22))
    (memory.copy (i32.add (local.get $out) (i32.const 22)) (local.get $in) (local.get $n))
    (i32.store8
      (i32.add (i32.add (local.get $out) (i32.const 22)) (local.get $n))
      (i32.const 125))
    (i64.or
      (i64.extend_i32_u (local.get $out))
      (i64.shl
        (i64.extend_i32_u (i32.add (local.get $n) (i32.const 23)))
        (i64.const 32)))))
"#;

/// Valid exports, but `handle` never returns.
const LOOPY: &str = r#"(module
  (memory (export "memory") 1)
  (func (export "alloc") (param i32) (result i32) (i32.const 4096))
  (func (export "handle") (param i32 i32) (result i64)
    (loop $l (br $l))
    (i64.const 0)))
"#;

/// Loops forever during instantiation (start section).
const LOOPY_START: &str = r#"(module
  (memory (export "memory") 1)
  (func $init (loop $l (br $l)))
  (start $init)
  (func (export "alloc") (param i32) (result i32) (i32.const 4096))
  (func (export "handle") (param i32 i32) (result i64) (i64.const 0)))
"#;

const TRAPPIER: &str = r#"(module
  (memory (export "memory") 1)
  (func (export "alloc") (param i32) (result i32) (i32.const 4096))
  (func (export "handle") (param i32 i32) (result i64) (unreachable)))
"#;

const DUMMY_EXPORTS: &str = r#"
  (memory (export "memory") 1)
  (func (export "alloc") (param i32) (result i32) (i32.const 4096))
  (func (export "handle") (param i32 i32) (result i64) (i64.const 0))"#;

fn limits() -> Limits {
    Limits::default()
}

fn tight_fuel() -> Limits {
    Limits {
        max_fuel: 100_000,
        max_cpu: Duration::from_secs(30),
        ..Limits::default()
    }
}

fn tight_cpu() -> Limits {
    Limits {
        max_cpu: Duration::from_millis(200),
        max_fuel: u64::MAX,
        ..Limits::default()
    }
}

// ---------------------------------------------------------------- measurement

#[test]
fn measurement_is_stable_hex() {
    let a = measure_module(ECHO.as_bytes()).unwrap();
    let b = measure_module(ECHO.as_bytes()).unwrap();
    assert_eq!(a, b);
    assert_eq!(runner_core::to_hex(&a.1).len(), 64);
}

#[test]
fn measurement_changes_with_module_bytes() {
    let a = script_measurement(b"(module)", &Manifest::default());
    let b = script_measurement(b"(module) ", &Manifest::default());
    assert_ne!(a, b);
}

#[test]
fn measurement_binds_capability_set() {
    let bytes = b"module bytes";
    let none = script_measurement(bytes, &Manifest::default());
    let log = script_measurement(bytes, &Manifest::new([Capability::Log]));
    assert_ne!(none, log);

    // Canonical: set order does not matter.
    let a = script_measurement(bytes, &Manifest::new([Capability::Log, Capability::State]));
    let b = script_measurement(bytes, &Manifest::new([Capability::State, Capability::Log]));
    assert_eq!(a, b);
}

#[test]
fn runner_measurement_matches_helper() {
    let runner = Runner::new(ECHO.as_bytes(), limits()).unwrap();
    let (manifest, measurement) = measure_module(ECHO.as_bytes()).unwrap();
    assert_eq!(runner.manifest(), &manifest);
    assert_eq!(runner.measurement(), measurement);
}

// -------------------------------------------------------- module validation

#[test]
fn required_exports_are_enforced() {
    let err = Runner::new(b"(module (func))", limits()).unwrap_err();
    assert!(matches!(err, RunnerError::MissingExport(_)));

    let missing_handle = r#"(module (memory (export "memory") 1)
            (func (export "alloc") (param i32) (result i32) (i32.const 4096)))"#;
    let err = Runner::new(missing_handle.as_bytes(), limits()).unwrap_err();
    assert!(matches!(err, RunnerError::MissingExport(name) if name == "handle"));
}

#[test]
fn unknown_import_modules_are_rejected() {
    let wat = format!(
        r#"(module
            (import "wasi_snapshot_preview1" "fd_write"
                (func (param i32 i32) (result i64)))
            {DUMMY_EXPORTS})"#
    );
    let err = Runner::new(wat.as_bytes(), limits()).unwrap_err();
    match err {
        RunnerError::InvalidManifest(msg) => assert!(msg.contains("wasi_snapshot_preview1")),
        other => panic!("expected invalid manifest, got {other:?}"),
    }
}

#[test]
fn unknown_import_fields_are_rejected() {
    let wat = format!(
        r#"(module
            (import "state" "gett" (func (param i32 i32) (result i64)))
            {DUMMY_EXPORTS})"#
    );
    let err = Runner::new(wat.as_bytes(), limits()).unwrap_err();
    match err {
        RunnerError::InvalidManifest(msg) => assert!(msg.contains("state.gett")),
        other => panic!("expected invalid manifest, got {other:?}"),
    }
}

#[test]
fn wrong_host_signatures_are_rejected() {
    let wat = format!(
        r#"(module
            (import "clock" "unix_seconds" (func (param i32) (result i64)))
            {DUMMY_EXPORTS})"#
    );
    let err = Runner::new(wat.as_bytes(), limits()).unwrap_err();
    match err {
        RunnerError::InvalidManifest(msg) => assert!(msg.contains("wrong signature")),
        other => panic!("expected invalid manifest, got {other:?}"),
    }
}

#[test]
fn manifest_is_derived_from_imports() {
    let wat = format!(
        r#"(module
            (import "state" "get" (func (param i32 i32) (result i64)))
            (import "log" "log" (func (param i32 i32) (result i64)))
            {DUMMY_EXPORTS})"#
    );
    let runner = Runner::new(wat.as_bytes(), limits()).unwrap();
    let caps: Vec<Capability> = runner.manifest().iter().collect();
    assert_eq!(caps, vec![Capability::Log, Capability::State]);
    assert!(!runner.manifest().contains(Capability::Clock));
}

// --------------------------------------------------------------------- rpc

#[test]
fn json_roundtrip_via_abi() {
    let mut runner = Runner::new(ECHO.as_bytes(), limits()).unwrap();
    let req = json!({"a": [1, 2, 3], "b": {"c": "d"}, "s": "hello"});
    assert_eq!(runner.call_handle(req.clone()).unwrap(), req);
}

#[test]
fn guest_error_envelope_is_reported() {
    let mut runner = Runner::new(TRAPPIER.as_bytes(), limits()).unwrap();
    match runner.call_handle(json!({})) {
        Err(RunnerError::Script(msg)) => assert!(msg.contains("trapped"), "unexpected: {msg}"),
        other => panic!("expected script error, got {other:?}"),
    }
}

#[test]
fn request_and_response_sizes_are_capped() {
    let mut runner = Runner::new(
        ECHO.as_bytes(),
        Limits {
            max_request_bytes: 32,
            ..Limits::default()
        },
    )
    .unwrap();
    assert!(matches!(
        runner.call_handle(
            json!({"key": "value that is definitely long enough to exceed thirty-two bytes"})
        ),
        Err(RunnerError::RequestTooLarge { .. })
    ));

    let mut runner = Runner::new(
        ECHO.as_bytes(),
        Limits {
            max_response_bytes: 64,
            ..Limits::default()
        },
    )
    .unwrap();
    let req = json!({"padding": "0123456789012345678901234567890123456789"});
    assert!(matches!(
        runner.call_handle(req),
        Err(RunnerError::ResponseTooLarge { .. })
    ));
}

// ------------------------------------------------------------------- limits

#[test]
fn fuel_limit_breaks_infinite_loop() {
    let mut runner = Runner::new(LOOPY.as_bytes(), tight_fuel()).unwrap();
    let started = Instant::now();
    let err = runner.call_handle(json!({})).unwrap_err();
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "fuel limit did not stop the guest"
    );
    assert!(matches!(err, RunnerError::LimitExceeded(Limit::Fuel(_))));
}

#[test]
fn wall_clock_limit_breaks_infinite_loop() {
    let mut runner = Runner::new(LOOPY.as_bytes(), tight_cpu()).unwrap();
    let started = Instant::now();
    let err = runner.call_handle(json!({})).unwrap_err();
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "epoch interruption did not stop the guest"
    );
    assert!(matches!(err, RunnerError::LimitExceeded(Limit::Cpu(_))));
}

#[test]
fn limits_apply_at_instantiation() {
    let mut runner = Runner::new(LOOPY_START.as_bytes(), tight_fuel()).unwrap();
    let started = Instant::now();
    let err = runner.call_handle(json!({})).unwrap_err();
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "start-section loop was not stopped"
    );
    assert!(matches!(err, RunnerError::LimitExceeded(_)));
}

#[test]
fn memory_floor_rejected_at_build() {
    // 1024 pages = 64 MiB, above the default 32 MiB cap.
    let wat = r#"(module
        (memory (export "memory") 1024)
        (func (export "alloc") (param i32) (result i32) (i32.const 4096))
        (func (export "handle") (param i32 i32) (result i64) (i64.const 0)))"#;
    let err = Runner::new(wat.as_bytes(), limits()).unwrap_err();
    assert!(matches!(
        err,
        RunnerError::LimitExceeded(Limit::Memory { .. })
    ));
}
