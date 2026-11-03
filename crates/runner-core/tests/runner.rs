use std::rc::Rc;
use std::time::{Duration, Instant};

use runner_core::{
    parse_manifest, script_measurement, Capability, Limit, Limits, Manifest, Runner, RunnerError,
};
use serde_json::json;
use tee_attest::{AttestError, Attestor};

fn limits() -> Limits {
    Limits::default()
}

fn tight_cpu(ms: u64) -> Limits {
    Limits {
        max_cpu: Duration::from_millis(ms),
        ..Limits::default()
    }
}

// ---------------------------------------------------------------- measurement

#[test]
fn measurement_is_stable_hex() {
    let src = "function handle(req) return req end";
    let a = script_measurement(src, &Manifest::default());
    let b = script_measurement(src, &Manifest::default());
    assert_eq!(a, b);
    assert_eq!(runner_core::to_hex(&a).len(), 64);
}

#[test]
fn measurement_changes_with_script_bytes() {
    let m1 = script_measurement("function handle(req) return req end", &Manifest::default());
    let m2 = script_measurement("function handle(req) return req end ", &Manifest::default());
    assert_ne!(m1, m2);
}

#[test]
fn measurement_binds_capability_set() {
    let src = "function handle(req) return req end";
    let none = script_measurement(src, &Manifest::default());
    let log = script_measurement(src, &Manifest::new([Capability::Log]));
    assert_ne!(none, log);

    // Manifest is canonicalized: set order does not matter.
    let a = script_measurement(src, &Manifest::new([Capability::Log, Capability::State]));
    let b = script_measurement(src, &Manifest::new([Capability::State, Capability::Log]));
    assert_eq!(a, b);
}

#[test]
fn runner_measurement_matches_helper() {
    let src = "-- @capability log\nfunction handle(req) return req end\n";
    let runner = Runner::new(src, limits()).unwrap();
    let manifest = parse_manifest(src).unwrap();
    assert_eq!(runner.measurement(), script_measurement(src, &manifest));
}

// -------------------------------------------------------------------- sandbox

#[test]
fn sandbox_blocks_dangerous_globals() {
    let src = r#"
        function handle(req)
            return {
                os = os == nil,
                io = io == nil,
                debug = debug == nil,
                require = require == nil,
                package = package == nil,
                load = load == nil,
                dofile = dofile == nil,
                loadfile = loadfile == nil,
                print = print == nil,
                warn = warn == nil,
                collectgarbage = collectgarbage == nil,
                dump = string.dump == nil,
                -- the safe subset must be available
                base_ok = type(type) == "function" and type(pcall) == "function"
                    and type(error) == "function" and type(string.format) == "function",
            }
        end
    "#;
    let mut runner = Runner::new(src, limits()).unwrap();
    let resp = runner.call_handle(json!({})).unwrap();
    let obj = resp.as_object().unwrap();
    for (key, val) in obj {
        if key == "base_ok" {
            assert_eq!(val, &json!(true), "safe base functions must exist");
        } else {
            assert_eq!(val, &json!(true), "{key} must be stripped from the sandbox");
        }
    }
}

#[test]
fn capability_is_gated() {
    // Without the manifest line, `clock` is not installed at all.
    let src = "function handle(req) return { t = clock.unix_seconds() } end";
    let mut runner = Runner::new(src, limits()).unwrap();
    let err = runner.call_handle(json!({})).unwrap_err();
    match err {
        RunnerError::Script(msg) => assert!(msg.contains("clock"), "unexpected error: {msg}"),
        other => panic!("expected script error, got {other:?}"),
    }
}

#[test]
fn capability_granted_works() {
    let src = "-- @capability clock\nfunction handle(req) return { t = clock.unix_seconds() } end";
    let mut runner = Runner::new(src, limits()).unwrap();
    let resp = runner.call_handle(json!({})).unwrap();
    assert!(resp["t"].as_i64().unwrap() > 1_600_000_000);
}

#[test]
fn manifest_errors_are_hard() {
    assert!(matches!(
        parse_manifest("-- @capability nope\nfunction handle() end"),
        Err(RunnerError::InvalidManifest(_))
    ));
    assert!(matches!(
        parse_manifest("function handle() end\n-- @capability log\n"),
        Err(RunnerError::InvalidManifest(_))
    ));
    assert!(matches!(
        parse_manifest("-- @capability\nfunction handle() end"),
        Err(RunnerError::InvalidManifest(_))
    ));
}

// ----------------------------------------------------------------------- rpc

#[test]
fn json_roundtrip() {
    let src = "function handle(req) return req end";
    let mut runner = Runner::new(src, limits()).unwrap();
    let req = json!({"a": [1, 2, 3], "b": {"c": "d"}, "s": "hello"});
    assert_eq!(runner.call_handle(req.clone()).unwrap(), req);
}

#[test]
fn no_handler_is_reported() {
    let mut runner = Runner::new("local x = 1", limits()).unwrap();
    assert!(matches!(
        runner.call_handle(json!({})),
        Err(RunnerError::NoHandler)
    ));
}

#[test]
fn script_error_is_reported() {
    let src = r#"function handle(req) error("boom") end"#;
    let mut runner = Runner::new(src, limits()).unwrap();
    match runner.call_handle(json!({})) {
        Err(RunnerError::Script(msg)) => assert!(msg.contains("boom"), "unexpected: {msg}"),
        other => panic!("expected script error, got {other:?}"),
    }
}

// ------------------------------------------------------------------ state/log

#[test]
fn state_roundtrip() {
    let src = r#"
        -- @capability state
        function handle(req)
            if req.method == "set" then
                state.set(req.key, req.value)
                return { ok = true }
            elseif req.method == "get" then
                return { value = state.get(req.key) }
            elseif req.method == "keys" then
                return { keys = state.keys() }
            end
            error("bad method")
        end
    "#;
    let mut runner = Runner::new(src, limits()).unwrap();
    runner
        .call_handle(json!({"method": "set", "key": "k1", "value": {"n": 42}}))
        .unwrap();
    runner
        .call_handle(json!({"method": "set", "key": "k2", "value": "v"}))
        .unwrap();
    let resp = runner
        .call_handle(json!({"method": "get", "key": "k1"}))
        .unwrap();
    assert_eq!(resp["value"], json!({"n": 42}));
    let resp = runner.call_handle(json!({"method": "keys"})).unwrap();
    assert_eq!(resp["keys"], json!(["k1", "k2"]));
}

#[test]
fn logs_are_captured_and_levels_validated() {
    let src = r#"
        -- @capability log
        function handle(req)
            log("info", "hello")
            log("nonsense", "bad level")
            return {}
        end
    "#;
    let mut runner = Runner::new(src, limits()).unwrap();
    assert!(matches!(
        runner.call_handle(json!({})),
        Err(RunnerError::Script(_))
    ));
    let logs = runner.take_logs();
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].level, "info");
    assert_eq!(logs[0].message, "hello");
}

// ------------------------------------------------------------------- attest

struct FakeAttestor;

impl Attestor for FakeAttestor {
    fn attest(&self, nonce: &[u8], user_data: &[u8]) -> Result<Vec<u8>, AttestError> {
        let mut doc = b"FAKE-DOC".to_vec();
        doc.extend_from_slice(nonce);
        doc.extend_from_slice(user_data);
        Ok(doc)
    }
}

#[test]
fn attest_without_backend_errors() {
    let src = "-- @capability attest\nfunction handle(req) return { doc = tee.attest('n') } end";
    let mut runner = Runner::new(src, limits()).unwrap();
    match runner.call_handle(json!({})) {
        Err(RunnerError::Script(msg)) => {
            assert!(msg.contains("no attestation backend"), "unexpected: {msg}")
        }
        other => panic!("expected script error, got {other:?}"),
    }
}

#[test]
fn attest_binds_measurement_and_nonce() {
    let src =
        "-- @capability attest\nfunction handle(req) return { doc = tee.attest(req.nonce) } end";
    let attestor: Rc<dyn Attestor> = Rc::new(FakeAttestor);
    let mut runner = Runner::build(src, limits(), Some(attestor)).unwrap();
    let resp = runner.call_handle(json!({"nonce": "abc"})).unwrap();

    let mut expected = b"FAKE-DOC".to_vec();
    expected.extend_from_slice(b"abc");
    expected.extend_from_slice(&runner.measurement());
    assert_eq!(resp["doc"], json!(runner_core::to_hex(&expected)));
}

// ------------------------------------------------------------------- limits

#[test]
fn cpu_limit_breaks_infinite_loop() {
    let src = "function handle(req) while true do end end";
    let mut runner = Runner::new(src, tight_cpu(100)).unwrap();
    let started = Instant::now();
    let err = runner.call_handle(json!({})).unwrap_err();
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "limit did not stop the script"
    );
    assert!(matches!(err, RunnerError::LimitExceeded(Limit::Cpu(_))));
}

#[test]
fn cpu_limit_cannot_be_swallowed_by_pcall() {
    // The script catches the limit error and keeps spinning; the re-armed
    // stride-1 hook must make this terminate anyway.
    let src = r#"
        function handle(req)
            while true do
                pcall(function() while true do end end)
            end
        end
    "#;
    let mut runner = Runner::new(src, tight_cpu(100)).unwrap();
    let started = Instant::now();
    let err = runner.call_handle(json!({})).unwrap_err();
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "pcall swallowed the limit error and the runner hung"
    );
    assert!(matches!(err, RunnerError::LimitExceeded(_)));
}

#[test]
fn limit_applies_at_load_time() {
    let src = "while true do end";
    let started = Instant::now();
    let err = Runner::new(src, tight_cpu(100)).unwrap_err();
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "load-time loop was not stopped"
    );
    assert!(matches!(err, RunnerError::LimitExceeded(_)));
}

#[test]
fn memory_limit_trips() {
    let src = r#"
        function handle(req)
            local t = {}
            local i = 1
            while true do
                t[i] = "payload" .. i
                i = i + 1
            end
        end
    "#;
    let limits = Limits {
        max_cpu: Duration::from_secs(10),
        max_memory_bytes: 256 * 1024,
        ..Limits::default()
    };
    let mut runner = Runner::new(src, limits).unwrap();
    let err = runner.call_handle(json!({})).unwrap_err();
    assert!(matches!(
        err,
        RunnerError::LimitExceeded(Limit::Memory { .. })
    ));
}

#[test]
fn string_rep_is_bounded() {
    let src = r#"
        function handle(req)
            local s = ("x"):rep(2 * 1024 * 1024)
            return { n = #s }
        end
    "#;
    let limits = Limits {
        max_memory_bytes: 1024 * 1024,
        ..Limits::default()
    };
    let mut runner = Runner::new(src, limits).unwrap();
    match runner.call_handle(json!({})) {
        Err(RunnerError::Script(msg)) => {
            assert!(msg.contains("string.rep"), "unexpected: {msg}")
        }
        other => panic!("expected script error, got {other:?}"),
    }
}

#[test]
fn request_and_response_sizes_are_capped() {
    let src = "function handle(req) return req end";
    let limits = Limits {
        max_request_bytes: 16,
        max_response_bytes: 16,
        ..Limits::default()
    };
    let mut runner = Runner::new(src, limits.clone()).unwrap();
    assert!(matches!(
        runner.call_handle(json!({"key": "value that is long"})),
        Err(RunnerError::RequestTooLarge { .. })
    ));

    let src = "function handle(req) return { big = ('x'):rep(1000) } end";
    let mut runner = Runner::new(src, limits.clone()).unwrap();
    assert!(matches!(
        runner.call_handle(json!({})),
        Err(RunnerError::ResponseTooLarge { .. })
    ));
}
