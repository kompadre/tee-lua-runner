use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::sync::Once;
use std::time::Duration;

/// Builds scripts/examples/*.wasm once per test process.
fn ensure_examples() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let script = format!(
            "{}/../../scripts/build-guest-examples.sh",
            env!("CARGO_MANIFEST_DIR")
        );
        let out = Command::new("bash")
            .arg(&script)
            .output()
            .expect("running build-guest-examples.sh");
        assert!(
            out.status.success(),
            "example build failed:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
    });
}

fn bin() -> Command {
    ensure_examples();
    Command::new(env!("CARGO_BIN_EXE_tee-runner"))
}

fn example(name: &str) -> String {
    format!(
        "{}/../../scripts/examples/{name}",
        env!("CARGO_MANIFEST_DIR")
    )
}

// Capability goldens pin the *import-derived manifest* (formatting-invariant):
// they catch a service pulling in capabilities it should not need (or losing
// ones it does). The full artifact hex is deliberately NOT pinned here: guest
// binaries embed panic-location strings, so artifact bytes shift with source
// line numbers — pinning them would break on any comment reflow. Artifact
// measurements are pinned at release time instead (Stage 7 manifests).
#[test]
fn measure_golden() {
    let check = |file: &str, capabilities: &str| {
        let path = example(file);
        let out = bin().args(["measure", &path]).output().unwrap();
        assert!(out.status.success(), "measure {file} failed");
        let stdout = String::from_utf8(out.stdout).unwrap();
        assert_eq!(
            stdout.lines().next().unwrap(),
            format!("capabilities: {capabilities}")
        );

        // The CLI must report exactly what the library computes for the file.
        let bytes = std::fs::read(&path).unwrap();
        let (manifest, measurement) = runner_core::measure_module(&bytes).unwrap();
        let caps: Vec<&str> = manifest.iter().map(|c| c.as_str()).collect();
        let expected_caps = if capabilities == "(none)" {
            String::new()
        } else {
            capabilities.to_string()
        };
        assert_eq!(caps.join(","), expected_caps);
        assert_eq!(
            stdout.lines().nth(1).unwrap(),
            format!("measurement: {}", runner_core::to_hex(&measurement))
        );
    };

    check("echo.wasm", "(none)");
    check("counter.wasm", "log,state,clock");
    check("hasher.wasm", "random,crypto");
}

/// Production builds compile Wasmtime *without* the `wat` feature: only
/// binary wasm modules are ever accepted.
#[test]
fn measure_rejects_text_wasm() {
    let path = std::env::temp_dir().join(format!("tee-runner-test-{}.wat", std::process::id()));
    std::fs::write(&path, "(module)").unwrap();
    let out = bin()
        .args(["measure", path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!out.status.success(), "text input must be rejected");
    assert!(String::from_utf8(out.stderr).unwrap().contains("error:"));
    std::fs::remove_file(&path).ok();
}

#[test]
fn run_echo_from_stdin() {
    let mut child = bin()
        .args(["run", &example("echo.wasm")])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(br#"{"hello": ["world", 1]}"#)
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(stdout.trim()).unwrap(),
        serde_json::json!({"echo": {"hello": ["world", 1]}})
    );
}

#[test]
fn run_script_error_exits_nonzero() {
    let mut child = bin()
        .args(["run", &example("hasher.wasm")])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(br#"{"method":"nope"}"#)
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8(out.stderr).unwrap().contains("error:"));
}

#[test]
fn run_hasher_sha256() {
    let mut child = bin()
        .args(["run", &example("hasher.wasm")])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(br#"{"method":"sha256","data":"abc"}"#)
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    let resp: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        resp["digest"],
        serde_json::json!("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    );
}

/// Full attestation wire path: guest module calls `tee.attest` → mock backend
/// signs → doc crosses the CLI → relying party verifies signature, freshness
/// nonce, and the bound module measurement.
#[test]
fn mock_attestation_end_to_end() {
    let mut child = bin()
        .args(["run", &example("attest.wasm"), "--mock-attest"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(br#"{"method":"doc","nonce_hex":"001122aabbcc"}"#)
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());

    let stderr = String::from_utf8(out.stderr).unwrap();
    let root_hex = stderr
        .lines()
        .find_map(|line| line.strip_prefix("mock-attest-root: "))
        .expect("mock root must be printed on stderr")
        .to_string();

    let resp: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let doc = hex::decode(resp["doc_hex"].as_str().unwrap()).unwrap();

    let module_bytes = std::fs::read(example("attest.wasm")).unwrap();
    let (_, measurement) = runner_core::measure_module(&module_bytes).unwrap();
    let root = tee_attest::TrustRoot::from_hex(&root_hex).unwrap();
    let payload = tee_attest::verify(
        &root,
        &doc,
        &tee_attest::Expectations::new()
            .with_nonce(&hex::decode("001122aabbcc").unwrap())
            .with_user_data(&measurement),
    )
    .expect("document must verify");
    assert_eq!(payload.module_id, "tee-runner-mock");
    assert_eq!(payload.algorithm, "EdDSA");
    assert_eq!(
        payload.pcrs.get("0").map(String::len),
        Some(64),
        "PCR0 must be a sha256 hex digest of the runner binary"
    );

    // Any tampering fails.
    let mut tampered = doc.clone();
    tampered[8] ^= 0xff;
    assert!(tee_attest::verify(&root, &tampered, &tee_attest::Expectations::default()).is_err());

    // The `verify` subcommand (reference client) agrees.
    let out = bin()
        .args([
            "verify",
            "--root",
            &root_hex,
            "--doc",
            &hex::encode(&doc),
            "--nonce",
            "001122aabbcc",
            "--user-data",
            &hex::encode(measurement),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "verify failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let printed: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(printed["module_id"], serde_json::json!("tee-runner-mock"));

    // A wrong nonce is rejected with a non-zero exit.
    let out = bin()
        .args([
            "verify",
            "--root",
            &root_hex,
            "--doc",
            &hex::encode(&doc),
            "--nonce",
            "deadbeef",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8(out.stderr).unwrap().contains("error:"));
}

fn write_frame(stream: &mut TcpStream, payload: &[u8]) {
    stream
        .write_all(&(payload.len() as u32).to_be_bytes())
        .unwrap();
    stream.write_all(payload).unwrap();
    stream.flush().unwrap();
}

fn read_frame(stream: &mut TcpStream) -> Option<serde_json::Value> {
    let mut len_buf = [0u8; 4];
    match stream.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(_) => return None,
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).unwrap();
    Some(serde_json::from_slice(&payload).unwrap())
}

#[test]
fn serve_frames_keep_state_and_report_errors() {
    let mut child = bin()
        .args(["serve", &example("counter.wasm"), "--listen", "127.0.0.1:0"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    // Read "listening on 127.0.0.1:PORT" from stdout.
    let mut line = String::new();
    {
        use std::io::BufRead;
        let mut reader = std::io::BufReader::new(child.stdout.take().unwrap());
        reader.read_line(&mut line).unwrap();
    }
    let port: u16 = line
        .trim()
        .rsplit(':')
        .next()
        .expect("listening line")
        .parse()
        .unwrap();

    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();

    // Two frames on one connection: host-side state persists between requests.
    write_frame(&mut stream, br#"{"method":"incr","key":"a"}"#);
    let r1 = read_frame(&mut stream).unwrap();
    assert_eq!(r1["ok"], serde_json::json!(true));
    assert_eq!(r1["response"]["value"], serde_json::json!(1));

    write_frame(&mut stream, br#"{"method":"incr","key":"a"}"#);
    let r2 = read_frame(&mut stream).unwrap();
    assert_eq!(r2["response"]["value"], serde_json::json!(2));

    write_frame(&mut stream, br#"{"method":"get","key":"a"}"#);
    let r3 = read_frame(&mut stream).unwrap();
    assert_eq!(r3["response"]["value"], serde_json::json!(2));

    // Guest errors come back in-band on a live connection.
    write_frame(&mut stream, br#"{"method":"nope"}"#);
    let r4 = read_frame(&mut stream).unwrap();
    assert_eq!(r4["ok"], serde_json::json!(false));
    assert!(r4["error"].as_str().unwrap().contains("unknown method"));

    // A malformed frame is a transport error: connection closes without reply.
    write_frame(&mut stream, b"not json");
    assert!(read_frame(&mut stream).is_none());

    child.kill().unwrap();
    child.wait().unwrap();
}
