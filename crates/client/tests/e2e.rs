//! Full-system e2e: real `tee-runner serve` process + real `tpass` binary —
//! init → attest (TOFU pin) → insert → show (plaintext recovery through the
//! gate) → generate/list/audit → revoke → refused; plus the channel-mode
//! plaintext restriction.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::Once;
use std::time::Duration;

use tee_proto::framing::{read_frame, write_frame};

fn ensure_tools() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let manifest = env!("CARGO_MANIFEST_DIR");
        let repo = Path::new(manifest).join("../..");

        let built = Command::new("cargo")
            .current_dir(&repo)
            .args(["build", "-p", "runner-cli"])
            .output()
            .expect("cargo build -p runner-cli");
        assert!(
            built.status.success(),
            "runner build failed:\n{}",
            String::from_utf8_lossy(&built.stderr)
        );

        let built = Command::new("bash")
            .current_dir(&repo)
            .arg("scripts/build-guest-examples.sh")
            .output()
            .expect("building guest examples");
        assert!(
            built.status.success(),
            "guest build failed:\n{}",
            String::from_utf8_lossy(&built.stderr)
        );
    });
}

fn runner_bin() -> PathBuf {
    ensure_tools();
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/tee-runner")
}

fn tpass(store: &Path, passphrase_file: Option<&Path>, args: &[&str]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tpass"));
    cmd.arg("--store").arg(store);
    if let Some(path) = passphrase_file {
        cmd.arg("--passphrase-file").arg(path);
    }
    cmd.args(args).output().expect("tpass invocation")
}

fn stdout_of(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).unwrap()
}

fn stderr_of(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).unwrap()
}

struct Serve {
    child: Child,
    port: u16,
    root_hex: String,
    tee_pk_hex: String,
    measurement_hex: String,
}

/// Spawns `serve throttle.wasm --tee-key --channel --mock-attest`.
/// Documented stderr order: tee-pk, mock-attest-root, channel-pk, measurement.
fn spawn_serve() -> Serve {
    ensure_tools();
    let throttle =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/examples/throttle.wasm");
    let mut child = Command::new(runner_bin())
        .args([
            "serve",
            throttle.to_str().unwrap(),
            "--listen",
            "127.0.0.1:0",
            "--tee-key",
            &hex::encode([42u8; 32]),
            "--channel",
            "--mock-attest",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawning tee-runner serve");

    let mut stderr = BufReader::new(child.stderr.take().unwrap());
    let read = |stderr: &mut BufReader<std::process::ChildStderr>, prefix: &str| -> String {
        let mut line = String::new();
        stderr.read_line(&mut line).unwrap();
        line.strip_prefix(prefix)
            .unwrap_or_else(|| panic!("expected {prefix:?} line, got: {line}"))
            .trim()
            .to_string()
    };
    let tee_pk_hex = read(&mut stderr, "tee-pk: ");
    let root_hex = read(&mut stderr, "mock-attest-root: ");
    let _channel_pk = read(&mut stderr, "channel-pk: ");
    let measurement_hex = read(&mut stderr, "module measurement: ");

    let mut line = String::new();
    {
        let mut stdout = BufReader::new(child.stdout.take().unwrap());
        stdout.read_line(&mut line).unwrap();
    }
    let port: u16 = line
        .trim()
        .rsplit(':')
        .next()
        .expect("listening line")
        .parse()
        .unwrap();

    Serve {
        child,
        port,
        root_hex,
        tee_pk_hex,
        measurement_hex,
    }
}

impl Drop for Serve {
    fn drop(&mut self) {
        self.child.kill().ok();
        self.child.wait().ok();
    }
}

fn temp_store(tag: &str) -> PathBuf {
    let store = std::env::temp_dir().join(format!("tpass-e2e-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&store);
    std::fs::create_dir_all(&store).unwrap();
    store
}

#[test]
fn tpass_full_system_flow() {
    let serve = spawn_serve();
    let store = temp_store("flow");
    let server = format!("127.0.0.1:{}", serve.port);
    let passphrase = store.join("pass.txt");
    std::fs::write(&passphrase, "correct horse battery staple\n").unwrap();

    // 1. init: identity + sealed keystore + public half + config.
    let out = tpass(
        &store,
        Some(&passphrase),
        &["init", "--server", &server, "--tee-pk", &serve.tee_pk_hex],
    );
    assert!(out.status.success(), "init: {}", stderr_of(&out));
    assert!(store.join("keystore").exists());
    assert!(store.join("public.json").exists());
    assert!(store.join("config.json").exists());
    // Re-init must not clobber.
    assert!(!tpass(&store, Some(&passphrase), &["init"]).status.success());

    // 2. attest --save: verify + TOFU-pin the measurement, discover channel.
    let out = tpass(
        &store,
        None,
        &["attest", "--root", &serve.root_hex, "--save"],
    );
    assert!(out.status.success(), "attest: {}", stderr_of(&out));
    let stdout = stdout_of(&out);
    assert!(stdout.contains("attestation verified"), "{stdout}");
    assert!(stdout.contains(&serve.measurement_hex), "{stdout}");
    let config: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(store.join("config.json")).unwrap()).unwrap();
    assert_eq!(
        config["measurement_hex"],
        serde_json::json!(serve.measurement_hex)
    );
    assert_eq!(
        config["channel"],
        serde_json::json!(true),
        "channel mode must be discovered"
    );

    // A wrong measurement pin must fail verification.
    let out = tpass(
        &store,
        None,
        &["attest", "--measurement", &hex::encode([0u8; 32])],
    );
    assert!(!out.status.success(), "pinned measurement must be enforced");
    assert!(
        stderr_of(&out).contains("attestation verification"),
        "{}",
        stderr_of(&out)
    );

    // 3. insert: sealed at rest (no passphrase needed — public half only).
    let mut insert = Command::new(env!("CARGO_BIN_EXE_tpass"))
        .args(["--store", store.to_str().unwrap(), "insert", "hunter2"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    insert
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"hunter2-secret\n")
        .unwrap();
    let out = insert.wait_with_output().unwrap();
    assert!(out.status.success(), "insert: {}", stderr_of(&out));
    let entry = std::fs::read(store.join("hunter2.entry")).unwrap();
    assert!(
        !entry.windows(13).any(|w| w == b"hunter2-secret"),
        "plaintext must not appear at rest"
    );

    // 4. show: full chain — attest bootstrap → channel fetch → local open.
    let out = tpass(&store, Some(&passphrase), &["show", "hunter2"]);
    assert!(out.status.success(), "show: {}", stderr_of(&out));
    assert_eq!(stdout_of(&out), "hunter2-secret\n");

    // Wrong passphrase fails before any network work.
    let wrong = store.join("wrong.txt");
    std::fs::write(&wrong, "nope\n").unwrap();
    let out = tpass(&store, Some(&wrong), &["show", "hunter2"]);
    assert!(!out.status.success());
    assert!(
        stderr_of(&out).contains("wrong passphrase"),
        "{}",
        stderr_of(&out)
    );

    // 5. generate: 24-char password, insert without a passphrase.
    let out = tpass(&store, None, &["generate", "app", "--length", "24"]);
    assert!(out.status.success(), "generate: {}", stderr_of(&out));
    let out = tpass(&store, Some(&passphrase), &["show", "app"]);
    assert!(out.status.success(), "show app: {}", stderr_of(&out));
    assert_eq!(stdout_of(&out).trim_end().len(), 24);

    // 6. list + 7. audit (decisions visible, secrets never).
    let out = tpass(&store, None, &["list"]);
    let list = stdout_of(&out);
    assert!(list.contains("hunter2") && list.contains("app"), "{list}");
    let out = tpass(&store, None, &["audit"]);
    assert!(out.status.success(), "audit: {}", stderr_of(&out));
    let audit = stdout_of(&out);
    assert!(audit.contains("fetch") && audit.contains("ok"), "{audit}");
    assert!(
        !audit.contains("hunter2-secret"),
        "secret leaked into audit"
    );

    // 8. revoke: PoP-gated blacklist → all further fetches refused.
    let out = tpass(&store, Some(&passphrase), &["revoke"]);
    assert!(out.status.success(), "revoke: {}", stderr_of(&out));
    let out = tpass(&store, Some(&passphrase), &["show", "app"]);
    assert!(!out.status.success(), "revoked identity must be refused");
    assert!(
        stderr_of(&out).contains("[blacklisted]"),
        "{}",
        stderr_of(&out)
    );

    // 9. rm: local deletion.
    let out = tpass(&store, None, &["rm", "hunter2"]);
    assert!(out.status.success(), "rm: {}", stderr_of(&out));
    let out = tpass(&store, None, &["list"]);
    assert!(!stdout_of(&out).contains("hunter2"));
    assert!(!tpass(&store, Some(&passphrase), &["show", "hunter2"])
        .status
        .success());

    // 10. Channel mode: plaintext is refused for everything except attest.
    let mut stream = TcpStream::connect(("127.0.0.1", serve.port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let plain_fetch = serde_json::json!({
        "op": "fetch",
        "sign_pk": hex::encode([1u8; 32]),
        "enc_pk": hex::encode([2u8; 32]),
        "envelope": hex::encode([3u8; 96]),
        "pop": hex::encode([4u8; 64]),
    });
    write_frame(&mut stream, &serde_json::to_vec(&plain_fetch).unwrap()).unwrap();
    // The server refuses and closes: clean EOF or a reset, never a reply —
    // but a timeout (server silently ignoring) must fail the test.
    match read_frame(&mut stream) {
        Ok(None) => {}
        Err(err) => assert!(
            matches!(
                err.kind(),
                std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::BrokenPipe
            ),
            "unexpected error on plaintext fetch: {err}"
        ),
        Ok(Some(frame)) => panic!("plaintext fetch was served: {frame:?}"),
    }

    let _ = std::fs::remove_dir_all(&store);
}
