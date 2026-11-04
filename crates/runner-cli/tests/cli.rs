use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::sync::Once;
use std::time::Duration;

use tee_attest::Attestor as _;
use tee_crypto::ChannelClient;

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
    let payload = read_raw_frame(stream)?;
    Some(serde_json::from_slice(&payload).unwrap())
}

fn read_raw_frame(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).ok()?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).ok()?;
    Some(payload)
}

/// Full Stage 3 flow: frames wrapped in the end-to-end channel, with the
/// channel key authenticated *through the mock attestation document*
/// (`public_key` + measurement + freshness nonce) — i.e. an attacker who can
/// speak to `serve` but not produce attestations cannot present a convincing
/// channel endpoint. Proves the sealed request/response path and that
/// tampering breaks it.
#[test]
fn attested_channel_end_to_end() {
    let mut child = bin()
        .args([
            "serve",
            &example("attest.wasm"),
            "--channel",
            "--mock-attest",
            "--listen",
            "127.0.0.1:0",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    // Documented stderr order: mock-attest-root, channel-pk, measurement.
    let mut stderr = BufReader::new(child.stderr.take().unwrap());
    let mut line = String::new();
    stderr.read_line(&mut line).unwrap();
    let root_hex = line
        .strip_prefix("mock-attest-root: ")
        .expect("root line")
        .trim()
        .to_string();
    line.clear();
    stderr.read_line(&mut line).unwrap();
    let channel_hex = line
        .strip_prefix("channel-pk: ")
        .expect("channel line")
        .trim()
        .to_string();
    line.clear();
    stderr.read_line(&mut line).unwrap();
    assert!(
        line.starts_with("module measurement: "),
        "measurement line, got: {line}"
    );

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

    let server_pk: [u8; 32] = hex::decode(&channel_hex)
        .unwrap()
        .try_into()
        .expect("32-byte channel key");
    let client = ChannelClient::new(server_pk);

    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();

    // Sealed request through the channel.
    let (msg, pending) = client
        .seal_request(br#"{"method":"doc","nonce_hex":"feedbeef"}"#)
        .unwrap();
    write_frame(&mut stream, &msg);
    let response = read_raw_frame(&mut stream).expect("response frame");
    let envelope_bytes = client.open_response(&pending, &response).unwrap();
    let envelope: serde_json::Value = serde_json::from_slice(&envelope_bytes).unwrap();
    assert_eq!(envelope["ok"], serde_json::json!(true));
    let doc = hex::decode(envelope["response"]["doc_hex"].as_str().unwrap()).unwrap();

    // The attestation binds: this channel key (public_key), this module
    // measurement (user_data), and this freshness nonce.
    let module_bytes = std::fs::read(example("attest.wasm")).unwrap();
    let (_, measurement) = runner_core::measure_module(&module_bytes).unwrap();
    let root = tee_attest::TrustRoot::from_hex(&root_hex).unwrap();
    let payload = tee_attest::verify(
        &root,
        &doc,
        &tee_attest::Expectations::new()
            .with_nonce(&hex::decode("feedbeef").unwrap())
            .with_user_data(&measurement),
    )
    .expect("attestation must verify");
    assert_eq!(
        payload.public_key.as_deref(),
        Some(channel_hex.as_str()),
        "attestation must bind the channel key"
    );

    // A tampered response frame is rejected by the client (connection stays
    // open — the server saw a valid request).
    let (msg2, pending2) = client
        .seal_request(br#"{"method":"doc","nonce_hex":"feedbeef"}"#)
        .unwrap();
    write_frame(&mut stream, &msg2);
    let mut response2 = read_raw_frame(&mut stream).expect("response frame");
    let middle = response2.len() / 2;
    response2[middle] ^= 0xff;
    assert!(client.open_response(&pending2, &response2).is_err());

    // Replaying a wire message is a transport error: the nonce was consumed
    // and the connection closes without executing anything again.
    write_frame(&mut stream, &msg);
    assert!(
        read_raw_frame(&mut stream).is_none(),
        "replayed channel message must be refused"
    );

    // A tampered request frame never opens on the server side (connection
    // closes without a reply) — on a fresh connection after the replay close.
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut bad = msg.clone();
    let middle = bad.len() / 2;
    bad[middle] ^= 0xff;
    write_frame(&mut stream, &bad);
    assert!(read_raw_frame(&mut stream).is_none());

    child.kill().unwrap();
    child.wait().unwrap();
}

/// Stage 4: the reference workload end-to-end over the channel — provisioned
/// TEE key, sealed fetch → gate unwrap → client-side decrypt, rolling-window
/// throttling, revocation, and the audit ring (no secrets).
#[test]
fn throttle_service_end_to_end_over_channel() {
    use std::io::BufRead;
    use tee_crypto::{open_local, seal_secret, ChannelClient, LocalIdentity};
    use zeroize::Zeroizing;

    let tee_seed = [42u8; 32];
    let mut child = bin()
        .args([
            "serve",
            &example("throttle.wasm"),
            "--tee-key",
            &hex::encode(tee_seed),
            "--channel",
            "--listen",
            "127.0.0.1:0",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    // stderr order without --mock-attest: tee-pk, channel-pk, measurement.
    let mut stderr = BufReader::new(child.stderr.take().unwrap());
    let mut line = String::new();
    stderr.read_line(&mut line).unwrap();
    let tee_pk_hex = line
        .strip_prefix("tee-pk: ")
        .expect("tee-pk line")
        .trim()
        .to_string();
    line.clear();
    stderr.read_line(&mut line).unwrap();
    let channel_hex = line
        .strip_prefix("channel-pk: ")
        .expect("channel line")
        .trim()
        .to_string();
    line.clear();
    stderr.read_line(&mut line).unwrap();
    assert!(line.starts_with("module measurement: "), "got: {line}");

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

    let tee_pk: [u8; 32] = hex::decode(&tee_pk_hex).unwrap().try_into().unwrap();
    let channel_pk: [u8; 32] = hex::decode(&channel_hex).unwrap().try_into().unwrap();
    let client = ChannelClient::new(channel_pk);
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();

    let identity = LocalIdentity::from_seed(Zeroizing::new([5u8; 64]));
    let public = identity.public();
    let envelope = seal_secret(&tee_pk, &public.encryption, b"s3cr3t-entry").unwrap();

    let fetch_request = || {
        let pop = identity.sign(&tee_proto::fetch_pop_message(
            &public.signing,
            &public.encryption,
            &envelope,
        ));
        serde_json::to_value(tee_proto::Request::Fetch {
            sign_pk: hex::encode(public.signing),
            enc_pk: hex::encode(public.encryption),
            envelope: hex::encode(&envelope),
            pop: hex::encode(pop),
        })
        .unwrap()
    };

    let mut roundtrip = |request: &serde_json::Value| -> serde_json::Value {
        let payload = serde_json::to_vec(request).unwrap();
        let (msg, pending) = client.seal_request(&payload).unwrap();
        write_frame(&mut stream, &msg);
        let response = read_raw_frame(&mut stream).expect("channel response");
        let envelope_bytes = client.open_response(&pending, &response).unwrap();
        let wrapper: serde_json::Value = serde_json::from_slice(&envelope_bytes).unwrap();
        assert_eq!(wrapper["ok"], serde_json::json!(true), "{wrapper}");
        wrapper["response"].clone()
    };

    // 1. Full blind-gatekeeper flow: fetch returns the inner blob, which the
    //    client opens with its local key — plaintext never touched the host.
    let response = roundtrip(&fetch_request());
    assert_eq!(response["result"], serde_json::json!("fetch"), "{response}");
    let inner = hex::decode(response["inner"].as_str().unwrap()).unwrap();
    let seed = identity.to_seed();
    let owner_sk: [u8; 32] = seed[32..].try_into().unwrap();
    assert_eq!(open_local(&owner_sk, &inner).unwrap(), b"s3cr3t-entry");

    // 2. Rolling window: exactly MAX_FETCHES succeed, the next is throttled
    //    with a retry hint.
    for _ in 0..4 {
        let response = roundtrip(&fetch_request());
        assert_eq!(response["result"], serde_json::json!("fetch"), "{response}");
    }
    let response = roundtrip(&fetch_request());
    assert_eq!(response["result"], serde_json::json!("error"), "{response}");
    assert_eq!(
        response["code"],
        serde_json::json!("throttled"),
        "{response}"
    );
    assert!(
        response["retry_after_ms"].as_u64().unwrap() > 0,
        "{response}"
    );

    // 3. Revocation: PoP-gated, then the identity is hard-refused.
    let revoke = tee_proto::Request::Revoke {
        sign_pk: hex::encode(public.signing),
        enc_pk: hex::encode(public.encryption),
        pop: hex::encode(identity.sign(&tee_proto::revoke_pop_message(
            &public.signing,
            &public.encryption,
        ))),
    };
    let response = roundtrip(&serde_json::to_value(revoke).unwrap());
    assert_eq!(
        response["result"],
        serde_json::json!("revoke"),
        "{response}"
    );
    let response = roundtrip(&fetch_request());
    assert_eq!(
        response["code"],
        serde_json::json!("blacklisted"),
        "{response}"
    );

    // 4. The audit ring records decisions for this identity and contains no
    //    secrets.
    let response = roundtrip(&serde_json::json!({ "op": "audit" }));
    assert_eq!(response["result"], serde_json::json!("audit"), "{response}");
    let entries = response["entries"].as_array().unwrap();
    let owner_hex = hex::encode(public.signing);
    let outcomes: Vec<&str> = entries
        .iter()
        .filter(|e| e["owner"] == serde_json::json!(owner_hex))
        .filter_map(|e| e["outcome"].as_str())
        .collect();
    assert!(outcomes.contains(&"ok"), "{outcomes:?}");
    assert!(outcomes.contains(&"throttled"), "{outcomes:?}");
    assert!(outcomes.contains(&"blacklisted"), "{outcomes:?}");
    let blob = serde_json::to_string(entries).unwrap();
    assert!(!blob.contains("s3cr3t-entry"), "secret leaked into audit");
    assert!(!blob.contains(&hex::encode(&envelope)), "envelope leaked");

    child.kill().unwrap();
    child.wait().unwrap();
}

/// The NSM seam, end-to-end without QEMU: stand-in daemon → remote attestor
/// → verification (signature, freshness, user_data, pcr0, public_key
/// binding). This is exactly the flow the QEMU guest drives over vsock.
#[test]
fn nsm_standin_and_remote_attestor_roundtrip() {
    use std::io::BufRead;

    let mut child = bin()
        .args([
            "nsm-standin",
            "--listen",
            "127.0.0.1:0",
            "--seed-hex",
            &hex::encode([77u8; 32]),
            "--pcr0",
            &"ab".repeat(32),
            "--module-id",
            "qemu-guest-mock",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let mut stderr = BufReader::new(child.stderr.take().unwrap());
    let mut line = String::new();
    stderr.read_line(&mut line).unwrap();
    let root_hex = line
        .strip_prefix("nsm-standin trust root: ")
        .expect("root line")
        .trim()
        .to_string();
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

    // Bind a fake channel key like an enclave would (NSM public_key field).
    let channel_pk_hex = hex::encode([9u8; 32]);
    let attestor = tee_attest::NsmRemoteAttestor::new(
        &format!("127.0.0.1:{port}"),
        Some(channel_pk_hex.clone()),
    )
    .unwrap();

    let nonce = b"fresh-challenge";
    let measurement = [5u8; 32];
    let document = attestor.attest(nonce, &measurement).unwrap();

    let root = tee_attest::TrustRoot::from_hex(&root_hex).unwrap();
    let payload = tee_attest::verify(
        &root,
        &document,
        &tee_attest::Expectations::new()
            .with_nonce(nonce)
            .with_user_data(&measurement),
    )
    .expect("stand-in document must verify");
    assert_eq!(payload.module_id, "qemu-guest-mock");
    assert_eq!(
        payload.pcrs.get("0").map(String::as_str),
        Some(("ab".repeat(32)).as_str()),
        "pcr0 must round-trip"
    );
    assert_eq!(
        payload.public_key.as_deref(),
        Some(channel_pk_hex.as_str()),
        "channel key must be bound via the NSM public_key field"
    );

    // Wrong expectations are rejected.
    let err = tee_attest::verify(
        &root,
        &document,
        &tee_attest::Expectations::new().with_nonce(b"other"),
    )
    .unwrap_err();
    assert!(
        matches!(err, tee_attest::VerifyError::NonceMismatch),
        "{err:?}"
    );

    child.kill().unwrap();
    child.wait().unwrap();
}

/// `--nsm` and `--mock-attest` are mutually exclusive.
#[test]
fn serve_rejects_nsm_with_mock_attest() {
    let out = bin()
        .args([
            "serve",
            &example("throttle.wasm"),
            "--nsm",
            "127.0.0.1:9",
            "--mock-attest",
            "--listen",
            "127.0.0.1:0",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8(out.stderr)
        .unwrap()
        .contains("mutually exclusive"));
}

/// Garbage against the stand-in produces an error response, not a crash.
#[test]
fn nsm_standin_survives_bad_requests() {
    use std::io::Read;
    use tee_proto::framing;

    fn call(port: u16, payload: &[u8]) -> tee_attest::NsmResponse {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        framing::write_frame(&mut stream, payload).unwrap();
        let mut len = [0u8; 4];
        stream.read_exact(&mut len).unwrap();
        let mut payload = vec![0u8; u32::from_be_bytes(len) as usize];
        stream.read_exact(&mut payload).unwrap();
        serde_json::from_slice(&payload).unwrap()
    }

    let mut child = bin()
        .args(["nsm-standin", "--listen", "127.0.0.1:0"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stderr = BufReader::new(child.stderr.take().unwrap());
    let mut line = String::new();
    stderr.read_line(&mut line).unwrap();
    let root_line = line.clone(); // trust root printed first
    assert!(root_line.contains("nsm-standin trust root:"));
    let mut line = String::new();
    {
        let mut stdout = BufReader::new(child.stdout.take().unwrap());
        stdout.read_line(&mut line).unwrap();
    }
    let port: u16 = line.trim().rsplit(':').next().unwrap().parse().unwrap();

    // Not JSON at all → error response, connection survives.
    let response = call(port, b"garbage");
    assert!(
        response.error.as_deref().unwrap().contains("bad request"),
        "{response:?}"
    );
    assert!(response.document.is_none());

    // JSON with wrong field types → same treatment.
    let response = call(port, br#"{"nonce":42}"#);
    assert!(response.error.is_some(), "{response:?}");

    // The daemon is still alive after abuse.
    let attestor = tee_attest::NsmRemoteAttestor::new(&format!("127.0.0.1:{port}"), None).unwrap();
    let doc = attestor.attest(b"n", &[1u8; 32]).unwrap();
    let root_hex = root_line
        .strip_prefix("nsm-standin trust root: ")
        .unwrap()
        .trim();
    tee_attest::verify(
        &tee_attest::TrustRoot::from_hex(root_hex).unwrap(),
        &doc,
        &tee_attest::Expectations::new().with_nonce(b"n"),
    )
    .unwrap();

    child.kill().unwrap();
    child.wait().unwrap();
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
