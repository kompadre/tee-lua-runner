use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::time::Duration;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_tee-runner"))
}

fn example(name: &str) -> String {
    format!(
        "{}/../../scripts/examples/{name}",
        env!("CARGO_MANIFEST_DIR")
    )
}

// Golden measurements: these pin the measurement construction AND the example
// scripts. If either changes intentionally, update the goldens.
#[test]
fn measure_golden() {
    let out = bin()
        .args(["measure", &example("echo.lua")])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert_eq!(
        stdout,
        "capabilities: log\n\
         measurement: f3094126fe8da35f08d365ed2c99244cd3311bb42a780aacca94dc4afdf20e38\n"
    );

    let out = bin()
        .args(["measure", &example("counter.lua")])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert_eq!(
        stdout,
        "capabilities: log,state,clock\n\
         measurement: 5957f5d4403744d11d461d6f04a1a3068d3b4ddafbacf7f1d8d99085d46e21de\n"
    );
}

#[test]
fn run_echo_from_stdin() {
    let mut child = bin()
        .args(["run", &example("echo.lua")])
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
    // logs go to stderr, stdout stays clean JSON
    assert!(String::from_utf8(out.stderr).unwrap().contains("log[info]"));
}

#[test]
fn run_script_error_exits_nonzero() {
    let mut child = bin()
        .args(["run", &example("hasher.lua")])
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
        .args(["serve", &example("counter.lua"), "--listen", "127.0.0.1:0"])
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

    // Two frames on one connection: state persists between requests.
    write_frame(&mut stream, br#"{"method":"incr","key":"a"}"#);
    let r1 = read_frame(&mut stream).unwrap();
    assert_eq!(r1["ok"], serde_json::json!(true));
    assert_eq!(r1["response"]["value"], serde_json::json!(1));

    write_frame(&mut stream, br#"{"method":"incr","key":"a"}"#);
    let r2 = read_frame(&mut stream).unwrap();
    assert_eq!(r2["response"]["value"], serde_json::json!(2));

    // Script errors come back in-band on a live connection.
    write_frame(&mut stream, br#"{"method":"nope"}"#);
    let r3 = read_frame(&mut stream).unwrap();
    assert_eq!(r3["ok"], serde_json::json!(false));
    assert!(r3["error"].as_str().unwrap().contains("unknown method"));

    // A malformed frame is a transport error: connection closes without reply.
    write_frame(&mut stream, b"not json");
    assert!(read_frame(&mut stream).is_none());

    child.kill().unwrap();
    child.wait().unwrap();
}
