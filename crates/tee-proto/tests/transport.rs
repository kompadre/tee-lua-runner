//! Transport tests: address parsing and a real TCP roundtrip. Vsock is
//! covered by the QEMU e2e (`deploy/qemu/e2e.sh`) — a host-local vsock test
//! would require the loopback transport module (root), so it is not part of
//! the portable suite.

use std::io::{Read, Write};
use std::str::FromStr;
use std::time::Duration;

use tee_proto::transport::{Addr, Listener, Stream};

#[test]
fn parses_tcp_and_vsock_addresses() {
    assert_eq!(
        Addr::from_str("127.0.0.1:7000").unwrap(),
        Addr::Tcp {
            host: "127.0.0.1".into(),
            port: 7000
        }
    );
    assert_eq!(
        Addr::from_str("[::1]:8080").unwrap(),
        Addr::Tcp {
            host: "[::1]".into(),
            port: 8080
        }
    );
    assert_eq!(
        Addr::from_str("vsock:3:1234").unwrap(),
        Addr::VsockDial { cid: 3, port: 1234 }
    );
    assert_eq!(
        Addr::from_str("vsock:7999").unwrap(),
        Addr::VsockListen { port: 7999 }
    );

    for bad in [
        "",
        "no-port",
        "vsock:",
        "vsock:1:2:3",
        "vsock:abc:9",
        "host:port",
    ] {
        assert!(Addr::from_str(bad).is_err(), "must reject {bad:?}");
    }

    // Display round-trips.
    assert_eq!(
        Addr::from_str("vsock:2:50").unwrap().to_string(),
        "vsock:2:50"
    );
    assert_eq!(Addr::from_str("vsock:50").unwrap().to_string(), "vsock:50");
}

#[test]
fn vsock_addrs_reject_wrong_direction() {
    assert!(Listener::bind(&Addr::VsockDial { cid: 3, port: 1 }).is_err());
    assert!(Stream::dial(&Addr::VsockListen { port: 1 }).is_err());
}

#[test]
fn tcp_listen_dial_roundtrip_and_timeouts() {
    let listener = Listener::bind(&Addr::Tcp {
        host: "127.0.0.1".into(),
        port: 0,
    })
    .unwrap();
    // The `listening on …` label keeps the HOST:PORT shape clients parse.
    let label = listener.local_label().unwrap();
    let port: u16 = label.rsplit(':').next().unwrap().parse().unwrap();

    let mut client = Stream::dial(&Addr::Tcp {
        host: "127.0.0.1".into(),
        port,
    })
    .unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    client
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();

    let mut server = listener.accept().unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    client.write_all(b"ping").unwrap();
    let mut buf = [0u8; 4];
    server.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"ping");
    server.write_all(b"pong").unwrap();
    let mut buf = [0u8; 4];
    client.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"pong");
}
