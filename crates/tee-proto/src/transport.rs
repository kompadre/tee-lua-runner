//! Address scheme and stream/listener abstractions for TCP and vsock.
//!
//! Addresses:
//!
//! ```text
//! HOST:PORT        TCP dial (default — existing behavior)
//! vsock:CID:PORT   vsock dial   (e.g. vsock:3:1234 from host to guest)
//! vsock:PORT       vsock listen (bind VMADDR_CID_ANY)
//! ```
//!
//! Linux-only (the `vsock` crate). vsock offers full parity with TCP here,
//! including read/write timeouts.

use std::fmt;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::str::FromStr;
use std::time::Duration;

use vsock::{VsockListener, VsockStream, VMADDR_CID_ANY};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Addr {
    Tcp { host: String, port: u16 },
    VsockDial { cid: u32, port: u32 },
    VsockListen { port: u32 },
}

impl FromStr for Addr {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(rest) = s.strip_prefix("vsock:") {
            let parts: Vec<&str> = rest.split(':').collect();
            return match parts.as_slice() {
                [port] => port
                    .parse()
                    .map(|port| Addr::VsockListen { port })
                    .map_err(|err| format!("bad vsock port in {s:?}: {err}")),
                [cid, port] => {
                    let cid = cid
                        .parse()
                        .map_err(|err| format!("bad vsock cid in {s:?}: {err}"))?;
                    let port = port
                        .parse()
                        .map_err(|err| format!("bad vsock port in {s:?}: {err}"))?;
                    Ok(Addr::VsockDial { cid, port })
                }
                _ => Err(format!(
                    "vsock address must be vsock:PORT (listen) or vsock:CID:PORT (dial), got {s:?}"
                )),
            };
        }
        let (host, port) = s
            .rsplit_once(':')
            .ok_or_else(|| format!("address must be HOST:PORT or vsock:…, got {s:?}"))?;
        if host.is_empty() {
            return Err(format!("missing host in {s:?}"));
        }
        let port = port
            .parse()
            .map_err(|err| format!("bad port in {s:?}: {err}"))?;
        Ok(Addr::Tcp {
            host: host.to_string(),
            port,
        })
    }
}

impl fmt::Display for Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Addr::Tcp { host, port } => write!(f, "{host}:{port}"),
            Addr::VsockDial { cid, port } => write!(f, "vsock:{cid}:{port}"),
            Addr::VsockListen { port } => write!(f, "vsock:{port}"),
        }
    }
}

/// Connected stream over either transport.
pub enum Stream {
    Tcp(TcpStream),
    Vsock(VsockStream),
}

impl Stream {
    pub fn dial(addr: &Addr) -> io::Result<Stream> {
        match addr {
            Addr::Tcp { host, port } => TcpStream::connect((host.as_str(), *port)).map(Stream::Tcp),
            Addr::VsockDial { cid, port } => {
                VsockStream::connect_with_cid_port(*cid, *port).map(Stream::Vsock)
            }
            Addr::VsockListen { .. } => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "not a dial address",
            )),
        }
    }

    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        match self {
            Stream::Tcp(inner) => inner.set_read_timeout(timeout),
            Stream::Vsock(inner) => inner.set_read_timeout(timeout),
        }
    }

    pub fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        match self {
            Stream::Tcp(inner) => inner.set_write_timeout(timeout),
            Stream::Vsock(inner) => inner.set_write_timeout(timeout),
        }
    }
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Stream::Tcp(inner) => inner.read(buf),
            Stream::Vsock(inner) => inner.read(buf),
        }
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Stream::Tcp(inner) => inner.write(buf),
            Stream::Vsock(inner) => inner.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Stream::Tcp(inner) => inner.flush(),
            Stream::Vsock(inner) => inner.flush(),
        }
    }
}

/// Listener over either transport.
pub enum Listener {
    Tcp(TcpListener),
    Vsock(VsockListener),
}

impl Listener {
    pub fn bind(addr: &Addr) -> io::Result<Listener> {
        match addr {
            Addr::Tcp { host, port } => {
                TcpListener::bind((host.as_str(), *port)).map(Listener::Tcp)
            }
            Addr::VsockListen { port } => {
                VsockListener::bind_with_cid_port(VMADDR_CID_ANY, *port).map(Listener::Vsock)
            }
            Addr::VsockDial { .. } => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "not a listen address",
            )),
        }
    }

    pub fn accept(&self) -> io::Result<Stream> {
        match self {
            Listener::Tcp(inner) => inner.accept().map(|(stream, _)| Stream::Tcp(stream)),
            Listener::Vsock(inner) => inner.accept().map(|(stream, _)| Stream::Vsock(stream)),
        }
    }

    /// Label for the `listening on …` line; keeps the `HOST:PORT` shape on
    /// TCP (clients parse the port from it) and `vsock:…:PORT` on vsock.
    pub fn local_label(&self) -> io::Result<String> {
        match self {
            Listener::Tcp(inner) => Ok(inner.local_addr()?.to_string()),
            Listener::Vsock(inner) => {
                let addr = inner.local_addr()?;
                Ok(format!("vsock:{}:{}", addr.cid(), addr.port()))
            }
        }
    }
}
