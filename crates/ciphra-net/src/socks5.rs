//! Minimal SOCKS5 CONNECT client (RFC 1928, with RFC 1929 username/password
//! auth), so outbound TCP can be routed through a SOCKS5 proxy. Tor is exactly
//! this — a SOCKS5 proxy (Orbot listens on `127.0.0.1:9050`) — so the same path
//! covers "use Tor" and "use my SOCKS5 proxy".
//!
//! A process-wide [`set_proxy`] switches it on; when unset, [`dial`] connects
//! directly, so nothing changes for callers that don't configure a proxy.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::RwLock;
use std::time::Duration;

/// A SOCKS5 proxy to route dials through.
#[derive(Clone, Debug)]
pub struct ProxyConfig {
    /// The proxy endpoint, `host:port` (e.g. `127.0.0.1:9050` for Tor/Orbot).
    pub proxy: String,
    /// Optional username/password (RFC 1929). `None` ⇒ no-auth only.
    pub username: Option<String>,
    pub password: Option<String>,
}

static PROXY: RwLock<Option<ProxyConfig>> = RwLock::new(None);

/// Install the process-wide SOCKS5 proxy, or clear it with `None`. Affects every
/// subsequent [`dial`].
pub fn set_proxy(cfg: Option<ProxyConfig>) {
    *PROXY.write().expect("proxy lock") = cfg;
}

/// The currently configured proxy, if any.
pub fn current() -> Option<ProxyConfig> {
    PROXY.read().expect("proxy lock").clone()
}

/// Connect to `addr` — directly if no proxy is set, else tunneled through the
/// configured SOCKS5 proxy. A drop-in for `TcpStream::connect`.
pub fn dial(addr: impl ToSocketAddrs) -> io::Result<TcpStream> {
    match current() {
        None => TcpStream::connect(addr),
        Some(proxy) => {
            let target = addr.to_socket_addrs()?.next().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "no target address")
            })?;
            connect(&proxy, target, Duration::from_secs(20))
        }
    }
}

/// Open a tunnel to `target` through the SOCKS5 `proxy`, returning the connected
/// stream (its read/write timeouts are left at the handshake bound; callers may
/// re-arm them).
pub fn connect(
    proxy: &ProxyConfig,
    target: SocketAddr,
    timeout: Duration,
) -> io::Result<TcpStream> {
    let paddr = proxy
        .proxy
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "bad proxy address"))?;
    let mut s = TcpStream::connect_timeout(&paddr, timeout)?;
    s.set_read_timeout(Some(timeout))?;
    s.set_write_timeout(Some(timeout))?;

    // Greeting: offer no-auth, plus username/password if we have credentials.
    if proxy.username.is_some() {
        s.write_all(&[0x05, 0x02, 0x00, 0x02])?;
    } else {
        s.write_all(&[0x05, 0x01, 0x00])?;
    }
    s.flush()?;
    let mut sel = [0u8; 2];
    s.read_exact(&mut sel)?;
    if sel[0] != 0x05 {
        return Err(io::Error::other("not a SOCKS5 proxy"));
    }
    match sel[1] {
        0x00 => {} // no auth required
        0x02 => authenticate(&mut s, proxy)?,
        0xFF => return Err(io::Error::other("SOCKS5 proxy rejected our auth methods")),
        _ => return Err(io::Error::other("SOCKS5 unsupported auth method")),
    }

    // CONNECT to the target IP:port.
    let mut req = vec![0x05, 0x01, 0x00];
    match target {
        SocketAddr::V4(a) => {
            req.push(0x01);
            req.extend_from_slice(&a.ip().octets());
        }
        SocketAddr::V6(a) => {
            req.push(0x04);
            req.extend_from_slice(&a.ip().octets());
        }
    }
    req.extend_from_slice(&target.port().to_be_bytes());
    s.write_all(&req)?;
    s.flush()?;

    // Reply: VER REP RSV ATYP BND.ADDR BND.PORT — REP 0 == success.
    let mut head = [0u8; 4];
    s.read_exact(&mut head)?;
    if head[1] != 0x00 {
        return Err(io::Error::other(format!(
            "SOCKS5 connect refused (code {})",
            head[1]
        )));
    }
    let addr_len = match head[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l)?;
            l[0] as usize
        }
        _ => return Err(io::Error::other("SOCKS5 bad reply address type")),
    };
    let mut rest = vec![0u8; addr_len + 2]; // bound addr + port, discarded
    s.read_exact(&mut rest)?;
    Ok(s)
}

fn authenticate(s: &mut TcpStream, proxy: &ProxyConfig) -> io::Result<()> {
    let u = proxy.username.clone().unwrap_or_default();
    let p = proxy.password.clone().unwrap_or_default();
    if u.len() > 255 || p.len() > 255 {
        return Err(io::Error::other("SOCKS5 credentials too long"));
    }
    let mut req = Vec::with_capacity(3 + u.len() + p.len());
    req.push(0x01); // auth subnegotiation version
    req.push(u.len() as u8);
    req.extend_from_slice(u.as_bytes());
    req.push(p.len() as u8);
    req.extend_from_slice(p.as_bytes());
    s.write_all(&req)?;
    s.flush()?;
    let mut resp = [0u8; 2];
    s.read_exact(&mut resp)?;
    if resp[1] != 0x00 {
        return Err(io::Error::other("SOCKS5 authentication failed"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    /// A tiny SOCKS5 proxy for tests: performs the server side of the handshake
    /// (optionally requiring user/pass), then splices to the requested IPv4
    /// target. Returns its listen address.
    fn fake_proxy(require_auth: Option<(String, String)>) -> SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        thread::spawn(move || {
            for conn in l.incoming() {
                let mut c = conn.unwrap();
                let creds = require_auth.clone();
                // Greeting.
                let mut h = [0u8; 2];
                c.read_exact(&mut h).unwrap();
                let n = h[1] as usize;
                let mut methods = vec![0u8; n];
                c.read_exact(&mut methods).unwrap();
                if let Some((user, pass)) = creds {
                    c.write_all(&[0x05, 0x02]).unwrap(); // require user/pass
                    let mut v = [0u8; 2];
                    c.read_exact(&mut v).unwrap();
                    let ul = v[1] as usize;
                    let mut ub = vec![0u8; ul];
                    c.read_exact(&mut ub).unwrap();
                    let mut pl = [0u8; 1];
                    c.read_exact(&mut pl).unwrap();
                    let mut pb = vec![0u8; pl[0] as usize];
                    c.read_exact(&mut pb).unwrap();
                    let ok = ub == user.as_bytes() && pb == pass.as_bytes();
                    c.write_all(&[0x01, if ok { 0x00 } else { 0x01 }]).unwrap();
                    if !ok {
                        continue;
                    }
                } else {
                    c.write_all(&[0x05, 0x00]).unwrap(); // no auth
                }
                // CONNECT request.
                let mut r = [0u8; 4];
                c.read_exact(&mut r).unwrap();
                assert_eq!(r[3], 0x01, "test proxy handles IPv4 only");
                let mut ip = [0u8; 4];
                c.read_exact(&mut ip).unwrap();
                let mut port = [0u8; 2];
                c.read_exact(&mut port).unwrap();
                let target = SocketAddr::from((ip, u16::from_be_bytes(port)));
                // Success reply, echoing a zero bound address.
                c.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).unwrap();
                // Splice to the real target.
                let mut up = TcpStream::connect(target).unwrap();
                let mut c2 = c.try_clone().unwrap();
                let mut up2 = up.try_clone().unwrap();
                thread::spawn(move || {
                    io::copy(&mut c2, &mut up2).ok();
                });
                io::copy(&mut up, &mut c).ok();
            }
        });
        addr
    }

    /// An echo server; returns its address.
    fn echo_server() -> SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        thread::spawn(move || {
            for conn in l.incoming() {
                let mut c = conn.unwrap();
                thread::spawn(move || {
                    let mut buf = [0u8; 64];
                    let n = c.read(&mut buf).unwrap();
                    c.write_all(&buf[..n]).unwrap();
                });
            }
        });
        addr
    }

    #[test]
    fn tunnels_through_a_socks5_proxy() {
        let target = echo_server();
        let proxy = fake_proxy(None);
        let cfg = ProxyConfig {
            proxy: proxy.to_string(),
            username: None,
            password: None,
        };
        let mut s = connect(&cfg, target, Duration::from_secs(5)).unwrap();
        s.write_all(b"ping").unwrap();
        let mut buf = [0u8; 4];
        s.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"ping");
    }

    #[test]
    fn username_password_auth_succeeds_and_fails() {
        let target = echo_server();
        let proxy = fake_proxy(Some(("bob".into(), "s3cret".into())));
        // Right credentials tunnel through.
        let ok = ProxyConfig {
            proxy: proxy.to_string(),
            username: Some("bob".into()),
            password: Some("s3cret".into()),
        };
        let mut s = connect(&ok, target, Duration::from_secs(5)).unwrap();
        s.write_all(b"hey!").unwrap();
        let mut buf = [0u8; 4];
        s.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"hey!");
        // Wrong password is rejected.
        let bad = ProxyConfig {
            proxy: proxy.to_string(),
            username: Some("bob".into()),
            password: Some("nope".into()),
        };
        assert!(connect(&bad, target, Duration::from_secs(5)).is_err());
    }

    #[test]
    fn dial_without_a_proxy_connects_directly() {
        set_proxy(None);
        let target = echo_server();
        let mut s = dial(target).unwrap();
        s.write_all(b"dir!").unwrap();
        let mut buf = [0u8; 4];
        s.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"dir!");
    }
}
