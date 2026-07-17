//! Minimal SOCKS5 CONNECT client (RFC 1928, with RFC 1929 username/password
//! auth), so outbound TCP can be routed through a SOCKS5 proxy — or a **chain**
//! of them. Tor is exactly a SOCKS5 proxy (Orbot listens on `127.0.0.1:9050`),
//! so the same path covers "use Tor", "use my SOCKS5 proxy", and
//! "app → SOCKS5 → Tor" (a two-hop chain).
//!
//! A process-wide chain (see [`set_chain`]) switches it on; when empty, [`dial`]
//! connects directly, so nothing changes for callers that don't configure one.

use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::RwLock;
use std::time::Duration;

/// One SOCKS5 hop in the chain.
#[derive(Clone, Debug)]
pub struct ProxyConfig {
    /// The proxy endpoint, `host:port` (e.g. `127.0.0.1:9050` for Tor/Orbot).
    pub proxy: String,
    /// Optional username/password (RFC 1929). `None` ⇒ no-auth only.
    pub username: Option<String>,
    pub password: Option<String>,
}

static CHAIN: RwLock<Vec<ProxyConfig>> = RwLock::new(Vec::new());

/// Install the process-wide proxy **chain** (traversed in order,
/// `app → chain[0] → chain[1] → … → target`), or clear it with an empty vec.
pub fn set_chain(chain: Vec<ProxyConfig>) {
    *CHAIN.write().expect("proxy lock") = chain;
}

/// Convenience for a single hop (or none): sets the chain to `[]` or `[cfg]`.
pub fn set_proxy(cfg: Option<ProxyConfig>) {
    set_chain(cfg.into_iter().collect());
}

/// The current proxy chain (empty ⇒ direct).
pub fn current_chain() -> Vec<ProxyConfig> {
    CHAIN.read().expect("proxy lock").clone()
}

/// Connect to `addr` — directly if the chain is empty, else tunneled through the
/// configured SOCKS5 chain. A drop-in for `TcpStream::connect`.
pub fn dial(addr: impl ToSocketAddrs) -> io::Result<TcpStream> {
    let chain = current_chain();
    if chain.is_empty() {
        return TcpStream::connect(addr);
    }
    let target = addr
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no target address"))?;
    dial_chain(&chain, target, Duration::from_secs(20))
}

/// Open a tunnel to `target` through a single SOCKS5 `proxy`. Kept for the
/// single-hop path and tests.
pub fn connect(
    proxy: &ProxyConfig,
    target: SocketAddr,
    timeout: Duration,
) -> io::Result<TcpStream> {
    dial_chain(std::slice::from_ref(proxy), target, timeout)
}

/// Open a tunnel to `target` through `chain` (in order). Connects to the first
/// hop directly, then does a SOCKS5 handshake at each hop to reach the next hop
/// — and the last hop to reach `target`.
fn dial_chain(
    chain: &[ProxyConfig],
    target: SocketAddr,
    timeout: Duration,
) -> io::Result<TcpStream> {
    let first = chain
        .first()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "empty proxy chain"))?;
    let paddr = first
        .proxy
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "bad proxy address"))?;
    let mut s = TcpStream::connect_timeout(&paddr, timeout)?;
    s.set_read_timeout(Some(timeout))?;
    s.set_write_timeout(Some(timeout))?;

    for (i, hop) in chain.iter().enumerate() {
        negotiate_auth(&mut s, hop)?;
        // This hop connects to the next hop, or (at the end) to the target.
        if let Some(next) = chain.get(i + 1) {
            let (host, port) = split_host_port(&next.proxy)?;
            send_connect(&mut s, &host, port)?;
        } else {
            send_connect(&mut s, &target.ip().to_string(), target.port())?;
        }
        read_reply(&mut s)?;
    }
    Ok(s)
}

/// SOCKS5 greeting + method selection (+ user/pass sub-negotiation if offered).
fn negotiate_auth(s: &mut TcpStream, proxy: &ProxyConfig) -> io::Result<()> {
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
        0x00 => Ok(()),
        0x02 => {
            let u = proxy.username.clone().unwrap_or_default();
            let p = proxy.password.clone().unwrap_or_default();
            if u.len() > 255 || p.len() > 255 {
                return Err(io::Error::other("SOCKS5 credentials too long"));
            }
            let mut req = Vec::with_capacity(3 + u.len() + p.len());
            req.push(0x01);
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
        0xFF => Err(io::Error::other("SOCKS5 proxy rejected our auth methods")),
        _ => Err(io::Error::other("SOCKS5 unsupported auth method")),
    }
}

/// Send a CONNECT request for `host:port`. An IP literal goes as an IPv4/IPv6
/// address; anything else goes as a DOMAINNAME so the proxy resolves it (no
/// local DNS leak for a hostname hop).
fn send_connect(s: &mut TcpStream, host: &str, port: u16) -> io::Result<()> {
    let mut req = vec![0x05, 0x01, 0x00];
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        req.push(0x01);
        req.extend_from_slice(&ip.octets());
    } else if let Ok(ip) = host.parse::<Ipv6Addr>() {
        req.push(0x04);
        req.extend_from_slice(&ip.octets());
    } else {
        let hb = host.as_bytes();
        if hb.len() > 255 {
            return Err(io::Error::other("SOCKS5 hostname too long"));
        }
        req.push(0x03);
        req.push(hb.len() as u8);
        req.extend_from_slice(hb);
    }
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req)?;
    s.flush()
}

/// Read and validate a CONNECT reply (VER REP RSV ATYP BND.ADDR BND.PORT).
fn read_reply(s: &mut TcpStream) -> io::Result<()> {
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
    Ok(())
}

fn split_host_port(hp: &str) -> io::Result<(String, u16)> {
    let i = hp
        .rfind(':')
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "hop needs host:port"))?;
    let host = hp[..i].trim_matches(['[', ']']).to_string();
    let port = hp[i + 1..]
        .parse::<u16>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bad hop port"))?;
    Ok((host, port))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    /// A tiny SOCKS5 proxy for tests: performs the server side of the handshake
    /// (optionally requiring user/pass), then splices to the requested target
    /// (IPv4 or DOMAINNAME). Returns its listen address.
    fn fake_proxy(require_auth: Option<(String, String)>) -> SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        thread::spawn(move || {
            for conn in l.incoming() {
                let mut c = conn.unwrap();
                let creds = require_auth.clone();
                let mut h = [0u8; 2];
                c.read_exact(&mut h).unwrap();
                let n = h[1] as usize;
                let mut methods = vec![0u8; n];
                c.read_exact(&mut methods).unwrap();
                if let Some((user, pass)) = creds {
                    c.write_all(&[0x05, 0x02]).unwrap();
                    let mut v = [0u8; 2];
                    c.read_exact(&mut v).unwrap();
                    let mut ub = vec![0u8; v[1] as usize];
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
                    c.write_all(&[0x05, 0x00]).unwrap();
                }
                // CONNECT: read ver/cmd/rsv/atyp, then the address.
                let mut r = [0u8; 4];
                c.read_exact(&mut r).unwrap();
                let host = match r[3] {
                    0x01 => {
                        let mut ip = [0u8; 4];
                        c.read_exact(&mut ip).unwrap();
                        SocketAddr::from((ip, 0)).ip().to_string()
                    }
                    0x03 => {
                        let mut l = [0u8; 1];
                        c.read_exact(&mut l).unwrap();
                        let mut hb = vec![0u8; l[0] as usize];
                        c.read_exact(&mut hb).unwrap();
                        String::from_utf8(hb).unwrap()
                    }
                    _ => panic!("test proxy: unsupported atyp"),
                };
                let mut port = [0u8; 2];
                c.read_exact(&mut port).unwrap();
                let target = format!("{host}:{}", u16::from_be_bytes(port));
                c.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).unwrap();
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

    fn cfg(addr: SocketAddr) -> ProxyConfig {
        ProxyConfig {
            proxy: addr.to_string(),
            username: None,
            password: None,
        }
    }

    #[test]
    fn tunnels_through_a_socks5_proxy() {
        let target = echo_server();
        let proxy = fake_proxy(None);
        let mut s = connect(&cfg(proxy), target, Duration::from_secs(5)).unwrap();
        s.write_all(b"ping").unwrap();
        let mut buf = [0u8; 4];
        s.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"ping");
    }

    #[test]
    fn chains_two_socks5_hops() {
        let target = echo_server();
        let hop2 = fake_proxy(None);
        let hop1 = fake_proxy(None);
        // app → hop1 → hop2 → target
        let mut s =
            dial_chain(&[cfg(hop1), cfg(hop2)], target, Duration::from_secs(5)).unwrap();
        s.write_all(b"chn!").unwrap();
        let mut buf = [0u8; 4];
        s.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"chn!");
    }

    #[test]
    fn username_password_auth_succeeds_and_fails() {
        let target = echo_server();
        let proxy = fake_proxy(Some(("bob".into(), "s3cret".into())));
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
        let bad = ProxyConfig {
            proxy: proxy.to_string(),
            username: Some("bob".into()),
            password: Some("nope".into()),
        };
        assert!(connect(&bad, target, Duration::from_secs(5)).is_err());
    }

    #[test]
    fn dial_without_a_proxy_connects_directly() {
        let target = echo_server();
        let mut s = TcpStream::connect(target).unwrap();
        s.write_all(b"dir!").unwrap();
        let mut buf = [0u8; 4];
        s.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"dir!");
    }
}
