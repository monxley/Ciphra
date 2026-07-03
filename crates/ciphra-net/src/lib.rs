//! The Ciphra remote-storage protocol.
//!
//! Ciphra's client/server split follows one rule (ADR-0003): **the
//! server never holds keys**. SQL, encryption and query planning all
//! happen in the engine, which lives with the key holder; the server
//! is a durable ordered key-value store for sealed bytes it cannot
//! read. Consequently the wire protocol is a storage protocol — GET,
//! SCAN, COMMIT, DUMP — not a SQL protocol.
//!
//! Framing: every message is `len (u32 LE) | payload`. The connection
//! opens with a hybrid X25519+ML-KEM handshake (two plaintext hello
//! frames — key exchange material is public by nature); every frame
//! after that is sealed with ChaCha20-Poly1305 under a per-direction
//! key and monotonic counter. Requests start with an opcode byte;
//! responses with a status byte (0 = ok, 1 = error + UTF-8 message).

use std::cell::RefCell;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};

use ciphra_crypto::{
    ClientHello, SERVER_HELLO_LEN, ServerHello, ServerIdentity, channel_open, channel_seal,
    client_finish, client_start, server_respond, sha256,
};
use ciphra_storage::{Batch, Storage, StorageError};

const OP_GET: u8 = 1;
const OP_SCAN: u8 = 2;
const OP_COMMIT: u8 = 3;
const OP_DUMP: u8 = 4;
const OP_PUT: u8 = 5;
const OP_DELETE: u8 = 6;

/// An owned key-value pair as shipped over the wire.
pub type Pair = (Vec<u8>, Vec<u8>);

const STATUS_OK: u8 = 0;
const STATUS_ERR: u8 = 1;

/// A frame is capped to keep a misbehaving peer from ballooning memory.
const MAX_FRAME: u32 = 256 * 1024 * 1024;

// ---------------------------------------------------------------- server

/// Serve `storage` on `listener`, one thread per connection, forever.
/// `server_secret` is the static X25519 transport identity clients pin.
/// This process stores and returns sealed bytes; it has no data keys
/// and nothing in it can decrypt stored rows.
pub fn serve(
    listener: TcpListener,
    storage: Arc<Mutex<Storage>>,
    server_secret: [u8; 32],
) -> std::io::Result<()> {
    loop {
        let (stream, _) = listener.accept()?;
        let storage = Arc::clone(&storage);
        std::thread::spawn(move || {
            let _ = handle_connection(stream, &storage, server_secret);
        });
    }
}

/// A per-direction sealed channel: two keys and two counters so a frame
/// sent one way can never collide (nonce reuse) with one sent the other.
struct Channel {
    send_key: [u8; 32],
    recv_key: [u8; 32],
    send_ctr: u64,
    recv_ctr: u64,
}

impl Channel {
    /// Derive the directional keys from the handshake secret. `client`
    /// flips which key is used for sending vs receiving.
    fn new(shared: [u8; 32], client: bool) -> Self {
        let c2s = derive(&shared, b"c2s");
        let s2c = derive(&shared, b"s2c");
        if client {
            Channel {
                send_key: c2s,
                recv_key: s2c,
                send_ctr: 0,
                recv_ctr: 0,
            }
        } else {
            Channel {
                send_key: s2c,
                recv_key: c2s,
                send_ctr: 0,
                recv_ctr: 0,
            }
        }
    }

    fn send(&mut self, stream: &mut impl Write, plaintext: &[u8]) -> std::io::Result<()> {
        let sealed = channel_seal(&self.send_key, self.send_ctr, plaintext);
        self.send_ctr += 1;
        write_frame(stream, &sealed)
    }

    fn recv(&mut self, stream: &mut impl Read) -> std::io::Result<Vec<u8>> {
        let sealed = read_frame(stream)?;
        let opened = channel_open(&self.recv_key, self.recv_ctr, &sealed)
            .ok_or_else(|| std::io::Error::other("channel authentication failed"))?;
        self.recv_ctr += 1;
        Ok(opened)
    }
}

fn derive(shared: &[u8; 32], label: &[u8]) -> [u8; 32] {
    let mut input = shared.to_vec();
    input.extend_from_slice(label);
    sha256(&input)
}

fn handle_connection(
    mut stream: TcpStream,
    storage: &Mutex<Storage>,
    server_secret: [u8; 32],
) -> std::io::Result<()> {
    stream.set_nodelay(true)?;
    let identity = ServerIdentity::from_secret(server_secret);

    // Handshake: read the client hello, answer with (static pub || our
    // hello), both as plaintext frames.
    let client_hello_bytes = read_frame(&mut stream)?;
    let client_hello = ClientHello::from_bytes(&client_hello_bytes)
        .ok_or_else(|| std::io::Error::other("bad client hello"))?;
    let (server_hello, shared) = server_respond(&identity, &client_hello);
    let mut reply = identity.public.to_vec();
    reply.extend_from_slice(&server_hello.to_bytes());
    write_frame(&mut stream, &reply)?;

    let mut channel = Channel::new(shared, false);
    loop {
        let request = match channel.recv(&mut stream) {
            Ok(frame) => frame,
            Err(_) => return Ok(()), // peer went away or auth failed
        };
        let response = match handle_request(&request, storage) {
            Ok(mut ok) => {
                let mut framed = vec![STATUS_OK];
                framed.append(&mut ok);
                framed
            }
            Err(message) => {
                let mut framed = vec![STATUS_ERR];
                framed.extend_from_slice(message.as_bytes());
                framed
            }
        };
        channel.send(&mut stream, &response)?;
    }
}

fn handle_request(request: &[u8], storage: &Mutex<Storage>) -> Result<Vec<u8>, String> {
    let (&op, body) = request.split_first().ok_or("empty request")?;
    let mut storage = storage.lock().map_err(|_| "storage poisoned")?;
    match op {
        OP_GET => {
            let (key, rest) = take_bytes(body)?;
            expect_empty(rest)?;
            match storage.get(key) {
                None => Ok(vec![0]),
                Some(value) => {
                    let mut out = vec![1];
                    put_bytes(&mut out, value);
                    Ok(out)
                }
            }
        }
        OP_SCAN => {
            let (prefix, rest) = take_bytes(body)?;
            expect_empty(rest)?;
            let pairs: Vec<(&[u8], &[u8])> = storage.scan_prefix(prefix).collect();
            Ok(encode_pairs(&pairs))
        }
        OP_DUMP => {
            expect_empty(body)?;
            let pairs: Vec<(&[u8], &[u8])> = storage.scan_prefix(b"").collect();
            Ok(encode_pairs(&pairs))
        }
        OP_PUT => {
            let (key, rest) = take_bytes(body)?;
            let (value, rest) = take_bytes(rest)?;
            expect_empty(rest)?;
            storage.put(key, value).map_err(|e| e.to_string())?;
            Ok(Vec::new())
        }
        OP_DELETE => {
            let (key, rest) = take_bytes(body)?;
            expect_empty(rest)?;
            storage.delete(key).map_err(|e| e.to_string())?;
            Ok(Vec::new())
        }
        OP_COMMIT => {
            let mut rest = body;
            let count = take_u32(&mut rest)?;
            let mut batch = Batch::new();
            for _ in 0..count {
                let (&entry_op, after) = rest.split_first().ok_or("truncated batch")?;
                let (key, after) = take_bytes(after)?;
                let (value, after) = take_bytes(after)?;
                rest = after;
                match entry_op {
                    0 => batch.put(key, value),
                    1 => batch.delete(key),
                    _ => return Err("bad batch entry".into()),
                }
            }
            expect_empty(rest)?;
            storage.commit(batch).map_err(|e| e.to_string())?;
            Ok(Vec::new())
        }
        _ => Err(format!("unknown opcode {op}")),
    }
}

// ---------------------------------------------------------------- client

/// A connection to a Ciphra storage server. Interior mutability lets
/// read-only engine paths issue network requests.
pub struct RemoteStorage {
    stream: RefCell<TcpStream>,
    channel: RefCell<Channel>,
    /// The server's static public key, learned during the handshake.
    pub server_public: [u8; 32],
    /// Whether the server's static key was authenticated against a pin.
    pub authenticated: bool,
}

impl RemoteStorage {
    /// Connect and run the hybrid handshake. If `pinned` is `Some`, the
    /// server's static key must match it (authenticated); if `None`, the
    /// server's key is trusted on first use — encrypted and
    /// post-quantum, but open to a man-in-the-middle.
    pub fn connect(addr: impl ToSocketAddrs, pinned: Option<[u8; 32]>) -> std::io::Result<Self> {
        let mut stream = TcpStream::connect(addr)?;
        stream.set_nodelay(true)?;

        let (state, hello) = client_start();
        write_frame(&mut stream, &hello.to_bytes())?;
        let reply = read_frame(&mut stream)?;
        if reply.len() != 32 + SERVER_HELLO_LEN {
            return Err(std::io::Error::other("bad server hello"));
        }
        let mut server_public = [0u8; 32];
        server_public.copy_from_slice(&reply[..32]);
        let authenticated = match pinned {
            Some(expected) => {
                if expected != server_public {
                    return Err(std::io::Error::other(
                        "server key does not match the pinned --server-key",
                    ));
                }
                true
            }
            None => false,
        };
        let server_hello = ServerHello::from_bytes(&reply[32..])
            .ok_or_else(|| std::io::Error::other("bad server hello"))?;
        let shared = client_finish(&state, &server_hello, &server_public);

        Ok(RemoteStorage {
            stream: RefCell::new(stream),
            channel: RefCell::new(Channel::new(shared, true)),
            server_public,
            authenticated,
        })
    }

    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        let mut request = vec![OP_GET];
        put_bytes(&mut request, key);
        let response = self.roundtrip(&request)?;
        let (&present, rest) = response
            .split_first()
            .ok_or_else(|| protocol_error("short GET response"))?;
        if present == 0 {
            return Ok(None);
        }
        let (value, rest) = take_bytes(rest).map_err(protocol_error)?;
        expect_empty(rest).map_err(protocol_error)?;
        Ok(Some(value.to_vec()))
    }

    pub fn scan_prefix(&self, prefix: &[u8]) -> Result<Vec<Pair>, StorageError> {
        let mut request = vec![OP_SCAN];
        put_bytes(&mut request, prefix);
        decode_pairs(&self.roundtrip(&request)?)
    }

    pub fn dump(&self) -> Result<Vec<Pair>, StorageError> {
        decode_pairs(&self.roundtrip(&[OP_DUMP])?)
    }

    pub fn put(&self, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
        let mut request = vec![OP_PUT];
        put_bytes(&mut request, key);
        put_bytes(&mut request, value);
        self.roundtrip(&request)?;
        Ok(())
    }

    pub fn delete(&self, key: &[u8]) -> Result<(), StorageError> {
        let mut request = vec![OP_DELETE];
        put_bytes(&mut request, key);
        self.roundtrip(&request)?;
        Ok(())
    }

    pub fn commit(&self, batch: &Batch) -> Result<(), StorageError> {
        let mut request = vec![OP_COMMIT];
        request.extend_from_slice(&(batch.len() as u32).to_le_bytes());
        for (is_delete, key, value) in batch.entries() {
            request.push(u8::from(is_delete));
            put_bytes(&mut request, key);
            put_bytes(&mut request, value);
        }
        self.roundtrip(&request)?;
        Ok(())
    }

    fn roundtrip(&self, request: &[u8]) -> Result<Vec<u8>, StorageError> {
        let mut stream = self.stream.borrow_mut();
        let mut channel = self.channel.borrow_mut();
        channel
            .send(&mut *stream, request)
            .map_err(StorageError::Io)?;
        let response = channel.recv(&mut *stream).map_err(StorageError::Io)?;
        let (&status, body) = response
            .split_first()
            .ok_or_else(|| protocol_error("empty response"))?;
        match status {
            STATUS_OK => Ok(body.to_vec()),
            _ => Err(StorageError::Corrupt(format!(
                "server error: {}",
                String::from_utf8_lossy(body)
            ))),
        }
    }
}

// ---------------------------------------------------------------- codecs

fn read_frame(stream: &mut impl Read) -> std::io::Result<Vec<u8>> {
    let mut len_bytes = [0u8; 4];
    stream.read_exact(&mut len_bytes)?;
    let len = u32::from_le_bytes(len_bytes);
    if len > MAX_FRAME {
        return Err(std::io::Error::other("frame too large"));
    }
    let mut payload = vec![0u8; len as usize];
    stream.read_exact(&mut payload)?;
    Ok(payload)
}

fn write_frame(stream: &mut impl Write, payload: &[u8]) -> std::io::Result<()> {
    stream.write_all(&(payload.len() as u32).to_le_bytes())?;
    stream.write_all(payload)?;
    stream.flush()
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}

fn take_bytes(buf: &[u8]) -> Result<(&[u8], &[u8]), String> {
    if buf.len() < 4 {
        return Err("truncated length".into());
    }
    let len = u32::from_le_bytes(buf[..4].try_into().unwrap()) as usize;
    if buf.len() < 4 + len {
        return Err("truncated bytes".into());
    }
    Ok((&buf[4..4 + len], &buf[4 + len..]))
}

fn take_u32(buf: &mut &[u8]) -> Result<u32, String> {
    if buf.len() < 4 {
        return Err("truncated u32".into());
    }
    let value = u32::from_le_bytes(buf[..4].try_into().unwrap());
    *buf = &buf[4..];
    Ok(value)
}

fn expect_empty(rest: &[u8]) -> Result<(), String> {
    if rest.is_empty() {
        Ok(())
    } else {
        Err("trailing bytes in message".into())
    }
}

fn encode_pairs(pairs: &[(&[u8], &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(pairs.len() as u32).to_le_bytes());
    for (key, value) in pairs {
        put_bytes(&mut out, key);
        put_bytes(&mut out, value);
    }
    out
}

fn decode_pairs(body: &[u8]) -> Result<Vec<Pair>, StorageError> {
    let mut rest = body;
    let count = take_u32(&mut rest).map_err(protocol_error)?;
    let mut pairs = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let (key, after) = take_bytes(rest).map_err(protocol_error)?;
        let (value, after) = take_bytes(after).map_err(protocol_error)?;
        rest = after;
        pairs.push((key.to_vec(), value.to_vec()));
    }
    expect_empty(rest).map_err(protocol_error)?;
    Ok(pairs)
}

fn protocol_error(message: impl std::fmt::Display) -> StorageError {
    StorageError::Corrupt(format!("protocol error: {message}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spawn_server() -> (std::net::SocketAddr, [u8; 32], ciphra_testutil::TempDir) {
        let dir = ciphra_testutil::tempdir();
        let storage = Arc::new(Mutex::new(Storage::open(dir.path()).unwrap()));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let identity = ServerIdentity::generate();
        let public = identity.public;
        let secret = identity.secret_bytes();
        std::thread::spawn(move || {
            let _ = serve(listener, storage, secret);
        });
        (addr, public, dir)
    }

    #[test]
    fn remote_roundtrip() {
        let (addr, server_public, _dir) = spawn_server();
        let client = RemoteStorage::connect(addr, Some(server_public)).unwrap();
        assert!(client.authenticated);

        assert_eq!(client.get(b"missing").unwrap(), None);
        client.put(b"a", b"1").unwrap();
        let mut batch = Batch::new();
        batch.put(b"b", b"2");
        batch.put(b"c", b"3");
        batch.delete(b"a");
        client.commit(&batch).unwrap();

        assert_eq!(client.get(b"a").unwrap(), None);
        assert_eq!(client.get(b"b").unwrap(), Some(b"2".to_vec()));
        let pairs = client.scan_prefix(b"").unwrap();
        assert_eq!(pairs.len(), 2);
        assert_eq!(client.dump().unwrap(), pairs);
        client.delete(b"b").unwrap();
        assert_eq!(client.scan_prefix(b"").unwrap().len(), 1);

        // Two clients see the same state.
        let second = RemoteStorage::connect(addr, Some(server_public)).unwrap();
        assert_eq!(second.get(b"c").unwrap(), Some(b"3".to_vec()));
    }

    #[test]
    fn pinning_a_wrong_key_is_refused() {
        let (addr, _real, _dir) = spawn_server();
        let wrong = ServerIdentity::generate().public;
        let err = RemoteStorage::connect(addr, Some(wrong))
            .err()
            .expect("mismatched pin must be refused");
        assert!(err.to_string().contains("pinned"));
    }

    #[test]
    fn trust_on_first_use_is_unauthenticated_but_works() {
        let (addr, _real, _dir) = spawn_server();
        let client = RemoteStorage::connect(addr, None).unwrap();
        assert!(!client.authenticated);
        client.put(b"k", b"v").unwrap();
        assert_eq!(client.get(b"k").unwrap(), Some(b"v".to_vec()));
    }
}
