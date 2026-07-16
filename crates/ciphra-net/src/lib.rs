//! The Ciphra remote-storage protocol.
//!
//! Ciphra's client/server split follows one rule (ADR-0003): **the
//! server never holds keys**. SQL, encryption and query planning all
//! happen in the engine, which lives with the key holder; the server
//! is a durable ordered key-value store for sealed bytes it cannot
//! read. Consequently the wire protocol is a storage protocol — GET,
//! SCAN, COMMIT, DUMP — not a SQL protocol. A SUBSCRIBE opcode turns a
//! connection into a replication follower: the server pushes a sealed
//! snapshot and then every subsequent commit, in order (see [`follow`]).
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
/// Turn this connection into a replication follower: the server replies
/// with a snapshot record and then streams every subsequent commit.
const OP_SUBSCRIBE: u8 = 7;

/// Replication record kinds, streamed to a subscriber over the sealed
/// channel. A snapshot is sent once, first; batches follow, in order.
const REC_SNAPSHOT: u8 = 0;
const REC_BATCH: u8 = 1;

/// An owned key-value pair as shipped over the wire.
pub type Pair = (Vec<u8>, Vec<u8>);

const STATUS_OK: u8 = 0;
const STATUS_ERR: u8 = 1;

/// A frame is capped to keep a misbehaving peer from ballooning memory.
const MAX_FRAME: u32 = 256 * 1024 * 1024;

// ---------------------------------------------------------------- server

/// Shared server storage: sealed bytes plus the replication fan-out
/// (a commit sequence number and the list of subscriber channels). A
/// leader mutates and broadcasts; a read-only replica rejects network
/// writes and is fed by [`follow`] instead. Cheap to `clone` — it is an
/// `Arc` handle, so `serve` and `follow` can share one store.
#[derive(Clone)]
pub struct SharedStorage(Arc<Mutex<ServerState>>);

impl SharedStorage {
    /// A writable leader store.
    pub fn new(storage: Storage) -> Self {
        Self(Arc::new(Mutex::new(ServerState::new(storage, false))))
    }

    /// A read-only replica store: network `PUT`/`DELETE`/`COMMIT` are
    /// refused, so its only writer is the replication stream.
    pub fn read_only(storage: Storage) -> Self {
        Self(Arc::new(Mutex::new(ServerState::new(storage, true))))
    }
}

struct ServerState {
    storage: Storage,
    read_only: bool,
    /// Monotonic commit counter; mirrors the leader's on a follower.
    seq: u64,
    /// Live replication followers. A closed channel is dropped on the
    /// next broadcast.
    subscribers: Vec<std::sync::mpsc::Sender<Vec<u8>>>,
}

impl ServerState {
    fn new(storage: Storage, read_only: bool) -> Self {
        ServerState {
            storage,
            read_only,
            seq: 0,
            subscribers: Vec::new(),
        }
    }

    /// Bump the sequence and push a batch record to every follower,
    /// dropping any whose receiver has gone away.
    fn replicate(&mut self, entries: Vec<u8>) {
        self.seq += 1;
        let msg = record(REC_BATCH, self.seq, &entries);
        self.subscribers.retain(|tx| tx.send(msg.clone()).is_ok());
    }
}

/// Serve `shared` on `listener`, one thread per connection, forever.
/// `server_secret` is the static X25519 transport identity clients pin.
/// This process stores and returns sealed bytes; it has no data keys
/// and nothing in it can decrypt stored rows.
pub fn serve(
    listener: TcpListener,
    shared: SharedStorage,
    server_secret: [u8; 32],
) -> std::io::Result<()> {
    loop {
        let (stream, _) = listener.accept()?;
        let shared = shared.clone();
        std::thread::spawn(move || {
            let _ = handle_connection(stream, shared, server_secret);
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
    shared: SharedStorage,
    server_secret: [u8; 32],
) -> std::io::Result<()> {
    stream.set_nodelay(true)?;
    let identity = ServerIdentity::from_secret(server_secret);

    // Handshake: read the client hello, answer with (static pub || our
    // hello), both as plaintext frames.
    let client_hello_bytes = read_frame(&mut stream)?;
    let client_hello = ClientHello::from_bytes(&client_hello_bytes)
        .ok_or_else(|| std::io::Error::other("bad client hello"))?;
    let (server_hello, secret) = server_respond(&identity, &client_hello);
    let mut reply = identity.public.to_vec();
    reply.extend_from_slice(&server_hello.to_bytes());
    write_frame(&mut stream, &reply)?;

    let mut channel = Channel::new(secret, false);
    loop {
        let request = match channel.recv(&mut stream) {
            Ok(frame) => frame,
            Err(_) => return Ok(()), // peer went away or auth failed
        };
        // A subscription hijacks the connection into a one-way push loop
        // and never returns to request/response, so handle it here.
        if request.first() == Some(&OP_SUBSCRIBE) {
            return stream_to_subscriber(&mut stream, &mut channel, &shared.0);
        }
        let response = match handle_request(&request, &shared.0) {
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

/// Register `stream` as a replication follower and push it the current
/// snapshot followed by every future commit. Snapshot capture and
/// subscriber registration happen under one lock, so no commit can slip
/// through the gap between them: the first batch a follower sees is
/// always `snapshot_seq + 1`.
fn stream_to_subscriber(
    stream: &mut TcpStream,
    channel: &mut Channel,
    state: &Mutex<ServerState>,
) -> std::io::Result<()> {
    let (rx, snapshot) = {
        let mut st = state
            .lock()
            .map_err(|_| std::io::Error::other("storage poisoned"))?;
        let pairs: Vec<Pair> = st
            .storage
            .scan_prefix(b"")
            .map(|(k, v)| (k.to_vec(), v.to_vec()))
            .collect();
        let snapshot = record(REC_SNAPSHOT, st.seq, &encode_owned_pairs(&pairs));
        let (tx, rx) = std::sync::mpsc::channel();
        st.subscribers.push(tx);
        (rx, snapshot)
    };
    channel.send(stream, &snapshot)?;
    while let Ok(msg) = rx.recv() {
        if channel.send(stream, &msg).is_err() {
            break; // follower disconnected; the leader will drop us
        }
    }
    Ok(())
}

fn handle_request(request: &[u8], state: &Mutex<ServerState>) -> Result<Vec<u8>, String> {
    let (&op, body) = request.split_first().ok_or("empty request")?;
    let mut st = state.lock().map_err(|_| "storage poisoned")?;
    match op {
        OP_GET => {
            let (key, rest) = take_bytes(body)?;
            expect_empty(rest)?;
            match st.storage.get(key) {
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
            let pairs: Vec<(&[u8], &[u8])> = st.storage.scan_prefix(prefix).collect();
            Ok(encode_pairs(&pairs))
        }
        OP_DUMP => {
            expect_empty(body)?;
            let pairs: Vec<(&[u8], &[u8])> = st.storage.scan_prefix(b"").collect();
            Ok(encode_pairs(&pairs))
        }
        OP_PUT => {
            let (key, rest) = take_bytes(body)?;
            let (value, rest) = take_bytes(rest)?;
            expect_empty(rest)?;
            if st.read_only {
                return Err("server is a read-only replica".into());
            }
            st.storage.put(key, value).map_err(|e| e.to_string())?;
            let mut batch = Batch::new();
            batch.put(key, value);
            let entries = encode_batch(&batch);
            st.replicate(entries);
            Ok(Vec::new())
        }
        OP_DELETE => {
            let (key, rest) = take_bytes(body)?;
            expect_empty(rest)?;
            if st.read_only {
                return Err("server is a read-only replica".into());
            }
            st.storage.delete(key).map_err(|e| e.to_string())?;
            let mut batch = Batch::new();
            batch.delete(key);
            let entries = encode_batch(&batch);
            st.replicate(entries);
            Ok(Vec::new())
        }
        OP_COMMIT => {
            if st.read_only {
                return Err("server is a read-only replica".into());
            }
            let batch = decode_batch(body)?;
            let entries = encode_batch(&batch);
            st.storage.commit(batch).map_err(|e| e.to_string())?;
            st.replicate(entries);
            Ok(Vec::new())
        }
        _ => Err(format!("unknown opcode {op}")),
    }
}

// ------------------------------------------------------------- replication

/// Connect to a leader at `addr` and mirror its commit stream into
/// `shared` forever. The follower first applies a full snapshot (a state
/// replace: keys absent from the snapshot are deleted), then applies each
/// streamed batch in order, mirroring the leader's sequence number.
///
/// `on_event` is called for the initial connection and after every
/// applied record, so callers can log progress. This function only
/// returns on a connection or protocol error.
pub fn follow(
    addr: impl ToSocketAddrs,
    pinned: Option<[u8; 32]>,
    shared: SharedStorage,
    mut on_event: impl FnMut(FollowEvent),
) -> std::io::Result<()> {
    let mut stream = TcpStream::connect(addr)?;
    stream.set_nodelay(true)?;
    let (mut channel, server_public, authenticated) = client_handshake(&mut stream, pinned)?;
    on_event(FollowEvent::Connected {
        server_public,
        authenticated,
    });
    channel.send(&mut stream, &[OP_SUBSCRIBE])?;
    loop {
        let msg = channel.recv(&mut stream)?;
        let event = apply_record(&msg, &shared.0)?;
        on_event(event);
    }
}

/// Progress reported by [`follow`].
pub enum FollowEvent {
    /// The handshake completed. `authenticated` is true only if a pin
    /// was supplied and matched.
    Connected {
        server_public: [u8; 32],
        authenticated: bool,
    },
    /// The initial snapshot was applied, replacing local state.
    Snapshot { seq: u64, rows: usize },
    /// A live commit was applied.
    Applied { seq: u64, changes: usize },
}

/// Apply one replication record to `state` under a single lock and
/// return what happened. Snapshots replace state wholesale; batches are
/// applied in order. Applying also re-broadcasts to this node's own
/// followers, so replicas can be chained.
fn apply_record(msg: &[u8], state: &Mutex<ServerState>) -> std::io::Result<FollowEvent> {
    let (&kind, rest) = msg
        .split_first()
        .ok_or_else(|| std::io::Error::other("empty replication record"))?;
    if rest.len() < 8 {
        return Err(std::io::Error::other("truncated replication record"));
    }
    let seq = u64::from_le_bytes(rest[..8].try_into().unwrap());
    let body = &rest[8..];
    let mut st = state
        .lock()
        .map_err(|_| std::io::Error::other("storage poisoned"))?;
    match kind {
        REC_SNAPSHOT => {
            let pairs = decode_pairs(body).map_err(io_err)?;
            let rows = pairs.len();
            // State replace: drop any local key the snapshot doesn't have,
            // then write every snapshot pair — one atomic commit.
            let incoming: std::collections::HashSet<&[u8]> =
                pairs.iter().map(|(k, _)| k.as_slice()).collect();
            let stale: Vec<Vec<u8>> = st
                .storage
                .scan_prefix(b"")
                .filter(|(k, _)| !incoming.contains(k))
                .map(|(k, _)| k.to_vec())
                .collect();
            let mut batch = Batch::new();
            for key in &stale {
                batch.delete(key);
            }
            for (key, value) in &pairs {
                batch.put(key, value);
            }
            st.storage.commit(batch).map_err(io_err)?;
            st.seq = seq;
            Ok(FollowEvent::Snapshot { seq, rows })
        }
        REC_BATCH => {
            let batch = decode_batch(body).map_err(io_err)?;
            let changes = batch.len();
            let entries = body.to_vec();
            st.storage.commit(batch).map_err(io_err)?;
            st.seq = seq;
            // Cascade to our own followers, preserving the leader's seq.
            let msg = record(REC_BATCH, seq, &entries);
            st.subscribers.retain(|tx| tx.send(msg.clone()).is_ok());
            Ok(FollowEvent::Applied { seq, changes })
        }
        other => Err(std::io::Error::other(format!(
            "unknown replication record kind {other}"
        ))),
    }
}

fn io_err(e: impl std::fmt::Display) -> std::io::Error {
    std::io::Error::other(e.to_string())
}

/// A replication record: `kind (u8) | seq (u64 LE) | body`.
fn record(kind: u8, seq: u64, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 8 + body.len());
    out.push(kind);
    out.extend_from_slice(&seq.to_le_bytes());
    out.extend_from_slice(body);
    out
}

/// Encode a batch as `count (u32) | [op (u8) | key | value]…`, the same
/// framing `OP_COMMIT` accepts, so it round-trips through [`decode_batch`].
fn encode_batch(batch: &Batch) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(batch.len() as u32).to_le_bytes());
    for (is_delete, key, value) in batch.entries() {
        out.push(u8::from(is_delete));
        put_bytes(&mut out, key);
        put_bytes(&mut out, value);
    }
    out
}

fn decode_batch(body: &[u8]) -> Result<Batch, String> {
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
    Ok(batch)
}

// ---------------------------------------------------------------- client

/// Run the client side of the hybrid handshake on an open `stream` and
/// return the sealed channel plus the server's learned static key. If
/// `pinned` is `Some`, the server key must match it (authenticated);
/// otherwise it is trusted on first use — encrypted and post-quantum,
/// but open to a man-in-the-middle.
fn client_handshake(
    stream: &mut TcpStream,
    pinned: Option<[u8; 32]>,
) -> std::io::Result<(Channel, [u8; 32], bool)> {
    let (state, hello) = client_start();
    write_frame(stream, &hello.to_bytes())?;
    let reply = read_frame(stream)?;
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
    Ok((Channel::new(shared, true), server_public, authenticated))
}

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
        // Bound every read/write. Without this a half-open connection — the
        // mobile-NAT case, where the peer's mapping is dropped with no RST — makes
        // a blocking read wait forever, silently wedging a client that polls this
        // connection (e.g. a messenger's mailbox reader). A timeout turns the wedge
        // into a recoverable error the caller can reconnect on.
        let t = Some(std::time::Duration::from_secs(20));
        stream.set_read_timeout(t)?;
        stream.set_write_timeout(t)?;
        let (channel, server_public, authenticated) = client_handshake(&mut stream, pinned)?;
        Ok(RemoteStorage {
            stream: RefCell::new(stream),
            channel: RefCell::new(channel),
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

fn encode_owned_pairs(pairs: &[Pair]) -> Vec<u8> {
    let refs: Vec<(&[u8], &[u8])> = pairs
        .iter()
        .map(|(k, v)| (k.as_slice(), v.as_slice()))
        .collect();
    encode_pairs(&refs)
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
        let shared = SharedStorage::new(Storage::open(dir.path()).unwrap());
        let (addr, public) = spawn_on(shared);
        (addr, public, dir)
    }

    /// Serve an existing `SharedStorage` on an ephemeral port and return
    /// its address and pinnable public key.
    fn spawn_on(shared: SharedStorage) -> (std::net::SocketAddr, [u8; 32]) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let identity = ServerIdentity::generate();
        let public = identity.public;
        let secret = identity.secret_bytes();
        std::thread::spawn(move || {
            let _ = serve(listener, shared, secret);
        });
        (addr, public)
    }

    /// Poll `cond` for up to ~5s; panic if it never holds.
    fn wait_until(mut cond: impl FnMut() -> bool) {
        for _ in 0..500 {
            if cond() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        panic!("condition never became true");
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

    /// Snapshot on subscribe, then live commits, land on the follower —
    /// including deletes, so the follower tracks state exactly.
    #[test]
    fn follower_replicates_snapshot_then_stream() {
        // Leader with one pre-existing row (must arrive via snapshot).
        let leader_dir = ciphra_testutil::tempdir();
        let leader = SharedStorage::new(Storage::open(leader_dir.path()).unwrap());
        {
            let mut st = leader.0.lock().unwrap();
            st.storage.put(b"a", b"1").unwrap();
        }
        let (addr, public) = spawn_on(leader.clone());

        // Follower subscribes and applies into its own read-only store.
        let follower_dir = ciphra_testutil::tempdir();
        let follower = SharedStorage::read_only(Storage::open(follower_dir.path()).unwrap());
        let follow_handle = follower.clone();
        std::thread::spawn(move || {
            let _ = follow(addr, Some(public), follow_handle, |_| {});
        });

        // Snapshot lands.
        let f = follower.clone();
        wait_until(move || f.0.lock().unwrap().storage.get(b"a") == Some(b"1".to_vec()).as_deref());

        // Live commits: a batch (add b, drop a) and a single put.
        let client = RemoteStorage::connect(addr, Some(public)).unwrap();
        let mut batch = Batch::new();
        batch.put(b"b", b"2");
        batch.delete(b"a");
        client.commit(&batch).unwrap();
        client.put(b"c", b"3").unwrap();

        let f = follower.clone();
        wait_until(move || {
            let st = f.0.lock().unwrap();
            st.storage.get(b"c") == Some(b"3".to_vec()).as_deref()
                && st.storage.get(b"a").is_none()
                && st.storage.get(b"b") == Some(b"2".to_vec()).as_deref()
        });

        // The follower's sequence number tracks the leader's: two commits.
        assert_eq!(follower.0.lock().unwrap().seq, 2);
    }

    #[test]
    fn read_only_replica_refuses_writes() {
        let dir = ciphra_testutil::tempdir();
        let replica = SharedStorage::read_only(Storage::open(dir.path()).unwrap());
        let (addr, public) = spawn_on(replica);
        let client = RemoteStorage::connect(addr, Some(public)).unwrap();
        let err = client.put(b"k", b"v").expect_err("write must be refused");
        assert!(err.to_string().contains("read-only"));
    }
}
