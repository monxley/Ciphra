//! The Ciphra remote-storage protocol.
//!
//! Ciphra's client/server split follows one rule (ADR-0003): **the
//! server never holds keys**. SQL, encryption and query planning all
//! happen in the engine, which lives with the key holder; the server
//! is a durable ordered key-value store for sealed bytes it cannot
//! read. Consequently the wire protocol is a storage protocol — GET,
//! SCAN, COMMIT, DUMP — not a SQL protocol.
//!
//! Framing: every message is `len (u32 LE) | payload`. Requests start
//! with an opcode byte; responses with a status byte (0 = ok, 1 =
//! error + UTF-8 message). v1 is plain TCP; the transport-security
//! layer (and its post-quantum key exchange) attaches at exactly this
//! boundary later.

use std::cell::RefCell;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};

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
/// This process stores and returns sealed bytes; it has no keys and
/// nothing in it can decrypt.
pub fn serve(listener: TcpListener, storage: Arc<Mutex<Storage>>) -> std::io::Result<()> {
    loop {
        let (stream, _) = listener.accept()?;
        let storage = Arc::clone(&storage);
        std::thread::spawn(move || {
            let _ = handle_connection(stream, &storage);
        });
    }
}

fn handle_connection(mut stream: TcpStream, storage: &Mutex<Storage>) -> std::io::Result<()> {
    stream.set_nodelay(true)?;
    loop {
        let request = match read_frame(&mut stream) {
            Ok(frame) => frame,
            Err(_) => return Ok(()), // peer went away
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
        write_frame(&mut stream, &response)?;
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
}

impl RemoteStorage {
    pub fn connect(addr: impl ToSocketAddrs) -> std::io::Result<Self> {
        let stream = TcpStream::connect(addr)?;
        stream.set_nodelay(true)?;
        Ok(RemoteStorage {
            stream: RefCell::new(stream),
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
        write_frame(&mut *stream, request).map_err(StorageError::Io)?;
        let response = read_frame(&mut *stream).map_err(StorageError::Io)?;
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

    fn spawn_server() -> (std::net::SocketAddr, ciphra_testutil::TempDir) {
        let dir = ciphra_testutil::tempdir();
        let storage = Arc::new(Mutex::new(Storage::open(dir.path()).unwrap()));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let _ = serve(listener, storage);
        });
        (addr, dir)
    }

    #[test]
    fn remote_roundtrip() {
        let (addr, _dir) = spawn_server();
        let client = RemoteStorage::connect(addr).unwrap();

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
        let second = RemoteStorage::connect(addr).unwrap();
        assert_eq!(second.get(b"c").unwrap(), Some(b"3".to_vec()));
    }
}
