//! Ciphra storage engine, v0: a durable ordered key-value store.
//!
//! Design: every mutation is appended to a checksummed write-ahead log
//! before being applied to an in-memory ordered table (`BTreeMap`). On
//! open, the WAL is replayed; a torn tail (partial write after a crash)
//! is detected via CRC-32 and truncated. `compact()` rewrites the log
//! to contain only the live state.
//!
//! This is deliberately the simplest thing that is *correct*. SSTables,
//! compaction levels and MVCC come later (see ROADMAP.md); the public
//! API is designed so callers won't have to change when they do.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

const WAL_FILE: &str = "ciphra.wal";
const OP_PUT: u8 = 1;
const OP_DELETE: u8 = 2;

/// Errors produced by the storage layer.
#[derive(Debug)]
pub enum StorageError {
    Io(io::Error),
    Corrupt(String),
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StorageError::Io(e) => write!(f, "storage io error: {e}"),
            StorageError::Corrupt(msg) => write!(f, "storage corruption: {msg}"),
        }
    }
}

impl std::error::Error for StorageError {}

impl From<io::Error> for StorageError {
    fn from(e: io::Error) -> Self {
        StorageError::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, StorageError>;

/// A durable ordered key-value store backed by a write-ahead log.
pub struct Storage {
    map: BTreeMap<Vec<u8>, Vec<u8>>,
    wal: File,
    wal_path: PathBuf,
}

impl Storage {
    /// Open (or create) a store in `dir`, replaying the WAL.
    ///
    /// A corrupted tail — the typical result of a crash mid-write — is
    /// truncated so the store recovers to the last fully written record.
    pub fn open(dir: impl AsRef<Path>) -> Result<Self> {
        let dir = dir.as_ref();
        fs::create_dir_all(dir)?;
        let wal_path = dir.join(WAL_FILE);
        let mut wal = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(&wal_path)?;

        let mut buf = Vec::new();
        wal.seek(SeekFrom::Start(0))?;
        wal.read_to_end(&mut buf)?;

        let mut map = BTreeMap::new();
        let mut pos = 0usize;
        while pos < buf.len() {
            match decode_record(&buf[pos..]) {
                Some((consumed, op, key, value)) => {
                    match op {
                        OP_PUT => {
                            map.insert(key, value);
                        }
                        OP_DELETE => {
                            map.remove(&key);
                        }
                        _ => break, // unknown opcode: treat as torn tail
                    }
                    pos += consumed;
                }
                None => break, // truncated or checksum-failed tail
            }
        }
        if pos < buf.len() {
            wal.set_len(pos as u64)?;
        }
        wal.seek(SeekFrom::End(0))?;

        Ok(Storage { map, wal, wal_path })
    }

    /// Insert or replace `key` with `value`. Durable once this returns.
    pub fn put(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
        self.append(OP_PUT, key, value)?;
        self.map.insert(key.to_vec(), value.to_vec());
        Ok(())
    }

    /// Remove `key` if present. Durable once this returns.
    pub fn delete(&mut self, key: &[u8]) -> Result<()> {
        self.append(OP_DELETE, key, &[])?;
        self.map.remove(key);
        Ok(())
    }

    pub fn get(&self, key: &[u8]) -> Option<&[u8]> {
        self.map.get(key).map(Vec::as_slice)
    }

    /// Iterate all pairs whose key starts with `prefix`, in key order.
    pub fn scan_prefix<'a>(
        &'a self,
        prefix: &'a [u8],
    ) -> impl Iterator<Item = (&'a [u8], &'a [u8])> + 'a {
        self.map
            .range(prefix.to_vec()..)
            .take_while(move |(k, _)| k.starts_with(prefix))
            .map(|(k, v)| (k.as_slice(), v.as_slice()))
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Rewrite the WAL so it contains exactly the live state.
    pub fn compact(&mut self) -> Result<()> {
        let tmp_path = self.wal_path.with_extension("wal.tmp");
        let mut tmp = File::create(&tmp_path)?;
        for (key, value) in &self.map {
            tmp.write_all(&encode_record(OP_PUT, key, value))?;
        }
        tmp.sync_all()?;
        drop(tmp);
        fs::rename(&tmp_path, &self.wal_path)?;
        self.wal = OpenOptions::new()
            .read(true)
            .append(true)
            .open(&self.wal_path)?;
        Ok(())
    }

    fn append(&mut self, op: u8, key: &[u8], value: &[u8]) -> Result<()> {
        self.wal.write_all(&encode_record(op, key, value))?;
        self.wal.sync_data()?;
        Ok(())
    }
}

/// Record layout: `crc32(payload) (4 LE) | payload_len (4 LE) | payload`
/// where `payload = op (1) | key_len (4 LE) | key | value_len (4 LE) | value`.
fn encode_record(op: u8, key: &[u8], value: &[u8]) -> Vec<u8> {
    let payload_len = 1 + 4 + key.len() + 4 + value.len();
    let mut payload = Vec::with_capacity(payload_len);
    payload.push(op);
    payload.extend_from_slice(&(key.len() as u32).to_le_bytes());
    payload.extend_from_slice(key);
    payload.extend_from_slice(&(value.len() as u32).to_le_bytes());
    payload.extend_from_slice(value);

    let mut record = Vec::with_capacity(8 + payload_len);
    record.extend_from_slice(&crc32(&payload).to_le_bytes());
    record.extend_from_slice(&(payload_len as u32).to_le_bytes());
    record.extend_from_slice(&payload);
    record
}

/// Decode one record from the front of `buf`.
/// Returns `(bytes_consumed, op, key, value)`, or `None` if the record is
/// truncated or fails its checksum.
fn decode_record(buf: &[u8]) -> Option<(usize, u8, Vec<u8>, Vec<u8>)> {
    if buf.len() < 8 {
        return None;
    }
    let crc = u32::from_le_bytes(buf[0..4].try_into().unwrap());
    let payload_len = u32::from_le_bytes(buf[4..8].try_into().unwrap()) as usize;
    if buf.len() < 8 + payload_len || payload_len < 9 {
        return None;
    }
    let payload = &buf[8..8 + payload_len];
    if crc32(payload) != crc {
        return None;
    }
    let op = payload[0];
    let key_len = u32::from_le_bytes(payload[1..5].try_into().unwrap()) as usize;
    if payload.len() < 5 + key_len + 4 {
        return None;
    }
    let key = payload[5..5 + key_len].to_vec();
    let vstart = 5 + key_len;
    let value_len = u32::from_le_bytes(payload[vstart..vstart + 4].try_into().unwrap()) as usize;
    if payload.len() != vstart + 4 + value_len {
        return None;
    }
    let value = payload[vstart + 4..].to_vec();
    Some((8 + payload_len, op, key, value))
}

static CRC_TABLE: OnceLock<[u32; 256]> = OnceLock::new();

fn crc_table() -> &'static [u32; 256] {
    CRC_TABLE.get_or_init(|| {
        let mut table = [0u32; 256];
        for (i, entry) in table.iter_mut().enumerate() {
            let mut c = i as u32;
            for _ in 0..8 {
                c = if c & 1 != 0 {
                    0xEDB8_8320 ^ (c >> 1)
                } else {
                    c >> 1
                };
            }
            *entry = c;
        }
        table
    })
}

/// Standard CRC-32 (IEEE 802.3).
fn crc32(data: &[u8]) -> u32 {
    let table = crc_table();
    let mut c = 0xFFFF_FFFFu32;
    for &byte in data {
        c = table[((c ^ byte as u32) & 0xFF) as usize] ^ (c >> 8);
    }
    c ^ 0xFFFF_FFFF
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_get_delete() {
        let dir = ciphra_testutil::tempdir();
        let mut db = Storage::open(dir.path()).unwrap();
        db.put(b"alpha", b"1").unwrap();
        db.put(b"beta", b"2").unwrap();
        assert_eq!(db.get(b"alpha"), Some(&b"1"[..]));
        db.put(b"alpha", b"updated").unwrap();
        assert_eq!(db.get(b"alpha"), Some(&b"updated"[..]));
        db.delete(b"alpha").unwrap();
        assert_eq!(db.get(b"alpha"), None);
        assert_eq!(db.len(), 1);
    }

    #[test]
    fn survives_reopen() {
        let dir = ciphra_testutil::tempdir();
        {
            let mut db = Storage::open(dir.path()).unwrap();
            db.put(b"k1", b"v1").unwrap();
            db.put(b"k2", b"v2").unwrap();
            db.delete(b"k1").unwrap();
        }
        let db = Storage::open(dir.path()).unwrap();
        assert_eq!(db.get(b"k1"), None);
        assert_eq!(db.get(b"k2"), Some(&b"v2"[..]));
    }

    #[test]
    fn recovers_from_torn_tail() {
        let dir = ciphra_testutil::tempdir();
        {
            let mut db = Storage::open(dir.path()).unwrap();
            db.put(b"good", b"record").unwrap();
        }
        // Simulate a crash mid-append: garbage after the last record.
        {
            let mut wal = OpenOptions::new()
                .append(true)
                .open(dir.path().join(WAL_FILE))
                .unwrap();
            wal.write_all(&[0xDE, 0xAD, 0xBE]).unwrap();
        }
        let mut db = Storage::open(dir.path()).unwrap();
        assert_eq!(db.get(b"good"), Some(&b"record"[..]));
        // The store must still be writable after truncating the tail.
        db.put(b"after", b"crash").unwrap();
        drop(db);
        let db = Storage::open(dir.path()).unwrap();
        assert_eq!(db.get(b"after"), Some(&b"crash"[..]));
    }

    #[test]
    fn scan_prefix_is_ordered_and_bounded() {
        let dir = ciphra_testutil::tempdir();
        let mut db = Storage::open(dir.path()).unwrap();
        db.put(b"t/users/2", b"bob").unwrap();
        db.put(b"t/users/1", b"alice").unwrap();
        db.put(b"t/orders/1", b"x").unwrap();
        let hits: Vec<_> = db.scan_prefix(b"t/users/").collect();
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0], (&b"t/users/1"[..], &b"alice"[..]));
        assert_eq!(hits[1], (&b"t/users/2"[..], &b"bob"[..]));
    }

    #[test]
    fn compact_preserves_state() {
        let dir = ciphra_testutil::tempdir();
        let mut db = Storage::open(dir.path()).unwrap();
        for i in 0..50u32 {
            db.put(format!("key{i}").as_bytes(), b"old").unwrap();
            db.put(format!("key{i}").as_bytes(), b"new").unwrap();
        }
        for i in 0..25u32 {
            db.delete(format!("key{i}").as_bytes()).unwrap();
        }
        let before = fs::metadata(dir.path().join(WAL_FILE)).unwrap().len();
        db.compact().unwrap();
        let after = fs::metadata(dir.path().join(WAL_FILE)).unwrap().len();
        assert!(after < before);
        db.put(b"post-compact", b"works").unwrap();
        drop(db);
        let db = Storage::open(dir.path()).unwrap();
        assert_eq!(db.len(), 26);
        assert_eq!(db.get(b"key30"), Some(&b"new"[..]));
        assert_eq!(db.get(b"key10"), None);
        assert_eq!(db.get(b"post-compact"), Some(&b"works"[..]));
    }
}
