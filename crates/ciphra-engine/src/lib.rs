//! Ciphra execution engine.
//!
//! Ties the layers together: SQL statements from `ciphra-sql` are
//! executed against `ciphra-storage`, with every row sealed by
//! `ciphra-crypto` before it touches disk.
//!
//! Encryption model: each table gets its own ChaCha20-Poly1305 key
//! derived from the master key (`HKDF(master, "table:<name>")`). Whole
//! rows are encrypted; the AAD binds each ciphertext to its table and
//! row id, so encrypted rows cannot be moved or replayed across
//! tables/rows without detection. Plaintext row data never reaches the
//! storage layer.
//!
//! Tables are identified inside storage keys by an opaque 16-byte
//! keyed tag (`HMAC(master-derived key, name)`), never by name — the
//! name itself lives only inside the sealed schema record. With that,
//! no plaintext produced by the user (values, column names, table
//! names) appears anywhere on disk.
//!
//! Key layout inside storage (every value is sealed):
//!
//! ```text
//! \x00canary                        -> sealed marker to detect a wrong passphrase
//! \x00keyparams                     -> plaintext KDF parameters + salt (not secret)
//! \x00catalog\x00<tag16>            -> sealed TableSchema (incl. the real name)
//! \x00seq\x00<tag16>                -> sealed next row id (u64 LE)
//! r\x00<tag16><id BE>               -> sealed row
//! x\x00<tag16><col BE2><vtag16><id BE> -> sealed marker: equality-index entry
//! ```
//!
//! One index format serves both the PRIMARY KEY (which additionally
//! enforces uniqueness) and `CREATE INDEX` columns: `<vtag16>` is a
//! keyed tag of the column *value*, the row id lives in the key, and
//! the sealed empty payload makes every entry tamper-evident. Equality
//! lookups are prefix scans that never materialize the value on disk.
//! Documented leakage: which entries a lookup touches, and — for
//! secondary indexes — repetitions of the indexed column across rows
//! (opt-in per column via CREATE INDEX, never silent). PK values are
//! unique among live rows, so their tags repeat only across
//! delete/re-insert cycles.
//!
//! Every statement commits as a single WAL batch record under one
//! checksum: one fsync per statement (group commit) and all-or-nothing
//! crash recovery — a torn statement is dropped whole, never applied
//! partially. Readers still tolerate a dangling index entry (treated
//! as absent) as defense in depth for databases written before batch
//! records. Multi-statement transactions are on the roadmap.

mod codec;

use std::cmp::Ordering;
use std::path::{Path, PathBuf};

pub use ciphra_sql::{ColumnDef, DataType};
pub use codec::TableSchema;

use ciphra_crypto::{CipherKey, CryptoError, MasterKey};
use ciphra_sql::{
    Assignment, CmpOp, Expr, Limit, Literal, OrderBy, ParseError, Projection, Statement,
};
use ciphra_storage::{Batch, Storage, StorageError};

/// Legacy sidecar file holding KDF parameters; still read (and migrated
/// into the WAL) for databases created before the in-WAL record.
const KEYPARAMS_FILE: &str = "ciphra.keyparams";
/// Storage key of the (plaintext) KDF parameters record. Not secret —
/// it must be readable before any key exists; tampering with it only
/// yields BadPassphrase, since the canary no longer decrypts.
const KEYPARAMS_KEY: &[u8] = b"\x00keyparams";
/// Scratch directory used while rebuilding the database during key
/// rotation; safe to delete whenever no rotation is running.
const ROTATE_TMP_DIR: &str = ".rotate-tmp";
/// Prefix of sealed range-index blobs: `z\x00<tag16><col u16 BE>`.
const RANGE_PREFIX: &[u8] = b"z\x00";
/// Prefix of sealed audit-chain entries: `a\x00<seq u64 BE>`.
const AUDIT_PREFIX: &[u8] = b"a\x00";
/// Storage key of the sealed audit head: `seq u64 LE | root (32)`.
const AUDIT_HEAD_KEY: &[u8] = b"\x00audit";
/// Fixed size of a serialized audit entry (see [`AuditEntry`]).
const AUDIT_ENTRY_LEN: usize = 8 + 8 + 1 + 16 + 32 + 32;

/// Statement kinds recorded in the audit chain.
pub mod audit_kind {
    pub const CREATE_TABLE: u8 = 1;
    pub const DROP_TABLE: u8 = 2;
    pub const CREATE_INDEX: u8 = 3;
    pub const DROP_INDEX: u8 = 4;
    pub const INSERT: u8 = 5;
    pub const UPDATE: u8 = 6;
    pub const DELETE: u8 = 7;
    pub const ROTATE: u8 = 8;
}
/// v1 layout: `magic | iterations u32 LE | salt` (PBKDF2 implied).
const KEYPARAMS_MAGIC_V1: &[u8; 8] = b"CIPHRA\x00\x01";
/// v2 layout: `magic | kdf u8 | params | salt` where kdf 1 = PBKDF2
/// (`iterations u32`), kdf 2 = Argon2id (`m_kib u32 | passes u32 |
/// lanes u32`), all LE.
const KEYPARAMS_MAGIC_V2: &[u8; 8] = b"CIPHRA\x00\x02";
/// One decoded audit-chain entry.
///
/// Deliberately contains no user plaintext: the table is identified by
/// its opaque tag and the writes by a digest over the *sealed* bytes,
/// so a published root cannot be used to brute-force secret content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEntry {
    pub seq: u64,
    /// Seconds since the Unix epoch.
    pub time: u64,
    pub kind: u8,
    /// Opaque table tag; zeros for statements without a single table.
    pub table_tag: [u8; 16],
    /// SHA-256 over the committed (sealed) writes of the statement.
    pub writes_digest: [u8; 32],
    /// The chain root this entry extends.
    pub prev_root: [u8; 32],
}

impl AuditEntry {
    fn encode(&self) -> [u8; AUDIT_ENTRY_LEN] {
        let mut out = [0u8; AUDIT_ENTRY_LEN];
        out[..8].copy_from_slice(&self.seq.to_le_bytes());
        out[8..16].copy_from_slice(&self.time.to_le_bytes());
        out[16] = self.kind;
        out[17..33].copy_from_slice(&self.table_tag);
        out[33..65].copy_from_slice(&self.writes_digest);
        out[65..97].copy_from_slice(&self.prev_root);
        out
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != AUDIT_ENTRY_LEN {
            return Err(EngineError::Corrupt("bad audit entry".into()));
        }
        Ok(AuditEntry {
            seq: u64::from_le_bytes(bytes[..8].try_into().unwrap()),
            time: u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
            kind: bytes[16],
            table_tag: bytes[17..33].try_into().unwrap(),
            writes_digest: bytes[33..65].try_into().unwrap(),
            prev_root: bytes[65..97].try_into().unwrap(),
        })
    }

    /// The chain root after this entry.
    fn root(&self) -> [u8; 32] {
        ciphra_crypto::sha256(&self.encode())
    }
}

const KDF_PBKDF2: u8 = 1;
const KDF_ARGON2ID: u8 = 2;
const CANARY_KEY: &[u8] = b"\x00canary";
const CANARY_PLAINTEXT: &[u8] = b"ciphra-canary-v1";
const CATALOG_PREFIX: &[u8] = b"\x00catalog\x00";
const TABLE_TAG_LEN: usize = 16;

/// A single value in a row.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Int(i64),
    Text(String),
}

impl std::fmt::Display for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Value::Null => write!(f, "NULL"),
            Value::Int(n) => write!(f, "{n}"),
            Value::Text(s) => write!(f, "{s}"),
        }
    }
}

#[derive(Debug)]
pub enum EngineError {
    Parse(ParseError),
    Storage(StorageError),
    Crypto(CryptoError),
    /// The passphrase does not match the one this database was created with.
    BadPassphrase,
    /// Schema-level problem: unknown table/column, duplicate table, etc.
    Schema(String),
    /// Constraint violation: duplicate or NULL primary key.
    Constraint(String),
    /// The audit chain failed verification: history was tampered with.
    Audit(String),
    /// Value/type mismatch.
    Type(String),
    Corrupt(String),
    Io(std::io::Error),
}

impl std::fmt::Display for EngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EngineError::Parse(e) => write!(f, "{e}"),
            EngineError::Storage(e) => write!(f, "{e}"),
            EngineError::Crypto(e) => write!(f, "crypto error: {e}"),
            EngineError::BadPassphrase => write!(f, "wrong passphrase for this database"),
            EngineError::Schema(msg) => write!(f, "schema error: {msg}"),
            EngineError::Constraint(msg) => write!(f, "constraint violation: {msg}"),
            EngineError::Audit(msg) => write!(f, "audit chain violation: {msg}"),
            EngineError::Type(msg) => write!(f, "type error: {msg}"),
            EngineError::Corrupt(msg) => write!(f, "corrupt data: {msg}"),
            EngineError::Io(e) => write!(f, "io error: {e}"),
        }
    }
}

impl std::error::Error for EngineError {}

impl From<ParseError> for EngineError {
    fn from(e: ParseError) -> Self {
        EngineError::Parse(e)
    }
}
impl From<StorageError> for EngineError {
    fn from(e: StorageError) -> Self {
        EngineError::Storage(e)
    }
}
impl From<CryptoError> for EngineError {
    fn from(e: CryptoError) -> Self {
        EngineError::Crypto(e)
    }
}
impl From<std::io::Error> for EngineError {
    fn from(e: std::io::Error) -> Self {
        EngineError::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, EngineError>;

/// How the master key is derived from the passphrase. Recorded in
/// `ciphra.keyparams` when a database is created; existing databases
/// always open with the parameters they were created with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdfParams {
    /// PBKDF2-HMAC-SHA256 — legacy, kept for older databases.
    Pbkdf2 { iterations: u32 },
    /// Argon2id — memory-hard, the default.
    Argon2id {
        memory_kib: u32,
        passes: u32,
        lanes: u32,
    },
}

impl KdfParams {
    /// The recommended default for new databases.
    pub fn recommended() -> Self {
        KdfParams::Argon2id {
            memory_kib: ciphra_crypto::DEFAULT_ARGON2_MEMORY_KIB,
            passes: ciphra_crypto::DEFAULT_ARGON2_PASSES,
            lanes: ciphra_crypto::DEFAULT_ARGON2_LANES,
        }
    }

    fn derive(self, passphrase: &str, salt: &[u8]) -> MasterKey {
        match self {
            KdfParams::Pbkdf2 { iterations } => {
                MasterKey::derive_from_passphrase(passphrase, salt, iterations)
            }
            KdfParams::Argon2id {
                memory_kib,
                passes,
                lanes,
            } => MasterKey::derive_argon2id(passphrase, salt, memory_kib, passes, lanes),
        }
    }
}

/// Result of executing one statement.
#[derive(Debug, PartialEq)]
pub enum QueryResult {
    Created(String),
    Dropped(String),
    IndexCreated {
        table: String,
        column: String,
        range: bool,
    },
    IndexDropped {
        table: String,
        column: String,
        range: bool,
    },
    Inserted(usize),
    Updated(usize),
    Deleted(usize),
    Rows {
        columns: Vec<String>,
        rows: Vec<Vec<Value>>,
    },
}

/// An open Ciphra database.
pub struct Engine {
    storage: Storage,
    master: MasterKey,
    dir: PathBuf,
    /// Cached audit head: (next sequence number, current chain root).
    audit_head: (u64, [u8; 32]),
}

impl Engine {
    /// Open (or create) a database in `dir` with the recommended KDF
    /// ([`KdfParams::recommended`], Argon2id).
    ///
    /// On first open a random salt and the KDF parameters are recorded
    /// inside the WAL (they are not secret) and a sealed canary is
    /// stored; subsequent opens verify the canary and fail with
    /// [`EngineError::BadPassphrase`] on a mismatch.
    pub fn open(dir: impl AsRef<Path>, passphrase: &str) -> Result<Self> {
        Self::open_with_kdf(dir, passphrase, KdfParams::recommended())
    }

    /// Open with an explicit PBKDF2 work factor for a database being
    /// created. Kept for compatibility and fast test setups; new code
    /// should prefer [`Engine::open`] or [`Engine::open_with_kdf`].
    pub fn open_with_iterations(
        dir: impl AsRef<Path>,
        passphrase: &str,
        iterations: u32,
    ) -> Result<Self> {
        Self::open_with_kdf(dir, passphrase, KdfParams::Pbkdf2 { iterations })
    }

    /// Like [`Engine::open`], with explicit KDF parameters for a
    /// database being created. An existing database always uses the
    /// parameters recorded at creation time.
    pub fn open_with_kdf(dir: impl AsRef<Path>, passphrase: &str, kdf: KdfParams) -> Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&dir)?;

        // A leftover rotation directory means a rotation was interrupted
        // before its atomic rename — the current WAL is still authoritative.
        let leftover = dir.join(ROTATE_TMP_DIR);
        if leftover.exists() {
            let _ = std::fs::remove_dir_all(&leftover);
        }

        let mut storage = Storage::open(&dir)?;

        // KDF parameters live inside the WAL, so the database is one
        // file and rotation can swap it atomically. Databases created
        // before this migrate from the legacy sidecar file on open.
        let params_path = dir.join(KEYPARAMS_FILE);
        let recorded = storage.get(KEYPARAMS_KEY).map(<[u8]>::to_vec);
        let (kdf, salt) = if let Some(record) = recorded {
            read_keyparams(&record)?
        } else if params_path.exists() {
            let (kdf, salt) = read_keyparams(&std::fs::read(&params_path)?)?;
            storage.put(KEYPARAMS_KEY, &encode_keyparams(kdf, &salt))?;
            (kdf, salt)
        } else {
            let salt = ciphra_crypto::random_salt().to_vec();
            storage.put(KEYPARAMS_KEY, &encode_keyparams(kdf, &salt))?;
            (kdf, salt)
        };

        let master = kdf.derive(passphrase, &salt);

        let canary_key = master.derive_key("canary");
        match storage.get(CANARY_KEY) {
            Some(sealed) => {
                canary_key
                    .open(sealed, CANARY_KEY)
                    .map_err(|_| EngineError::BadPassphrase)?;
            }
            None => {
                let sealed = canary_key.seal(CANARY_PLAINTEXT, CANARY_KEY);
                storage.put(CANARY_KEY, &sealed)?;
            }
        }

        // Load the audit head; a fresh database starts at the genesis
        // root (all zeros) with sequence 0.
        let audit_key = master.derive_key("audit");
        let audit_head = match storage.get(AUDIT_HEAD_KEY) {
            None => (0, [0u8; 32]),
            Some(sealed) => {
                let plain = audit_key.open(sealed, AUDIT_HEAD_KEY)?;
                if plain.len() != 8 + 32 {
                    return Err(EngineError::Corrupt("bad audit head".into()));
                }
                (
                    u64::from_le_bytes(plain[..8].try_into().unwrap()),
                    plain[8..].try_into().unwrap(),
                )
            }
        };

        Ok(Engine {
            storage,
            master,
            dir,
            audit_head,
        })
    }

    /// The current audit head: how many statements the chain covers and
    /// the root that commits to all of them. Safe to publish or store
    /// externally — comparing it later detects history rollback.
    pub fn audit_root(&self) -> (u64, [u8; 32]) {
        self.audit_head
    }

    /// Recompute the audit chain from genesis and check every link.
    ///
    /// Verifies: entries decrypt (authentic, in-place), sequence numbers
    /// are contiguous from 0, each entry extends the previous root, and
    /// the final root matches the stored head. Returns the decoded
    /// entries so callers can also check an externally recorded
    /// `(seq, root)` pair against history.
    pub fn audit_verify(&self) -> Result<Vec<AuditEntry>> {
        let audit_key = self.master.derive_key("audit");
        let mut entries = Vec::new();
        let mut root = [0u8; 32];
        for (key, sealed) in self.storage.scan_prefix(AUDIT_PREFIX) {
            let plain = audit_key
                .open(sealed, key)
                .map_err(|_| EngineError::Audit("audit entry failed authentication".into()))?;
            let entry = AuditEntry::decode(&plain)?;
            if entry.seq != entries.len() as u64 {
                return Err(EngineError::Audit(format!(
                    "audit chain has a gap: expected seq {}, found {}",
                    entries.len(),
                    entry.seq
                )));
            }
            if entry.prev_root != root {
                return Err(EngineError::Audit(format!(
                    "audit entry {} does not extend the previous root",
                    entry.seq
                )));
            }
            root = entry.root();
            entries.push(entry);
        }
        if (entries.len() as u64, root) != self.audit_head {
            return Err(EngineError::Audit(
                "audit head does not match the recomputed chain".into(),
            ));
        }
        Ok(entries)
    }

    /// Re-encrypt the whole database under a new passphrase (and KDF).
    ///
    /// Everything derived from the master key changes: sealed values,
    /// table tags, index value tags — so the entire keyspace is rebuilt
    /// into a scratch WAL, which then replaces the live one with a
    /// single atomic rename. A crash before the rename leaves the old
    /// database untouched (the scratch directory is cleaned up on the
    /// next open); a crash after it leaves the new database complete.
    pub fn rotate_to(&mut self, new_passphrase: &str, kdf: KdfParams) -> Result<()> {
        // Snapshot everything through the current master key.
        let mut snapshot = Vec::new();
        for name in self.tables()? {
            let schema = self.expect_schema(&name)?;
            let table_key = self.table_key(&name);
            let seq = self.load_seq(&name, &table_key)?;
            let mut rows = Vec::new();
            for (key, sealed) in self.storage.scan_prefix(&self.row_prefix(&name)) {
                rows.push((
                    rowid_from_key(key),
                    codec::decode_row(&table_key.open(sealed, key)?)?,
                ));
            }
            snapshot.push((schema, seq, rows));
        }

        // Rebuild into a scratch database under the new master.
        let tmp = self.dir.join(ROTATE_TMP_DIR);
        if tmp.exists() {
            std::fs::remove_dir_all(&tmp)?;
        }
        let mut fresh = Engine::open_with_kdf(&tmp, new_passphrase, kdf)?;
        for (schema, seq, rows) in snapshot {
            // One batch (one fsync) per table.
            let mut writes = Batch::new();
            fresh.add_schema(&mut writes, &schema);
            let table_key = fresh.table_key(&schema.name);
            fresh.add_seq(&mut writes, &schema.name, &table_key, seq);
            let maintained = maintained_columns(&schema);
            for (rowid, row) in &rows {
                let key = fresh.row_key(&schema.name, *rowid);
                let sealed = table_key.seal(&codec::encode_row(row), &key);
                writes.put(&key, &sealed);
                for &col in &maintained {
                    if row[col] != Value::Null {
                        fresh.add_index_entry(
                            &mut writes,
                            &schema.name,
                            &table_key,
                            col,
                            &row[col],
                            *rowid,
                        );
                    }
                }
            }
            for col in range_indexed_columns(&schema) {
                let mut entries: Vec<(Value, u64)> = rows
                    .iter()
                    .filter(|(_, row)| row[col] != Value::Null)
                    .map(|(rowid, row)| (row[col].clone(), *rowid))
                    .collect();
                sort_range_entries(&mut entries);
                fresh.add_range_blob(&mut writes, &schema.name, &table_key, col, &entries);
            }
            fresh.storage.commit(writes)?;
        }

        // Carry the audit chain across, re-sealed under the new audit
        // key (chain roots are over plaintext entries, so they remain
        // valid), then record the rotation itself as the next entry.
        let old_audit = self.master.derive_key("audit");
        let new_audit = fresh.master.derive_key("audit");
        let mut audit_writes = Batch::new();
        for (key, sealed) in self.storage.scan_prefix(AUDIT_PREFIX) {
            let plain = old_audit.open(sealed, key)?;
            audit_writes.put(key, &new_audit.seal(&plain, key));
        }
        fresh.storage.commit(audit_writes)?;
        fresh.audit_head = self.audit_head;
        fresh.commit_with_audit(audit_kind::ROTATE, [0u8; 16], [0u8; 32], Batch::new())?;
        drop(fresh);

        // The atomic switch, then cleanup of everything now stale.
        std::fs::rename(
            tmp.join(ciphra_storage::WAL_FILE),
            self.dir.join(ciphra_storage::WAL_FILE),
        )?;
        if let Ok(dir_handle) = std::fs::File::open(&self.dir) {
            let _ = dir_handle.sync_all();
        }
        let _ = std::fs::remove_dir_all(&tmp);
        let _ = std::fs::remove_file(self.dir.join(KEYPARAMS_FILE));

        // Reopen through the recorded (new) parameters.
        *self = Engine::open(&self.dir, new_passphrase)?;
        Ok(())
    }

    /// Parse and execute a string of `;`-separated SQL statements,
    /// returning one result per statement.
    pub fn execute(&mut self, sql: &str) -> Result<Vec<QueryResult>> {
        let statements = ciphra_sql::parse_statements(sql)?;
        let mut results = Vec::with_capacity(statements.len());
        for statement in statements {
            results.push(self.execute_statement(statement)?);
        }
        Ok(results)
    }

    /// List the names of all tables, alphabetically.
    ///
    /// Names only exist inside sealed catalog records, so this decrypts
    /// each schema rather than reading storage keys.
    pub fn tables(&self) -> Result<Vec<String>> {
        let catalog_key = self.master.derive_key("catalog");
        let mut names = Vec::new();
        for (key, sealed) in self.storage.scan_prefix(CATALOG_PREFIX) {
            let plain = catalog_key.open(sealed, key)?;
            names.push(codec::decode_schema(&plain)?.name);
        }
        names.sort();
        Ok(names)
    }

    /// Fetch the schema of `table`, if it exists.
    pub fn schema(&self, table: &str) -> Result<Option<TableSchema>> {
        let key = self.catalog_key(table);
        match self.storage.get(&key) {
            None => Ok(None),
            Some(sealed) => {
                let plain = self.master.derive_key("catalog").open(sealed, &key)?;
                Ok(Some(codec::decode_schema(&plain)?))
            }
        }
    }

    fn execute_statement(&mut self, statement: Statement) -> Result<QueryResult> {
        match statement {
            Statement::CreateTable { name, columns } => self.create_table(name, columns),
            Statement::DropTable { name } => self.drop_table(&name),
            Statement::CreateIndex {
                table,
                column,
                range: false,
            } => self.create_index(&table, &column),
            Statement::CreateIndex {
                table,
                column,
                range: true,
            } => self.create_range_index(&table, &column),
            Statement::DropIndex {
                table,
                column,
                range: false,
            } => self.drop_index(&table, &column),
            Statement::DropIndex {
                table,
                column,
                range: true,
            } => self.drop_range_index(&table, &column),
            Statement::Insert {
                table,
                columns,
                rows,
            } => self.insert(&table, columns, rows),
            Statement::Select {
                columns,
                table,
                predicate,
                order_by,
                limit,
            } => self.select(&table, columns, predicate, order_by, limit),
            Statement::Update {
                table,
                assignments,
                predicate,
            } => self.update(&table, assignments, predicate),
            Statement::Delete { table, predicate } => self.delete(&table, predicate),
            Statement::Explain(inner) => self.explain(*inner),
        }
    }

    /// Describe how a statement would be executed, without running it.
    fn explain(&self, inner: Statement) -> Result<QueryResult> {
        let (action, table, predicate, order_by, limit) = match &inner {
            Statement::Select {
                table,
                predicate,
                order_by,
                limit,
                ..
            } => (
                "SELECT",
                table,
                predicate,
                order_by.as_ref(),
                limit.as_ref(),
            ),
            Statement::Update {
                table, predicate, ..
            } => ("UPDATE", table, predicate, None, None),
            Statement::Delete { table, predicate } => ("DELETE", table, predicate, None, None),
            _ => {
                return Err(EngineError::Schema(
                    "EXPLAIN supports SELECT, UPDATE and DELETE".into(),
                ));
            }
        };
        let schema = self.expect_schema(table)?;
        let compiled = predicate
            .clone()
            .map(|p| compile_expr(&schema, p))
            .transpose()?;

        let mut steps = Vec::new();
        match compiled.as_ref().and_then(|f| indexed_eq_value(f, &schema)) {
            Some((col, _)) => {
                let kind = if schema.columns[col].primary_key {
                    "primary key"
                } else {
                    "secondary index"
                };
                steps.push(format!(
                    "{action}: {kind} lookup on {}.{}",
                    schema.name, schema.columns[col].name
                ));
            }
            None => match compiled
                .as_ref()
                .and_then(|f| range_indexed_pred(f, &schema))
            {
                Some((col, op, _)) => steps.push(format!(
                    "{action}: sealed range-index scan on {}.{} ({op})",
                    schema.name, schema.columns[col].name
                )),
                None => steps.push(format!("{action}: full scan of {}", schema.name)),
            },
        }
        if let Some(predicate) = predicate {
            steps.push(format!("filter: {predicate}"));
        }
        if let Some(ob) = order_by {
            steps.push(format!(
                "sort by {}{}",
                ob.column,
                if ob.descending { " DESC" } else { "" }
            ));
        }
        if let Some(l) = limit {
            steps.push(format!("limit {} offset {}", l.count, l.offset));
        }
        Ok(QueryResult::Rows {
            columns: vec!["plan".into()],
            rows: steps.into_iter().map(|s| vec![Value::Text(s)]).collect(),
        })
    }

    fn create_table(&mut self, name: String, columns: Vec<ColumnDef>) -> Result<QueryResult> {
        if self.schema(&name)?.is_some() {
            return Err(EngineError::Schema(format!(
                "table {name:?} already exists"
            )));
        }
        let mut seen = std::collections::HashSet::new();
        for col in &columns {
            if !seen.insert(col.name.as_str()) {
                return Err(EngineError::Schema(format!(
                    "duplicate column {:?} in table {name:?}",
                    col.name
                )));
            }
        }
        if columns.iter().filter(|c| c.primary_key).count() > 1 {
            return Err(EngineError::Schema(format!(
                "table {name:?} declares more than one PRIMARY KEY column"
            )));
        }
        let schema = TableSchema {
            name: name.clone(),
            columns,
        };
        let mut batch = Batch::new();
        self.add_schema(&mut batch, &schema);
        let tag = self.table_tag(&name);
        self.commit_audited(audit_kind::CREATE_TABLE, tag, batch)?;
        Ok(QueryResult::Created(name))
    }

    fn create_index(&mut self, table: &str, column: &str) -> Result<QueryResult> {
        let mut schema = self.expect_schema(table)?;
        let col = schema.column_index(column).ok_or_else(|| {
            EngineError::Schema(format!("unknown column {column:?} in table {table:?}"))
        })?;
        if schema.columns[col].primary_key {
            return Err(EngineError::Schema(format!(
                "column {column:?} is already indexed by PRIMARY KEY"
            )));
        }
        if schema.columns[col].indexed {
            return Err(EngineError::Schema(format!(
                "column {column:?} of table {table:?} is already indexed"
            )));
        }
        // Backfill entries for existing rows and flip the schema flag in
        // one committed batch: the index either exists fully or not at all.
        let table_key = self.table_key(table);
        let mut batch = Batch::new();
        for (key, sealed) in self.storage.scan_prefix(&self.row_prefix(table)) {
            let row = codec::decode_row(&table_key.open(sealed, key)?)?;
            if row[col] != Value::Null {
                self.add_index_entry(
                    &mut batch,
                    table,
                    &table_key,
                    col,
                    &row[col],
                    rowid_from_key(key),
                );
            }
        }
        schema.columns[col].indexed = true;
        self.add_schema(&mut batch, &schema);
        self.commit_audited(audit_kind::CREATE_INDEX, self.table_tag(table), batch)?;
        Ok(QueryResult::IndexCreated {
            table: table.to_string(),
            column: column.to_string(),
            range: false,
        })
    }

    fn drop_index(&mut self, table: &str, column: &str) -> Result<QueryResult> {
        let mut schema = self.expect_schema(table)?;
        let col = schema.column_index(column).ok_or_else(|| {
            EngineError::Schema(format!("unknown column {column:?} in table {table:?}"))
        })?;
        if !schema.columns[col].indexed {
            return Err(EngineError::Schema(format!(
                "column {column:?} of table {table:?} is not indexed \
                 (a PRIMARY KEY index cannot be dropped)"
            )));
        }
        let mut batch = Batch::new();
        for (key, _) in self
            .storage
            .scan_prefix(&self.index_column_prefix(table, col))
        {
            batch.delete(key);
        }
        schema.columns[col].indexed = false;
        self.add_schema(&mut batch, &schema);
        self.commit_audited(audit_kind::DROP_INDEX, self.table_tag(table), batch)?;
        Ok(QueryResult::IndexDropped {
            table: table.to_string(),
            column: column.to_string(),
            range: false,
        })
    }

    fn create_range_index(&mut self, table: &str, column: &str) -> Result<QueryResult> {
        let mut schema = self.expect_schema(table)?;
        let col = schema.column_index(column).ok_or_else(|| {
            EngineError::Schema(format!("unknown column {column:?} in table {table:?}"))
        })?;
        if schema.columns[col].range_indexed {
            return Err(EngineError::Schema(format!(
                "column {column:?} of table {table:?} already has a range index"
            )));
        }
        // Build the sorted blob from existing rows and persist it with
        // the schema flag in one committed batch.
        let table_key = self.table_key(table);
        let mut entries: Vec<(Value, u64)> = Vec::new();
        for (key, sealed) in self.storage.scan_prefix(&self.row_prefix(table)) {
            let row = codec::decode_row(&table_key.open(sealed, key)?)?;
            if row[col] != Value::Null {
                entries.push((row[col].clone(), rowid_from_key(key)));
            }
        }
        sort_range_entries(&mut entries);
        let mut batch = Batch::new();
        self.add_range_blob(&mut batch, table, &table_key, col, &entries);
        schema.columns[col].range_indexed = true;
        self.add_schema(&mut batch, &schema);
        self.commit_audited(audit_kind::CREATE_INDEX, self.table_tag(table), batch)?;
        Ok(QueryResult::IndexCreated {
            table: table.to_string(),
            column: column.to_string(),
            range: true,
        })
    }

    fn drop_range_index(&mut self, table: &str, column: &str) -> Result<QueryResult> {
        let mut schema = self.expect_schema(table)?;
        let col = schema.column_index(column).ok_or_else(|| {
            EngineError::Schema(format!("unknown column {column:?} in table {table:?}"))
        })?;
        if !schema.columns[col].range_indexed {
            return Err(EngineError::Schema(format!(
                "column {column:?} of table {table:?} has no range index"
            )));
        }
        let mut batch = Batch::new();
        batch.delete(&self.range_index_key(table, col));
        schema.columns[col].range_indexed = false;
        self.add_schema(&mut batch, &schema);
        self.commit_audited(audit_kind::DROP_INDEX, self.table_tag(table), batch)?;
        Ok(QueryResult::IndexDropped {
            table: table.to_string(),
            column: column.to_string(),
            range: true,
        })
    }

    fn drop_table(&mut self, name: &str) -> Result<QueryResult> {
        self.expect_schema(name)?;
        let mut batch = Batch::new();
        for prefix in [
            self.row_prefix(name),
            self.index_prefix(name),
            self.range_prefix(name),
        ] {
            for (key, _) in self.storage.scan_prefix(&prefix) {
                batch.delete(key);
            }
        }
        batch.delete(&self.seq_key(name));
        batch.delete(&self.catalog_key(name));
        self.commit_audited(audit_kind::DROP_TABLE, self.table_tag(name), batch)?;
        Ok(QueryResult::Dropped(name.to_string()))
    }

    fn insert(
        &mut self,
        table: &str,
        columns: Option<Vec<String>>,
        rows: Vec<Vec<Literal>>,
    ) -> Result<QueryResult> {
        let schema = self.expect_schema(table)?;

        // Map the provided column order onto schema positions.
        let positions: Vec<usize> = match &columns {
            None => (0..schema.columns.len()).collect(),
            Some(names) => names
                .iter()
                .map(|n| {
                    schema.column_index(n).ok_or_else(|| {
                        EngineError::Schema(format!("unknown column {n:?} in table {table:?}"))
                    })
                })
                .collect::<Result<_>>()?,
        };

        let table_key = self.table_key(table);
        let pk = pk_column(&schema);
        let maintained = maintained_columns(&schema);

        // Validate the whole batch — types, arity and the primary key —
        // before writing anything, so a rejected INSERT statement never
        // leaves some of its rows behind.
        let mut batch: Vec<Vec<Value>> = Vec::with_capacity(rows.len());
        let mut batch_pk_prefixes = std::collections::HashSet::new();
        for literals in rows {
            if literals.len() != positions.len() {
                return Err(EngineError::Type(format!(
                    "expected {} values, got {}",
                    positions.len(),
                    literals.len()
                )));
            }
            let mut row = vec![Value::Null; schema.columns.len()];
            for (pos, literal) in positions.iter().zip(literals) {
                row[*pos] = coerce(literal, &schema.columns[*pos])?;
            }
            if let Some(pk_idx) = pk {
                let value = &row[pk_idx];
                if *value == Value::Null {
                    return Err(EngineError::Constraint(format!(
                        "primary key {:?} cannot be NULL",
                        schema.columns[pk_idx].name
                    )));
                }
                let duplicate = !batch_pk_prefixes
                    .insert(self.index_value_prefix(table, pk_idx, value))
                    || !self
                        .index_rowids(table, &table_key, pk_idx, value)?
                        .is_empty();
                if duplicate {
                    return Err(EngineError::Constraint(format!(
                        "duplicate value for primary key {:?}",
                        schema.columns[pk_idx].name
                    )));
                }
            }
            batch.push(row);
        }

        // One WAL record and one fsync for the whole statement: rows,
        // index entries and the sequence land atomically together.
        let mut next_id = self.load_seq(table, &table_key)?;
        let count = batch.len();
        let inserted_rows = batch;
        let mut writes = Batch::new();
        for row in &inserted_rows {
            let key = self.row_key(table, next_id);
            let sealed = table_key.seal(&codec::encode_row(row), &key);
            writes.put(&key, &sealed);
            for &col in &maintained {
                if row[col] != Value::Null {
                    self.add_index_entry(&mut writes, table, &table_key, col, &row[col], next_id);
                }
            }
            next_id += 1;
        }
        self.add_seq(&mut writes, table, &table_key, next_id);
        for col in range_indexed_columns(&schema) {
            let mut entries = self.load_range_index(table, &table_key, col)?;
            let first_id = next_id - count as u64;
            for (offset, row) in inserted_rows.iter().enumerate() {
                if row[col] != Value::Null {
                    entries.push((row[col].clone(), first_id + offset as u64));
                }
            }
            sort_range_entries(&mut entries);
            self.add_range_blob(&mut writes, table, &table_key, col, &entries);
        }
        self.commit_audited(audit_kind::INSERT, self.table_tag(table), writes)?;
        Ok(QueryResult::Inserted(count))
    }

    fn select(
        &mut self,
        table: &str,
        projection: Projection,
        predicate: Option<Expr>,
        order_by: Option<OrderBy>,
        limit: Option<Limit>,
    ) -> Result<QueryResult> {
        let schema = self.expect_schema(table)?;
        let filter = predicate.map(|p| compile_expr(&schema, p)).transpose()?;

        let output: Vec<usize> = match &projection {
            Projection::All => (0..schema.columns.len()).collect(),
            Projection::Columns(names) => names
                .iter()
                .map(|n| {
                    schema.column_index(n).ok_or_else(|| {
                        EngineError::Schema(format!("unknown column {n:?} in table {table:?}"))
                    })
                })
                .collect::<Result<_>>()?,
        };
        let column_names: Vec<String> = output
            .iter()
            .map(|&i| schema.columns[i].name.clone())
            .collect();

        let sort_index = order_by
            .as_ref()
            .map(|ob| {
                schema.column_index(&ob.column).ok_or_else(|| {
                    EngineError::Schema(format!(
                        "unknown column {:?} in table {table:?}",
                        ob.column
                    ))
                })
            })
            .transpose()?;

        let table_key = self.table_key(table);
        let mut rows = Vec::new();
        for (_, row) in self.candidate_rows(table, &schema, filter.as_ref(), &table_key)? {
            if let Some(filter) = &filter
                && !filter.matches(&row)?
            {
                continue;
            }
            rows.push(row);
        }

        // Sort whole rows first so ORDER BY works on unprojected columns.
        if let (Some(index), Some(ob)) = (sort_index, &order_by) {
            rows.sort_by(|a, b| {
                let ord = compare_values(&a[index], &b[index]);
                if ob.descending { ord.reverse() } else { ord }
            });
        }

        let rows: Vec<Vec<Value>> = match limit {
            Some(Limit { count, offset }) => rows
                .into_iter()
                .skip(offset as usize)
                .take(count as usize)
                .map(|row| output.iter().map(|&i| row[i].clone()).collect())
                .collect(),
            None => rows
                .into_iter()
                .map(|row| output.iter().map(|&i| row[i].clone()).collect())
                .collect(),
        };
        Ok(QueryResult::Rows {
            columns: column_names,
            rows,
        })
    }

    fn update(
        &mut self,
        table: &str,
        assignments: Vec<Assignment>,
        predicate: Option<Expr>,
    ) -> Result<QueryResult> {
        let schema = self.expect_schema(table)?;
        let filter = predicate.map(|p| compile_expr(&schema, p)).transpose()?;

        // Resolve `SET` targets to (index, typed value) against the schema.
        let mut resolved: Vec<(usize, Value)> = Vec::with_capacity(assignments.len());
        let mut seen = std::collections::HashSet::new();
        for assignment in assignments {
            let index = schema.column_index(&assignment.column).ok_or_else(|| {
                EngineError::Schema(format!(
                    "unknown column {:?} in table {table:?}",
                    assignment.column
                ))
            })?;
            if !seen.insert(index) {
                return Err(EngineError::Schema(format!(
                    "column {:?} assigned twice",
                    assignment.column
                )));
            }
            resolved.push((index, coerce(assignment.value, &schema.columns[index])?));
        }

        let table_key = self.table_key(table);
        let pk = pk_column(&schema);
        // The value a PK column is being set to, if any. Assignments are
        // literals, so every matched row would receive the same value.
        let new_pk: Option<&Value> = pk.and_then(|pk_idx| {
            resolved
                .iter()
                .find(|(index, _)| *index == pk_idx)
                .map(|(_, value)| value)
        });

        let mut changed: Vec<(Vec<u8>, Vec<Value>, Vec<Value>)> = Vec::new();
        for (key, row) in self.candidate_rows(table, &schema, filter.as_ref(), &table_key)? {
            let matches = match &filter {
                Some(filter) => filter.matches(&row)?,
                None => true,
            };
            if matches {
                let mut new_row = row.clone();
                for (index, value) in &resolved {
                    new_row[*index] = value.clone();
                }
                changed.push((key, row, new_row));
            }
        }

        // Validate a PK reassignment fully before writing anything.
        if let (Some(pk_idx), Some(new_pk)) = (pk, new_pk) {
            if *new_pk == Value::Null {
                return Err(EngineError::Constraint(format!(
                    "primary key {:?} cannot be NULL",
                    schema.columns[pk_idx].name
                )));
            }
            if changed.len() > 1 {
                return Err(EngineError::Constraint(format!(
                    "UPDATE would assign the same primary key to {} rows",
                    changed.len()
                )));
            }
            if let Some((key, _, _)) = changed.first() {
                let holders = self.index_rowids(table, &table_key, pk_idx, new_pk)?;
                if holders.iter().any(|&id| id != rowid_from_key(key)) {
                    return Err(EngineError::Constraint(format!(
                        "duplicate value for primary key {:?}",
                        schema.columns[pk_idx].name
                    )));
                }
            }
        }

        let maintained = maintained_columns(&schema);
        let count = changed.len();
        let mut writes = Batch::new();
        for (key, old_row, new_row) in &changed {
            let rowid = rowid_from_key(key);
            for &col in &maintained {
                if old_row[col] != new_row[col] {
                    if old_row[col] != Value::Null {
                        self.remove_index_entry(&mut writes, table, col, &old_row[col], rowid);
                    }
                    if new_row[col] != Value::Null {
                        self.add_index_entry(
                            &mut writes,
                            table,
                            &table_key,
                            col,
                            &new_row[col],
                            rowid,
                        );
                    }
                }
            }
            let sealed = table_key.seal(&codec::encode_row(new_row), key);
            writes.put(key, &sealed);
        }
        for col in range_indexed_columns(&schema) {
            if changed.iter().all(|(_, o, n)| o[col] == n[col]) {
                continue;
            }
            let mut entries = self.load_range_index(table, &table_key, col)?;
            for (key, old_row, new_row) in &changed {
                if old_row[col] == new_row[col] {
                    continue;
                }
                let rowid = rowid_from_key(key);
                entries.retain(|(v, id)| !(*id == rowid && *v == old_row[col]));
                if new_row[col] != Value::Null {
                    entries.push((new_row[col].clone(), rowid));
                }
            }
            sort_range_entries(&mut entries);
            self.add_range_blob(&mut writes, table, &table_key, col, &entries);
        }
        self.commit_audited(audit_kind::UPDATE, self.table_tag(table), writes)?;
        Ok(QueryResult::Updated(count))
    }

    fn delete(&mut self, table: &str, predicate: Option<Expr>) -> Result<QueryResult> {
        let schema = self.expect_schema(table)?;
        let filter = predicate.map(|p| compile_expr(&schema, p)).transpose()?;
        let table_key = self.table_key(table);

        let maintained = maintained_columns(&schema);
        let mut doomed: Vec<(Vec<u8>, Vec<Value>)> = Vec::new();
        for (key, row) in self.candidate_rows(table, &schema, filter.as_ref(), &table_key)? {
            let matches = match &filter {
                Some(filter) => filter.matches(&row)?,
                None => true,
            };
            if matches {
                doomed.push((key, row));
            }
        }
        let count = doomed.len();
        let mut writes = Batch::new();
        for (key, row) in &doomed {
            let rowid = rowid_from_key(key);
            for &col in &maintained {
                if row[col] != Value::Null {
                    self.remove_index_entry(&mut writes, table, col, &row[col], rowid);
                }
            }
            writes.delete(key);
        }
        for col in range_indexed_columns(&schema) {
            if doomed.iter().all(|(_, row)| row[col] == Value::Null) {
                continue;
            }
            let mut entries = self.load_range_index(table, &table_key, col)?;
            for (key, row) in &doomed {
                let rowid = rowid_from_key(key);
                entries.retain(|(v, id)| !(*id == rowid && *v == row[col]));
            }
            self.add_range_blob(&mut writes, table, &table_key, col, &entries);
        }
        self.commit_audited(audit_kind::DELETE, self.table_tag(table), writes)?;
        Ok(QueryResult::Deleted(count))
    }

    // -- helpers -------------------------------------------------------

    fn expect_schema(&self, table: &str) -> Result<TableSchema> {
        self.schema(table)?
            .ok_or_else(|| EngineError::Schema(format!("no such table: {table:?}")))
    }

    fn table_key(&self, table: &str) -> CipherKey {
        self.master.derive_key(&format!("table:{table}"))
    }

    /// Opaque identifier for a table inside storage keys. Deterministic
    /// (lookups must be repeatable) but reveals nothing about the name.
    fn table_tag(&self, table: &str) -> [u8; TABLE_TAG_LEN] {
        let full = self.master.keyed_tag("table-name", table.as_bytes());
        full[..TABLE_TAG_LEN].try_into().unwrap()
    }

    fn catalog_key(&self, table: &str) -> Vec<u8> {
        let mut key = CATALOG_PREFIX.to_vec();
        key.extend_from_slice(&self.table_tag(table));
        key
    }

    fn seq_key(&self, table: &str) -> Vec<u8> {
        let mut key = b"\x00seq\x00".to_vec();
        key.extend_from_slice(&self.table_tag(table));
        key
    }

    fn row_prefix(&self, table: &str) -> Vec<u8> {
        let mut prefix = b"r\x00".to_vec();
        prefix.extend_from_slice(&self.table_tag(table));
        prefix
    }

    fn index_prefix(&self, table: &str) -> Vec<u8> {
        let mut prefix = b"x\x00".to_vec();
        prefix.extend_from_slice(&self.table_tag(table));
        prefix
    }

    /// Prefix of all index entries for one column of a table.
    fn index_column_prefix(&self, table: &str, col: usize) -> Vec<u8> {
        let mut prefix = self.index_prefix(table);
        prefix.extend_from_slice(&(col as u16).to_be_bytes());
        prefix
    }

    /// Prefix of the index entries for one column *value*: the value
    /// never appears in the key, only its keyed tag (equality leakage
    /// only). The row id is appended to form the full entry key, so a
    /// non-unique column simply has several entries under this prefix.
    fn index_value_prefix(&self, table: &str, col: usize, value: &Value) -> Vec<u8> {
        let encoded = codec::encode_row(std::slice::from_ref(value));
        let value_tag = self
            .master
            .keyed_tag(&format!("index:{table}:{col}"), &encoded);
        let mut prefix = self.index_column_prefix(table, col);
        prefix.extend_from_slice(&value_tag[..TABLE_TAG_LEN]);
        prefix
    }

    /// Row ids holding `value` in column `col`, via the equality index.
    /// Every entry's sealed marker is verified, so tampered or misplaced
    /// entries fail instead of steering queries to wrong rows.
    fn index_rowids(
        &self,
        table: &str,
        table_key: &CipherKey,
        col: usize,
        value: &Value,
    ) -> Result<Vec<u64>> {
        let prefix = self.index_value_prefix(table, col, value);
        let mut rowids = Vec::new();
        for (key, sealed) in self.storage.scan_prefix(&prefix) {
            table_key.open(sealed, key)?;
            rowids.push(rowid_from_key(key));
        }
        Ok(rowids)
    }

    fn range_prefix(&self, table: &str) -> Vec<u8> {
        let mut prefix = RANGE_PREFIX.to_vec();
        prefix.extend_from_slice(&self.table_tag(table));
        prefix
    }

    /// Key of the sealed range-index blob for one column.
    fn range_index_key(&self, table: &str, col: usize) -> Vec<u8> {
        let mut key = self.range_prefix(table);
        key.extend_from_slice(&(col as u16).to_be_bytes());
        key
    }

    /// Decrypt and decode a column's range blob (empty if absent).
    fn load_range_index(
        &self,
        table: &str,
        table_key: &CipherKey,
        col: usize,
    ) -> Result<Vec<(Value, u64)>> {
        let key = self.range_index_key(table, col);
        match self.storage.get(&key) {
            None => Ok(Vec::new()),
            Some(sealed) => codec::decode_range_blob(&table_key.open(sealed, &key)?),
        }
    }

    /// Seal a sorted range blob into the batch.
    fn add_range_blob(
        &self,
        batch: &mut Batch,
        table: &str,
        table_key: &CipherKey,
        col: usize,
        entries: &[(Value, u64)],
    ) {
        let key = self.range_index_key(table, col);
        let sealed = table_key.seal(&codec::encode_range_blob(entries), &key);
        batch.put(&key, &sealed);
    }

    fn add_index_entry(
        &self,
        batch: &mut Batch,
        table: &str,
        table_key: &CipherKey,
        col: usize,
        value: &Value,
        rowid: u64,
    ) {
        let mut key = self.index_value_prefix(table, col, value);
        key.extend_from_slice(&rowid.to_be_bytes());
        let sealed = table_key.seal(b"", &key);
        batch.put(&key, &sealed);
    }

    fn remove_index_entry(
        &self,
        batch: &mut Batch,
        table: &str,
        col: usize,
        value: &Value,
        rowid: u64,
    ) {
        let mut key = self.index_value_prefix(table, col, value);
        key.extend_from_slice(&rowid.to_be_bytes());
        batch.delete(&key);
    }

    /// Fetch the rows a filtered operation must consider. When the
    /// predicate pins an indexed column to a value (an `col = literal`
    /// conjunct on the primary key or a `CREATE INDEX` column), this is
    /// an index lookup instead of a full scan. Callers still apply the
    /// complete predicate to what is returned.
    fn candidate_rows(
        &self,
        table: &str,
        schema: &TableSchema,
        filter: Option<&CompiledExpr>,
        table_key: &CipherKey,
    ) -> Result<Vec<(Vec<u8>, Vec<Value>)>> {
        if let Some(filter) = filter
            && let Some((col, value)) = indexed_eq_value(filter, schema)
        {
            let mut rows = Vec::new();
            for rowid in self.index_rowids(table, table_key, col, value)? {
                let key = self.row_key(table, rowid);
                match self.storage.get(&key) {
                    // A dangling index entry (crash between the two
                    // writes) reads as absent.
                    None => continue,
                    Some(sealed) => {
                        let row = codec::decode_row(&table_key.open(sealed, &key)?)?;
                        rows.push((key, row));
                    }
                }
            }
            return Ok(rows);
        }
        if let Some(filter) = filter
            && let Some((col, op, value)) = range_indexed_pred(filter, schema)
        {
            // One blob decrypt, then only matching rows are fetched.
            let mut rows = Vec::new();
            for (entry_value, rowid) in self.load_range_index(table, table_key, col)? {
                let ordering = compare_values(&entry_value, value);
                let hit = match op {
                    CmpOp::Eq => ordering.is_eq(),
                    CmpOp::Lt => ordering.is_lt(),
                    CmpOp::Le => ordering.is_le(),
                    CmpOp::Gt => ordering.is_gt(),
                    CmpOp::Ge => ordering.is_ge(),
                    CmpOp::Ne => unreachable!("Ne never selects a range path"),
                };
                if !hit {
                    continue;
                }
                let key = self.row_key(table, rowid);
                if let Some(sealed) = self.storage.get(&key) {
                    let row = codec::decode_row(&table_key.open(sealed, &key)?)?;
                    rows.push((key, row));
                }
            }
            return Ok(rows);
        }
        let mut rows = Vec::new();
        for (key, sealed) in self.storage.scan_prefix(&self.row_prefix(table)) {
            rows.push((
                key.to_vec(),
                codec::decode_row(&table_key.open(sealed, key)?)?,
            ));
        }
        Ok(rows)
    }

    /// Seal a schema into the batch's catalog entry.
    fn add_schema(&self, batch: &mut Batch, schema: &TableSchema) {
        let key = self.catalog_key(&schema.name);
        let sealed = self
            .master
            .derive_key("catalog")
            .seal(&codec::encode_schema(schema), &key);
        batch.put(&key, &sealed);
    }

    /// Big-endian row id so lexicographic key order equals insertion order.
    fn row_key(&self, table: &str, id: u64) -> Vec<u8> {
        let mut key = self.row_prefix(table);
        key.extend_from_slice(&id.to_be_bytes());
        key
    }

    fn load_seq(&self, table: &str, table_key: &CipherKey) -> Result<u64> {
        let key = self.seq_key(table);
        match self.storage.get(&key) {
            None => Ok(0),
            Some(sealed) => {
                let plain = table_key.open(sealed, &key)?;
                let bytes: [u8; 8] = plain
                    .as_slice()
                    .try_into()
                    .map_err(|_| EngineError::Corrupt(format!("bad sequence for {table:?}")))?;
                Ok(u64::from_le_bytes(bytes))
            }
        }
    }

    fn add_seq(&self, batch: &mut Batch, table: &str, table_key: &CipherKey, next: u64) {
        let key = self.seq_key(table);
        let sealed = table_key.seal(&next.to_le_bytes(), &key);
        batch.put(&key, &sealed);
    }

    /// Commit a statement's writes together with its audit-chain entry —
    /// one atomic batch, so history and data can never disagree. Empty
    /// batches (statements that changed nothing) do not advance the chain.
    fn commit_audited(&mut self, kind: u8, table_tag: [u8; 16], batch: Batch) -> Result<()> {
        if batch.is_empty() {
            return Ok(());
        }
        let digest = digest_batch(&batch);
        self.commit_with_audit(kind, table_tag, digest, batch)
    }

    /// Append an audit entry for `kind` to `batch` and commit everything.
    fn commit_with_audit(
        &mut self,
        kind: u8,
        table_tag: [u8; 16],
        writes_digest: [u8; 32],
        mut batch: Batch,
    ) -> Result<()> {
        let (seq, prev_root) = self.audit_head;
        let entry = AuditEntry {
            seq,
            time: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            kind,
            table_tag,
            writes_digest,
            prev_root,
        };
        let root = entry.root();
        let audit_key = self.master.derive_key("audit");

        let mut entry_key = AUDIT_PREFIX.to_vec();
        entry_key.extend_from_slice(&seq.to_be_bytes());
        batch.put(&entry_key, &audit_key.seal(&entry.encode(), &entry_key));

        let mut head = seq.wrapping_add(1).to_le_bytes().to_vec();
        head.extend_from_slice(&root);
        batch.put(AUDIT_HEAD_KEY, &audit_key.seal(&head, AUDIT_HEAD_KEY));

        self.storage.commit(batch)?;
        self.audit_head = (seq + 1, root);
        Ok(())
    }
}

/// SHA-256 over a batch's operations: `op | key_len | key | value_len |
/// value` per entry, all lengths LE. Binds an audit entry to the exact
/// sealed bytes the statement committed.
fn digest_batch(batch: &Batch) -> [u8; 32] {
    let mut hasher = ciphra_crypto::Sha256::new();
    for (is_delete, key, value) in batch.entries() {
        hasher.update(&[u8::from(is_delete)]);
        hasher.update(&(key.len() as u64).to_le_bytes());
        hasher.update(key);
        hasher.update(&(value.len() as u64).to_le_bytes());
        hasher.update(value);
    }
    hasher.finalize()
}

/// Index of the PRIMARY KEY column, if the table declares one.
fn pk_column(schema: &TableSchema) -> Option<usize> {
    schema.columns.iter().position(|c| c.primary_key)
}

/// The row id encoded in the trailing 8 bytes of a row key.
fn rowid_from_key(key: &[u8]) -> u64 {
    u64::from_be_bytes(key[key.len() - 8..].try_into().unwrap())
}

/// Columns carrying a sealed range index.
fn range_indexed_columns(schema: &TableSchema) -> Vec<usize> {
    schema
        .columns
        .iter()
        .enumerate()
        .filter(|(_, c)| c.range_indexed)
        .map(|(i, _)| i)
        .collect()
}

/// Sort range-blob entries by value (then row id, for determinism).
fn sort_range_entries(entries: &mut [(Value, u64)]) {
    entries.sort_by(|a, b| compare_values(&a.0, &b.0).then(a.1.cmp(&b.1)));
}

/// If the expression can only be true where `col` satisfies one
/// comparison, return it. AND-conjuncts qualify; OR/NOT do not.
fn range_pred_value(expr: &CompiledExpr, col: usize) -> Option<(CmpOp, &Value)> {
    match expr {
        CompiledExpr::Compare {
            column_index,
            op,
            value,
            ..
        } if *column_index == col
            && *value != Value::Null
            && matches!(
                op,
                CmpOp::Lt | CmpOp::Le | CmpOp::Gt | CmpOp::Ge | CmpOp::Eq
            ) =>
        {
            Some((*op, value))
        }
        CompiledExpr::And(a, b) => range_pred_value(a, col).or_else(|| range_pred_value(b, col)),
        _ => None,
    }
}

/// Pick a range-index access path: the first range-indexed column that
/// the predicate pins with a comparison.
fn range_indexed_pred<'a>(
    expr: &'a CompiledExpr,
    schema: &TableSchema,
) -> Option<(usize, CmpOp, &'a Value)> {
    schema
        .columns
        .iter()
        .enumerate()
        .filter(|(_, c)| c.range_indexed)
        .find_map(|(col, _)| range_pred_value(expr, col).map(|(op, v)| (col, op, v)))
}

/// Columns whose index entries must be maintained on every mutation:
/// the primary key plus all `CREATE INDEX` columns.
fn maintained_columns(schema: &TableSchema) -> Vec<usize> {
    schema
        .columns
        .iter()
        .enumerate()
        .filter(|(_, c)| c.primary_key || c.indexed)
        .map(|(i, _)| i)
        .collect()
}

/// If the expression can only be true when column `col` equals one
/// specific value, return that value. Only `col = literal` itself and
/// AND-conjuncts containing it qualify; anything under OR/NOT does not
/// pin the column.
fn eq_value_for(expr: &CompiledExpr, col: usize) -> Option<&Value> {
    match expr {
        CompiledExpr::Compare {
            column_index,
            op: CmpOp::Eq,
            value,
            ..
        } if *column_index == col && *value != Value::Null => Some(value),
        CompiledExpr::And(a, b) => eq_value_for(a, col).or_else(|| eq_value_for(b, col)),
        _ => None,
    }
}

/// Pick the best index for a predicate: the primary key if it is pinned
/// (at most one row), otherwise any pinned `CREATE INDEX` column.
fn indexed_eq_value<'a>(
    expr: &'a CompiledExpr,
    schema: &TableSchema,
) -> Option<(usize, &'a Value)> {
    if let Some(pk) = pk_column(schema)
        && let Some(value) = eq_value_for(expr, pk)
    {
        return Some((pk, value));
    }
    schema
        .columns
        .iter()
        .enumerate()
        .filter(|(_, c)| c.indexed)
        .find_map(|(col, _)| eq_value_for(expr, col).map(|value| (col, value)))
}

/// Serialize KDF parameters and salt into the v2 keyparams format.
fn encode_keyparams(kdf: KdfParams, salt: &[u8]) -> Vec<u8> {
    let mut out = KEYPARAMS_MAGIC_V2.to_vec();
    match kdf {
        KdfParams::Pbkdf2 { iterations } => {
            out.push(KDF_PBKDF2);
            out.extend_from_slice(&iterations.to_le_bytes());
        }
        KdfParams::Argon2id {
            memory_kib,
            passes,
            lanes,
        } => {
            out.push(KDF_ARGON2ID);
            out.extend_from_slice(&memory_kib.to_le_bytes());
            out.extend_from_slice(&passes.to_le_bytes());
            out.extend_from_slice(&lanes.to_le_bytes());
        }
    }
    out.extend_from_slice(salt);
    out
}

/// Parse a keyparams file, v1 (PBKDF2 implied) or v2 (KDF recorded).
fn read_keyparams(contents: &[u8]) -> Result<(KdfParams, Vec<u8>)> {
    let corrupt = || EngineError::Corrupt(format!("bad {KEYPARAMS_FILE} file"));
    if contents.len() < 8 {
        return Err(corrupt());
    }
    let (magic, rest) = contents.split_at(8);
    if magic == KEYPARAMS_MAGIC_V1 {
        if rest.len() < 4 + ciphra_crypto::SALT_LEN {
            return Err(corrupt());
        }
        let iterations = u32::from_le_bytes(rest[..4].try_into().unwrap());
        if iterations == 0 {
            return Err(corrupt());
        }
        return Ok((KdfParams::Pbkdf2 { iterations }, rest[4..].to_vec()));
    }
    if magic != KEYPARAMS_MAGIC_V2 || rest.is_empty() {
        return Err(corrupt());
    }
    let (kdf_id, rest) = rest.split_at(1);
    match kdf_id[0] {
        KDF_PBKDF2 => {
            if rest.len() < 4 + ciphra_crypto::SALT_LEN {
                return Err(corrupt());
            }
            let iterations = u32::from_le_bytes(rest[..4].try_into().unwrap());
            if iterations == 0 {
                return Err(corrupt());
            }
            Ok((KdfParams::Pbkdf2 { iterations }, rest[4..].to_vec()))
        }
        KDF_ARGON2ID => {
            if rest.len() < 12 + ciphra_crypto::SALT_LEN {
                return Err(corrupt());
            }
            let memory_kib = u32::from_le_bytes(rest[..4].try_into().unwrap());
            let passes = u32::from_le_bytes(rest[4..8].try_into().unwrap());
            let lanes = u32::from_le_bytes(rest[8..12].try_into().unwrap());
            if passes == 0 || lanes == 0 {
                return Err(corrupt());
            }
            Ok((
                KdfParams::Argon2id {
                    memory_kib,
                    passes,
                    lanes,
                },
                rest[12..].to_vec(),
            ))
        }
        _ => Err(corrupt()),
    }
}

/// Convert a literal to a schema-typed value, or fail with a type error.
fn coerce(literal: Literal, column: &ColumnDef) -> Result<Value> {
    match (literal, column.ty) {
        (Literal::Null, _) => Ok(Value::Null),
        (Literal::Int(n), DataType::Int) => Ok(Value::Int(n)),
        (Literal::Text(s), DataType::Text) => Ok(Value::Text(s)),
        (Literal::Int(_), DataType::Text) => Err(EngineError::Type(format!(
            "column {:?} is TEXT, got an integer",
            column.name
        ))),
        (Literal::Text(_), DataType::Int) => Err(EngineError::Type(format!(
            "column {:?} is INT, got a string",
            column.name
        ))),
    }
}

/// Total order for sorting within one (typed) column: NULLs sort first.
fn compare_values(a: &Value, b: &Value) -> Ordering {
    match (a, b) {
        (Value::Null, Value::Null) => Ordering::Equal,
        (Value::Null, _) => Ordering::Less,
        (_, Value::Null) => Ordering::Greater,
        (Value::Int(x), Value::Int(y)) => x.cmp(y),
        (Value::Text(x), Value::Text(y)) => x.cmp(y),
        // Unreachable with typed columns; defined for totality.
        (Value::Int(_), Value::Text(_)) => Ordering::Less,
        (Value::Text(_), Value::Int(_)) => Ordering::Greater,
    }
}

/// A predicate resolved against a schema: column indexes + typed values.
enum CompiledExpr {
    Compare {
        column_index: usize,
        column_name: String,
        op: CmpOp,
        value: Value,
    },
    IsNull {
        column_index: usize,
        negated: bool,
    },
    Not(Box<CompiledExpr>),
    And(Box<CompiledExpr>, Box<CompiledExpr>),
    Or(Box<CompiledExpr>, Box<CompiledExpr>),
}

fn compile_expr(schema: &TableSchema, expr: Expr) -> Result<CompiledExpr> {
    let resolve = |column: &str| {
        schema.column_index(column).ok_or_else(|| {
            EngineError::Schema(format!(
                "unknown column {column:?} in table {:?}",
                schema.name
            ))
        })
    };
    Ok(match expr {
        Expr::Compare { column, op, value } => CompiledExpr::Compare {
            column_index: resolve(&column)?,
            column_name: column,
            op,
            value: match value {
                Literal::Null => Value::Null,
                Literal::Int(n) => Value::Int(n),
                Literal::Text(s) => Value::Text(s),
            },
        },
        Expr::IsNull { column, negated } => CompiledExpr::IsNull {
            column_index: resolve(&column)?,
            negated,
        },
        Expr::Not(inner) => CompiledExpr::Not(Box::new(compile_expr(schema, *inner)?)),
        Expr::And(a, b) => CompiledExpr::And(
            Box::new(compile_expr(schema, *a)?),
            Box::new(compile_expr(schema, *b)?),
        ),
        Expr::Or(a, b) => CompiledExpr::Or(
            Box::new(compile_expr(schema, *a)?),
            Box::new(compile_expr(schema, *b)?),
        ),
    })
}

impl CompiledExpr {
    /// A row matches only when the expression is definitely true
    /// (SQL semantics: *unknown* filters the row out).
    fn matches(&self, row: &[Value]) -> Result<bool> {
        Ok(self.eval(row)? == Some(true))
    }

    /// Three-valued logic: `None` is SQL's *unknown*, produced by any
    /// comparison involving NULL and propagated per Kleene logic.
    fn eval(&self, row: &[Value]) -> Result<Option<bool>> {
        match self {
            CompiledExpr::Compare {
                column_index,
                column_name,
                op,
                value,
            } => {
                let cell = &row[*column_index];
                let ordering = match (cell, value) {
                    (Value::Null, _) | (_, Value::Null) => return Ok(None),
                    (Value::Int(a), Value::Int(b)) => a.cmp(b),
                    (Value::Text(a), Value::Text(b)) => a.cmp(b),
                    _ => {
                        return Err(EngineError::Type(format!(
                            "cannot compare column {column_name:?} with a value of a \
                             different type"
                        )));
                    }
                };
                Ok(Some(match op {
                    CmpOp::Eq => ordering.is_eq(),
                    CmpOp::Ne => ordering.is_ne(),
                    CmpOp::Lt => ordering.is_lt(),
                    CmpOp::Gt => ordering.is_gt(),
                    CmpOp::Le => ordering.is_le(),
                    CmpOp::Ge => ordering.is_ge(),
                }))
            }
            CompiledExpr::IsNull {
                column_index,
                negated,
            } => {
                let is_null = row[*column_index] == Value::Null;
                Ok(Some(is_null != *negated))
            }
            CompiledExpr::Not(inner) => Ok(inner.eval(row)?.map(|b| !b)),
            CompiledExpr::And(a, b) => Ok(match (a.eval(row)?, b.eval(row)?) {
                (Some(false), _) | (_, Some(false)) => Some(false),
                (Some(true), Some(true)) => Some(true),
                _ => None,
            }),
            CompiledExpr::Or(a, b) => Ok(match (a.eval(row)?, b.eval(row)?) {
                (Some(true), _) | (_, Some(true)) => Some(true),
                (Some(false), Some(false)) => Some(false),
                _ => None,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine(dir: &Path) -> Engine {
        // Low KDF work factor: tests exercise correctness, not brute-force cost.
        Engine::open_with_iterations(dir, "test-passphrase", 2).unwrap()
    }

    fn rows_of(results: Vec<QueryResult>) -> Vec<Vec<Value>> {
        match results.into_iter().next().unwrap() {
            QueryResult::Rows { rows, .. } => rows,
            other => panic!("expected rows, got {other:?}"),
        }
    }

    fn text(s: &str) -> Value {
        Value::Text(s.into())
    }

    #[test]
    fn end_to_end_crud() {
        let dir = ciphra_testutil::tempdir();
        let mut db = engine(dir.path());

        db.execute("CREATE TABLE users (id INT, name TEXT, ssn TEXT ENCRYPTED)")
            .unwrap();
        let results = db
            .execute(
                "INSERT INTO users VALUES (1, 'alice', '111-22-3333'), \
                 (2, 'bob', '444-55-6666'), (3, 'carol', NULL);",
            )
            .unwrap();
        assert_eq!(results, vec![QueryResult::Inserted(3)]);

        let results = db.execute("SELECT name FROM users WHERE id >= 2").unwrap();
        assert_eq!(
            rows_of(results),
            vec![vec![text("bob")], vec![text("carol")]]
        );

        let results = db.execute("DELETE FROM users WHERE name = 'bob'").unwrap();
        assert_eq!(results, vec![QueryResult::Deleted(1)]);
        let results = db.execute("SELECT * FROM users").unwrap();
        assert_eq!(rows_of(results).len(), 2);
    }

    #[test]
    fn update_rows() {
        let dir = ciphra_testutil::tempdir();
        let mut db = engine(dir.path());
        db.execute(
            "CREATE TABLE users (id INT, name TEXT); \
             INSERT INTO users VALUES (1, 'alice'), (2, 'bob'), (3, 'carol');",
        )
        .unwrap();

        let results = db
            .execute("UPDATE users SET name = 'robert' WHERE id = 2")
            .unwrap();
        assert_eq!(results, vec![QueryResult::Updated(1)]);
        let results = db.execute("SELECT name FROM users WHERE id = 2").unwrap();
        assert_eq!(rows_of(results), vec![vec![text("robert")]]);

        // Unfiltered update touches every row; NULL assignment works.
        let results = db.execute("UPDATE users SET name = NULL").unwrap();
        assert_eq!(results, vec![QueryResult::Updated(3)]);
        let results = db
            .execute("SELECT * FROM users WHERE name IS NULL")
            .unwrap();
        assert_eq!(rows_of(results).len(), 3);

        // Type errors and unknown/duplicate columns are rejected.
        assert!(matches!(
            db.execute("UPDATE users SET id = 'nope'"),
            Err(EngineError::Type(_))
        ));
        assert!(matches!(
            db.execute("UPDATE users SET nope = 1"),
            Err(EngineError::Schema(_))
        ));
        assert!(matches!(
            db.execute("UPDATE users SET id = 1, id = 2"),
            Err(EngineError::Schema(_))
        ));
    }

    #[test]
    fn compound_predicates() {
        let dir = ciphra_testutil::tempdir();
        let mut db = engine(dir.path());
        db.execute(
            "CREATE TABLE t (id INT, grp TEXT, score INT); \
             INSERT INTO t VALUES (1, 'a', 10), (2, 'a', 20), (3, 'b', 30), \
             (4, 'b', NULL), (5, 'c', 50);",
        )
        .unwrap();

        // AND binds tighter than OR.
        let rows = rows_of(
            db.execute("SELECT id FROM t WHERE grp = 'c' OR grp = 'a' AND score >= 20")
                .unwrap(),
        );
        assert_eq!(rows, vec![vec![Value::Int(2)], vec![Value::Int(5)]]);

        // Parentheses override.
        let rows = rows_of(
            db.execute("SELECT id FROM t WHERE (grp = 'c' OR grp = 'a') AND score >= 20")
                .unwrap(),
        );
        assert_eq!(rows, vec![vec![Value::Int(2)], vec![Value::Int(5)]]);

        // NULL comparisons are unknown: row 4 matches neither the
        // predicate nor its negation...
        let rows = rows_of(db.execute("SELECT id FROM t WHERE score >= 20").unwrap());
        assert_eq!(rows.len(), 3);
        let rows = rows_of(
            db.execute("SELECT id FROM t WHERE NOT score >= 20")
                .unwrap(),
        );
        assert_eq!(rows, vec![vec![Value::Int(1)]]);
        // ...but IS NULL finds it.
        let rows = rows_of(db.execute("SELECT id FROM t WHERE score IS NULL").unwrap());
        assert_eq!(rows, vec![vec![Value::Int(4)]]);
        let rows = rows_of(
            db.execute("SELECT id FROM t WHERE score IS NOT NULL AND id <= 2")
                .unwrap(),
        );
        assert_eq!(rows, vec![vec![Value::Int(1)], vec![Value::Int(2)]]);
    }

    #[test]
    fn order_by_limit_offset() {
        let dir = ciphra_testutil::tempdir();
        let mut db = engine(dir.path());
        db.execute(
            "CREATE TABLE t (id INT, score INT); \
             INSERT INTO t VALUES (1, 30), (2, 10), (3, NULL), (4, 20);",
        )
        .unwrap();

        // ASC: NULLs first; the sort column need not be projected.
        let rows = rows_of(db.execute("SELECT id FROM t ORDER BY score").unwrap());
        assert_eq!(
            rows,
            vec![
                vec![Value::Int(3)],
                vec![Value::Int(2)],
                vec![Value::Int(4)],
                vec![Value::Int(1)],
            ]
        );

        // DESC + LIMIT/OFFSET applied after the sort.
        let rows = rows_of(
            db.execute("SELECT id FROM t ORDER BY score DESC LIMIT 2 OFFSET 1")
                .unwrap(),
        );
        assert_eq!(rows, vec![vec![Value::Int(4)], vec![Value::Int(2)]]);

        // LIMIT without ORDER BY keeps insertion order.
        let rows = rows_of(db.execute("SELECT id FROM t LIMIT 2").unwrap());
        assert_eq!(rows, vec![vec![Value::Int(1)], vec![Value::Int(2)]]);

        // Unknown sort column is a schema error.
        assert!(matches!(
            db.execute("SELECT id FROM t ORDER BY nope"),
            Err(EngineError::Schema(_))
        ));
    }

    #[test]
    fn primary_key_uniqueness_is_enforced() {
        let dir = ciphra_testutil::tempdir();
        let mut db = engine(dir.path());
        db.execute("CREATE TABLE users (id INT PRIMARY KEY, name TEXT)")
            .unwrap();
        db.execute("INSERT INTO users VALUES (1, 'alice'), (2, 'bob')")
            .unwrap();

        // Duplicate against stored rows.
        assert!(matches!(
            db.execute("INSERT INTO users VALUES (1, 'imposter')"),
            Err(EngineError::Constraint(_))
        ));
        // Duplicate inside one batch.
        assert!(matches!(
            db.execute("INSERT INTO users VALUES (3, 'x'), (3, 'y')"),
            Err(EngineError::Constraint(_))
        ));
        // NULL primary key.
        assert!(matches!(
            db.execute("INSERT INTO users VALUES (NULL, 'z')"),
            Err(EngineError::Constraint(_))
        ));
        // Two PRIMARY KEY columns are rejected at CREATE time.
        assert!(matches!(
            db.execute("CREATE TABLE bad (a INT PRIMARY KEY, b INT PRIMARY KEY)"),
            Err(EngineError::Schema(_))
        ));
        // Uniqueness survives reopen (the index is rebuilt from disk).
        drop(db);
        let mut db = engine(dir.path());
        assert!(matches!(
            db.execute("INSERT INTO users VALUES (2, 'again')"),
            Err(EngineError::Constraint(_))
        ));
        db.execute("INSERT INTO users VALUES (3, 'carol')").unwrap();
    }

    #[test]
    fn primary_key_point_lookup_matches_scan() {
        let dir = ciphra_testutil::tempdir();
        let mut db = engine(dir.path());
        db.execute("CREATE TABLE t (id INT PRIMARY KEY, grp TEXT)")
            .unwrap();
        for i in 0..20 {
            db.execute(&format!("INSERT INTO t VALUES ({i}, 'g{}')", i % 3))
                .unwrap();
        }
        // Plain point lookup.
        let rows = rows_of(db.execute("SELECT grp FROM t WHERE id = 7").unwrap());
        assert_eq!(rows, vec![vec![text("g1")]]);
        // The full predicate still applies on top of the index hit.
        let rows = rows_of(
            db.execute("SELECT id FROM t WHERE id = 7 AND grp = 'g0'")
                .unwrap(),
        );
        assert_eq!(rows, Vec::<Vec<Value>>::new());
        // Misses report empty, not errors.
        let rows = rows_of(db.execute("SELECT * FROM t WHERE id = 999").unwrap());
        assert_eq!(rows, Vec::<Vec<Value>>::new());
        // OR does not pin the key: both sides must still be found.
        let rows = rows_of(
            db.execute("SELECT id FROM t WHERE id = 7 OR id = 8")
                .unwrap(),
        );
        assert_eq!(rows.len(), 2);
    }

    #[test]
    fn primary_key_survives_update_and_delete() {
        let dir = ciphra_testutil::tempdir();
        let mut db = engine(dir.path());
        db.execute("CREATE TABLE t (id INT PRIMARY KEY, name TEXT)")
            .unwrap();
        db.execute("INSERT INTO t VALUES (1, 'a'), (2, 'b')")
            .unwrap();

        // Moving a key updates the index: old value is free, new is taken.
        db.execute("UPDATE t SET id = 10 WHERE id = 1").unwrap();
        assert_eq!(
            rows_of(db.execute("SELECT name FROM t WHERE id = 10").unwrap()),
            vec![vec![text("a")]]
        );
        db.execute("INSERT INTO t VALUES (1, 'reused')").unwrap();

        // Collisions are rejected before anything is written.
        assert!(matches!(
            db.execute("UPDATE t SET id = 2 WHERE id = 10"),
            Err(EngineError::Constraint(_))
        ));
        // Assigning a row its own key is a no-op, not a collision.
        db.execute("UPDATE t SET id = 2 WHERE id = 2").unwrap();
        // One value for several rows cannot work.
        assert!(matches!(
            db.execute("UPDATE t SET id = 99"),
            Err(EngineError::Constraint(_))
        ));
        // NULL reassignment is rejected.
        assert!(matches!(
            db.execute("UPDATE t SET id = NULL WHERE id = 2"),
            Err(EngineError::Constraint(_))
        ));

        // DELETE frees the key for reuse; point lookups stop finding it.
        db.execute("DELETE FROM t WHERE id = 2").unwrap();
        assert_eq!(
            rows_of(db.execute("SELECT * FROM t WHERE id = 2").unwrap()),
            Vec::<Vec<Value>>::new()
        );
        db.execute("INSERT INTO t VALUES (2, 'back')").unwrap();

        // DROP clears the index too: same keys usable in a new table.
        db.execute("DROP TABLE t").unwrap();
        db.execute("CREATE TABLE t (id INT PRIMARY KEY)").unwrap();
        db.execute("INSERT INTO t VALUES (1), (2), (10)").unwrap();
    }

    #[test]
    fn secondary_index_full_lifecycle() {
        let dir = ciphra_testutil::tempdir();
        let mut db = engine(dir.path());
        db.execute("CREATE TABLE t (id INT PRIMARY KEY, grp TEXT, note TEXT)")
            .unwrap();
        db.execute(
            "INSERT INTO t VALUES (1, 'a', 'x'), (2, 'b', 'y'), (3, 'a', 'z'), \
             (4, NULL, 'w')",
        )
        .unwrap();

        // CREATE INDEX backfills existing rows (non-unique values included).
        db.execute("CREATE INDEX ON t (grp)").unwrap();
        let rows = rows_of(db.execute("SELECT id FROM t WHERE grp = 'a'").unwrap());
        assert_eq!(rows, vec![vec![Value::Int(1)], vec![Value::Int(3)]]);

        // Maintained on INSERT...
        db.execute("INSERT INTO t VALUES (5, 'a', 'v')").unwrap();
        let rows = rows_of(db.execute("SELECT id FROM t WHERE grp = 'a'").unwrap());
        assert_eq!(rows.len(), 3);
        // ...UPDATE (old value released, new value found; NULL clears)...
        db.execute("UPDATE t SET grp = 'b' WHERE id = 1").unwrap();
        let rows = rows_of(db.execute("SELECT id FROM t WHERE grp = 'b'").unwrap());
        assert_eq!(rows, vec![vec![Value::Int(1)], vec![Value::Int(2)]]);
        db.execute("UPDATE t SET grp = NULL WHERE id = 2").unwrap();
        let rows = rows_of(db.execute("SELECT id FROM t WHERE grp = 'b'").unwrap());
        assert_eq!(rows, vec![vec![Value::Int(1)]]);
        // ...and DELETE.
        db.execute("DELETE FROM t WHERE id = 3").unwrap();
        let rows = rows_of(db.execute("SELECT id FROM t WHERE grp = 'a'").unwrap());
        assert_eq!(rows, vec![vec![Value::Int(5)]]);

        // The full predicate still applies on top of the index hit.
        let rows = rows_of(
            db.execute("SELECT id FROM t WHERE grp = 'a' AND note = 'nope'")
                .unwrap(),
        );
        assert_eq!(rows, Vec::<Vec<Value>>::new());
        // IS NULL is not served by the index and still works.
        let rows = rows_of(db.execute("SELECT id FROM t WHERE grp IS NULL").unwrap());
        assert_eq!(rows, vec![vec![Value::Int(2)], vec![Value::Int(4)]]);

        // Survives reopen.
        drop(db);
        let mut db = engine(dir.path());
        let rows = rows_of(db.execute("SELECT id FROM t WHERE grp = 'a'").unwrap());
        assert_eq!(rows, vec![vec![Value::Int(5)]]);

        // DROP INDEX: results identical via fallback scan.
        db.execute("DROP INDEX ON t (grp)").unwrap();
        let rows = rows_of(db.execute("SELECT id FROM t WHERE grp = 'a'").unwrap());
        assert_eq!(rows, vec![vec![Value::Int(5)]]);
    }

    #[test]
    fn index_ddl_errors() {
        let dir = ciphra_testutil::tempdir();
        let mut db = engine(dir.path());
        db.execute("CREATE TABLE t (id INT PRIMARY KEY, grp TEXT)")
            .unwrap();
        assert!(matches!(
            db.execute("CREATE INDEX ON t (id)"),
            Err(EngineError::Schema(_)) // already indexed by PRIMARY KEY
        ));
        assert!(matches!(
            db.execute("CREATE INDEX ON t (nope)"),
            Err(EngineError::Schema(_))
        ));
        assert!(matches!(
            db.execute("CREATE INDEX ON missing (grp)"),
            Err(EngineError::Schema(_))
        ));
        db.execute("CREATE INDEX ON t (grp)").unwrap();
        assert!(matches!(
            db.execute("CREATE INDEX ON t (grp)"),
            Err(EngineError::Schema(_)) // duplicate index
        ));
        db.execute("DROP INDEX ON t (grp)").unwrap();
        assert!(matches!(
            db.execute("DROP INDEX ON t (grp)"),
            Err(EngineError::Schema(_)) // not indexed
        ));
    }

    #[test]
    fn data_survives_reopen() {
        let dir = ciphra_testutil::tempdir();
        {
            let mut db = engine(dir.path());
            db.execute("CREATE TABLE t (a INT); INSERT INTO t VALUES (7);")
                .unwrap();
        }
        let mut db = engine(dir.path());
        let results = db.execute("SELECT * FROM t").unwrap();
        assert_eq!(rows_of(results), vec![vec![Value::Int(7)]]);
        // Row ids keep counting after reopen — no collisions with old rows.
        db.execute("INSERT INTO t VALUES (8)").unwrap();
        assert_eq!(rows_of(db.execute("SELECT * FROM t").unwrap()).len(), 2);
    }

    #[test]
    fn argon2id_database_roundtrip() {
        let dir = ciphra_testutil::tempdir();
        // Tiny parameters: the test exercises wiring, not work factor.
        let kdf = KdfParams::Argon2id {
            memory_kib: 32,
            passes: 1,
            lanes: 1,
        };
        {
            let mut db = Engine::open_with_kdf(dir.path(), "argon-pass", kdf).unwrap();
            db.execute("CREATE TABLE t (a INT); INSERT INTO t VALUES (7);")
                .unwrap();
        }
        // Reopen reads the recorded KDF from the keyparams file — the
        // parameters passed here are ignored for an existing database.
        let mut db =
            Engine::open_with_kdf(dir.path(), "argon-pass", KdfParams::recommended()).unwrap();
        assert_eq!(
            rows_of(db.execute("SELECT * FROM t").unwrap()),
            vec![vec![Value::Int(7)]]
        );
        drop(db);
        let err = Engine::open_with_kdf(dir.path(), "wrong", kdf)
            .err()
            .expect("wrong passphrase must fail");
        assert!(matches!(err, EngineError::BadPassphrase), "got {err:?}");
    }

    #[test]
    fn explain_reports_access_paths() {
        let dir = ciphra_testutil::tempdir();
        let mut db = engine(dir.path());
        db.execute(
            "CREATE TABLE t (id INT PRIMARY KEY, grp TEXT, note TEXT); \
             CREATE INDEX ON t (grp);",
        )
        .unwrap();

        let plan = |db: &mut Engine, sql: &str| -> Vec<String> {
            rows_of(db.execute(sql).unwrap())
                .into_iter()
                .map(|row| row[0].to_string())
                .collect()
        };

        let steps = plan(
            &mut db,
            "EXPLAIN SELECT * FROM t WHERE id = 5 AND note = 'x'",
        );
        assert_eq!(steps[0], "SELECT: primary key lookup on t.id");
        assert_eq!(steps[1], "filter: (id = 5 AND note = 'x')");

        let steps = plan(
            &mut db,
            "EXPLAIN SELECT * FROM t WHERE grp = 'a' ORDER BY id DESC LIMIT 3",
        );
        assert_eq!(steps[0], "SELECT: secondary index lookup on t.grp");
        assert_eq!(steps[2], "sort by id DESC");
        assert_eq!(steps[3], "limit 3 offset 0");

        // OR does not pin a column; NOT and IS NULL render readably.
        let steps = plan(
            &mut db,
            "EXPLAIN DELETE FROM t WHERE id = 1 OR NOT grp IS NULL",
        );
        assert_eq!(steps[0], "DELETE: full scan of t");
        assert_eq!(steps[1], "filter: (id = 1 OR NOT (grp IS NULL))");

        let steps = plan(&mut db, "EXPLAIN UPDATE t SET note = 'y' WHERE id = 2");
        assert_eq!(steps[0], "UPDATE: primary key lookup on t.id");

        // EXPLAIN does not execute: no rows were touched.
        assert_eq!(rows_of(db.execute("SELECT * FROM t").unwrap()).len(), 0);
        // EXPLAIN of unsupported statements is a parse error.
        assert!(db.execute("EXPLAIN CREATE TABLE u (a INT)").is_err());
    }

    #[test]
    fn range_index_full_lifecycle() {
        let dir = ciphra_testutil::tempdir();
        let mut db = engine(dir.path());
        db.execute("CREATE TABLE t (id INT PRIMARY KEY, score INT, note TEXT)")
            .unwrap();
        db.execute(
            "INSERT INTO t VALUES (1, 30, 'a'), (2, 10, 'b'), (3, NULL, 'c'), \
             (4, 20, 'd'), (5, 10, 'e')",
        )
        .unwrap();

        // CREATE RANGE INDEX backfills existing rows (NULLs excluded).
        db.execute("CREATE RANGE INDEX ON t (score)").unwrap();

        let ids = |db: &mut Engine, sql: &str| -> Vec<i64> {
            rows_of(db.execute(sql).unwrap())
                .into_iter()
                .map(|row| match &row[0] {
                    Value::Int(n) => *n,
                    other => panic!("expected int, got {other:?}"),
                })
                .collect()
        };

        // Range predicates resolve through the sealed blob; results
        // must match what a full scan would produce.
        assert_eq!(
            ids(&mut db, "SELECT id FROM t WHERE score >= 20 ORDER BY id"),
            vec![1, 4]
        );
        assert_eq!(
            ids(&mut db, "SELECT id FROM t WHERE score < 20 ORDER BY id"),
            vec![2, 5]
        );
        assert_eq!(
            ids(&mut db, "SELECT id FROM t WHERE score = 10 ORDER BY id"),
            vec![2, 5]
        );
        // The full predicate still applies on top of the blob hits.
        assert_eq!(
            ids(
                &mut db,
                "SELECT id FROM t WHERE score >= 10 AND note = 'd' ORDER BY id"
            ),
            vec![4]
        );
        // NULL never matches a comparison.
        assert_eq!(
            ids(&mut db, "SELECT id FROM t WHERE score <= 100 ORDER BY id").len(),
            4
        );

        // Maintained by INSERT / UPDATE / DELETE.
        db.execute("INSERT INTO t VALUES (6, 15, 'f')").unwrap();
        assert_eq!(
            ids(&mut db, "SELECT id FROM t WHERE score < 20 ORDER BY id"),
            vec![2, 5, 6]
        );
        db.execute("UPDATE t SET score = 40 WHERE id = 2").unwrap();
        assert_eq!(
            ids(&mut db, "SELECT id FROM t WHERE score > 25 ORDER BY id"),
            vec![1, 2]
        );
        db.execute("UPDATE t SET score = NULL WHERE id = 5")
            .unwrap();
        db.execute("DELETE FROM t WHERE id = 6").unwrap();
        assert_eq!(
            ids(&mut db, "SELECT id FROM t WHERE score < 25 ORDER BY id"),
            vec![4]
        );

        // Survives reopen and rotation.
        drop(db);
        let mut db = engine(dir.path());
        assert_eq!(
            ids(&mut db, "SELECT id FROM t WHERE score > 25 ORDER BY id"),
            vec![1, 2]
        );
        db.rotate_to("rotated", KdfParams::Pbkdf2 { iterations: 3 })
            .unwrap();
        assert_eq!(
            ids(&mut db, "SELECT id FROM t WHERE score > 25 ORDER BY id"),
            vec![1, 2]
        );

        // EXPLAIN reports the path.
        let plan = rows_of(
            db.execute("EXPLAIN SELECT id FROM t WHERE score > 5")
                .unwrap(),
        );
        assert_eq!(
            plan[0][0].to_string(),
            "SELECT: sealed range-index scan on t.score (>)"
        );

        // DROP falls back to scans with identical results.
        db.execute("DROP RANGE INDEX ON t (score)").unwrap();
        assert_eq!(
            ids(&mut db, "SELECT id FROM t WHERE score > 25 ORDER BY id"),
            vec![1, 2]
        );
    }

    #[test]
    fn range_index_ddl_errors_and_leakage() {
        let dir = ciphra_testutil::tempdir();
        let mut db = engine(dir.path());
        db.execute("CREATE TABLE t (id INT PRIMARY KEY, secret TEXT)")
            .unwrap();
        db.execute("INSERT INTO t VALUES (1, 'CONFIDENTIAL-VALUE-XYZ')")
            .unwrap();
        db.execute("CREATE RANGE INDEX ON t (secret)").unwrap();

        assert!(matches!(
            db.execute("CREATE RANGE INDEX ON t (secret)"),
            Err(EngineError::Schema(_))
        ));
        assert!(matches!(
            db.execute("CREATE RANGE INDEX ON t (nope)"),
            Err(EngineError::Schema(_))
        ));
        assert!(matches!(
            db.execute("DROP RANGE INDEX ON t (id)"),
            Err(EngineError::Schema(_))
        ));

        // The blob is sealed: indexed values never reach disk in the clear.
        drop(db);
        for entry in std::fs::read_dir(dir.path()).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                continue;
            }
            let bytes = std::fs::read(&path).unwrap();
            assert!(
                !bytes
                    .windows(b"CONFIDENTIAL-VALUE-XYZ".len())
                    .any(|w| w == b"CONFIDENTIAL-VALUE-XYZ"),
                "range-indexed value leaked into {path:?}"
            );
        }
    }

    #[test]
    fn audit_chain_records_every_statement() {
        let dir = ciphra_testutil::tempdir();
        let mut db = engine(dir.path());
        assert_eq!(db.audit_root(), (0, [0u8; 32]));

        db.execute("CREATE TABLE t (id INT PRIMARY KEY, v TEXT)")
            .unwrap();
        db.execute("INSERT INTO t VALUES (1, 'a'), (2, 'b')")
            .unwrap();
        db.execute("UPDATE t SET v = 'c' WHERE id = 1").unwrap();
        db.execute("DELETE FROM t WHERE id = 2").unwrap();
        // A statement that changes nothing does not advance the chain.
        db.execute("DELETE FROM t WHERE id = 999").unwrap();

        let (seq, root) = db.audit_root();
        assert_eq!(seq, 4);
        assert_ne!(root, [0u8; 32]);

        let entries = db.audit_verify().unwrap();
        assert_eq!(entries.len(), 4);
        let kinds: Vec<u8> = entries.iter().map(|e| e.kind).collect();
        assert_eq!(
            kinds,
            vec![
                audit_kind::CREATE_TABLE,
                audit_kind::INSERT,
                audit_kind::UPDATE,
                audit_kind::DELETE,
            ]
        );
        // All four touched the same table: same opaque tag, never zeros.
        assert!(entries.iter().all(|e| e.table_tag == entries[0].table_tag));
        assert_ne!(entries[0].table_tag, [0u8; 16]);

        // Chain and head survive reopen.
        drop(db);
        let db = engine(dir.path());
        assert_eq!(db.audit_root(), (seq, root));
        db.audit_verify().unwrap();
    }

    #[test]
    fn audit_chain_detects_history_tampering() {
        let dir = ciphra_testutil::tempdir();
        {
            let mut db = engine(dir.path());
            db.execute(
                "CREATE TABLE t (a INT); INSERT INTO t VALUES (1); \
                 INSERT INTO t VALUES (2); INSERT INTO t VALUES (3);",
            )
            .unwrap();
        }
        // An attacker with file access deletes one audit entry (storage
        // itself permits this - it is the chain that must catch it).
        {
            let mut raw = ciphra_storage::Storage::open(dir.path()).unwrap();
            let keys: Vec<Vec<u8>> = raw.scan_prefix(b"a\x00").map(|(k, _)| k.to_vec()).collect();
            assert_eq!(keys.len(), 4);
            raw.delete(&keys[1]).unwrap();
        }
        let db = engine(dir.path());
        let err = db.audit_verify().expect_err("tampered chain must fail");
        assert!(matches!(err, EngineError::Audit(_)), "got {err:?}");
    }

    #[test]
    fn audit_chain_survives_rotation() {
        let dir = ciphra_testutil::tempdir();
        let mut db = engine(dir.path());
        db.execute("CREATE TABLE t (a INT); INSERT INTO t VALUES (1);")
            .unwrap();
        let (seq_before, _) = db.audit_root();

        db.rotate_to("rotated-pass", KdfParams::Pbkdf2 { iterations: 3 })
            .unwrap();

        // The chain continued: all old entries plus one ROTATE entry.
        let entries = db.audit_verify().unwrap();
        assert_eq!(entries.len() as u64, seq_before + 1);
        assert_eq!(entries.last().unwrap().kind, audit_kind::ROTATE);

        // And keeps extending after rotation.
        db.execute("INSERT INTO t VALUES (2)").unwrap();
        let entries = db.audit_verify().unwrap();
        assert_eq!(entries.last().unwrap().kind, audit_kind::INSERT);
    }

    #[test]
    fn rotation_reencrypts_everything() {
        let dir = ciphra_testutil::tempdir();
        let secret = "ROTATE-ME-SECRET-424242";
        let mut db = engine(dir.path());
        db.execute(
            "CREATE TABLE vault (id INT PRIMARY KEY, owner TEXT, secret TEXT ENCRYPTED); \
             CREATE INDEX ON vault (owner);",
        )
        .unwrap();
        db.execute(&format!(
            "INSERT INTO vault VALUES (1, 'alice', '{secret}'), (2, 'bob', 'x'), \
             (3, 'alice', 'y')"
        ))
        .unwrap();

        db.rotate_to("brand-new-passphrase", KdfParams::Pbkdf2 { iterations: 3 })
            .unwrap();

        // The same handle keeps working after rotation...
        let rows = rows_of(db.execute("SELECT secret FROM vault WHERE id = 1").unwrap());
        assert_eq!(rows, vec![vec![text(secret)]]);
        // ...including the secondary index and PK constraints.
        let rows = rows_of(
            db.execute("SELECT id FROM vault WHERE owner = 'alice'")
                .unwrap(),
        );
        assert_eq!(rows.len(), 2);
        assert!(matches!(
            db.execute("INSERT INTO vault VALUES (2, 'eve', 'z')"),
            Err(EngineError::Constraint(_))
        ));
        db.execute("INSERT INTO vault VALUES (4, 'dave', 'w')")
            .unwrap();
        drop(db);

        // Old passphrase is dead, new one opens; data intact on reopen.
        let err = Engine::open(dir.path(), "test-passphrase")
            .err()
            .expect("old passphrase must be rejected after rotation");
        assert!(matches!(err, EngineError::BadPassphrase), "got {err:?}");
        let mut db = Engine::open(dir.path(), "brand-new-passphrase").unwrap();
        assert_eq!(rows_of(db.execute("SELECT * FROM vault").unwrap()).len(), 4);

        // Still zero plaintext on disk after the rebuild.
        for entry in std::fs::read_dir(dir.path()).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                continue;
            }
            let bytes = std::fs::read(&path).unwrap();
            for needle in ["alice", "vault", "owner", secret] {
                assert!(
                    !contains_subslice(&bytes, needle.as_bytes()),
                    "plaintext {needle:?} leaked into {path:?} after rotation"
                );
            }
        }
    }

    #[test]
    fn interrupted_rotation_leftovers_are_harmless() {
        let dir = ciphra_testutil::tempdir();
        {
            let mut db = engine(dir.path());
            db.execute("CREATE TABLE t (a INT); INSERT INTO t VALUES (1);")
                .unwrap();
        }
        // Simulate a crash mid-rotation: a stale scratch directory with
        // a half-built database in it.
        let tmp = dir.path().join(".rotate-tmp");
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(tmp.join("ciphra.wal"), b"half-written garbage").unwrap();

        // The old passphrase still opens the old data; leftovers are gone.
        let mut db = engine(dir.path());
        assert_eq!(rows_of(db.execute("SELECT * FROM t").unwrap()).len(), 1);
        assert!(!tmp.exists());
    }

    #[test]
    fn v1_keyparams_files_still_open() {
        let dir = ciphra_testutil::tempdir();
        // Create a v1-format keyparams file by hand: PBKDF2 implied.
        let salt = ciphra_crypto::random_salt();
        let mut contents = b"CIPHRA\x00\x01".to_vec();
        contents.extend_from_slice(&2u32.to_le_bytes());
        contents.extend_from_slice(&salt);
        std::fs::write(dir.path().join(KEYPARAMS_FILE), &contents).unwrap();

        let mut db = Engine::open(dir.path(), "legacy-pass").unwrap();
        db.execute("CREATE TABLE t (a INT); INSERT INTO t VALUES (1);")
            .unwrap();
        drop(db);
        let mut db = Engine::open(dir.path(), "legacy-pass").unwrap();
        assert_eq!(rows_of(db.execute("SELECT * FROM t").unwrap()).len(), 1);
    }

    #[test]
    fn wrong_passphrase_is_rejected() {
        let dir = ciphra_testutil::tempdir();
        {
            let mut db = engine(dir.path());
            db.execute("CREATE TABLE t (a INT)").unwrap();
        }
        let err = Engine::open(dir.path(), "not-the-passphrase")
            .err()
            .expect("open with a wrong passphrase must fail");
        assert!(matches!(err, EngineError::BadPassphrase), "got {err:?}");
    }

    #[test]
    fn no_user_plaintext_touches_disk() {
        let dir = ciphra_testutil::tempdir();
        let secret = "SUPER-SECRET-SSN-987654321";
        {
            let mut db = engine(dir.path());
            db.execute("CREATE TABLE vault (owner TEXT, secret TEXT ENCRYPTED)")
                .unwrap();
            db.execute(&format!("INSERT INTO vault VALUES ('alice', '{secret}')"))
                .unwrap();
        }
        // Scan every file in the data directory: no value, no column
        // name and — since v2 — no table name may appear in plaintext.
        for entry in std::fs::read_dir(dir.path()).unwrap() {
            let path = entry.unwrap().path();
            let bytes = std::fs::read(&path).unwrap();
            for needle in ["alice", "owner", "secret", "vault"] {
                assert!(
                    !contains_subslice(&bytes, needle.as_bytes()),
                    "plaintext {needle:?} leaked into {path:?}"
                );
            }
            assert!(
                !contains_subslice(&bytes, secret.as_bytes()),
                "secret value leaked into {path:?}"
            );
        }
        // And yet the data is fully queryable with the right key.
        let mut db = engine(dir.path());
        let results = db
            .execute("SELECT secret FROM vault WHERE owner = 'alice'")
            .unwrap();
        assert_eq!(rows_of(results), vec![vec![text(secret)]]);
        assert_eq!(db.tables().unwrap(), vec!["vault".to_string()]);
    }

    #[test]
    fn tables_are_listed_by_decrypting_the_catalog() {
        let dir = ciphra_testutil::tempdir();
        let mut db = engine(dir.path());
        db.execute("CREATE TABLE zebra (a INT); CREATE TABLE apple (a INT);")
            .unwrap();
        assert_eq!(
            db.tables().unwrap(),
            vec!["apple".to_string(), "zebra".to_string()]
        );
    }

    #[test]
    fn type_errors_are_caught() {
        let dir = ciphra_testutil::tempdir();
        let mut db = engine(dir.path());
        db.execute("CREATE TABLE t (a INT, b TEXT)").unwrap();
        assert!(matches!(
            db.execute("INSERT INTO t VALUES ('oops', 'x')"),
            Err(EngineError::Type(_))
        ));
        assert!(matches!(
            db.execute("INSERT INTO t VALUES (1)"),
            Err(EngineError::Type(_))
        ));
        db.execute("INSERT INTO t VALUES (1, 'x')").unwrap();
        assert!(matches!(
            db.execute("SELECT * FROM t WHERE a = 'text'"),
            Err(EngineError::Type(_))
        ));
    }

    #[test]
    fn schema_errors_are_caught() {
        let dir = ciphra_testutil::tempdir();
        let mut db = engine(dir.path());
        assert!(matches!(
            db.execute("SELECT * FROM nope"),
            Err(EngineError::Schema(_))
        ));
        db.execute("CREATE TABLE t (a INT)").unwrap();
        assert!(matches!(
            db.execute("CREATE TABLE t (b INT)"),
            Err(EngineError::Schema(_))
        ));
        assert!(matches!(
            db.execute("SELECT nope FROM t"),
            Err(EngineError::Schema(_))
        ));
        assert!(matches!(
            db.execute("CREATE TABLE dup (a INT, a TEXT)"),
            Err(EngineError::Schema(_))
        ));
    }

    #[test]
    fn drop_table_removes_everything() {
        let dir = ciphra_testutil::tempdir();
        let mut db = engine(dir.path());
        db.execute("CREATE TABLE t (a INT); INSERT INTO t VALUES (1), (2);")
            .unwrap();
        db.execute("DROP TABLE t").unwrap();
        assert!(db.tables().unwrap().is_empty());
        // Recreating the table must start from a clean slate.
        db.execute("CREATE TABLE t (a INT)").unwrap();
        assert_eq!(
            rows_of(db.execute("SELECT * FROM t").unwrap()),
            Vec::<Vec<Value>>::new()
        );
    }

    fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }
}
