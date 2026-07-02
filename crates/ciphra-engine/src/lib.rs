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
//! Multi-key mutations (row + index entry) are not atomic yet: a crash
//! between the two writes can leave a dangling index entry, which
//! readers treat as absent. Transactions are on the roadmap.

mod codec;

use std::cmp::Ordering;
use std::path::{Path, PathBuf};

pub use ciphra_sql::{ColumnDef, DataType};
pub use codec::TableSchema;

use ciphra_crypto::{CipherKey, CryptoError, MasterKey};
use ciphra_sql::{
    Assignment, CmpOp, Expr, Limit, Literal, OrderBy, ParseError, Projection, Statement,
};
use ciphra_storage::{Storage, StorageError};

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
/// v1 layout: `magic | iterations u32 LE | salt` (PBKDF2 implied).
const KEYPARAMS_MAGIC_V1: &[u8; 8] = b"CIPHRA\x00\x01";
/// v2 layout: `magic | kdf u8 | params | salt` where kdf 1 = PBKDF2
/// (`iterations u32`), kdf 2 = Argon2id (`m_kib u32 | passes u32 |
/// lanes u32`), all LE.
const KEYPARAMS_MAGIC_V2: &[u8; 8] = b"CIPHRA\x00\x02";
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
    },
    IndexDropped {
        table: String,
        column: String,
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

        Ok(Engine {
            storage,
            master,
            dir,
        })
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
            fresh.store_schema(&schema)?;
            let table_key = fresh.table_key(&schema.name);
            fresh.store_seq(&schema.name, &table_key, seq)?;
            let maintained = maintained_columns(&schema);
            for (rowid, row) in rows {
                let key = fresh.row_key(&schema.name, rowid);
                let sealed = table_key.seal(&codec::encode_row(&row), &key);
                fresh.storage.put(&key, &sealed)?;
                for &col in &maintained {
                    if row[col] != Value::Null {
                        fresh.put_index_entry(&schema.name, &table_key, col, &row[col], rowid)?;
                    }
                }
            }
        }
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
            Statement::CreateIndex { table, column } => self.create_index(&table, &column),
            Statement::DropIndex { table, column } => self.drop_index(&table, &column),
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
            None => steps.push(format!("{action}: full scan of {}", schema.name)),
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
        self.store_schema(&schema)?;
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
        // Backfill entries for existing rows, then persist the flag.
        let table_key = self.table_key(table);
        let mut backfill: Vec<(Value, u64)> = Vec::new();
        for (key, sealed) in self.storage.scan_prefix(&self.row_prefix(table)) {
            let row = codec::decode_row(&table_key.open(sealed, key)?)?;
            if row[col] != Value::Null {
                backfill.push((row[col].clone(), rowid_from_key(key)));
            }
        }
        for (value, rowid) in backfill {
            self.put_index_entry(table, &table_key, col, &value, rowid)?;
        }
        schema.columns[col].indexed = true;
        self.store_schema(&schema)?;
        Ok(QueryResult::IndexCreated {
            table: table.to_string(),
            column: column.to_string(),
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
        let keys: Vec<Vec<u8>> = self
            .storage
            .scan_prefix(&self.index_column_prefix(table, col))
            .map(|(k, _)| k.to_vec())
            .collect();
        for key in keys {
            self.storage.delete(&key)?;
        }
        schema.columns[col].indexed = false;
        self.store_schema(&schema)?;
        Ok(QueryResult::IndexDropped {
            table: table.to_string(),
            column: column.to_string(),
        })
    }

    fn drop_table(&mut self, name: &str) -> Result<QueryResult> {
        self.expect_schema(name)?;
        for prefix in [self.row_prefix(name), self.index_prefix(name)] {
            let keys: Vec<Vec<u8>> = self
                .storage
                .scan_prefix(&prefix)
                .map(|(k, _)| k.to_vec())
                .collect();
            for key in keys {
                self.storage.delete(&key)?;
            }
        }
        let seq = self.seq_key(name);
        self.storage.delete(&seq)?;
        let catalog = self.catalog_key(name);
        self.storage.delete(&catalog)?;
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

        let mut next_id = self.load_seq(table, &table_key)?;
        let count = batch.len();
        for row in batch {
            let key = self.row_key(table, next_id);
            let sealed = table_key.seal(&codec::encode_row(&row), &key);
            self.storage.put(&key, &sealed)?;
            for &col in &maintained {
                if row[col] != Value::Null {
                    self.put_index_entry(table, &table_key, col, &row[col], next_id)?;
                }
            }
            next_id += 1;
        }
        self.store_seq(table, &table_key, next_id)?;
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
        for (key, old_row, new_row) in changed {
            let rowid = rowid_from_key(&key);
            for &col in &maintained {
                if old_row[col] != new_row[col] {
                    if old_row[col] != Value::Null {
                        self.delete_index_entry(table, col, &old_row[col], rowid)?;
                    }
                    if new_row[col] != Value::Null {
                        self.put_index_entry(table, &table_key, col, &new_row[col], rowid)?;
                    }
                }
            }
            let sealed = table_key.seal(&codec::encode_row(&new_row), &key);
            self.storage.put(&key, &sealed)?;
        }
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
        for (key, row) in doomed {
            let rowid = rowid_from_key(&key);
            for &col in &maintained {
                if row[col] != Value::Null {
                    self.delete_index_entry(table, col, &row[col], rowid)?;
                }
            }
            self.storage.delete(&key)?;
        }
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

    fn put_index_entry(
        &mut self,
        table: &str,
        table_key: &CipherKey,
        col: usize,
        value: &Value,
        rowid: u64,
    ) -> Result<()> {
        let mut key = self.index_value_prefix(table, col, value);
        key.extend_from_slice(&rowid.to_be_bytes());
        let sealed = table_key.seal(b"", &key);
        self.storage.put(&key, &sealed)?;
        Ok(())
    }

    fn delete_index_entry(
        &mut self,
        table: &str,
        col: usize,
        value: &Value,
        rowid: u64,
    ) -> Result<()> {
        let mut key = self.index_value_prefix(table, col, value);
        key.extend_from_slice(&rowid.to_be_bytes());
        self.storage.delete(&key)?;
        Ok(())
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
        let mut rows = Vec::new();
        for (key, sealed) in self.storage.scan_prefix(&self.row_prefix(table)) {
            rows.push((
                key.to_vec(),
                codec::decode_row(&table_key.open(sealed, key)?)?,
            ));
        }
        Ok(rows)
    }

    /// Seal and store a schema in the catalog.
    fn store_schema(&mut self, schema: &TableSchema) -> Result<()> {
        let key = self.catalog_key(&schema.name);
        let sealed = self
            .master
            .derive_key("catalog")
            .seal(&codec::encode_schema(schema), &key);
        self.storage.put(&key, &sealed)?;
        Ok(())
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

    fn store_seq(&mut self, table: &str, table_key: &CipherKey, next: u64) -> Result<()> {
        let key = self.seq_key(table);
        let sealed = table_key.seal(&next.to_le_bytes(), &key);
        self.storage.put(&key, &sealed)?;
        Ok(())
    }
}

/// Index of the PRIMARY KEY column, if the table declares one.
fn pk_column(schema: &TableSchema) -> Option<usize> {
    schema.columns.iter().position(|c| c.primary_key)
}

/// The row id encoded in the trailing 8 bytes of a row key.
fn rowid_from_key(key: &[u8]) -> u64 {
    u64::from_be_bytes(key[key.len() - 8..].try_into().unwrap())
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
