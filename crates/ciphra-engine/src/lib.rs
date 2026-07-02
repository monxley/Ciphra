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
//! \x00canary               -> sealed marker to detect a wrong passphrase
//! \x00catalog\x00<tag16>   -> sealed TableSchema (incl. the real name)
//! \x00seq\x00<tag16>       -> sealed next row id (u64 LE)
//! r\x00<tag16><id BE>      -> sealed row
//! x\x00<tag16><vtag16>     -> sealed row id: PRIMARY KEY index entry
//! ```
//!
//! `<vtag16>` is a keyed tag of the primary-key *value*, so equality
//! lookups are O(log n) without ever storing the value itself. The
//! documented leakage: which index entry a lookup touches, and (since
//! PK values are unique) nothing about repeats across live rows.
//!
//! Multi-key mutations (row + index entry) are not atomic yet: a crash
//! between the two writes can leave a dangling index entry, which
//! readers treat as absent. Transactions are on the roadmap.

mod codec;

use std::cmp::Ordering;
use std::path::Path;

pub use ciphra_sql::{ColumnDef, DataType};
pub use codec::TableSchema;

use ciphra_crypto::{CipherKey, CryptoError, MasterKey};
use ciphra_sql::{
    Assignment, CmpOp, Expr, Limit, Literal, OrderBy, ParseError, Projection, Statement,
};
use ciphra_storage::{Storage, StorageError};

const KEYPARAMS_FILE: &str = "ciphra.keyparams";
const KEYPARAMS_MAGIC: &[u8; 8] = b"CIPHRA\x00\x01";
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

/// Result of executing one statement.
#[derive(Debug, PartialEq)]
pub enum QueryResult {
    Created(String),
    Dropped(String),
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
}

impl Engine {
    /// Open (or create) a database in `dir` with the default KDF work
    /// factor ([`ciphra_crypto::DEFAULT_KDF_ITERATIONS`]).
    ///
    /// On first open a random salt and the KDF parameters are written
    /// next to the data (they are not secret) and a sealed canary is
    /// stored; subsequent opens verify the canary and fail with
    /// [`EngineError::BadPassphrase`] on a mismatch.
    pub fn open(dir: impl AsRef<Path>, passphrase: &str) -> Result<Self> {
        Self::open_with_iterations(dir, passphrase, ciphra_crypto::DEFAULT_KDF_ITERATIONS)
    }

    /// Like [`Engine::open`], with an explicit KDF work factor for a
    /// database being created. An existing database always uses the
    /// iteration count recorded at creation time.
    pub fn open_with_iterations(
        dir: impl AsRef<Path>,
        passphrase: &str,
        iterations: u32,
    ) -> Result<Self> {
        let dir = dir.as_ref();
        std::fs::create_dir_all(dir)?;

        let params_path = dir.join(KEYPARAMS_FILE);
        let (iterations, salt) = if params_path.exists() {
            read_keyparams(&std::fs::read(&params_path)?)?
        } else {
            let salt = ciphra_crypto::random_salt().to_vec();
            let mut contents = KEYPARAMS_MAGIC.to_vec();
            contents.extend_from_slice(&iterations.to_le_bytes());
            contents.extend_from_slice(&salt);
            std::fs::write(&params_path, &contents)?;
            (iterations, salt)
        };

        let master = MasterKey::derive_from_passphrase(passphrase, &salt, iterations);
        let mut storage = Storage::open(dir)?;

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

        Ok(Engine { storage, master })
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
        }
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
        let key = self.catalog_key(&name);
        let sealed = self
            .master
            .derive_key("catalog")
            .seal(&codec::encode_schema(&schema), &key);
        self.storage.put(&key, &sealed)?;
        Ok(QueryResult::Created(name))
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

        // Validate the whole batch — types, arity and the primary key —
        // before writing anything, so a rejected INSERT statement never
        // leaves some of its rows behind.
        let mut batch: Vec<Vec<Value>> = Vec::with_capacity(rows.len());
        let mut batch_pk_keys = std::collections::HashSet::new();
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
                let duplicate = !batch_pk_keys.insert(self.index_key(table, value))
                    || self.lookup_pk(table, &table_key, value)?.is_some();
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
            if let Some(pk_idx) = pk {
                self.put_index_entry(table, &table_key, &row[pk_idx], next_id)?;
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
            if let Some((key, _, _)) = changed.first()
                && let Some(existing) = self.lookup_pk(table, &table_key, new_pk)?
                && existing != rowid_from_key(key)
            {
                return Err(EngineError::Constraint(format!(
                    "duplicate value for primary key {:?}",
                    schema.columns[pk_idx].name
                )));
            }
        }

        let count = changed.len();
        for (key, old_row, new_row) in changed {
            if let (Some(pk_idx), Some(_)) = (pk, new_pk)
                && old_row[pk_idx] != new_row[pk_idx]
            {
                let old_index_key = self.index_key(table, &old_row[pk_idx]);
                self.storage.delete(&old_index_key)?;
                self.put_index_entry(table, &table_key, &new_row[pk_idx], rowid_from_key(&key))?;
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

        let pk = pk_column(&schema);
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
            if let Some(pk_idx) = pk {
                let index_key = self.index_key(table, &row[pk_idx]);
                self.storage.delete(&index_key)?;
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

    /// Index entry key for a primary-key value: the value never appears
    /// in the key, only its keyed tag (equality leakage only).
    fn index_key(&self, table: &str, value: &Value) -> Vec<u8> {
        let encoded = codec::encode_row(std::slice::from_ref(value));
        let value_tag = self.master.keyed_tag(&format!("pk:{table}"), &encoded);
        let mut key = self.index_prefix(table);
        key.extend_from_slice(&value_tag[..TABLE_TAG_LEN]);
        key
    }

    /// Look up the row id holding `value` in the primary-key index.
    fn lookup_pk(&self, table: &str, table_key: &CipherKey, value: &Value) -> Result<Option<u64>> {
        let key = self.index_key(table, value);
        match self.storage.get(&key) {
            None => Ok(None),
            Some(sealed) => {
                let plain = table_key.open(sealed, &key)?;
                let bytes: [u8; 8] = plain
                    .as_slice()
                    .try_into()
                    .map_err(|_| EngineError::Corrupt(format!("bad index entry for {table:?}")))?;
                Ok(Some(u64::from_le_bytes(bytes)))
            }
        }
    }

    fn put_index_entry(
        &mut self,
        table: &str,
        table_key: &CipherKey,
        value: &Value,
        rowid: u64,
    ) -> Result<()> {
        let key = self.index_key(table, value);
        let sealed = table_key.seal(&rowid.to_le_bytes(), &key);
        self.storage.put(&key, &sealed)?;
        Ok(())
    }

    /// Fetch the rows a filtered operation must consider. When the
    /// predicate pins the primary key to a value (a `pk = literal`
    /// conjunct), this is a single index lookup instead of a full scan.
    /// Callers still apply the complete predicate to what is returned.
    fn candidate_rows(
        &self,
        table: &str,
        schema: &TableSchema,
        filter: Option<&CompiledExpr>,
        table_key: &CipherKey,
    ) -> Result<Vec<(Vec<u8>, Vec<Value>)>> {
        if let Some(pk_idx) = pk_column(schema)
            && let Some(filter) = filter
            && let Some(value) = pk_eq_value(filter, pk_idx)
        {
            return match self.lookup_pk(table, table_key, value)? {
                None => Ok(Vec::new()),
                Some(rowid) => {
                    let key = self.row_key(table, rowid);
                    match self.storage.get(&key) {
                        // A dangling index entry (crash between the two
                        // writes) reads as absent.
                        None => Ok(Vec::new()),
                        Some(sealed) => {
                            let row = codec::decode_row(&table_key.open(sealed, &key)?)?;
                            Ok(vec![(key, row)])
                        }
                    }
                }
            };
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

/// If the expression can only be true when the primary key equals one
/// specific value, return that value. Only `pk = literal` itself and
/// AND-conjuncts containing it qualify; anything under OR/NOT does not
/// pin the key.
fn pk_eq_value(expr: &CompiledExpr, pk_index: usize) -> Option<&Value> {
    match expr {
        CompiledExpr::Compare {
            column_index,
            op: CmpOp::Eq,
            value,
            ..
        } if *column_index == pk_index && *value != Value::Null => Some(value),
        CompiledExpr::And(a, b) => pk_eq_value(a, pk_index).or_else(|| pk_eq_value(b, pk_index)),
        _ => None,
    }
}

/// Parse the keyparams file: `magic (8) | iterations (4 LE) | salt`.
fn read_keyparams(contents: &[u8]) -> Result<(u32, Vec<u8>)> {
    if contents.len() < 12 + ciphra_crypto::SALT_LEN || &contents[..8] != KEYPARAMS_MAGIC {
        return Err(EngineError::Corrupt(format!("bad {KEYPARAMS_FILE} file")));
    }
    let iterations = u32::from_le_bytes(contents[8..12].try_into().unwrap());
    if iterations == 0 {
        return Err(EngineError::Corrupt(format!("bad {KEYPARAMS_FILE} file")));
    }
    Ok((iterations, contents[12..].to_vec()))
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
