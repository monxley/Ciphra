//! Ciphra execution engine.
//!
//! Ties the layers together: SQL statements from `ciphra-sql` are
//! executed against `ciphra-storage`, with every row sealed by
//! `ciphra-crypto` before it touches disk.
//!
//! Encryption model (v0): each table gets its own ChaCha20-Poly1305 key
//! derived from the master key (`HKDF(master, "table:<name>")`). Whole
//! rows are encrypted; the AAD binds each ciphertext to its table and
//! row id, so encrypted rows cannot be moved or replayed across
//! tables/rows without detection. Plaintext row data never reaches the
//! storage layer.
//!
//! Key layout inside storage (every value is sealed):
//!
//! ```text
//! \x00canary                 -> sealed marker to detect a wrong passphrase
//! \x00catalog\x00<table>     -> sealed TableSchema
//! \x00seq\x00<table>         -> sealed next row id (u64 LE)
//! r\x00<table>\x00<id BE>    -> sealed row
//! ```

mod codec;

use std::path::Path;

pub use ciphra_sql::{ColumnDef, DataType};
pub use codec::TableSchema;

use ciphra_crypto::{CipherKey, CryptoError, MasterKey};
use ciphra_sql::{CmpOp, Literal, ParseError, Predicate, Projection, Statement};
use ciphra_storage::{Storage, StorageError};

const KEYPARAMS_FILE: &str = "ciphra.keyparams";
const KEYPARAMS_MAGIC: &[u8; 8] = b"CIPHRA\x00\x01";
const CANARY_KEY: &[u8] = b"\x00canary";
const CANARY_PLAINTEXT: &[u8] = b"ciphra-canary-v1";

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

    /// List the names of all tables.
    pub fn tables(&self) -> Result<Vec<String>> {
        let prefix = b"\x00catalog\x00";
        let mut names = Vec::new();
        for (key, _) in self.storage.scan_prefix(prefix) {
            let name = std::str::from_utf8(&key[prefix.len()..])
                .map_err(|_| EngineError::Corrupt("non-utf8 table name in catalog".into()))?;
            names.push(name.to_string());
        }
        Ok(names)
    }

    /// Fetch the schema of `table`, if it exists.
    pub fn schema(&self, table: &str) -> Result<Option<TableSchema>> {
        let key = catalog_key(table);
        match self.storage.get(&key) {
            None => Ok(None),
            Some(sealed) => {
                let plain = self.master.derive_key("catalog").open(sealed, &key)?;
                Ok(Some(codec::decode_schema(table, &plain)?))
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
            } => self.select(&table, columns, predicate),
            Statement::Delete { table, predicate } => self.delete(&table, predicate),
        }
    }

    fn create_table(
        &mut self,
        name: String,
        columns: Vec<ciphra_sql::ColumnDef>,
    ) -> Result<QueryResult> {
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
        let schema = TableSchema {
            name: name.clone(),
            columns,
        };
        let key = catalog_key(&name);
        let sealed = self
            .master
            .derive_key("catalog")
            .seal(&codec::encode_schema(&schema), &key);
        self.storage.put(&key, &sealed)?;
        Ok(QueryResult::Created(name))
    }

    fn drop_table(&mut self, name: &str) -> Result<QueryResult> {
        self.expect_schema(name)?;
        let row_keys: Vec<Vec<u8>> = self
            .storage
            .scan_prefix(&row_prefix(name))
            .map(|(k, _)| k.to_vec())
            .collect();
        for key in row_keys {
            self.storage.delete(&key)?;
        }
        self.storage.delete(&seq_key(name))?;
        self.storage.delete(&catalog_key(name))?;
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
        let mut next_id = self.load_seq(table, &table_key)?;
        let count = rows.len();

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
            let key = row_key(table, next_id);
            let sealed = table_key.seal(&codec::encode_row(&row), &key);
            self.storage.put(&key, &sealed)?;
            next_id += 1;
        }
        self.store_seq(table, &table_key, next_id)?;
        Ok(QueryResult::Inserted(count))
    }

    fn select(
        &mut self,
        table: &str,
        projection: Projection,
        predicate: Option<Predicate>,
    ) -> Result<QueryResult> {
        let schema = self.expect_schema(table)?;
        let filter = predicate
            .map(|p| compile_predicate(&schema, p))
            .transpose()?;

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

        let table_key = self.table_key(table);
        let mut rows = Vec::new();
        for (key, sealed) in self.storage.scan_prefix(&row_prefix(table)) {
            let row = codec::decode_row(&table_key.open(sealed, key)?)?;
            if let Some(filter) = &filter
                && !filter.matches(&row)?
            {
                continue;
            }
            rows.push(output.iter().map(|&i| row[i].clone()).collect());
        }
        Ok(QueryResult::Rows {
            columns: column_names,
            rows,
        })
    }

    fn delete(&mut self, table: &str, predicate: Option<Predicate>) -> Result<QueryResult> {
        let schema = self.expect_schema(table)?;
        let filter = predicate
            .map(|p| compile_predicate(&schema, p))
            .transpose()?;
        let table_key = self.table_key(table);

        let mut doomed = Vec::new();
        for (key, sealed) in self.storage.scan_prefix(&row_prefix(table)) {
            let row = codec::decode_row(&table_key.open(sealed, key)?)?;
            let matches = match &filter {
                Some(filter) => filter.matches(&row)?,
                None => true,
            };
            if matches {
                doomed.push(key.to_vec());
            }
        }
        let count = doomed.len();
        for key in doomed {
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

    fn load_seq(&self, table: &str, table_key: &CipherKey) -> Result<u64> {
        let key = seq_key(table);
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
        let key = seq_key(table);
        let sealed = table_key.seal(&next.to_le_bytes(), &key);
        self.storage.put(&key, &sealed)?;
        Ok(())
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

fn catalog_key(table: &str) -> Vec<u8> {
    let mut key = b"\x00catalog\x00".to_vec();
    key.extend_from_slice(table.as_bytes());
    key
}

fn seq_key(table: &str) -> Vec<u8> {
    let mut key = b"\x00seq\x00".to_vec();
    key.extend_from_slice(table.as_bytes());
    key
}

fn row_prefix(table: &str) -> Vec<u8> {
    let mut prefix = b"r\x00".to_vec();
    prefix.extend_from_slice(table.as_bytes());
    prefix.push(0);
    prefix
}

/// Big-endian row id so lexicographic key order equals insertion order.
fn row_key(table: &str, id: u64) -> Vec<u8> {
    let mut key = row_prefix(table);
    key.extend_from_slice(&id.to_be_bytes());
    key
}

/// Convert a literal to a schema-typed value, or fail with a type error.
fn coerce(literal: Literal, column: &ciphra_sql::ColumnDef) -> Result<Value> {
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

/// A predicate resolved against a schema: column index + typed comparison.
struct CompiledPredicate {
    column_index: usize,
    column_name: String,
    op: CmpOp,
    value: Value,
}

fn compile_predicate(schema: &TableSchema, predicate: Predicate) -> Result<CompiledPredicate> {
    let column_index = schema.column_index(&predicate.column).ok_or_else(|| {
        EngineError::Schema(format!(
            "unknown column {:?} in table {:?}",
            predicate.column, schema.name
        ))
    })?;
    let value = match predicate.value {
        Literal::Null => Value::Null,
        Literal::Int(n) => Value::Int(n),
        Literal::Text(s) => Value::Text(s),
    };
    Ok(CompiledPredicate {
        column_index,
        column_name: predicate.column,
        op: predicate.op,
        value,
    })
}

impl CompiledPredicate {
    fn matches(&self, row: &[Value]) -> Result<bool> {
        let cell = &row[self.column_index];
        let ordering = match (cell, &self.value) {
            // SQL semantics: comparisons involving NULL are never true.
            (Value::Null, _) | (_, Value::Null) => return Ok(false),
            (Value::Int(a), Value::Int(b)) => a.cmp(b),
            (Value::Text(a), Value::Text(b)) => a.cmp(b),
            _ => {
                return Err(EngineError::Type(format!(
                    "cannot compare column {:?} with a value of a different type",
                    self.column_name
                )));
            }
        };
        Ok(match self.op {
            CmpOp::Eq => ordering.is_eq(),
            CmpOp::Ne => ordering.is_ne(),
            CmpOp::Lt => ordering.is_lt(),
            CmpOp::Gt => ordering.is_gt(),
            CmpOp::Le => ordering.is_le(),
            CmpOp::Ge => ordering.is_ge(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine(dir: &Path) -> Engine {
        // Low KDF work factor: tests exercise correctness, not brute-force cost.
        Engine::open_with_iterations(dir, "test-passphrase", 2).unwrap()
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
            results,
            vec![QueryResult::Rows {
                columns: vec!["name".into()],
                rows: vec![
                    vec![Value::Text("bob".into())],
                    vec![Value::Text("carol".into())],
                ],
            }]
        );

        let results = db.execute("DELETE FROM users WHERE name = 'bob'").unwrap();
        assert_eq!(results, vec![QueryResult::Deleted(1)]);
        let results = db.execute("SELECT * FROM users").unwrap();
        match &results[0] {
            QueryResult::Rows { rows, .. } => assert_eq!(rows.len(), 2),
            other => panic!("unexpected result: {other:?}"),
        }
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
        assert_eq!(
            results,
            vec![QueryResult::Rows {
                columns: vec!["a".into()],
                rows: vec![vec![Value::Int(7)]],
            }]
        );
        // Row ids keep counting after reopen — no collisions with old rows.
        db.execute("INSERT INTO t VALUES (8)").unwrap();
        let results = db.execute("SELECT * FROM t").unwrap();
        match &results[0] {
            QueryResult::Rows { rows, .. } => assert_eq!(rows.len(), 2),
            other => panic!("unexpected result: {other:?}"),
        }
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
    fn plaintext_never_touches_disk() {
        let dir = ciphra_testutil::tempdir();
        let secret = "SUPER-SECRET-SSN-987654321";
        {
            let mut db = engine(dir.path());
            db.execute("CREATE TABLE vault (owner TEXT, secret TEXT ENCRYPTED)")
                .unwrap();
            db.execute(&format!("INSERT INTO vault VALUES ('alice', '{secret}')"))
                .unwrap();
        }
        // Scan every file in the data directory for the plaintext.
        for entry in std::fs::read_dir(dir.path()).unwrap() {
            let path = entry.unwrap().path();
            let bytes = std::fs::read(&path).unwrap();
            assert!(
                !contains_subslice(&bytes, secret.as_bytes()),
                "plaintext secret leaked into {path:?}"
            );
            assert!(
                !contains_subslice(&bytes, b"alice"),
                "plaintext value leaked into {path:?}"
            );
            // Table and column names are sealed inside the catalog too.
            assert!(
                !contains_subslice(&bytes, b"owner"),
                "column name leaked into {path:?}"
            );
        }
        // And yet the data is fully queryable with the right key.
        let mut db = engine(dir.path());
        let results = db
            .execute("SELECT secret FROM vault WHERE owner = 'alice'")
            .unwrap();
        assert_eq!(
            results,
            vec![QueryResult::Rows {
                columns: vec!["secret".into()],
                rows: vec![vec![Value::Text(secret.into())]],
            }]
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
        let results = db.execute("SELECT * FROM t").unwrap();
        assert_eq!(
            results,
            vec![QueryResult::Rows {
                columns: vec!["a".into()],
                rows: vec![]
            }]
        );
    }

    fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }
}
