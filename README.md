# Ciphra

**An encrypted-by-default SQL database, written from scratch in Rust.**

Every row is sealed with ChaCha20-Poly1305 before it touches disk. The
encryption key never leaves the client side of the engine — it is derived
from your passphrase and exists only in memory. Grep the database files
all you want: there is no plaintext in them.

```
$ export CIPHRA_PASSPHRASE='correct horse battery staple'
$ ciphra --data ./db
ciphra> CREATE TABLE users (id INT, name TEXT, ssn TEXT ENCRYPTED);
created table users
ciphra> INSERT INTO users VALUES (1, 'alice', '111-22-3333'), (2, 'bob', '444-55-6666');
inserted 2 rows
ciphra> SELECT name, ssn FROM users WHERE id >= 2;
+------+-------------+
| name | ssn         |
+------+-------------+
| bob  | 444-55-6666 |
+------+-------------+
1 row

$ grep -c 'alice\|111-22-3333\|users\|ssn' db/ciphra.wal
0
$ CIPHRA_PASSPHRASE='wrong' ciphra --data ./db -e 'SELECT * FROM users;'
error: wrong passphrase for this database
```

> **Status: v0, pre-alpha.** Ciphra is in active early development. Do not
> put production data in it yet. The on-disk format will change.

## Why

Databases treat encryption as an afterthought: a TDE checkbox, a plugin,
a cloud KMS toggle — and the server still sees your plaintext. Ciphra is
built the other way around: the storage engine *never* receives plaintext,
and the roadmap builds toward queryable encryption, a post-quantum-ready
key exchange, and a tamper-evident audit log as first-class features
rather than add-ons.

## What works today

- **SQL engine written from scratch**: hand-written lexer/parser —
  `CREATE TABLE`, `INSERT`, `SELECT`, `UPDATE`, `DELETE`, `DROP TABLE`;
  compound `WHERE` (`AND`/`OR`/`NOT`, parentheses, `IS [NOT] NULL`)
  with proper SQL three-valued logic; `ORDER BY` / `LIMIT` / `OFFSET`;
  aggregates (`COUNT`/`SUM`/`AVG`/`MIN`/`MAX`) with `GROUP BY` and
  `HAVING`; typed columns (`INT`, `REAL`, `TEXT`). Aggregates run in the
  engine over decrypted rows, so they carry the same leakage profile as
  a plain `SELECT`.
- **`PRIMARY KEY`** with uniqueness and non-NULL enforcement, backed by
  an encrypted equality index: `WHERE pk = x` is a point lookup, not a
  scan — and the index stores only keyed tags of values, never values.
- **Range queries over encrypted data** (`CREATE RANGE INDEX ON t
  (col)`): a sorted value list sealed inside a single ciphertext —
  unlike OPE/ORE, the disk learns nothing about order or equality, only
  the blob's size. `WHERE amount >= x` decrypts one blob and fetches
  only matching rows.
- **Secondary indexes** (`CREATE INDEX ON t (col)` / `DROP INDEX`):
  the same value-tag construction, non-unique, backfilled on creation
  and maintained by every INSERT/UPDATE/DELETE. Opt-in per column, with
  a documented leakage profile (equality repetitions only).
- **Durable storage engine**: checksummed write-ahead log with crash
  recovery (torn writes are detected via CRC-32 and truncated) and log
  compaction.
- **Encryption at rest by construction**: per-table keys derived from a
  passphrase (Argon2id → HKDF-SHA256), whole-row ChaCha20-Poly1305 with
  AAD binding each ciphertext to its table and row id — encrypted rows
  cannot be swapped or replayed undetected. Argon2id (memory-hard,
  RFC 9106) is the default KDF; databases created with PBKDF2 keep
  opening with their recorded parameters.
- **No user plaintext on disk at all**: values, column names *and table
  names*. Tables are addressed in storage by opaque keyed tags
  (HMAC under a master-derived key); the real name lives only inside
  the sealed catalog record.
- **Zero third-party dependencies.** The entire engine — including
  SHA-256, HMAC, HKDF, PBKDF2, ChaCha20, Poly1305, BLAKE2b, Argon2id,
  SHA-3/SHAKE, X25519, ML-KEM-768 and ML-DSA-65 — is implemented in this
  repository and verified against official RFC/NIST/FIPS test vectors.
  The supply chain is: the Rust standard library, and this repo.
- **Vector search over encrypted embeddings**: `VECTOR(dim)` columns
  and `ORDER BY emb NEAREST TO [0.1, ...] LIMIT k` — exact cosine
  similarity computed over sealed rows, so Ciphra doubles as an
  encrypted vector store for RAG workloads.
- **Tamper-evident audit chain, post-quantum signed, with inclusion
  proofs**: every mutating statement appends a sealed hash-chain entry
  in the same atomic commit as its data. `.audit verify` re-checks all
  of history; `.audit sign` signs the current root with **ML-DSA-65**
  (FIPS 204, from scratch) under a key derived from the passphrase —
  publish the signature and anyone can verify offline, with no
  passphrase and no way for a quantum adversary to forge a rolled-back
  root. `.audit prove <n>` emits an **O(log n) Merkle inclusion proof**:
  a compact, publicly verifiable receipt that one specific statement is
  recorded in history, checkable against the signed Merkle root.
- **Key rotation**: `ciphra --rotate-passphrase` re-encrypts the whole
  database under a new passphrase (new salt, new KDF, new table and
  index tags) with an atomic file swap — a crash cannot strand the
  database between two keys.
- **Client/server with a blind server** (`ciphra-server` +
  `ciphra --remote host:port`): the server stores sealed bytes and
  *cannot* decrypt them. The connection runs a **hybrid post-quantum
  handshake** — X25519 + ML-KEM-768, all implemented from scratch — so
  the channel is forward-secret, server-authenticated (pin the printed
  key with `--server-key`), and safe against harvest-now-decrypt-later.
  SQL, keys and plaintext never leave the client (ADR-0003).
- **Replication (log shipping)**: `ciphra-server --follow <leader>`
  runs a read-only replica that subscribes to the leader's commit
  stream — it receives a sealed snapshot, then every subsequent commit
  in order, and applies them into its own store. Since the whole stream
  is sealed bytes, the replica is as blind as the leader: it mirrors the
  ciphertext without ever seeing a key. Replicas can be chained.
- **Language drivers for Python, Go and JavaScript**: a small C ABI
  (`ciphra-ffi`) exposes the engine so each driver runs the *real* Rust
  engine in-process — encryption and keys stay on the client, and for a
  remote database only sealed bytes reach the blind server. Each binding
  is standard-library only (`ctypes`, `cgo`, `bun:ffi`), no packages to
  install. See [drivers/](drivers/).
- **Sealed backup/restore**: `--backup file` exports one
  self-contained encrypted snapshot (audit chain included);
  `--restore file` verifies the passphrase and the chain before use.
- **Light MySQL migration**: `ciphra --import-mysql dump.sql` translates
  a `mysqldump` file into Ciphra — mapping MySQL types to `INT`/`REAL`/
  `TEXT`, stripping backticks and engine/charset clauses, turning
  single-column `KEY`s into indexes, and skipping the rest with notes.
  The imported database is encrypted at rest like any other.
- **Index advisor**: `.advise` watches this session's queries — which
  columns are filtered by equality vs range, and how many rows the
  unindexed ones scan — and suggests the `CREATE INDEX` / `CREATE RANGE
  INDEX` statements that would help most. The telemetry is in-memory
  only (it describes *which columns you query*, so it never touches
  disk).
- **CLI/REPL** with meta commands (`.tables`, `.schema`, `.audit`,
  `.help`).

## Usage

### Build

```sh
cargo build --release
# binaries land in ./target/release/: `ciphra` (client/REPL) and
# `ciphra-server` (the blind storage server)
```

### The passphrase

Every database is sealed under a passphrase supplied through the
`CIPHRA_PASSPHRASE` environment variable — it is never a command-line
argument (that would leak it into shell history and the process table)
and it never touches disk. Lose it and the data is unrecoverable; that
is the point.

```sh
export CIPHRA_PASSPHRASE='correct horse battery staple'
```

### Local database (single node)

```sh
# Interactive REPL against ./mydb (created on first use)
./target/release/ciphra --data ./mydb

# One-shot: run a statement (or several, ';'-separated) and exit
./target/release/ciphra --data ./mydb -e 'SELECT * FROM users;'
```

Inside the REPL, SQL statements run directly; lines starting with `.`
are meta commands:

```
ciphra> CREATE TABLE users (id INT PRIMARY KEY, name TEXT, ssn TEXT ENCRYPTED);
ciphra> INSERT INTO users VALUES (1, 'alice', '111-22-3333');
ciphra> SELECT name, ssn FROM users WHERE id = 1;
ciphra> SELECT count(*), max(id) FROM users;          -- aggregates
ciphra> SELECT name, count(*) FROM users GROUP BY name;
ciphra> .tables                 -- list tables
ciphra> .schema users           -- show a table's columns
ciphra> .audit verify           -- re-check the whole tamper-evident chain
ciphra> .audit root             -- print the current audit root to publish
ciphra> .audit sign             -- ML-DSA-65 signature over the root (post-quantum)
ciphra> .audit pubkey           -- the audit signing public key (publish once)
ciphra> .audit prove 2          -- Merkle inclusion proof that entry 2 is in history
ciphra> .advise                 -- suggest indexes from this session's query patterns
ciphra> .help                   -- SQL cheatsheet
ciphra> .exit
```

### Queryable encryption

```sql
-- Point lookups through an encrypted equality index (keyed tags only):
CREATE TABLE t (id INT PRIMARY KEY, email TEXT ENCRYPTED);
CREATE INDEX ON t (email);            -- opt-in equality index
SELECT * FROM t WHERE email = 'a@b.c';

-- Range queries over a sealed sorted blob (leaks neither order nor
-- equality to disk — only the blob's size):
CREATE RANGE INDEX ON t (id);
SELECT * FROM t WHERE id >= 100 AND id < 200;

-- Vector similarity search over sealed embeddings (encrypted RAG store):
CREATE TABLE docs (id INT PRIMARY KEY, body TEXT, emb VECTOR(3));
SELECT id FROM docs ORDER BY emb NEAREST TO [0.1, 0.9, 0.2] LIMIT 5;
```

### Key rotation, backup and restore

```sh
# Re-encrypt the whole database under a new passphrase (atomic swap):
CIPHRA_PASSPHRASE='old' CIPHRA_NEW_PASSPHRASE='new' \
  ./target/release/ciphra --data ./mydb --rotate-passphrase

# Export one self-contained sealed snapshot (audit chain included):
./target/release/ciphra --data ./mydb --backup mydb.ciphra

# Restore it (verifies the passphrase and the audit chain first):
./target/release/ciphra --data ./restored --restore mydb.ciphra
```

### Migrate from MySQL

Point Ciphra at a `mysqldump` file to import its schema and data into a
fresh encrypted database. Unsupported constructs are skipped with notes.

```sh
mysqldump mydb > dump.sql                       # on the MySQL side
export CIPHRA_PASSPHRASE='pick a long passphrase'
./target/release/ciphra --data ./mydb --import-mysql dump.sql
#   imported from dump.sql: 4 statement(s) applied (1200 row(s)), 0 failed, 2 note(s)
./target/release/ciphra --data ./mydb -e 'SELECT COUNT(*) FROM employees;'
```

MySQL types map to `INT` / `REAL` / `TEXT` (`DECIMAL` becomes `REAL`, so
exact decimal precision is not kept); a single-column `KEY`/`UNIQUE`
becomes a Ciphra index; `SET`, `LOCK TABLES`, foreign keys, triggers and
the like are skipped. Review the printed notes after importing.

### Client / server (blind server)

The server stores sealed bytes and holds no keys. Run it, then point a
client at it — the engine, passphrase and all plaintext stay client-side.

```sh
# 1. Start the server. It prints a transport key on first boot — pin it.
./target/release/ciphra-server --data ./srv --listen 127.0.0.1:5077
#   server key (pin this on clients with --server-key):
#     3af1…e09c

# 2. Connect a client, pinning that key so the handshake is authenticated
#    (X25519 + ML-KEM-768, forward-secret and post-quantum):
export CIPHRA_PASSPHRASE='correct horse battery staple'
./target/release/ciphra --remote 127.0.0.1:5077 --server-key 3af1…e09c
```

Without `--server-key` the channel is still encrypted and post-quantum
but trust-on-first-use (open to a man-in-the-middle); the client warns.

### Replication (read replica)

A replica subscribes to a leader's commit stream and mirrors it. It is
read-only for clients and as blind as the leader.

```sh
# Leader (as above):
./target/release/ciphra-server --data ./leader --listen 127.0.0.1:5077
#   server key: 3af1…e09c

# Replica: follow the leader, pin its key, serve reads on another port:
./target/release/ciphra-server \
    --follow 127.0.0.1:5077 --server-key 3af1…e09c \
    --data ./replica --listen 127.0.0.1:5078

# Clients can read from the replica (writes are refused there):
./target/release/ciphra --remote 127.0.0.1:5078 --server-key <replica-key>
```

### Language drivers (Python / Go / JavaScript)

Embed Ciphra in your app through a thin, dependency-free binding over
`libciphra`. The engine runs in-process, so keys and plaintext stay on
the client; for a remote database only sealed bytes reach the server.

```sh
cargo build --release -p ciphra-ffi   # builds libciphra the drivers link against
```

```python
from ciphra import Ciphra                       # drivers/python (ctypes)
with Ciphra.open("./mydb", "pick a long passphrase") as db:
    db.execute("CREATE TABLE t (id INT PRIMARY KEY, note TEXT ENCRYPTED)")
    db.execute("INSERT INTO t VALUES (1, 'hello')")
    print(db.query("SELECT id, note FROM t"))    # [{'id': 1, 'note': 'hello'}]
```

Go (`cgo`) and JavaScript (Bun, `bun:ffi`) drivers expose the same API —
see [drivers/README.md](drivers/README.md).

## Architecture

```
┌─────────────────────────────────────────────────┐
│ ciphra (CLI / REPL)                             │
├─────────────────────────────────────────────────┤
│ ciphra-engine    catalog · row codec · executor │
├──────────────────────────┬──────────────────────┤
│ ciphra-sql               │ ciphra-crypto        │
│ lexer · parser · AST     │ KDF · HKDF · AEAD    │
├──────────────────────────┴──────────────────────┤
│ ciphra-storage   WAL · ordered KV · recovery    │
└─────────────────────────────────────────────────┘
```

Plaintext stops at the engine boundary: `ciphra-storage` only ever sees
sealed bytes. See [ARCHITECTURE.md](ARCHITECTURE.md) for the full design,
including the honest threat model — what v0 protects against and what it
deliberately does not yet.

## Roadmap (abridged)

- **Phase 1** ✅ — richer SQL, encrypted table names, primary keys,
  secondary indexes, Argon2id KDF, key rotation, `EXPLAIN`,
  benchmark baseline ([docs/BENCHMARKS.md](docs/BENCHMARKS.md)).
- **Phase 2** — queryable encryption (deterministic/order-revealing
  layers with an explicit leakage profile), Merkle-tree audit log,
  vector type + similarity search.
- **Phase 3** — wire protocol + drivers, replication, post-quantum key
  exchange (ML-KEM) for the transport, external security audit.

The full plan lives in [ROADMAP.md](ROADMAP.md).

## Development

```sh
cargo test          # all tests, including RFC/NIST crypto vectors
cargo clippy --all-targets
cargo fmt --check
cargo run --release -p ciphra-bench   # honest numbers: docs/BENCHMARKS.md
```

Design decisions are recorded in [docs/adr/](docs/adr/).

## Security

Ciphra has **not** been audited. The v0 crypto implementations follow the
primary specifications and pass official test vectors, but until an
external audit lands, treat this as a development-grade system. Found
something? Please open a security advisory rather than a public issue.

For operators whose trust anchor is a specific audited library, an opt-in
`audited` Cargo feature is the seam for building against audited
third-party crypto crates instead of the from-scratch primitives, behind
the same `ciphra-crypto` API. It fails closed (enabling it without
providing the backend is a build error, never a silent fallback); the
design and exact crate mapping are in
[ADR-0004](docs/adr/0004-audited-crypto-backend.md).

## Support the project

Ciphra is built in the open with no third-party dependencies. If it is
useful to you, donations help fund the work toward an external security
audit:

- **BTC** — `bc1qlakzxqgaahuqf7newzfc4dfnhk4knnm4pht6q3`
- **ETH** — `0x6be4c971f7c7e765ab92a9f1eed4098ffdf77805`

## License

[Apache-2.0](LICENSE)
