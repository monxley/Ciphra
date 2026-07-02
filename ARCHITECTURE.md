# Ciphra Architecture

This document describes the system as it exists (v0), plus the
constraints that shaped it. Decisions with alternatives worth recording
live in [docs/adr/](docs/adr/).

## Crate layout

| Crate | Role | Depends on |
|---|---|---|
| `ciphra-storage` | Durable ordered key-value store: WAL + in-memory BTree | — |
| `ciphra-crypto` | Primitives (SHA-256, HMAC, HKDF, PBKDF2, ChaCha20-Poly1305), key hierarchy | — |
| `ciphra-sql` | Lexer, recursive-descent parser, AST | — |
| `ciphra-engine` | Catalog, row codec, executor; the only place plaintext and ciphertext meet | storage, crypto, sql |
| `ciphra` | CLI / REPL binary | engine |
| `ciphra-testutil` | Test-only temp-dir helper | — |

The three foundation crates are deliberately independent of each other;
`ciphra-engine` is the composition point. This keeps the trusted
computing base explicit: anything that can see plaintext lives in
`ciphra-engine` and `ciphra-crypto`.

## Storage engine (v0)

A single write-ahead log plus an in-memory `BTreeMap`.

- Record: `crc32(payload) | len | payload`, payload = op, key, value.
- Every mutation is appended and fsynced before the in-memory table is
  updated; a put/delete that returned `Ok` is durable.
- On open the log is replayed; a checksum failure or truncated record
  marks the torn tail from a crash, which is cut off.
- `compact()` rewrites the log to the live state via tmp-file + rename.

Chosen for correctness-first simplicity: the API (`put`/`get`/`delete`/
`scan_prefix`) is the contract; memtable+SSTable/LSM layering, MVCC and
concurrent access replace the internals later without touching callers.

## Cryptography

### Key hierarchy

```
passphrase ── PBKDF2-HMAC-SHA256(salt, iterations) ──► MasterKey   (memory only)
MasterKey  ── HKDF-SHA256("catalog")               ──► catalog key
MasterKey  ── HKDF-SHA256("table:<name>")          ──► per-table key
MasterKey  ── HKDF-SHA256("canary")                ──► canary key
```

- The salt and iteration count are stored in `ciphra.keyparams` (they
  are not secret). The master key and everything below it never touch
  disk.
- A sealed canary value is checked on open so a wrong passphrase fails
  fast and loudly, instead of surfacing as "corrupt data" later.

### Sealing

Envelope: `nonce (12, random per seal) | ciphertext | tag (16)` using
ChaCha20-Poly1305 (RFC 8439). The AAD is the full storage key of the
object (e.g. `r\0users\0<rowid>`), which binds every ciphertext to its
location: an attacker who can edit the files cannot swap row 5 into row
7, move a row between tables, or replay an old catalog entry without
the tag check failing.

What is sealed: every stored value — rows, table schemas (including
column names), and row-id sequences.

### Why hand-written primitives?

The core is dependency-free by policy (see ADR-0002): for an encrypted
database, "audit the supply chain" should mean "read this repo". All
primitives are implemented from the primary specs and verified against
official test vectors (NIST for SHA-256; RFC 4231, 5869, 7914, 8439).
ChaCha20 was chosen over AES specifically because a straightforward
software implementation has no secret-indexed table lookups, i.e. no
cache-timing side channel. The planned upgrade path is optional builds
against audited implementations once an external audit of ours exists —
behind the same `ciphra-crypto` API either way.

## Threat model (v0) — read this honestly

Protected against:

- **Disk theft / file read**: all values are ciphertext; without the
  passphrase nothing decrypts.
- **File tampering**: any bit flip, row swap, cross-table replay or
  truncation of a value fails AEAD verification. WAL corruption is
  additionally caught by CRC (integrity of *storage*, not secrecy).
- **Wrong-key confusion**: canary check refuses to open.

NOT protected against (yet — see ROADMAP):

- **Metadata leakage**: table *names* appear in storage keys; row count,
  row sizes and write patterns are visible. Column names are sealed.
- **A compromised host at runtime**: the master key lives in process
  memory while the engine is open. Memory-safety of Rust helps; it is
  not a defense against root.
- **Passphrase quality**: PBKDF2 slows brute force; it cannot save a
  weak passphrase. Argon2id (memory-hard) is the planned default.
- **Side channels beyond cache timing**: no claims yet.

## SQL engine (v0)

Dialect: `CREATE TABLE` (INT/TEXT, `ENCRYPTED` column marker), `INSERT`
(multi-row, optional column list), `SELECT` (projection, single
comparison predicate), `DELETE`, `DROP TABLE`. Execution is a straight
scan-filter-project over `scan_prefix` — no planner yet, by design: the
planner earns its complexity only once secondary indexes exist.

The `ENCRYPTED` marker is accepted and recorded in the schema today
(all rows are sealed regardless); it reserves the syntax for per-column
queryable-encryption levels, which will need it.

## Key storage layout

```
\x00canary                  sealed wrong-passphrase detector
\x00catalog\x00<table>      sealed schema
\x00seq\x00<table>          sealed next row id (u64)
r\x00<table>\x00<id BE>     sealed row (big-endian id keeps key order = insert order)
```
