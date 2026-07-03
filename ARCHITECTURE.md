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
| `ciphra-net` | Remote-storage protocol: blind server + client (ADR-0003) | storage |
| `ciphra-server` | Server binary — stores sealed bytes, holds no keys | net, storage |
| `ciphra` | CLI / REPL binary | engine |
| `ciphra-testutil` | Test-only temp-dir helper | — |

`ciphra-server` deliberately cannot depend on `ciphra-crypto`: the
server's blindness is enforced by the dependency graph, not by
promises. The three foundation crates are deliberately independent
of each other;
`ciphra-engine` is the composition point. This keeps the trusted
computing base explicit: anything that can see plaintext lives in
`ciphra-engine` and `ciphra-crypto`.

## Storage engine (v0)

A single write-ahead log plus an in-memory `BTreeMap`.

- Record: `crc32(payload) | len | payload`; a payload is one put/delete
  or a *batch* of them (`Storage::commit`), which is how the engine
  writes every SQL statement: one WAL record, one fsync, and — because
  the whole batch sits under one checksum — all-or-nothing replay.
  A mutation that returned `Ok` is durable.
- On open the log is replayed; a checksum failure or truncated record
  marks the torn tail from a crash, which is cut off.
- `compact()` rewrites the log to the live state via tmp-file + rename.

Chosen for correctness-first simplicity: the API (`put`/`get`/`delete`/
`scan_prefix`) is the contract; memtable+SSTable/LSM layering, MVCC and
concurrent access replace the internals later without touching callers.

## Cryptography

### Key hierarchy

```
passphrase ── Argon2id(salt, m, t, p) ─────────────► MasterKey   (memory only)
              (PBKDF2-HMAC-SHA256 for pre-Argon2 databases)
MasterKey  ── HKDF-SHA256("catalog")               ──► catalog key
MasterKey  ── HKDF-SHA256("table:<name>")          ──► per-table key
MasterKey  ── HKDF-SHA256("canary")                ──► canary key
MasterKey  ── HMAC(HKDF("tag:table-name"), name)   ──► opaque table tag (16 bytes)
```

- The salt and KDF parameters are recorded as a plaintext entry inside
  the WAL (they are not secret; tampering only yields BadPassphrase
  because the canary stops decrypting). An existing database always
  opens with the parameters it was created with; legacy sidecar
  `ciphra.keyparams` files are migrated on open. Argon2id defaults:
  19 MiB, t=2, p=1 (OWASP).
- A sealed canary value is checked on open so a wrong passphrase fails
  fast and loudly, instead of surfacing as "corrupt data" later.

### Key rotation

`Engine::rotate_to` (CLI: `--rotate-passphrase`) re-encrypts the whole
database under a new passphrase and KDF: everything derived from the
master key changes — sealed values, table tags, index value tags — so
the keyspace is rebuilt into a scratch WAL, which then replaces the
live one with a single atomic rename. A crash before the rename leaves
the old database untouched (the scratch directory is swept on the next
open); a crash after it leaves the new database complete. Keeping the
KDF parameters inside the WAL is what makes the database a single file
and the swap atomic.

### Audit chain

Every mutating statement appends a sealed entry to a hash chain:
`root_i = SHA-256(entry_i)` where the entry contains the previous root,
a sequence number, a timestamp, the statement kind, the opaque table
tag and a digest over the statement's sealed writes. The entry commits
in the *same atomic batch* as the data it describes, so history and
data cannot disagree. Entries contain no user plaintext — a published
root cannot be used to brute-force secret content.

What it adds on top of AEAD: per-value encryption already stops
*modification*, but an attacker with file access could still delete
whole WAL records or roll the entire file back to an older valid state.
The chain makes both evident: `.audit verify` recomputes the chain from
genesis (catching deletion, reordering and splicing), and comparing
`.audit root` against an externally recorded `(seq, root)` pair catches
whole-file rollback — the one check that inherently needs a reference
point outside the attacker's reach. Key rotation carries the chain
across (roots are over plaintext entries, so re-sealing preserves them)
and records itself as a ROTATE entry.

v1 is a linear hash chain — the degenerate Merkle case; a tree for
O(log n) inclusion proofs is the planned upgrade and changes no on-disk
entry, only adds structure above it.

### Sealing

Envelope: `nonce (12, random per seal) | ciphertext | tag (16)` using
ChaCha20-Poly1305 (RFC 8439). The AAD is the full storage key of the
object (e.g. `r\0users\0<rowid>`), which binds every ciphertext to its
location: an attacker who can edit the files cannot swap row 5 into row
7, move a row between tables, or replay an old catalog entry without
the tag check failing.

What is sealed: every stored value — rows, table schemas (including
the table name and column names), and row-id sequences.

### Table tags

Storage keys cannot contain random nonces (lookups must be repeatable),
so tables are addressed by a deterministic keyed tag:
`HMAC-SHA256(master-derived tag key, table name)`, truncated to 16
bytes. Without the master key a tag reveals nothing about the name; the
only leakage is equality (the same table always maps to the same tag
within one database). The real name is recovered by decrypting the
catalog record, which is how `.tables` works.

### Queryable encryption: three mechanisms, three leakage profiles

| Mechanism | Serves | On-disk leakage |
|---|---|---|
| Keyed value tags (PK + `CREATE INDEX`) | `WHERE col = x` | equality repetitions of the column (deterministic-encryption class) |
| Sealed range index (`CREATE RANGE INDEX`) | `< <= > >= =` comparisons | **none about values or order** — only total blob size and update frequency |
| Full scan (always available) | everything else | none |

The sealed range index is one sorted `(value, row id)` list per column,
kept entirely inside a single ciphertext. Because the ordering lives
*inside* the envelope, disk shows nothing an OPE/ORE scheme would leak
— no order, no equality. The price is honest too: every mutation of the
column re-seals the whole blob (O(n) write amplification), which is the
right trade for small-to-medium tables; chunked sealed pages are the
planned upgrade for large ones. Queries pay one blob decrypt and then
fetch only matching rows. Indexes of both kinds are opt-in per column,
never created silently.

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
- **History tampering**: deleting/reordering audit entries breaks the
  chain; rolling the whole file back is caught by comparing the current
  audit root against one recorded externally.

NOT protected against (yet — see ROADMAP):

- **Metadata leakage**: row count, row sizes, table count and write
  patterns are visible. Names (tables and columns) and values are not:
  since format v2 no user-produced plaintext appears on disk.
- **A compromised host at runtime**: the master key lives in process
  memory while the engine is open. Memory-safety of Rust helps; it is
  not a defense against root.
- **Passphrase quality**: Argon2id makes brute force memory-expensive;
  it cannot save a truly weak passphrase.
- **Side channels beyond cache timing**: no claims yet.

## SQL engine (v0)

Dialect: `CREATE TABLE` (INT/TEXT/VECTOR(dim), `ENCRYPTED` column
marker), `INSERT`
(multi-row, optional column list), `SELECT` (projection, compound
`WHERE` with `AND`/`OR`/`NOT`/parentheses/`IS [NOT] NULL`, `ORDER BY
... ASC|DESC`, `LIMIT ... OFFSET`), `UPDATE ... SET`, `DELETE`,
`DROP TABLE`. Predicates follow SQL three-valued logic: comparisons
with NULL are *unknown* and filter the row out, and Kleene rules apply
through AND/OR/NOT. Execution is a straight scan-filter-sort-project
over `scan_prefix` — no planner yet, by design: the planner earns its
complexity only once secondary indexes exist.

Vector columns hold fixed-dimension f32 embeddings written as
`[0.1, -2, 0.5]` literals. They have no order: comparisons, plain
`ORDER BY` and all index kinds are rejected with a pointed error;
`ORDER BY col NEAREST TO [..] LIMIT k` runs an exact brute-force cosine
scan over decrypted candidate rows (nearest first, NULLs last). Exact
search over sealed rows adds no leakage beyond the query itself; a
sealed ANN structure for large corpora is the planned upgrade.

The `ENCRYPTED` marker is accepted and recorded in the schema today
(all rows are sealed regardless); it reserves the syntax for per-column
queryable-encryption levels, which will need it.

## Key storage layout

```
\x00canary                  sealed wrong-passphrase detector
z\x00<tag16><col>           sealed range-index blob (sorted values + row ids)
\x00catalog\x00<tag16>      sealed schema (incl. the real table name)
\x00seq\x00<tag16>          sealed next row id (u64)
r\x00<tag16><id BE>         sealed row (big-endian id keeps key order = insert order)
x\x00<tag16><col><vtag16><id BE>  sealed marker — equality-index entry
```

`<tag16>` is the opaque table tag described above — no plaintext table
names appear in keys. `<vtag16>` is the same construction applied to a
column *value* (`HMAC(master-derived per-column key, encoded value)`),
so `WHERE col = x` on an indexed column is a prefix scan that never
materializes the value on disk. One format serves both index kinds: the
PRIMARY KEY additionally enforces uniqueness (its value prefix may hold
at most one entry), while `CREATE INDEX` columns are non-unique — the
row id in the key distinguishes entries.

Leakage, stated plainly: a secondary index reveals *repetitions* of the
indexed column across rows (like deterministic encryption) — that is
why indexes are opt-in per column and never created silently. PK values
are unique among live rows, so their tags repeat only across
delete/re-insert cycles. `INSERT` validates a whole batch (types,
arity, PK) before writing anything, and every statement commits as one
atomic WAL record — rows, index entries and sequence together. Readers
still treat a dangling index entry as absent, as defense in depth.
