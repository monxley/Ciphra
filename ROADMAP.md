# Ciphra Roadmap

Positioning: not "a faster MySQL" — the encrypted-by-default database
whose crypto features are the product. Ship narrow and honest; widen
later.

## Phase 0 — Foundation ✅

- [x] Workspace: storage / crypto / sql / engine / cli crates
- [x] WAL storage with checksums, crash recovery, compaction
- [x] Zero-dependency crypto: SHA-256, HMAC, HKDF, PBKDF2,
      ChaCha20-Poly1305 — all against official test vectors
- [x] Key hierarchy (passphrase → master → per-table), AAD binding
- [x] SQL v0: CREATE/INSERT/SELECT/DELETE/DROP, INT/TEXT/NULL
- [x] REPL + `-e` execution, encrypted-at-rest end-to-end test
- [x] CI: fmt, clippy, tests

## Phase 1 — A real single-node database

- [x] `UPDATE`, `AND`/`OR`/`NOT`/`IS NULL` predicates (SQL three-valued
      logic), `ORDER BY`, `LIMIT`/`OFFSET`
- [x] Aggregates `COUNT`/`SUM`/`MIN`/`MAX` with `GROUP BY` (computed in
      the engine over decrypted rows; same leakage as a plain `SELECT`)
- [x] Encrypted table names via opaque keyed tags (no user plaintext
      on disk at all)
- [x] Primary keys: uniqueness + non-NULL enforcement, point lookups
      through an encrypted equality index (keyed value tags)
- [x] Secondary indexes: `CREATE INDEX` / `DROP INDEX` with backfill,
      unified entry format with the PK index, opt-in equality leakage
- [x] Argon2id as the default KDF (BLAKE2b + Argon2id from RFC
      7693/9106, RFC test vectors; PBKDF2 databases keep opening)
- [x] Key rotation: whole-database re-encryption under a new
      passphrase/KDF with an atomic WAL swap (`--rotate-passphrase`)
- [x] `EXPLAIN` for SELECT/UPDATE/DELETE (access path, filter,
      sort, limit — without executing)
- [x] Benchmark harness + baseline numbers (docs/BENCHMARKS.md);
      vs-SQLite script included, needs an environment with sqlite3

## Phase 2 — The crypto features that justify the name

- [x] Group commit: one fsync + one atomic (all-or-nothing) WAL
      record per statement — 34x on inserts, crash-atomic statements

- [x] Queryable encryption with explicit leakage profiles: equality
      via keyed tags (deterministic class); range via *sealed* sorted
      blobs that leak neither order nor equality — strictly less than
      OPE/ORE, at O(n) re-seal cost per mutation. Opt-in per column,
      never silent. (Chunked sealed pages for large tables: planned)
- [x] Tamper-evident audit chain: sealed hash-chain entry per
      statement, committed atomically with its data; `.audit
      root`/`.audit verify`; rollback detection via external roots.
      Merkle tree over the entries gives O(log n) inclusion proofs
      (`.audit prove <n>`), verifiable against the signed Merkle root.
- [x] `VECTOR(dim)` type + `ORDER BY col NEAREST TO [..]` similarity
      search: exact brute-force cosine over sealed rows (sealed-blob
      ANN index for large corpora: planned)
- [x] Backup/restore: `--backup` writes a compacted sealed snapshot
      (single self-contained file, audit chain included); `--restore`
      verifies passphrase + chain and refuses to overwrite

## Phase 3 — Multi-node and hardening

- [x] Wire protocol v1: blind-server storage protocol (ADR-0003),
      `ciphra-server` binary + `--remote` client; plaintext and keys
      never cross the wire
- [x] Python/JS/Go drivers: a C ABI (`ciphra-ffi`) runs the engine
      in-process; thin stdlib-only bindings (`ctypes`, `cgo`, `bun:ffi`),
      local and remote, keys never leaving the client (drivers/)
- [x] Transport security: hybrid X25519 + ML-KEM-768 handshake
      (SHA-3/SHAKE, X25519 RFC 7748, ML-KEM-768 FIPS 203 — all from
      scratch), forward-secret + server-authenticated encrypted
      channel; `--server-key` pinning
- [x] Replication (log shipping): `ciphra-server --follow` runs a
      read-only replica that subscribes to the leader's commit stream —
      sealed snapshot, then ordered sealed batches — and applies them
      into its own blind store; replicas can be chained
- [x] Post-quantum key exchange (ML-KEM) — done in the transport above
- [x] ML-DSA-signed audit roots: ML-DSA-65 (FIPS 204) implemented from
      scratch; `.audit sign` signs the current root with a key
      deterministically derived from the passphrase, so a published root
      is verifiable offline by anyone (no passphrase) and unforgeable by
      a quantum adversary
- [ ] Optional build against audited crypto implementations
- [ ] External security audit — a release blocker for 1.0

## Phase 4 — 1.0 and beyond

- [ ] Managed cloud offering
- [ ] NL→SQL assistant (generates SQL, shows it, runs after approval)
- [ ] AI index advisor over slow-query telemetry

## Non-goals (v0–v2)

- MySQL/Postgres wire compatibility (revisit at Phase 3)
- Distributed transactions
- Being the fastest database in any benchmark that ignores encryption
