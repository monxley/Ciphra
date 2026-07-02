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

- [ ] Queryable encryption layers with an explicit, documented leakage
      profile (equality via deterministic tags; range via order-revealing
      structures — opt-in per column, never silent)
- [x] Tamper-evident audit chain: sealed hash-chain entry per
      statement, committed atomically with its data; `.audit
      root`/`.audit verify`; rollback detection via external roots.
      (Merkle tree for O(log n) inclusion proofs: planned upgrade)
- [ ] `VECTOR` type + similarity search over encrypted embeddings
- [ ] Backup/restore, snapshot export (sealed)

## Phase 3 — Multi-node and hardening

- [ ] Wire protocol + Python/JS/Go drivers
- [ ] Replication (log shipping first)
- [ ] Post-quantum transport: ML-KEM key exchange, ML-DSA-signed
      audit roots
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
