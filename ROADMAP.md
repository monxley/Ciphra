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
- [ ] Primary keys and secondary indexes (over sealed values;
      leakage-free point lookups first)
- [ ] Argon2id as the default KDF (memory-hard; PBKDF2 kept for compat)
- [ ] Key rotation: re-seal a table under a new master
- [ ] `EXPLAIN`, basic statistics
- [ ] Benchmarks vs SQLite (honest numbers, encryption cost included)

## Phase 2 — The crypto features that justify the name

- [ ] Queryable encryption layers with an explicit, documented leakage
      profile (equality via deterministic tags; range via order-revealing
      structures — opt-in per column, never silent)
- [ ] Tamper-evident audit log: Merkle tree over all mutations,
      externally verifiable roots
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
