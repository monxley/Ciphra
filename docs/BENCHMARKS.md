# Benchmarks

Honest numbers, encryption cost included. There is no "fast mode" to
quietly compare against: whole-row ChaCha20-Poly1305, keyed index tags
and one durable fsync per statement (group commit) are the only path.

## Running

```sh
cargo run --release -p ciphra-bench -- --rows 10000
scripts/bench-vs-sqlite.sh 10000     # needs the sqlite3 CLI
```

The workload is a single table `(id INT PRIMARY KEY, grp TEXT, payload
TEXT)` with a secondary index on `grp` (100 distinct values), exercised
through the SQL layer end to end.

## Baseline (v0, containerized Linux, 2026-07)

Numbers from a shared, containerized environment — treat them as an
order of magnitude, not a datasheet; run the harness on your hardware.

| Operation | Throughput |
|---|---|
| Argon2id open (19 MiB, t=2) — one-time | ~110 ms |
| `INSERT` (batches of 100) | ~13,000 rows/s |
| `SELECT` by PRIMARY KEY | ~42,000 ops/s |
| `SELECT` by secondary index (~100 hits) | ~1,500 ops/s (~150k rows/s decrypted) |
| `SELECT` full scan + filter (10k rows) | ~62 scans/s (~600k rows/s decrypted) |
| `UPDATE` by PRIMARY KEY | ~1,300 ops/s |
| `DELETE` by PRIMARY KEY | ~1,100 ops/s |

## Reading the numbers

- **Reads are already respectable.** Point lookups cost two storage
  reads plus two ChaCha20-Poly1305 opens; scans decrypt ~600k rows/s
  even with the deliberately simple byte-limb Poly1305.
- **Group commit moved inserts 34x.** v0 paid one fsync per storage
  `put` (four per inserted row) and managed ~390 rows/s; batching every
  statement into a single checksummed WAL record with one fsync raised
  that to ~13,000 rows/s without touching the encryption model — and
  made statements crash-atomic as a side effect (a torn batch fails its
  CRC and is dropped whole). Remaining write cost is dominated by the
  one honest fsync per statement.
- **The KDF cost is a feature.** ~110 ms of memory-hard work per
  database open is what makes passphrase brute force expensive; it is
  paid once per process, not per query.

## Comparing with SQLite

`scripts/bench-vs-sqlite.sh` runs the same workload through the
`sqlite3` CLI (WAL, `synchronous=FULL` for a comparable durability
level). SQLite is decades ahead on storage engineering and does not
encrypt — expect it to win everything; the interesting quantity is the
*multiple*, i.e. the current price of the encryption model. The
environment this baseline was produced in has no `sqlite3` binary, so
that column is intentionally absent rather than estimated.
