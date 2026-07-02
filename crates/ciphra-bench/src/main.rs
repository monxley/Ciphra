//! Ciphra micro-benchmarks. Run with `cargo run --release -p ciphra-bench`.
//!
//! Every number includes the full cost of the encryption model: whole-row
//! ChaCha20-Poly1305, keyed index tags, and one durable fsync per statement
//! (group commit).
//! There is deliberately no "fast mode" — the encrypted path is the only
//! path. Compare against SQLite with `scripts/bench-vs-sqlite.sh` on a
//! machine that has the `sqlite3` CLI.

use std::time::Instant;

use ciphra_engine::{Engine, KdfParams, QueryResult};

const GROUPS: u64 = 100;

fn main() {
    let rows: u64 = std::env::args()
        .skip_while(|a| a != "--rows")
        .nth(1)
        .map(|n| n.parse().expect("--rows takes an integer"))
        .unwrap_or(10_000);

    let dir = ciphra_testutil::tempdir();

    // KDF cost is a one-time, deliberate expense — report it separately
    // so it does not pollute the per-operation numbers below.
    let started = Instant::now();
    drop(Engine::open_with_kdf(dir.path(), "bench", KdfParams::recommended()).unwrap());
    let kdf_open = started.elapsed();

    let mut db = Engine::open(dir.path(), "bench").unwrap();
    db.execute(
        "CREATE TABLE t (id INT PRIMARY KEY, grp TEXT, payload TEXT); \
         CREATE INDEX ON t (grp);",
    )
    .unwrap();

    println!("ciphra-bench: {rows} rows, PK + one secondary index, one fsync per statement");
    println!(
        "(one-time) Argon2id open, 19 MiB t=2:      {:>10.1?}",
        kdf_open
    );

    // INSERT in batches of 100 rows per statement.
    let started = Instant::now();
    let mut inserted = 0u64;
    while inserted < rows {
        let batch: Vec<String> = (inserted..(inserted + 100).min(rows))
            .map(|i| format!("({i}, 'g{}', 'payload-{i}-{}')", i % GROUPS, lcg(i)))
            .collect();
        db.execute(&format!("INSERT INTO t VALUES {}", batch.join(", ")))
            .unwrap();
        inserted += batch.len() as u64;
    }
    report("INSERT (batches of 100)", rows, started);

    // Point lookups through the primary key index.
    let started = Instant::now();
    let lookups = 2_000.min(rows);
    for i in 0..lookups {
        let id = lcg(i) % rows;
        let n = row_count(
            db.execute(&format!("SELECT payload FROM t WHERE id = {id}"))
                .unwrap(),
        );
        assert_eq!(n, 1);
    }
    report("SELECT by PRIMARY KEY", lookups, started);

    // Equality lookups through the secondary index (~rows/GROUPS hits each).
    let started = Instant::now();
    let lookups = 500.min(rows);
    for i in 0..lookups {
        let g = lcg(i) % GROUPS;
        let n = row_count(
            db.execute(&format!("SELECT id FROM t WHERE grp = 'g{g}'"))
                .unwrap(),
        );
        assert!(n > 0);
    }
    report("SELECT by secondary index", lookups, started);

    // Full scan with a non-indexed predicate.
    let started = Instant::now();
    let scans = 20u64;
    for i in 0..scans {
        let needle = lcg(i) % rows;
        db.execute(&format!(
            "SELECT id FROM t WHERE payload = 'payload-{needle}-{}'",
            lcg(needle)
        ))
        .unwrap();
    }
    report("SELECT full scan + filter", scans, started);

    // UPDATE through the primary key.
    let started = Instant::now();
    let updates = 1_000.min(rows);
    for i in 0..updates {
        let id = lcg(i + 7) % rows;
        db.execute(&format!(
            "UPDATE t SET payload = 'updated-{i}' WHERE id = {id}"
        ))
        .unwrap();
    }
    report("UPDATE by PRIMARY KEY", updates, started);

    // DELETE through the primary key (each hits row + 2 index entries).
    let started = Instant::now();
    let deletes = 500.min(rows / 2);
    for id in 0..deletes {
        db.execute(&format!("DELETE FROM t WHERE id = {id}"))
            .unwrap();
    }
    report("DELETE by PRIMARY KEY", deletes, started);
}

fn report(label: &str, ops: u64, started: Instant) {
    let elapsed = started.elapsed();
    let per_sec = ops as f64 / elapsed.as_secs_f64();
    println!("{label:<42} {per_sec:>10.0} ops/s   ({ops} ops in {elapsed:.1?})");
}

fn row_count(results: Vec<QueryResult>) -> usize {
    match results.into_iter().next() {
        Some(QueryResult::Rows { rows, .. }) => rows.len(),
        _ => 0,
    }
}

/// Deterministic pseudo-random sequence (no dependencies, no seeds to
/// misreport): a 64-bit LCG.
fn lcg(i: u64) -> u64 {
    i.wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407)
        >> 17
}
