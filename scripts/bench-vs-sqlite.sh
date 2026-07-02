#!/usr/bin/env bash
# Compare Ciphra against SQLite on an equivalent single-table workload.
# Requires the `sqlite3` CLI. SQLite is configured for a comparable
# durability level (WAL + synchronous=FULL); it still has a decades-long
# performance head start — the point of these numbers is to quantify the
# cost of the encryption model honestly, not to win.
set -euo pipefail

ROWS="${1:-10000}"
command -v sqlite3 >/dev/null || { echo "sqlite3 not found; install it first" >&2; exit 1; }

echo "=== ciphra ==="
cargo run --release -q -p ciphra-bench -- --rows "$ROWS"

echo
echo "=== sqlite3 (WAL, synchronous=FULL) ==="
DB="$(mktemp -d)/bench.sqlite"
sqlite3 "$DB" <<SQL
PRAGMA journal_mode=WAL;
PRAGMA synchronous=FULL;
CREATE TABLE t (id INTEGER PRIMARY KEY, grp TEXT, payload TEXT);
CREATE INDEX idx_grp ON t (grp);
SQL

python3 - "$DB" "$ROWS" <<'PY'
import sqlite3, sys, time

db, rows = sys.argv[1], int(sys.argv[2])
conn = sqlite3.connect(db, isolation_level=None)
conn.execute("PRAGMA synchronous=FULL")

def lcg(i):
    return ((i * 6364136223846793005 + 1442695040888963407) % 2**64) >> 17

def report(label, ops, started):
    dt = time.perf_counter() - started
    print(f"{label:<42} {ops/dt:>10.0f} ops/s   ({ops} ops in {dt:.2f}s)")

started = time.perf_counter()
for base in range(0, rows, 100):
    batch = [(i, f"g{i % 100}", f"payload-{i}-{lcg(i)}") for i in range(base, min(base + 100, rows))]
    conn.execute("BEGIN"); conn.executemany("INSERT INTO t VALUES (?,?,?)", batch); conn.execute("COMMIT")
report("INSERT (batches of 100)", rows, started)

started = time.perf_counter()
lookups = min(2000, rows)
for i in range(lookups):
    conn.execute("SELECT payload FROM t WHERE id = ?", (lcg(i) % rows,)).fetchall()
report("SELECT by PRIMARY KEY", lookups, started)

started = time.perf_counter()
lookups = min(500, rows)
for i in range(lookups):
    conn.execute("SELECT id FROM t WHERE grp = ?", (f"g{lcg(i) % 100}",)).fetchall()
report("SELECT by secondary index", lookups, started)

started = time.perf_counter()
for i in range(20):
    needle = lcg(i) % rows
    conn.execute("SELECT id FROM t WHERE payload = ?", (f"payload-{needle}-{lcg(needle)}",)).fetchall()
report("SELECT full scan + filter", 20, started)

started = time.perf_counter()
updates = min(1000, rows)
for i in range(updates):
    conn.execute("UPDATE t SET payload = ? WHERE id = ?", (f"updated-{i}", lcg(i + 7) % rows))
report("UPDATE by PRIMARY KEY", updates, started)

started = time.perf_counter()
deletes = min(500, rows // 2)
for i in range(deletes):
    conn.execute("DELETE FROM t WHERE id = ?", (i,))
report("DELETE by PRIMARY KEY", deletes, started)
PY
