"""Standalone tests for the Python driver — run with `python3 test_ciphra.py`.

No pytest dependency (stdlib only). Requires libciphra to be built:
`cargo build --release -p ciphra-ffi`, or set CIPHRA_LIB.
"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ciphra import Ciphra, CiphraError, version  # noqa: E402


def test_local_round_trip() -> None:
    with tempfile.TemporaryDirectory() as d:
        with Ciphra.open(os.path.join(d, "db"), "correct horse battery staple") as db:
            db.execute(
                "CREATE TABLE t (id INT PRIMARY KEY, note TEXT ENCRYPTED, emb VECTOR(3))"
            )
            res = db.execute(
                "INSERT INTO t VALUES (1,'hello',[0.1,0.2,0.3]),(2,'world',[0.9,0.8,0.7])"
            )
            assert res == [{"kind": "inserted", "count": 2}], res

            rows = db.query("SELECT id, note FROM t WHERE id >= 1")
            assert rows == [
                {"id": 1, "note": "hello"},
                {"id": 2, "note": "world"},
            ], rows

            nn = db.query("SELECT id FROM t ORDER BY emb NEAREST TO [0.1,0.2,0.3] LIMIT 1")
            assert nn == [{"id": 1}], nn


def test_errors_surface() -> None:
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "db")
        db = Ciphra.open(path, "right passphrase")
        try:
            db.query("SELECT * FROM nope")
            raise AssertionError("expected error for missing table")
        except CiphraError as e:
            assert "missing" not in str(e) or "table" in str(e)
        db.close()

        try:
            Ciphra.open(path, "wrong passphrase")
            raise AssertionError("expected wrong-passphrase error")
        except CiphraError as e:
            assert "passphrase" in str(e), e


def main() -> int:
    assert version(), "empty version"
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"ok  {name}")
    print("all Python driver tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
