package ciphra

import (
	"path/filepath"
	"testing"
)

func TestLocalRoundTrip(t *testing.T) {
	if v := Version(); v == "" {
		t.Fatal("empty version")
	}

	db, err := Open(filepath.Join(t.TempDir(), "db"), "correct horse battery staple")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	if _, err := db.Execute(
		"CREATE TABLE t (id INT PRIMARY KEY, note TEXT ENCRYPTED)"); err != nil {
		t.Fatalf("create: %v", err)
	}
	res, err := db.Execute("INSERT INTO t VALUES (1, 'hello'), (2, 'world')")
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
	if len(res) != 1 || res[0].Kind != "inserted" || res[0].Count != 2 {
		t.Fatalf("unexpected insert result: %+v", res)
	}

	rows, err := db.Query("SELECT id, note FROM t WHERE id = 2")
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(rows) != 1 || rows[0]["note"] != "world" {
		t.Fatalf("unexpected rows: %+v", rows)
	}
}

func TestErrorsSurface(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "db")
	db, err := Open(dir, "right passphrase")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := db.Query("SELECT * FROM nope"); err == nil {
		t.Fatal("expected error for missing table")
	}
	db.Close()

	if _, err := Open(dir, "wrong passphrase"); err == nil {
		t.Fatal("expected wrong-passphrase error")
	}
}
