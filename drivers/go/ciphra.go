// Package ciphra is a Go driver for the Ciphra encrypted database.
//
// It binds, via cgo, to libciphra (the ciphra-ffi crate). The engine —
// SQL, encryption, key derivation, query planning — runs in this
// process; for a remote database only sealed bytes cross the wire to a
// blind ciphra-server. No third-party Go modules are used.
//
// Build/run needs the shared library. Build it with
//
//	cargo build --release -p ciphra-ffi
//
// The cgo directives below add target/release and target/debug to the
// link and rpath search, so `go test` / `go run` find it in a checkout.
package ciphra

/*
#cgo CFLAGS: -I${SRCDIR}/../../crates/ciphra-ffi/include
#cgo LDFLAGS: -L${SRCDIR}/../../target/release -L${SRCDIR}/../../target/debug -lciphra
#cgo LDFLAGS: -Wl,-rpath,${SRCDIR}/../../target/release -Wl,-rpath,${SRCDIR}/../../target/debug
#include <stdlib.h>
#include "ciphra.h"
*/
import "C"

import (
	"encoding/json"
	"errors"
	"runtime"
	"unsafe"
)

// DB is an open Ciphra database. It is not safe for concurrent use;
// guard it with your own lock if shared across goroutines.
type DB struct {
	handle *C.CiphraDb
}

// Result is one statement's outcome, tagged by Kind ("rows", "inserted",
// "created", "index_created", …). For a "rows" result Columns and Rows
// are populated; for a count result Count is; for DDL Name/Table/Column.
type Result struct {
	Kind    string   `json:"kind"`
	Name    string   `json:"name,omitempty"`
	Table   string   `json:"table,omitempty"`
	Column  string   `json:"column,omitempty"`
	Range   bool     `json:"range,omitempty"`
	Count   int      `json:"count,omitempty"`
	Columns []string `json:"columns,omitempty"`
	// Rows holds each row's values as decoded JSON (float64, string,
	// nil, or []interface{} for a vector).
	Rows [][]interface{} `json:"rows,omitempty"`
}

// Version returns the linked libciphra version.
func Version() string {
	return C.GoString(C.ciphra_version())
}

// Open opens (or creates) a local database in dataDir, sealed under
// passphrase.
func Open(dataDir, passphrase string) (*DB, error) {
	cDir := C.CString(dataDir)
	defer C.free(unsafe.Pointer(cDir))
	cPass := C.CString(passphrase)
	defer C.free(unsafe.Pointer(cPass))

	var errPtr *C.char
	handle := C.ciphra_open(cDir, cPass, &errPtr)
	if handle == nil {
		return nil, errors.New(takeString(errPtr))
	}
	return newDB(handle), nil
}

// OpenRemote connects to a ciphra-server at addr and opens the database
// it stores. serverKeyHex pins the server's static transport key (64 hex
// chars); pass "" to trust on first use.
func OpenRemote(addr, passphrase, serverKeyHex string) (*DB, error) {
	cAddr := C.CString(addr)
	defer C.free(unsafe.Pointer(cAddr))
	cPass := C.CString(passphrase)
	defer C.free(unsafe.Pointer(cPass))

	var cKey *C.char
	if serverKeyHex != "" {
		cKey = C.CString(serverKeyHex)
		defer C.free(unsafe.Pointer(cKey))
	}

	var errPtr *C.char
	handle := C.ciphra_open_remote(cAddr, cPass, cKey, &errPtr)
	if handle == nil {
		return nil, errors.New(takeString(errPtr))
	}
	return newDB(handle), nil
}

// Execute runs one or more ';'-separated statements and returns a result
// per statement.
func (db *DB) Execute(sql string) ([]Result, error) {
	if db.handle == nil {
		return nil, errors.New("database is closed")
	}
	cSQL := C.CString(sql)
	defer C.free(unsafe.Pointer(cSQL))

	var errPtr *C.char
	out := C.ciphra_execute(db.handle, cSQL, &errPtr)
	if out == nil {
		return nil, errors.New(takeString(errPtr))
	}
	payload := takeString(out)

	var results []Result
	if err := json.Unmarshal([]byte(payload), &results); err != nil {
		return nil, err
	}
	return results, nil
}

// Query runs sql and returns the last "rows" result as maps keyed by
// column name. It errors if no row set was produced.
func (db *DB) Query(sql string) ([]map[string]interface{}, error) {
	results, err := db.Execute(sql)
	if err != nil {
		return nil, err
	}
	for i := len(results) - 1; i >= 0; i-- {
		if results[i].Kind == "rows" {
			r := results[i]
			out := make([]map[string]interface{}, 0, len(r.Rows))
			for _, row := range r.Rows {
				m := make(map[string]interface{}, len(r.Columns))
				for j, col := range r.Columns {
					if j < len(row) {
						m[col] = row[j]
					}
				}
				out = append(out, m)
			}
			return out, nil
		}
	}
	return nil, errors.New("statement returned no rows")
}

// Close releases the handle. It is idempotent.
func (db *DB) Close() error {
	if db.handle != nil {
		C.ciphra_close(db.handle)
		db.handle = nil
	}
	return nil
}

func newDB(handle *C.CiphraDb) *DB {
	db := &DB{handle: handle}
	// Backstop against a caller that forgets Close(); explicit Close is
	// still expected.
	runtime.SetFinalizer(db, func(d *DB) { _ = d.Close() })
	return db
}

// takeString reads an owned C string and frees it with the library's
// allocator. A null pointer yields an empty string.
func takeString(s *C.char) string {
	if s == nil {
		return ""
	}
	defer C.ciphra_string_free(s)
	return C.GoString(s)
}
