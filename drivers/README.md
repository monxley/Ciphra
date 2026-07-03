# Ciphra drivers

Language drivers for embedding Ciphra in Python, Go and JavaScript.

## How they work

Ciphra's server is **blind** (ADR-0003): SQL parsing, encryption, key
derivation and query planning all run in the engine, which must live
with the key holder. A driver is therefore **not** a reimplementation of
Ciphra in another language — it is a thin binding that runs the real Rust
engine in-process through a small C ABI (`crates/ciphra-ffi`,
[`ciphra.h`](../crates/ciphra-ffi/include/ciphra.h)). For a remote
database the engine speaks Ciphra's sealed protocol to a `ciphra-server`;
keys and plaintext never leave the driver's process.

Every driver is **standard-library only** — `ctypes`, `cgo`, `bun:ffi` —
matching Ciphra's zero-dependency policy.

```
your Python / Go / JS program
        │  (thin binding)
   libciphra  (C ABI)  ── ciphra-ffi → ciphra-engine  (SQL · crypto · keys)
        │
   local WAL   ── or ──   sealed protocol ⇄ ciphra-server (blind)
```

## Build the library

All drivers link against `libciphra`, built from the `ciphra-ffi` crate:

```sh
cargo build --release -p ciphra-ffi
# produces target/release/libciphra.{so,dylib,dll} and libciphra.a
```

Drivers look for the library via `CIPHRA_LIB`, then `target/release`,
then `target/debug`, then the system loader path.

## Python (`ctypes`)

```python
import sys; sys.path.insert(0, "drivers/python")
from ciphra import Ciphra

with Ciphra.open("./mydb", "correct horse battery staple") as db:
    db.execute("CREATE TABLE t (id INT PRIMARY KEY, note TEXT ENCRYPTED)")
    db.execute("INSERT INTO t VALUES (1, 'hello')")
    print(db.query("SELECT id, note FROM t"))   # [{'id': 1, 'note': 'hello'}]

# Remote, pinning the server's transport key:
db = Ciphra.open_remote("127.0.0.1:5077", "pass", server_key="3af1…e09c")
```

## Go (`cgo`)

```go
import ciphra "github.com/monxley/ciphra/drivers/go"

db, err := ciphra.Open("./mydb", "correct horse battery staple")
if err != nil { panic(err) }
defer db.Close()

db.Execute("CREATE TABLE t (id INT PRIMARY KEY, note TEXT ENCRYPTED)")
db.Execute("INSERT INTO t VALUES (1, 'hello')")
rows, _ := db.Query("SELECT id, note FROM t")   // []map[string]any
```

```sh
cd drivers/go && CGO_ENABLED=1 go test ./...
```

The cgo directives add `target/{release,debug}` to the link and rpath
search, so `go test`/`go run` find the library in a checkout.

## JavaScript (Bun, `bun:ffi`)

Requires [Bun](https://bun.sh) for its built-in FFI (Node has no stable
stdlib FFI).

```js
import { Ciphra } from "./drivers/js/ciphra.js";

const db = Ciphra.open("./mydb", "correct horse battery staple");
db.execute("CREATE TABLE t (id INT PRIMARY KEY, note TEXT ENCRYPTED)");
db.execute("INSERT INTO t VALUES (1, 'hello')");
console.log(db.query("SELECT id, note FROM t")); // [{ id: 1, note: "hello" }]
db.close();
```

## Result shape

`execute()` returns one object per statement, tagged by `kind`:

| `kind`                         | fields                       |
| ------------------------------ | ---------------------------- |
| `rows`                         | `columns`, `rows`            |
| `inserted` / `updated` / `deleted` | `count`                  |
| `created` / `dropped`          | `name`                       |
| `index_created` / `index_dropped` | `table`, `column`, `range` |

Row values map to the language's null, integer, string, or a list of
numbers (a `VECTOR`). `query()` is a convenience that returns the last
`rows` result as records keyed by column name.
