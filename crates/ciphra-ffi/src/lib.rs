//! A C ABI over the Ciphra engine — the shared core every language
//! driver links against.
//!
//! The server is blind (ADR-0003): SQL parsing, encryption, key
//! derivation and query planning all run in [`ciphra_engine::Engine`],
//! which must live with the key holder. So a "driver" is not a
//! reimplementation of Ciphra in another language — it is a thin binding
//! that runs the real engine in-process and, for remote databases,
//! speaks the sealed protocol to a `ciphra-server`. This crate exposes
//! that engine through a small, stable C ABI; the Python, Go and JS
//! drivers are a few dozen lines each on top of it.
//!
//! ## Contract
//!
//! - Strings in are NUL-terminated UTF-8. Strings out are heap-allocated
//!   by this library and must be released with [`ciphra_string_free`] —
//!   never with the caller's own allocator.
//! - Fallible calls return `NULL` and, if `out_err` is non-null, write a
//!   freshly allocated error string to `*out_err` (also freed with
//!   [`ciphra_string_free`]). On success `*out_err` is set to `NULL`.
//! - A database handle from `ciphra_open*` is freed with
//!   [`ciphra_close`]. Handles are not synchronized: use one from one
//!   thread at a time.
//! - Panics never cross the boundary; they are caught and surfaced as
//!   errors.

use std::ffi::{CStr, CString, c_char};
use std::panic::{AssertUnwindSafe, catch_unwind};

use ciphra_engine::{Engine, QueryResult, Value};

/// Opaque database handle. See [`ciphra_open`] / [`ciphra_close`].
pub struct CiphraDb {
    engine: Engine,
}

/// The library version (`env!("CARGO_PKG_VERSION")`), as a static
/// NUL-terminated string. Do not free it.
///
/// # Safety
/// The returned pointer is valid for the life of the process.
#[unsafe(no_mangle)]
pub extern "C" fn ciphra_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr() as *const c_char
}

/// Open (or create) a local database in `data_dir`, sealed under
/// `passphrase`. Returns a handle, or `NULL` on error with `*out_err`
/// set.
///
/// # Safety
/// `data_dir` and `passphrase` must be valid NUL-terminated UTF-8
/// pointers. `out_err` may be null or a valid `*mut *mut c_char`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ciphra_open(
    data_dir: *const c_char,
    passphrase: *const c_char,
    out_err: *mut *mut c_char,
) -> *mut CiphraDb {
    clear_err(out_err);
    let result = catch_unwind(AssertUnwindSafe(|| {
        let dir = to_str(data_dir, "data_dir")?;
        let pass = to_str(passphrase, "passphrase")?;
        Engine::open(dir, pass).map_err(|e| e.to_string())
    }));
    finish_open(result, out_err)
}

/// Connect to a `ciphra-server` at `addr` and open the database it
/// stores. `server_key_hex` pins the server's static transport key (64
/// hex chars); pass `NULL` to trust on first use (encrypted and
/// post-quantum, but unauthenticated). Returns a handle, or `NULL` on
/// error with `*out_err` set.
///
/// # Safety
/// `addr` and `passphrase` must be valid NUL-terminated UTF-8 pointers.
/// `server_key_hex` may be null or a valid NUL-terminated pointer.
/// `out_err` may be null or a valid `*mut *mut c_char`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ciphra_open_remote(
    addr: *const c_char,
    passphrase: *const c_char,
    server_key_hex: *const c_char,
    out_err: *mut *mut c_char,
) -> *mut CiphraDb {
    clear_err(out_err);
    let result = catch_unwind(AssertUnwindSafe(|| {
        let addr = to_str(addr, "addr")?;
        let pass = to_str(passphrase, "passphrase")?;
        let pinned = if server_key_hex.is_null() {
            None
        } else {
            let hex = to_str(server_key_hex, "server_key_hex")?;
            Some(parse_key(hex)?)
        };
        Engine::open_remote(addr, pass, pinned).map_err(|e| e.to_string())
    }));
    finish_open(result, out_err)
}

/// Execute one or more `;`-separated SQL statements. On success returns a
/// heap-allocated UTF-8 JSON array of per-statement results (free it with
/// [`ciphra_string_free`]); on error returns `NULL` with `*out_err` set.
///
/// Each element is an object tagged by `kind`:
/// `rows` (`columns`, `rows`), `created`/`dropped` (`name`),
/// `index_created`/`index_dropped` (`table`, `column`, `range`),
/// `inserted`/`updated`/`deleted` (`count`). Row values map to JSON
/// null, integer, string or array-of-number (a vector).
///
/// # Safety
/// `db` must be a handle from `ciphra_open*` that has not been closed.
/// `sql` must be a valid NUL-terminated UTF-8 pointer. `out_err` may be
/// null or a valid `*mut *mut c_char`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ciphra_execute(
    db: *mut CiphraDb,
    sql: *const c_char,
    out_err: *mut *mut c_char,
) -> *mut c_char {
    clear_err(out_err);
    let result = catch_unwind(AssertUnwindSafe(|| {
        let db = unsafe { db.as_mut() }.ok_or_else(|| "null database handle".to_string())?;
        let sql = to_str(sql, "sql")?;
        let results = db.engine.execute(sql).map_err(|e| e.to_string())?;
        Ok(results_to_json(&results))
    }));
    match flatten(result) {
        Ok(json) => into_c_string(json),
        Err(message) => {
            set_err(out_err, message);
            std::ptr::null_mut()
        }
    }
}

/// Close and free a database handle. Passing `NULL` is a no-op. After
/// this the handle must not be used again.
///
/// # Safety
/// `db` must be a handle from `ciphra_open*` that has not already been
/// closed, or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ciphra_close(db: *mut CiphraDb) {
    if !db.is_null() {
        drop(unsafe { Box::from_raw(db) });
    }
}

/// Free a string returned by this library (`ciphra_execute`, an
/// `out_err` message). Passing `NULL` is a no-op.
///
/// # Safety
/// `s` must be a pointer returned by this library and not yet freed, or
/// null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ciphra_string_free(s: *mut c_char) {
    if !s.is_null() {
        drop(unsafe { CString::from_raw(s) });
    }
}

// ------------------------------------------------------------- internals

/// Turn a caught `open` result into a boxed handle or an error pointer.
fn finish_open(
    result: std::thread::Result<Result<Engine, String>>,
    out_err: *mut *mut c_char,
) -> *mut CiphraDb {
    match flatten(result) {
        Ok(engine) => Box::into_raw(Box::new(CiphraDb { engine })),
        Err(message) => {
            set_err(out_err, message);
            std::ptr::null_mut()
        }
    }
}

/// Collapse a `catch_unwind` result whose `Ok` is itself a `Result`.
fn flatten<T>(result: std::thread::Result<Result<T, String>>) -> Result<T, String> {
    match result {
        Ok(inner) => inner,
        Err(_) => Err("internal error: operation panicked".to_string()),
    }
}

fn to_str<'a>(ptr: *const c_char, what: &str) -> Result<&'a str, String> {
    if ptr.is_null() {
        return Err(format!("{what} must not be null"));
    }
    unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .map_err(|_| format!("{what} is not valid UTF-8"))
}

fn parse_key(hex: &str) -> Result<[u8; 32], String> {
    if hex.len() != 64 {
        return Err("server key must be 64 hex characters (32 bytes)".to_string());
    }
    let mut key = [0u8; 32];
    for (i, byte) in key.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|_| "server key must be valid hex".to_string())?;
    }
    Ok(key)
}

fn clear_err(out_err: *mut *mut c_char) {
    if !out_err.is_null() {
        unsafe { *out_err = std::ptr::null_mut() };
    }
}

fn set_err(out_err: *mut *mut c_char, message: String) {
    if !out_err.is_null() {
        unsafe { *out_err = into_c_string(message) };
    }
}

/// Allocate a C string, replacing any interior NUL so the whole message
/// survives the round trip. Never returns null for our own strings.
fn into_c_string(s: String) -> *mut c_char {
    let cleaned = s.replace('\0', "\u{fffd}");
    match CString::new(cleaned) {
        Ok(c) => c.into_raw(),
        Err(_) => CString::new("error message contained a NUL")
            .unwrap()
            .into_raw(),
    }
}

// --------------------------------------------------------- JSON encoding

/// Encode `[QueryResult]` as a JSON array. Hand-written to keep the crate
/// dependency-free, matching the rest of Ciphra.
fn results_to_json(results: &[QueryResult]) -> String {
    let mut out = String::from("[");
    for (i, r) in results.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        encode_result(&mut out, r);
    }
    out.push(']');
    out
}

fn encode_result(out: &mut String, result: &QueryResult) {
    match result {
        QueryResult::Created(name) => {
            out.push_str("{\"kind\":\"created\",\"name\":");
            encode_str(out, name);
            out.push('}');
        }
        QueryResult::Dropped(name) => {
            out.push_str("{\"kind\":\"dropped\",\"name\":");
            encode_str(out, name);
            out.push('}');
        }
        QueryResult::IndexCreated {
            table,
            column,
            range,
        } => encode_index(out, "index_created", table, column, *range),
        QueryResult::IndexDropped {
            table,
            column,
            range,
        } => encode_index(out, "index_dropped", table, column, *range),
        QueryResult::Inserted(n) => encode_count(out, "inserted", *n),
        QueryResult::Updated(n) => encode_count(out, "updated", *n),
        QueryResult::Deleted(n) => encode_count(out, "deleted", *n),
        QueryResult::Rows { columns, rows } => {
            out.push_str("{\"kind\":\"rows\",\"columns\":[");
            for (i, c) in columns.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                encode_str(out, c);
            }
            out.push_str("],\"rows\":[");
            for (i, row) in rows.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push('[');
                for (j, value) in row.iter().enumerate() {
                    if j > 0 {
                        out.push(',');
                    }
                    encode_value(out, value);
                }
                out.push(']');
            }
            out.push_str("]}");
        }
    }
}

fn encode_index(out: &mut String, kind: &str, table: &str, column: &str, range: bool) {
    out.push_str("{\"kind\":\"");
    out.push_str(kind);
    out.push_str("\",\"table\":");
    encode_str(out, table);
    out.push_str(",\"column\":");
    encode_str(out, column);
    out.push_str(",\"range\":");
    out.push_str(if range { "true" } else { "false" });
    out.push('}');
}

fn encode_count(out: &mut String, kind: &str, n: usize) {
    out.push_str("{\"kind\":\"");
    out.push_str(kind);
    out.push_str("\",\"count\":");
    out.push_str(&n.to_string());
    out.push('}');
}

fn encode_value(out: &mut String, value: &Value) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Int(n) => out.push_str(&n.to_string()),
        Value::Text(s) => encode_str(out, s),
        Value::Vector(v) => {
            out.push('[');
            for (i, x) in v.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                if x.is_finite() {
                    out.push_str(&x.to_string());
                } else {
                    // NaN/inf aren't valid JSON numbers; keep it parseable.
                    out.push_str("null");
                }
            }
            out.push(']');
        }
    }
}

/// Append `s` as a JSON string literal, escaping per RFC 8259.
fn encode_str(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_rows_and_scalars() {
        let results = vec![
            QueryResult::Created("t".into()),
            QueryResult::Inserted(2),
            QueryResult::Rows {
                columns: vec!["id".into(), "note".into(), "emb".into()],
                rows: vec![
                    vec![
                        Value::Int(1),
                        Value::Text("a\"b\\nc".into()),
                        Value::Vector(vec![0.5, -1.0]),
                    ],
                    vec![Value::Int(2), Value::Null, Value::Vector(vec![])],
                ],
            },
        ];
        let json = results_to_json(&results);
        assert_eq!(
            json,
            "[{\"kind\":\"created\",\"name\":\"t\"},\
             {\"kind\":\"inserted\",\"count\":2},\
             {\"kind\":\"rows\",\"columns\":[\"id\",\"note\",\"emb\"],\
             \"rows\":[[1,\"a\\\"b\\\\nc\",[0.5,-1]],[2,null,[]]]}]"
        );
    }

    #[test]
    fn escapes_control_characters() {
        let mut s = String::new();
        encode_str(&mut s, "tab\tnul\u{0}end");
        assert_eq!(s, "\"tab\\tnul\\u0000end\"");
    }

    #[test]
    fn parse_key_validates_length_and_hex() {
        assert!(parse_key("00").is_err());
        assert!(parse_key(&"zz".repeat(32)).is_err());
        assert_eq!(parse_key(&"ab".repeat(32)).unwrap(), [0xab; 32]);
    }
}
