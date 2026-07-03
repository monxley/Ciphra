// Ciphra — JavaScript driver (Bun).
//
// A thin binding over libciphra (the ciphra-ffi crate) using Bun's
// built-in `bun:ffi` — no npm packages, matching Ciphra's zero-dependency
// policy. The engine (SQL, encryption, key derivation) runs in this
// process; for a remote database only sealed bytes reach a blind
// ciphra-server.
//
// Requires Bun (for `bun:ffi`). Build the library first:
//   cargo build --release -p ciphra-ffi
// then set CIPHRA_LIB, or rely on the target/{release,debug} lookup.
//
//   import { Ciphra } from "./ciphra.js";
//   const db = Ciphra.open("./mydb", "correct horse battery staple");
//   db.execute("CREATE TABLE t (id INT PRIMARY KEY, note TEXT ENCRYPTED)");
//   db.execute("INSERT INTO t VALUES (1, 'hello')");
//   console.log(db.query("SELECT id, note FROM t"));
//   db.close();

import { dlopen, FFIType, CString, ptr, read } from "bun:ffi";
import { existsSync } from "node:fs";
import { join } from "node:path";

function libraryPath() {
  if (process.env.CIPHRA_LIB) return process.env.CIPHRA_LIB;
  const name =
    process.platform === "darwin"
      ? "libciphra.dylib"
      : process.platform === "win32"
        ? "ciphra.dll"
        : "libciphra.so";
  const root = join(import.meta.dir, "..", "..");
  for (const build of ["release", "debug"]) {
    const p = join(root, "target", build, name);
    if (existsSync(p)) return p;
  }
  return name; // let the loader search system paths
}

const { symbols: lib } = dlopen(libraryPath(), {
  ciphra_version: { args: [], returns: FFIType.ptr },
  ciphra_open: {
    args: [FFIType.ptr, FFIType.ptr, FFIType.ptr],
    returns: FFIType.ptr,
  },
  ciphra_open_remote: {
    args: [FFIType.ptr, FFIType.ptr, FFIType.ptr, FFIType.ptr],
    returns: FFIType.ptr,
  },
  ciphra_execute: {
    args: [FFIType.ptr, FFIType.ptr, FFIType.ptr],
    returns: FFIType.ptr,
  },
  ciphra_close: { args: [FFIType.ptr], returns: FFIType.void },
  ciphra_string_free: { args: [FFIType.ptr], returns: FFIType.void },
});

// A NUL-terminated UTF-8 buffer for passing a JS string as `const char*`.
function cstr(s) {
  return Buffer.from(s + "\0", "utf8");
}

// Read an owned `char*` returned by the library, then free it.
function takeString(pointer) {
  if (!pointer) return null;
  const s = new CString(pointer).toString();
  lib.ciphra_string_free(pointer);
  return s;
}

export class CiphraError extends Error {}

export class Ciphra {
  #handle;

  constructor(handle) {
    this.#handle = handle;
  }

  static version() {
    return new CString(lib.ciphra_version()).toString();
  }

  static open(dataDir, passphrase) {
    const errSlot = new BigInt64Array(1);
    const handle = lib.ciphra_open(cstr(dataDir), cstr(passphrase), ptr(errSlot));
    return Ciphra.#checked(handle, errSlot);
  }

  // serverKey pins the server's static transport key (64 hex chars);
  // pass null/undefined to trust on first use.
  static openRemote(addr, passphrase, serverKey = null) {
    const errSlot = new BigInt64Array(1);
    const key = serverKey ? cstr(serverKey) : null;
    const handle = lib.ciphra_open_remote(
      cstr(addr),
      cstr(passphrase),
      key,
      ptr(errSlot),
    );
    return Ciphra.#checked(handle, errSlot);
  }

  static #checked(handle, errSlot) {
    const message = takeString(read.ptr(ptr(errSlot), 0));
    if (!handle) throw new CiphraError(message ?? "failed to open database");
    return new Ciphra(handle);
  }

  // Run one or more ';'-separated statements; returns a result per
  // statement (parsed JSON, each tagged by `kind`).
  execute(sql) {
    if (!this.#handle) throw new CiphraError("database is closed");
    const errSlot = new BigInt64Array(1);
    const out = lib.ciphra_execute(this.#handle, cstr(sql), ptr(errSlot));
    const payload = takeString(out);
    if (payload === null) {
      throw new CiphraError(
        takeString(read.ptr(ptr(errSlot), 0)) ?? "execution failed",
      );
    }
    return JSON.parse(payload);
  }

  // Run sql and return the last `rows` result as {column: value} objects.
  query(sql) {
    const results = this.execute(sql);
    for (let i = results.length - 1; i >= 0; i--) {
      if (results[i].kind === "rows") {
        const { columns, rows } = results[i];
        return rows.map((row) =>
          Object.fromEntries(columns.map((c, j) => [c, row[j]])),
        );
      }
    }
    throw new CiphraError("statement returned no rows");
  }

  close() {
    if (this.#handle) {
      lib.ciphra_close(this.#handle);
      this.#handle = null;
    }
  }
}
