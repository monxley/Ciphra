"""Ciphra — Python driver.

A thin ``ctypes`` binding over ``libciphra`` (the ``ciphra-ffi`` crate).
The engine runs in this process: SQL, encryption and key derivation all
happen here, and for a remote database only sealed bytes cross the wire
to a blind ``ciphra-server``. No third-party packages — standard library
only, matching Ciphra's zero-dependency policy.

    from ciphra import Ciphra

    with Ciphra.open("./mydb", "correct horse battery staple") as db:
        db.execute("CREATE TABLE t (id INT PRIMARY KEY, note TEXT ENCRYPTED)")
        db.execute("INSERT INTO t VALUES (1, 'hello')")
        for row in db.query("SELECT id, note FROM t"):
            print(row["id"], row["note"])

Set ``CIPHRA_LIB`` to the shared library path, or pass ``lib_path=``.
"""

from __future__ import annotations

import ctypes
import json
import os
from ctypes import POINTER, byref, c_char_p, c_void_p
from typing import Any, Optional


class CiphraError(Exception):
    """An error raised by the engine (bad passphrase, SQL error, …)."""


def _candidate_paths() -> list[str]:
    env = os.environ.get("CIPHRA_LIB")
    if env:
        return [env]
    if os.name == "nt":
        name = "ciphra.dll"
    elif os.uname().sysname == "Darwin":  # type: ignore[attr-defined]
        name = "libciphra.dylib"
    else:
        name = "libciphra.so"
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.abspath(os.path.join(here, "..", ".."))
    return [
        os.path.join(root, "target", "release", name),
        os.path.join(root, "target", "debug", name),
        name,  # let the loader search the system paths
    ]


def _load_lib(lib_path: Optional[str]) -> ctypes.CDLL:
    paths = [lib_path] if lib_path else _candidate_paths()
    last: Optional[OSError] = None
    for path in paths:
        try:
            lib = ctypes.CDLL(path)
            break
        except OSError as exc:
            last = exc
    else:
        raise CiphraError(
            "could not load libciphra; build it with "
            "`cargo build --release -p ciphra-ffi` or set CIPHRA_LIB "
            f"(tried: {paths}; last error: {last})"
        )

    lib.ciphra_version.restype = c_char_p
    lib.ciphra_open.argtypes = [c_char_p, c_char_p, POINTER(c_void_p)]
    lib.ciphra_open.restype = c_void_p
    lib.ciphra_open_remote.argtypes = [c_char_p, c_char_p, c_char_p, POINTER(c_void_p)]
    lib.ciphra_open_remote.restype = c_void_p
    lib.ciphra_execute.argtypes = [c_void_p, c_char_p, POINTER(c_void_p)]
    lib.ciphra_execute.restype = c_void_p
    lib.ciphra_close.argtypes = [c_void_p]
    lib.ciphra_close.restype = None
    lib.ciphra_string_free.argtypes = [c_void_p]
    lib.ciphra_string_free.restype = None
    return lib


def _take_string(lib: ctypes.CDLL, ptr: Optional[int]) -> Optional[str]:
    """Read an owned ``char*`` and free it. ``None`` if the pointer is null."""
    if not ptr:
        return None
    try:
        return ctypes.cast(ptr, c_char_p).value.decode("utf-8")  # type: ignore[union-attr]
    finally:
        lib.ciphra_string_free(ptr)


class Ciphra:
    """An open Ciphra database. Use :meth:`open` / :meth:`open_remote`."""

    def __init__(self, lib: ctypes.CDLL, handle: int) -> None:
        self._lib = lib
        self._handle: Optional[int] = handle

    @classmethod
    def open(
        cls, data_dir: str, passphrase: str, *, lib_path: Optional[str] = None
    ) -> "Ciphra":
        """Open (or create) a local database in ``data_dir``."""
        lib = _load_lib(lib_path)
        err = c_void_p()
        handle = lib.ciphra_open(
            data_dir.encode("utf-8"), passphrase.encode("utf-8"), byref(err)
        )
        return cls._checked(lib, handle, err)

    @classmethod
    def open_remote(
        cls,
        addr: str,
        passphrase: str,
        *,
        server_key: Optional[str] = None,
        lib_path: Optional[str] = None,
    ) -> "Ciphra":
        """Connect to a ``ciphra-server`` and open the database it stores.

        ``server_key`` pins the server's static transport key (64 hex
        chars); ``None`` trusts on first use.
        """
        lib = _load_lib(lib_path)
        err = c_void_p()
        key = server_key.encode("utf-8") if server_key else None
        handle = lib.ciphra_open_remote(
            addr.encode("utf-8"), passphrase.encode("utf-8"), key, byref(err)
        )
        return cls._checked(lib, handle, err)

    @classmethod
    def _checked(cls, lib: ctypes.CDLL, handle: Optional[int], err: c_void_p) -> "Ciphra":
        message = _take_string(lib, err.value)
        if not handle:
            raise CiphraError(message or "failed to open database")
        return cls(lib, handle)

    def execute(self, sql: str) -> list[dict[str, Any]]:
        """Run one or more ``;``-separated statements.

        Returns a list of per-statement result objects (parsed JSON),
        each tagged by ``kind`` (``rows``, ``inserted``, ``created``, …).
        """
        if self._handle is None:
            raise CiphraError("database is closed")
        err = c_void_p()
        out = self._lib.ciphra_execute(self._handle, sql.encode("utf-8"), byref(err))
        payload = _take_string(self._lib, out)
        if payload is None:
            raise CiphraError(_take_string(self._lib, err.value) or "execution failed")
        return json.loads(payload)

    def query(self, sql: str) -> list[dict[str, Any]]:
        """Run ``sql`` and return the last ``rows`` result as dictionaries.

        Convenience for ``SELECT``: maps each row to ``{column: value}``.
        Raises if the statement produced no row set.
        """
        results = self.execute(sql)
        for result in reversed(results):
            if result.get("kind") == "rows":
                cols = result["columns"]
                return [dict(zip(cols, row)) for row in result["rows"]]
        raise CiphraError("statement returned no rows")

    def close(self) -> None:
        """Close the handle. Idempotent."""
        if self._handle is not None:
            self._lib.ciphra_close(self._handle)
            self._handle = None

    def __enter__(self) -> "Ciphra":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass


def version(lib_path: Optional[str] = None) -> str:
    """Return the linked ``libciphra`` version."""
    lib = _load_lib(lib_path)
    return lib.ciphra_version().decode("utf-8")
