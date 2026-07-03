# ADR-0003: The server never holds keys

- Status: accepted
- Date: 2026-07-03

## Context

Phase 3 opens the client/server split, and the first decision dictates
everything after it: where do the keys live?

**A. Trusted server** (the PostgreSQL/MySQL shape): clients speak SQL,
the server holds keys, decrypts, plans and executes. Compatible with
existing wire protocols — and it surrenders Ciphra's core promise. The
operator of the server can read every row; encryption degrades back
into TDE with extra steps.

**B. Blind server**: the engine — SQL, key hierarchy, sealing, query
planning — stays with the key holder, and the server is a durable
ordered KV store for sealed bytes it cannot read. This is the
manifesto's founding claim ("the server physically never sees
plaintext"), and every mechanism built since assumes it: sealed range
blobs and exact vector search are designs where *the key holder does
the query work*.

## Decision

B. The wire protocol is therefore a **storage protocol** (GET / SCAN /
COMMIT / DUMP over length-prefixed frames), not a SQL protocol.
`ciphra-net` implements both ends; `ciphra-server` is a ~100-line
binary with no dependency on `ciphra-crypto` at all — it *cannot*
decrypt, not merely *does not*.

Consequences of the placement:

- The engine's `Store` is `Local(Storage) | Remote(RemoteStorage)`;
  every feature (indexes, audit chain, vector search, backup) works
  identically over the wire because all of them already operated on
  sealed bytes.
- Key rotation stays a file-owner operation (it atomically swaps the
  WAL); a remote client is refused with a pointed error.
- Transport security (and the planned ML-KEM post-quantum key
  exchange) attaches at exactly this framing boundary. v1 is plain
  TCP for loopback/trusted networks and says so honestly.
- Concurrency story v1: the server serializes storage access with a
  mutex; multiple clients see committed state. Cross-client statement
  atomicity holds (single-frame COMMIT); multi-statement transactions
  remain on the roadmap.

## Trade-offs accepted

- Bandwidth: scans ship sealed rows to the client for filtering
  (indexes cut this the same way they cut local scan cost). Server-side
  filtering is impossible *by design* — that is the feature.
- Standard-protocol compatibility (MySQL/Postgres drivers) is off the
  table for the blind path; drivers will wrap the engine as a library
  plus this storage protocol instead.
