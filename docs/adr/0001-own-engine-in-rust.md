# ADR-0001: Build our own engine in Rust

- Status: accepted
- Date: 2026-07-02

## Context

Two paths were considered for Ciphra:

**A. Crypto/AI layer on a mature engine** (PostgreSQL extension or a
proxy over an embedded engine). Fastest to an MVP; inherits MVCC,
planner, ecosystem. But the encryption boundary is compromised from the
start: the host engine sees plaintext in its buffers, WAL and indexes
unless every subsystem is wrapped, at which point the "mature engine"
advantage is mostly gone — and the product is permanently "a Postgres
extension", not a database.

**B. Own engine, written from scratch in Rust.** Slower to broad SQL
coverage, but the core invariant — *the storage layer never sees
plaintext* — can be enforced structurally, by crate boundaries, instead
of by auditing someone else's buffer manager.

## Decision

Path B. Rust for memory safety (a crypto product should not have buffer
overflows), zero-cost abstractions, and no GC pauses in the storage
path. Scope is kept honest by the roadmap: v0 is a single-node embedded
engine with a tiny SQL dialect that grows with the executor, not ahead
of it.

## Consequences

- The invariant "plaintext stops at `ciphra-engine`" is testable and
  tested (see `plaintext_never_touches_disk`).
- We accept years of distance to full SQL coverage; the differentiator
  is the crypto model, not SQL breadth.
- Wire-protocol compatibility is deferred to Phase 3 rather than
  inherited for free.
