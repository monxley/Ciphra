# ADR-0002: Zero third-party dependencies; own crypto primitives

- Status: accepted
- Date: 2026-07-02

## Context

The original plan was to use the RustCrypto crates (`aes-gcm`, `argon2`,
`hkdf`, `sha2`) — pure-Rust, widely reviewed. Two forces pushed the
other way:

1. **Supply chain as a product property.** For an encrypted database,
   every dependency is an audit obligation transferred to the user.
   "The supply chain is the Rust stdlib plus this repo" is a claim none
   of the mainstream engines can make.
2. The build environment for this repository restricts network egress,
   so builds must not assume a package registry at all.

## Decision

The core workspace has **no third-party dependencies**. Cryptographic
primitives are implemented in `ciphra-crypto` from the primary
specifications and gated by official test vectors:

| Primitive | Spec | Vectors |
|---|---|---|
| SHA-256 | FIPS 180-4 | NIST CAVP |
| HMAC | RFC 2104 | RFC 4231 |
| HKDF | RFC 5869 | RFC 5869 |
| PBKDF2 | RFC 8018 | RFC 7914 §11 |
| ChaCha20, Poly1305, AEAD | RFC 8439 | RFC 8439 |

AEAD is ChaCha20-Poly1305 rather than AES-GCM deliberately: a plain
software ChaCha20 has no secret-indexed memory accesses (add-rotate-xor
only), so the classic AES cache-timing side channel does not exist to
begin with. Poly1305 is ported from the byte-limb reference
construction (as in TweetNaCl) — slow, but small enough to audit line
by line, with no carry-propagation subtleties.

## Consequences

- "Don't roll your own crypto" is answered, not ignored: primitives are
  implementations of standard constructions with published vectors, not
  invented schemes; the AEAD construction, key hierarchy and nonce
  policy follow the RFCs. The residual risk (implementation bugs beyond
  vector coverage) is explicitly on the audit checklist, and an
  *optional* build against audited external implementations behind the
  same API is planned (Phase 3).
- Performance is not competitive yet (byte-limb Poly1305, table-free
  scalar ChaCha20); acceptable for v0, optimized later without API
  changes.
- Argon2id (memory-hard KDF) is deferred to Phase 1 since it is a much
  larger implementation; PBKDF2 with 600k iterations is the interim
  default, recorded per-database in `ciphra.keyparams`.
