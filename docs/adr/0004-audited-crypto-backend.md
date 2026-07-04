# ADR-0004: Optional build against audited crypto implementations

- Status: accepted (switch + design landed; audited backend binding
  deferred — see "Status of the binding")
- Date: 2026-07-04

## Context

ADR-0002 committed to zero third-party dependencies and from-scratch
crypto primitives, verified against official RFC/NIST/FIPS test vectors.
That is the right default for an auditable-in-one-repo encrypted
database, but it is not the right *only* option:

- Some operators' trust anchor is a specific audited library (a
  FIPS-validated module, or a widely-reviewed crate) rather than our
  implementations, however well tested.
- Until Ciphra's own crypto has an external audit, offering a build that
  swaps in already-audited implementations is a pragmatic hedge.

The from-scratch code is also the crypto **boundary**: every layer above
`ciphra-crypto` (engine, net, ffi) depends only on its stable public
API, never on a specific implementation (this is why the blind-server
split in ADR-0003 works). That boundary is exactly what makes an
implementation swap tractable.

## Decision

Add an opt-in **`audited` Cargo feature** to `ciphra-crypto`, forwarded
by every crate that depends on it (`ciphra-net`, `ciphra-engine`,
`ciphra-ffi`, `ciphra`, `ciphra-server`). Building with
`--features audited` selects an audited third-party backend in place of
the from-scratch primitives; the default build is unchanged.

The public API of `ciphra-crypto` is the contract. Both backends must
implement it identically — same function signatures, same byte-for-byte
outputs on the same inputs — so nothing above the boundary changes.

### Fail closed, don't fake

The audited backend is **not bundled in this repository**, so enabling
the feature triggers a `compile_error!` that points here, rather than
silently compiling the from-scratch code. A feature named `audited` must
never quietly give you unaudited crypto. Turning the feature on is a
deliberate act that requires providing the backend.

### Crate mapping

The audited backend binds each primitive to a reviewed implementation.
The recommended mapping (all pure-Rust, widely used):

| Ciphra primitive (`ciphra-crypto`) | Audited crate |
|---|---|
| `sha256`, `Sha256` | `sha2` |
| `hmac_sha256` | `hmac` + `sha2` |
| `hkdf_extract` / `hkdf_expand` | `hkdf` |
| `pbkdf2_sha256` | `pbkdf2` |
| `blake2b`, `Blake2b` | `blake2` |
| `argon2id` | `argon2` |
| ChaCha20-Poly1305 (`aead::seal`/`open`) | `chacha20poly1305` |
| SHA-3 / SHAKE (`sha3_256`, `sha3_512`, `shake256`, `Keccak`) | `sha3` |
| X25519 (`x25519`) | `x25519-dalek` |
| ML-KEM-768 | `ml-kem` (RustCrypto) |
| ML-DSA-65 | `ml-dsa` (RustCrypto) |

Higher-level constructions that are *Ciphra's own* — the key hierarchy
(`MasterKey`/`CipherKey`), the hybrid transport handshake (`hybrid`),
the sealed-envelope layout — stay Ciphra code in both backends; they
merely call whichever primitives are active. Only the primitives above
are swapped.

### How to implement the backend

The from-scratch primitives live in named modules (`sha256`, `aead`,
`x25519`, `ml_kem`, …) so the swap is a module-selection change, not a
call-site change. To add the audited backend:

1. Move the from-scratch primitive modules under `src/scratch/` and add,
   for each swappable module, a companion under `src/audited/` that
   re-implements the same items via the crate in the table. Select per
   feature with `#[cfg_attr]` on the `mod` declarations:

   ```rust
   #[cfg(not(feature = "audited"))]
   #[path = "scratch/sha256.rs"] mod sha256;
   #[cfg(feature = "audited")]
   #[path = "audited/sha256.rs"]  mod sha256;
   ```

   Because the module *name* is unchanged, every internal caller
   (`crate::sha256::sha256`, `crate::aead::seal`, …) is untouched.

2. Declare the audited crates as **optional** dependencies enabled by the
   feature, e.g. in `ciphra-crypto/Cargo.toml`:

   ```toml
   [dependencies]
   sha2 = { version = "0.10", optional = true }
   # … one per row of the mapping table …

   [features]
   audited = ["dep:sha2", "dep:hmac", "dep:hkdf", "dep:pbkdf2",
              "dep:blake2", "dep:argon2", "dep:chacha20poly1305",
              "dep:sha3", "dep:x25519-dalek", "dep:ml-kem", "dep:ml-dsa"]
   ```

3. Delete the `compile_error!` guard in `lib.rs`.

### Verifying the swap: differential tests

The two backends must agree. Add a test build that compiles both and
checks byte-equality on the existing test vectors plus random inputs:
for every primitive, `scratch::f(x) == audited::f(x)` across the RFC/NIST
vectors and a batch of random inputs. Round-trip properties (AEAD
seal/open, KEM encaps/decaps, sign/verify) must hold under the audited
backend too. This is the acceptance gate for enabling `audited` in CI.

## Status of the binding

The switch, the fail-closed guard, the crate mapping and the
implementation recipe are in the repository now and are testable
(`cargo build` uses the from-scratch backend and passes all vectors;
`cargo build --features audited` fails closed with guidance).

The audited backend itself is **not yet bound**: this repository's build
environment blocks the package registry (`crates.io` returns HTTP 403),
so the audited crates cannot be added, resolved or compiled here — the
very constraint that motivated ADR-0002. Completing the binding (steps
1–3 above and the differential tests) is a mechanical change in an
environment with registry access, and requires no change above the
`ciphra-crypto` boundary.

## Consequences

- The default remains the auditable-in-one-repo from-scratch build; the
  supply-chain claim in ADR-0002 is unchanged for default builds.
- Operators who need an audited or FIPS-validated backend have a
  supported, documented path that touches only `ciphra-crypto`.
- `audited` can never silently degrade to unaudited crypto.
- We carry a small, standing obligation: keep the two backends'
  behaviour identical, enforced by the differential tests once bound.
