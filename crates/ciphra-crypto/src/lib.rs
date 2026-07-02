//! Ciphra cryptography layer — zero third-party dependencies.
//!
//! Everything here is implemented in this crate from the primary
//! specifications and verified against official test vectors:
//! SHA-256 (FIPS 180-4), HMAC (RFC 2104), HKDF (RFC 5869),
//! PBKDF2 (RFC 8018), ChaCha20-Poly1305 (RFC 8439).
//!
//! Key hierarchy:
//!
//! ```text
//! passphrase ── PBKDF2-HMAC-SHA256(salt, iters) ──► MasterKey (never stored)
//! MasterKey  ── HKDF-SHA256(context) ────────────► CipherKey per table/purpose
//! CipherKey  ── ChaCha20-Poly1305(nonce, AAD) ───► sealed envelope
//! ```
//!
//! Envelope layout: `nonce (12) | ciphertext | tag (16)`. The AAD binds
//! a ciphertext to its location (e.g. table + row id), so an attacker
//! with file access cannot swap encrypted rows around undetected.
//!
//! Threat model v0: protects data at rest against an attacker who can
//! read or tamper with the database files but does not know the
//! passphrase. It does NOT hide access patterns, key names or object
//! sizes — see ARCHITECTURE.md for the full model and the planned
//! upgrades (Argon2id, queryable encryption, audited implementations).

mod aead;
mod chacha20;
mod hmac;
mod poly1305;
mod rand;
mod sha256;

pub use hmac::{hkdf_expand, hkdf_extract, hmac_sha256, pbkdf2_sha256};
pub use rand::fill_random;
pub use sha256::{Sha256, sha256};

pub const KEY_LEN: usize = 32;
pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = aead::TAG_LEN;

/// PBKDF2 work factor used unless the caller picks another one.
/// OWASP's 2023+ recommendation for PBKDF2-HMAC-SHA256.
pub const DEFAULT_KDF_ITERATIONS: u32 = 600_000;

#[derive(Debug, PartialEq, Eq)]
pub enum CryptoError {
    /// Decryption failed: wrong key, tampered data, or mismatched AAD.
    Open,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::Open => {
                write!(f, "decryption failed: wrong key or tampered data")
            }
        }
    }
}

impl std::error::Error for CryptoError {}

pub type Result<T> = std::result::Result<T, CryptoError>;

/// Root of the key hierarchy. Derived from a passphrase, never persisted.
pub struct MasterKey([u8; KEY_LEN]);

impl MasterKey {
    /// Derive the master key with PBKDF2-HMAC-SHA256.
    /// Use [`random_salt`] for `salt` and persist it; `iterations` is the
    /// work factor (see [`DEFAULT_KDF_ITERATIONS`]).
    pub fn derive_from_passphrase(passphrase: &str, salt: &[u8], iterations: u32) -> Self {
        let mut key = [0u8; KEY_LEN];
        pbkdf2_sha256(passphrase.as_bytes(), salt, iterations, &mut key);
        MasterKey(key)
    }

    /// Derive a purpose-specific key, e.g. `derive_key("table:users")`.
    /// Deterministic: the same master key and context always yield the
    /// same key, so nothing but the salt needs to be stored.
    pub fn derive_key(&self, context: &str) -> CipherKey {
        let prk = hkdf_extract(b"ciphra/v0/subkey", &self.0);
        let mut key = [0u8; KEY_LEN];
        hkdf_expand(&prk, context.as_bytes(), &mut key);
        CipherKey(key)
    }
}

/// A ChaCha20-Poly1305 key for one table / purpose.
pub struct CipherKey([u8; KEY_LEN]);

impl CipherKey {
    /// Encrypt `plaintext`, binding it to `aad` (authenticated, not
    /// encrypted). Every call draws a fresh random nonce.
    pub fn seal(&self, plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
        let mut nonce = [0u8; NONCE_LEN];
        rand::fill_random(&mut nonce);
        let mut sealed = nonce.to_vec();
        sealed.extend_from_slice(&aead::seal(&self.0, &nonce, plaintext, aad));
        sealed
    }

    /// Decrypt an envelope produced by [`CipherKey::seal`] with the same `aad`.
    pub fn open(&self, sealed: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        if sealed.len() < NONCE_LEN + TAG_LEN {
            return Err(CryptoError::Open);
        }
        let (nonce, rest) = sealed.split_at(NONCE_LEN);
        let nonce: [u8; NONCE_LEN] = nonce.try_into().unwrap();
        aead::open(&self.0, &nonce, rest, aad).ok_or(CryptoError::Open)
    }
}

/// Generate a random salt for [`MasterKey::derive_from_passphrase`].
pub fn random_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    rand::fill_random(&mut salt);
    salt
}

#[cfg(test)]
pub(crate) mod test_util {
    /// Decode a hex string; test helper only.
    pub fn hex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        assert!(s.len().is_multiple_of(2), "odd-length hex string");
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("bad hex"))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn master() -> MasterKey {
        // Low iteration count: tests exercise correctness, not work factor.
        MasterKey::derive_from_passphrase("correct horse battery staple", b"0123456789abcdef", 2)
    }

    #[test]
    fn seal_open_roundtrip() {
        let key = master().derive_key("table:users");
        let sealed = key.seal(b"top secret row", b"users/1");
        assert!(!sealed.windows(14).any(|w| w == b"top secret row"));
        assert_eq!(key.open(&sealed, b"users/1").unwrap(), b"top secret row");
    }

    #[test]
    fn key_derivation_is_deterministic_and_domain_separated() {
        let a = master().derive_key("table:users");
        let b = master().derive_key("table:users");
        let c = master().derive_key("table:orders");
        let sealed = a.seal(b"x", b"");
        assert_eq!(b.open(&sealed, b"").unwrap(), b"x");
        assert_eq!(c.open(&sealed, b""), Err(CryptoError::Open));
    }

    #[test]
    fn wrong_passphrase_fails_to_open() {
        let key = master().derive_key("table:users");
        let sealed = key.seal(b"data", b"");
        let wrong = MasterKey::derive_from_passphrase("wrong", b"0123456789abcdef", 2)
            .derive_key("table:users");
        assert_eq!(wrong.open(&sealed, b""), Err(CryptoError::Open));
    }

    #[test]
    fn aad_mismatch_is_detected() {
        // A ciphertext moved to another row must not decrypt.
        let key = master().derive_key("t");
        let sealed = key.seal(b"row for id 1", b"users/1");
        assert_eq!(key.open(&sealed, b"users/2"), Err(CryptoError::Open));
    }

    #[test]
    fn nonces_are_unique_per_seal() {
        let key = master().derive_key("t");
        let a = key.seal(b"same plaintext", b"");
        let b = key.seal(b"same plaintext", b"");
        assert_ne!(a, b);
    }

    #[test]
    fn kdf_iterations_are_part_of_the_key() {
        let a = MasterKey::derive_from_passphrase("pass", b"0123456789abcdef", 2);
        let b = MasterKey::derive_from_passphrase("pass", b"0123456789abcdef", 3);
        let sealed = a.derive_key("k").seal(b"x", b"");
        assert_eq!(b.derive_key("k").open(&sealed, b""), Err(CryptoError::Open));
    }
}
