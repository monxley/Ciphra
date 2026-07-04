//! Hybrid post-quantum key exchange for Ciphra's transport, plus the
//! authenticated channel cipher built on it.
//!
//! One handshake mixes three secrets so the channel is safe if *any*
//! one survives:
//!
//! - **dh_e**: ephemeral-ephemeral X25519 → forward secrecy.
//! - **dh_s**: client-ephemeral × server-static X25519 → authenticates
//!   the server (only the holder of the pinned static key can derive it).
//! - **ss_pq**: ML-KEM-768 shared secret → post-quantum confidentiality,
//!   defeating "harvest now, decrypt later".
//!
//! `channel_key = SHA3-256(dh_e ∥ dh_s ∥ ss_pq ∥ transcript)`, where the
//! transcript binds every handshake message. All three primitives are
//! this crate's own, verified implementations.

use crate::keccak::Keccak;
use crate::ml_kem;
use crate::x25519::{KEY_LEN as X_LEN, SecretKey as XSecret};
use crate::{NONCE_LEN, aead, ml_kem::EK_LEN};

/// A server's long-term transport identity (X25519). Pinned by clients;
/// distinct from any data-encryption key — holding it does not let the
/// server decrypt stored data.
pub struct ServerIdentity {
    secret: [u8; 32],
    pub public: [u8; 32],
}

impl Drop for ServerIdentity {
    fn drop(&mut self) {
        crate::zeroize::secure_zero(&mut self.secret);
    }
}

impl ServerIdentity {
    pub fn generate() -> Self {
        Self::from_secret(random_bytes())
    }

    pub fn from_secret(secret: [u8; 32]) -> Self {
        let public = XSecret::from_bytes(secret).public_key();
        ServerIdentity { secret, public }
    }

    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret
    }
}

/// 32 fresh random bytes — the raw form of an X25519 secret we can keep.
fn random_bytes() -> [u8; 32] {
    let mut s = [0u8; 32];
    crate::fill_random(&mut s);
    s
}

/// The client's first message: ephemeral X25519 public + ML-KEM ek.
pub struct ClientHello {
    pub e_c: [u8; 32],
    pub ek: Vec<u8>,
}

/// The server's reply: ephemeral X25519 public + ML-KEM ciphertext.
pub struct ServerHello {
    pub e_s: [u8; 32],
    pub ct: Vec<u8>,
}

/// Client-side handshake state carried between the two messages.
pub struct ClientState {
    e_secret: [u8; 32],
    e_public: [u8; 32],
    ek: Vec<u8>,
    dk: Vec<u8>,
}

impl Drop for ClientState {
    fn drop(&mut self) {
        // The ephemeral X25519 secret and the ML-KEM decapsulation key
        // are the secrets here; the public halves need not be cleared.
        crate::zeroize::secure_zero(&mut self.e_secret);
        crate::zeroize::secure_zero(&mut self.dk);
    }
}

/// Begin a handshake: returns the state to keep and the hello to send.
pub fn client_start() -> (ClientState, ClientHello) {
    let e_secret = random_bytes();
    let e_public = XSecret::from_bytes(e_secret).public_key();
    let kp = ml_kem::KeyPair::generate();
    let hello = ClientHello {
        e_c: e_public,
        ek: kp.ek.clone(),
    };
    let state = ClientState {
        e_secret,
        e_public,
        ek: kp.ek,
        dk: kp.dk,
    };
    (state, hello)
}

/// Finish the handshake on the client, pinning `server_static_public`.
pub fn client_finish(
    state: &ClientState,
    hello: &ServerHello,
    server_static_public: &[u8; 32],
) -> [u8; 32] {
    let e = XSecret::from_bytes(state.e_secret);
    let dh_e = e.diffie_hellman(&hello.e_s);
    let dh_s = e.diffie_hellman(server_static_public);
    let ss_pq = ml_kem::decapsulate(&state.dk, &hello.ct);
    derive_key(
        &dh_e,
        &dh_s,
        &ss_pq,
        &state.e_public,
        &state.ek,
        &hello.e_s,
        &hello.ct,
    )
}

/// Server side: consume the client hello, return the reply and the key.
pub fn server_respond(identity: &ServerIdentity, hello: &ClientHello) -> (ServerHello, [u8; 32]) {
    let e_secret = random_bytes();
    let e = XSecret::from_bytes(e_secret);
    let e_public = e.public_key();

    let dh_e = e.diffie_hellman(&hello.e_c);
    let static_secret = XSecret::from_bytes(identity.secret);
    let dh_s = static_secret.diffie_hellman(&hello.e_c);
    let (ct, ss_pq) = ml_kem::encapsulate(&hello.ek);

    let key = derive_key(&dh_e, &dh_s, &ss_pq, &hello.e_c, &hello.ek, &e_public, &ct);
    (ServerHello { e_s: e_public, ct }, key)
}

#[allow(clippy::too_many_arguments)]
fn derive_key(
    dh_e: &[u8; 32],
    dh_s: &[u8; 32],
    ss_pq: &[u8; 32],
    e_c: &[u8; 32],
    ek: &[u8],
    e_s: &[u8; 32],
    ct: &[u8],
) -> [u8; 32] {
    let mut sponge = Keccak::sha3_256();
    sponge.absorb(b"ciphra/transport/v1");
    sponge.absorb(dh_e);
    sponge.absorb(dh_s);
    sponge.absorb(ss_pq);
    // Transcript binding.
    sponge.absorb(e_c);
    sponge.absorb(ek);
    sponge.absorb(e_s);
    sponge.absorb(ct);
    let mut key = [0u8; 32];
    sponge.squeeze(&mut key);
    key
}

/// Expected wire sizes, for framing.
pub const CLIENT_HELLO_LEN: usize = X_LEN + EK_LEN;
pub const SERVER_HELLO_LEN: usize = X_LEN + ml_kem::CT_LEN;

impl ClientHello {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.e_c.to_vec();
        out.extend_from_slice(&self.ek);
        out
    }
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != CLIENT_HELLO_LEN {
            return None;
        }
        let mut e_c = [0u8; 32];
        e_c.copy_from_slice(&bytes[..32]);
        Some(ClientHello {
            e_c,
            ek: bytes[32..].to_vec(),
        })
    }
}

impl ServerHello {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.e_s.to_vec();
        out.extend_from_slice(&self.ct);
        out
    }
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != SERVER_HELLO_LEN {
            return None;
        }
        let mut e_s = [0u8; 32];
        e_s.copy_from_slice(&bytes[..32]);
        Some(ServerHello {
            e_s,
            ct: bytes[32..].to_vec(),
        })
    }
}

/// Seal one channel message under `key` with an explicit `counter` as
/// the nonce (per-direction, monotonic). Reordering or replay changes
/// the nonce and fails authentication.
pub fn channel_seal(key: &[u8; 32], counter: u64, plaintext: &[u8]) -> Vec<u8> {
    aead::seal(
        key,
        &counter_nonce(counter),
        plaintext,
        b"ciphra/transport/v1",
    )
}

/// Open a message sealed by [`channel_seal`]; `None` on any mismatch.
pub fn channel_open(key: &[u8; 32], counter: u64, sealed: &[u8]) -> Option<Vec<u8>> {
    aead::open(key, &counter_nonce(counter), sealed, b"ciphra/transport/v1")
}

fn counter_nonce(counter: u64) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    nonce[..8].copy_from_slice(&counter.to_le_bytes());
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_sides_derive_the_same_key() {
        let server = ServerIdentity::generate();
        let (state, hello) = client_start();
        let (reply, server_key) = server_respond(&server, &hello);
        let client_key = client_finish(&state, &reply, &server.public);
        assert_eq!(client_key, server_key);
    }

    #[test]
    fn wrong_pinned_server_key_diverges() {
        // A client pinning the wrong static key derives a different
        // channel key than the server — so it will fail to talk to an
        // impersonator, and to the real server if it pins the wrong key.
        let server = ServerIdentity::generate();
        let impostor = ServerIdentity::generate();
        let (state, hello) = client_start();
        let (reply, server_key) = server_respond(&server, &hello);
        let mispinned = client_finish(&state, &reply, &impostor.public);
        assert_ne!(mispinned, server_key);
    }

    #[test]
    fn hello_serialization_roundtrips() {
        let (_, hello) = client_start();
        let bytes = hello.to_bytes();
        assert_eq!(bytes.len(), CLIENT_HELLO_LEN);
        let back = ClientHello::from_bytes(&bytes).unwrap();
        assert_eq!(back.e_c, hello.e_c);
        assert_eq!(back.ek, hello.ek);
        assert!(ClientHello::from_bytes(&bytes[..10]).is_none());
    }

    #[test]
    fn channel_cipher_roundtrip_and_counter_binding() {
        let key = [7u8; 32];
        let sealed = channel_seal(&key, 1, b"remote request");
        assert_eq!(channel_open(&key, 1, &sealed).unwrap(), b"remote request");
        // Wrong counter (reorder/replay) fails.
        assert!(channel_open(&key, 2, &sealed).is_none());
        // Wrong key fails.
        assert!(channel_open(&[8u8; 32], 1, &sealed).is_none());
    }
}
