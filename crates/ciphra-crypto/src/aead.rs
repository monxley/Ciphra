//! ChaCha20-Poly1305 AEAD (RFC 8439 §2.8), built from the primitives in
//! this crate and verified against the RFC test vector.

use crate::chacha20::{self, KEY_LEN, NONCE_LEN};
use crate::poly1305::{poly1305, tags_equal};

pub const TAG_LEN: usize = 16;

/// Encrypt `plaintext` and authenticate it together with `aad`.
/// Returns `ciphertext || tag`.
pub fn seal(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    let mut out = plaintext.to_vec();
    // Keystream block 0 is reserved for the one-time Poly1305 key;
    // encryption starts at block 1.
    chacha20::xor_stream(key, nonce, 1, &mut out);
    let tag = compute_tag(key, nonce, &out, aad);
    out.extend_from_slice(&tag);
    out
}

/// Verify and decrypt `ciphertext || tag`. Returns `None` if the tag,
/// key, nonce or AAD do not match — no partial plaintext ever escapes.
pub fn open(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    sealed: &[u8],
    aad: &[u8],
) -> Option<Vec<u8>> {
    if sealed.len() < TAG_LEN {
        return None;
    }
    let (ciphertext, tag_bytes) = sealed.split_at(sealed.len() - TAG_LEN);
    let expected: [u8; TAG_LEN] = tag_bytes.try_into().unwrap();
    let actual = compute_tag(key, nonce, ciphertext, aad);
    if !tags_equal(&actual, &expected) {
        return None;
    }
    let mut plaintext = ciphertext.to_vec();
    chacha20::xor_stream(key, nonce, 1, &mut plaintext);
    Some(plaintext)
}

/// mac_data = aad || pad16 || ciphertext || pad16 || len(aad) || len(ct),
/// authenticated with a one-time key from keystream block 0.
fn compute_tag(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
    aad: &[u8],
) -> [u8; TAG_LEN] {
    let block0 = chacha20::block(key, 0, nonce);
    let otk: [u8; 32] = block0[..32].try_into().unwrap();

    let mut mac_data = Vec::with_capacity(aad.len() + ciphertext.len() + 32);
    mac_data.extend_from_slice(aad);
    mac_data.resize(mac_data.len().next_multiple_of(16), 0);
    mac_data.extend_from_slice(ciphertext);
    mac_data.resize(mac_data.len().next_multiple_of(16), 0);
    mac_data.extend_from_slice(&(aad.len() as u64).to_le_bytes());
    mac_data.extend_from_slice(&(ciphertext.len() as u64).to_le_bytes());

    poly1305(&mac_data, &otk)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::hex;

    fn rfc_key() -> [u8; 32] {
        hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
            .try_into()
            .unwrap()
    }

    fn rfc_nonce() -> [u8; 12] {
        hex("070000004041424344454647").try_into().unwrap()
    }

    const RFC_AAD: [u8; 12] = [
        0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
    ];
    const RFC_PLAINTEXT: &[u8] = b"Ladies and Gentlemen of the class of '99: \
If I could offer you only one tip for the future, sunscreen would be it.";

    #[test]
    fn rfc8439_aead_vector() {
        // RFC 8439 §2.8.2
        let sealed = seal(&rfc_key(), &rfc_nonce(), RFC_PLAINTEXT, &RFC_AAD);
        let expected_ct = hex(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6\
             3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36\
             92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc\
             3ff4def08e4b7a9de576d26586cec64b6116",
        );
        let expected_tag = hex("1ae10b594f09e26a7e902ecbd0600691");
        assert_eq!(sealed[..sealed.len() - TAG_LEN].to_vec(), expected_ct);
        assert_eq!(sealed[sealed.len() - TAG_LEN..].to_vec(), expected_tag);

        let opened = open(&rfc_key(), &rfc_nonce(), &sealed, &RFC_AAD).unwrap();
        assert_eq!(opened, RFC_PLAINTEXT);
    }

    #[test]
    fn tamper_and_mismatch_are_rejected() {
        let sealed = seal(&rfc_key(), &rfc_nonce(), b"payload", b"aad");
        // Flipped ciphertext bit.
        let mut bad = sealed.clone();
        bad[0] ^= 1;
        assert!(open(&rfc_key(), &rfc_nonce(), &bad, b"aad").is_none());
        // Flipped tag bit.
        let mut bad = sealed.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert!(open(&rfc_key(), &rfc_nonce(), &bad, b"aad").is_none());
        // Wrong AAD.
        assert!(open(&rfc_key(), &rfc_nonce(), &sealed, b"other").is_none());
        // Wrong nonce.
        let other_nonce: [u8; 12] = hex("070000004041424344454648").try_into().unwrap();
        assert!(open(&rfc_key(), &other_nonce, &sealed, b"aad").is_none());
        // Too short to even hold a tag.
        assert!(open(&rfc_key(), &rfc_nonce(), &sealed[..8], b"aad").is_none());
    }

    #[test]
    fn empty_plaintext_roundtrip() {
        let sealed = seal(&rfc_key(), &rfc_nonce(), b"", b"context");
        assert_eq!(sealed.len(), TAG_LEN);
        assert_eq!(
            open(&rfc_key(), &rfc_nonce(), &sealed, b"context").unwrap(),
            b""
        );
    }
}
