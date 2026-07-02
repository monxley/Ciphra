//! ChaCha20 stream cipher (RFC 8439). Chosen over AES for the v0
//! software implementation because it is naturally constant-time: no
//! secret-indexed table lookups, so no cache-timing side channel.

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const BLOCK_LEN: usize = 64;

const SIGMA: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574]; // "expand 32-byte k"

#[inline(always)]
fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(12);
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(7);
}

/// Compute one 64-byte keystream block.
pub fn block(key: &[u8; KEY_LEN], counter: u32, nonce: &[u8; NONCE_LEN]) -> [u8; BLOCK_LEN] {
    let mut state = [0u32; 16];
    state[..4].copy_from_slice(&SIGMA);
    for (i, chunk) in key.chunks_exact(4).enumerate() {
        state[4 + i] = u32::from_le_bytes(chunk.try_into().unwrap());
    }
    state[12] = counter;
    for (i, chunk) in nonce.chunks_exact(4).enumerate() {
        state[13 + i] = u32::from_le_bytes(chunk.try_into().unwrap());
    }

    let mut working = state;
    for _ in 0..10 {
        // Column rounds.
        quarter_round(&mut working, 0, 4, 8, 12);
        quarter_round(&mut working, 1, 5, 9, 13);
        quarter_round(&mut working, 2, 6, 10, 14);
        quarter_round(&mut working, 3, 7, 11, 15);
        // Diagonal rounds.
        quarter_round(&mut working, 0, 5, 10, 15);
        quarter_round(&mut working, 1, 6, 11, 12);
        quarter_round(&mut working, 2, 7, 8, 13);
        quarter_round(&mut working, 3, 4, 9, 14);
    }

    let mut out = [0u8; BLOCK_LEN];
    for i in 0..16 {
        let word = working[i].wrapping_add(state[i]);
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    out
}

/// XOR `data` with the keystream starting at `counter` (encrypts and
/// decrypts; ChaCha20 is an involution under XOR).
pub fn xor_stream(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], counter: u32, data: &mut [u8]) {
    for (i, chunk) in data.chunks_mut(BLOCK_LEN).enumerate() {
        let keystream = block(key, counter.wrapping_add(i as u32), nonce);
        for (byte, k) in chunk.iter_mut().zip(keystream) {
            *byte ^= k;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::hex;

    #[test]
    fn rfc8439_block_vector() {
        // RFC 8439 §2.3.2
        let key: [u8; 32] = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .try_into()
            .unwrap();
        let nonce: [u8; 12] = hex("000000090000004a00000000").try_into().unwrap();
        let expected = hex(
            "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e\
             d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e",
        );
        assert_eq!(block(&key, 1, &nonce).to_vec(), expected);
    }

    #[test]
    fn rfc8439_encryption_vector() {
        // RFC 8439 §2.4.2
        let key: [u8; 32] = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .try_into()
            .unwrap();
        let nonce: [u8; 12] = hex("000000000000004a00000000").try_into().unwrap();
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you \
only one tip for the future, sunscreen would be it.";
        let mut data = plaintext.to_vec();
        xor_stream(&key, &nonce, 1, &mut data);
        let expected = hex(
            "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b\
             f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8\
             07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736\
             5af90bbf74a35be6b40b8eedf2785e42874d",
        );
        assert_eq!(data, expected);
        // Decrypt back.
        xor_stream(&key, &nonce, 1, &mut data);
        assert_eq!(data, plaintext);
    }
}
