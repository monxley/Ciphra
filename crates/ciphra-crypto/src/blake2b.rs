//! BLAKE2b (RFC 7693), unkeyed, with variable digest length 1..=64.
//! Needed by Argon2 (RFC 9106), which uses BLAKE2b as its base hash.

const IV: [u64; 8] = [
    0x6a09_e667_f3bc_c908,
    0xbb67_ae85_84ca_a73b,
    0x3c6e_f372_fe94_f82b,
    0xa54f_f53a_5f1d_36f1,
    0x510e_527f_ade6_82d1,
    0x9b05_688c_2b3e_6c1f,
    0x1f83_d9ab_fb41_bd6b,
    0x5be0_cd19_137e_2179,
];

const SIGMA: [[usize; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

/// Streaming BLAKE2b with a digest length fixed at construction.
pub struct Blake2b {
    h: [u64; 8],
    t: u128,
    buffer: [u8; 128],
    buffered: usize,
    out_len: usize,
}

impl Blake2b {
    /// `out_len` must be in 1..=64.
    pub fn new(out_len: usize) -> Self {
        assert!(
            (1..=64).contains(&out_len),
            "BLAKE2b digest length out of range"
        );
        let mut h = IV;
        // Parameter block for sequential, unkeyed hashing:
        // digest_length | key_length << 8 | fanout << 16 | depth << 24.
        h[0] ^= 0x0101_0000 ^ out_len as u64;
        Blake2b {
            h,
            t: 0,
            buffer: [0; 128],
            buffered: 0,
            out_len,
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            // Only flush a full buffer when more input follows: the
            // final block must go through the `last` path in finalize.
            if self.buffered == 128 {
                self.t += 128;
                let block = self.buffer;
                self.compress(&block, false);
                self.buffered = 0;
            }
            let take = (128 - self.buffered).min(data.len());
            self.buffer[self.buffered..self.buffered + take].copy_from_slice(&data[..take]);
            self.buffered += take;
            data = &data[take..];
        }
    }

    pub fn finalize(mut self) -> Vec<u8> {
        self.t += self.buffered as u128;
        let mut block = self.buffer;
        block[self.buffered..].fill(0);
        self.compress(&block, true);

        let mut out = Vec::with_capacity(self.out_len);
        for word in self.h {
            out.extend_from_slice(&word.to_le_bytes());
        }
        out.truncate(self.out_len);
        out
    }

    fn compress(&mut self, block: &[u8; 128], last: bool) {
        let mut m = [0u64; 16];
        for (word, chunk) in m.iter_mut().zip(block.chunks_exact(8)) {
            *word = u64::from_le_bytes(chunk.try_into().unwrap());
        }

        let mut v = [0u64; 16];
        v[..8].copy_from_slice(&self.h);
        v[8..].copy_from_slice(&IV);
        v[12] ^= self.t as u64;
        v[13] ^= (self.t >> 64) as u64;
        if last {
            v[14] = !v[14];
        }

        for round in 0..12 {
            let s = &SIGMA[round % 10];
            g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
            g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
            g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
            g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
            g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
            g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
            g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
            g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
        }

        for i in 0..8 {
            self.h[i] ^= v[i] ^ v[i + 8];
        }
    }
}

#[inline(always)]
fn g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

/// One-shot BLAKE2b.
pub fn blake2b(out_len: usize, data: &[u8]) -> Vec<u8> {
    let mut hasher = Blake2b::new(out_len);
    hasher.update(data);
    hasher.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::hex;

    #[test]
    fn rfc7693_abc_vector() {
        // RFC 7693 Appendix A: BLAKE2b-512("abc").
        assert_eq!(
            blake2b(64, b"abc"),
            hex(
                "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1\
                 7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
            )
        );
    }

    #[test]
    fn empty_input_vector() {
        // Well-known BLAKE2b-512("") value.
        assert_eq!(
            blake2b(64, b""),
            hex(
                "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419\
                 d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
            )
        );
    }

    #[test]
    fn streaming_matches_oneshot_at_all_boundaries() {
        let data: Vec<u8> = (0..500u32).map(|i| (i % 251) as u8).collect();
        let expected = blake2b(64, &data);
        for split in [0, 1, 127, 128, 129, 255, 256, 300, 500] {
            let mut hasher = Blake2b::new(64);
            hasher.update(&data[..split]);
            hasher.update(&data[split..]);
            assert_eq!(hasher.finalize(), expected, "split at {split}");
        }
    }

    #[test]
    fn digest_lengths_are_distinct_prefix_free() {
        // Different out_len parameterizations are different functions,
        // not truncations of each other.
        let d32 = blake2b(32, b"ciphra");
        let d64 = blake2b(64, b"ciphra");
        assert_eq!(d32.len(), 32);
        assert_eq!(d64.len(), 64);
        assert_ne!(&d64[..32], &d32[..]);
    }
}
