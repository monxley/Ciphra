//! Keccak-f[1600], SHA-3 and SHAKE (FIPS 202). SHA-3/SHAKE are the base
//! symmetric primitives of ML-KEM (FIPS 203), which is why they live
//! here; all are verified against the NIST test vectors below.

const ROUNDS: usize = 24;

const RC: [u64; ROUNDS] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808a,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808b,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008a,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000a,
    0x0000_0000_8000_808b,
    0x8000_0000_0000_008b,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800a,
    0x8000_0000_8000_000a,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];

/// Rotation offsets r[x][y], indexed as `RHO[x + 5*y]`.
const RHO: [u32; 25] = [
    0, 1, 62, 28, 27, //
    36, 44, 6, 55, 20, //
    3, 10, 43, 25, 39, //
    41, 45, 15, 21, 8, //
    18, 2, 61, 56, 14,
];

/// The Keccak-f[1600] permutation over 25 64-bit lanes.
fn keccak_f(state: &mut [u64; 25]) {
    for &rc in RC.iter() {
        // θ
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        let mut d = [0u64; 5];
        for x in 0..5 {
            d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
        }
        for x in 0..5 {
            for y in 0..5 {
                state[x + 5 * y] ^= d[x];
            }
        }

        // ρ and π: B[y, 2x+3y] = rot(A[x,y], r[x,y])
        let mut b = [0u64; 25];
        for x in 0..5 {
            for y in 0..5 {
                let nx = y;
                let ny = (2 * x + 3 * y) % 5;
                b[nx + 5 * ny] = state[x + 5 * y].rotate_left(RHO[x + 5 * y]);
            }
        }

        // χ
        for x in 0..5 {
            for y in 0..5 {
                state[x + 5 * y] =
                    b[x + 5 * y] ^ ((!b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y]);
            }
        }

        // ι
        state[0] ^= rc;
    }
}

/// A Keccak sponge parameterized by rate (bytes) and domain-separation
/// suffix (0x06 for SHA-3, 0x1F for SHAKE).
pub struct Keccak {
    state: [u64; 25],
    rate: usize,
    suffix: u8,
    offset: usize,
    squeezing: bool,
}

impl Keccak {
    fn new(rate: usize, suffix: u8) -> Self {
        Keccak {
            state: [0u64; 25],
            rate,
            suffix,
            offset: 0,
            squeezing: false,
        }
    }

    pub fn sha3_256() -> Self {
        Self::new(136, 0x06)
    }
    pub fn sha3_512() -> Self {
        Self::new(72, 0x06)
    }
    pub fn shake128() -> Self {
        Self::new(168, 0x1f)
    }
    pub fn shake256() -> Self {
        Self::new(136, 0x1f)
    }

    fn xor_byte(&mut self, index: usize, byte: u8) {
        let lane = index / 8;
        let shift = 8 * (index % 8);
        self.state[lane] ^= (byte as u64) << shift;
    }

    fn byte(&self, index: usize) -> u8 {
        let lane = index / 8;
        let shift = 8 * (index % 8);
        (self.state[lane] >> shift) as u8
    }

    pub fn absorb(&mut self, mut data: &[u8]) {
        assert!(!self.squeezing, "absorb after squeeze");
        while !data.is_empty() {
            let take = (self.rate - self.offset).min(data.len());
            for (i, &byte) in data[..take].iter().enumerate() {
                self.xor_byte(self.offset + i, byte);
            }
            self.offset += take;
            data = &data[take..];
            if self.offset == self.rate {
                keccak_f(&mut self.state);
                self.offset = 0;
            }
        }
    }

    fn pad_and_switch(&mut self) {
        self.xor_byte(self.offset, self.suffix);
        self.xor_byte(self.rate - 1, 0x80);
        keccak_f(&mut self.state);
        self.offset = 0;
        self.squeezing = true;
    }

    pub fn squeeze(&mut self, out: &mut [u8]) {
        if !self.squeezing {
            self.pad_and_switch();
        }
        let mut written = 0;
        while written < out.len() {
            if self.offset == self.rate {
                keccak_f(&mut self.state);
                self.offset = 0;
            }
            let take = (self.rate - self.offset).min(out.len() - written);
            for i in 0..take {
                out[written + i] = self.byte(self.offset + i);
            }
            self.offset += take;
            written += take;
        }
    }
}

/// SHA3-256(data).
pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    let mut sponge = Keccak::sha3_256();
    sponge.absorb(data);
    let mut out = [0u8; 32];
    sponge.squeeze(&mut out);
    out
}

/// SHA3-512(data).
pub fn sha3_512(data: &[u8]) -> [u8; 64] {
    let mut sponge = Keccak::sha3_512();
    sponge.absorb(data);
    let mut out = [0u8; 64];
    sponge.squeeze(&mut out);
    out
}

/// SHAKE256(data) squeezed to `out.len()` bytes.
pub fn shake256(data: &[u8], out: &mut [u8]) {
    let mut sponge = Keccak::shake256();
    sponge.absorb(data);
    sponge.squeeze(out);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::hex;

    #[test]
    fn sha3_256_vectors() {
        assert_eq!(
            sha3_256(b"").to_vec(),
            hex("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a")
        );
        assert_eq!(
            sha3_256(b"abc").to_vec(),
            hex("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532")
        );
    }

    #[test]
    fn sha3_512_vector() {
        assert_eq!(
            sha3_512(b"abc").to_vec(),
            hex(
                "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e\
                 10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
            )
        );
    }

    #[test]
    fn shake_vectors() {
        let mut out = [0u8; 32];
        let mut s128 = Keccak::shake128();
        s128.absorb(b"");
        s128.squeeze(&mut out);
        assert_eq!(
            out.to_vec(),
            hex("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26")
        );
        shake256(b"", &mut out);
        assert_eq!(
            out.to_vec(),
            hex("46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f")
        );
    }

    #[test]
    fn shake_is_incremental_xof() {
        // Squeezing N bytes then M more equals squeezing N+M at once.
        let mut whole = [0u8; 64];
        shake256(b"ciphra", &mut whole);
        let mut sponge = Keccak::shake256();
        sponge.absorb(b"ciphra");
        let mut a = [0u8; 20];
        let mut b = [0u8; 44];
        sponge.squeeze(&mut a);
        sponge.squeeze(&mut b);
        assert_eq!(&whole[..20], &a);
        assert_eq!(&whole[20..], &b);
    }

    #[test]
    fn absorb_is_incremental() {
        let mut sponge = Keccak::sha3_256();
        sponge.absorb(b"ab");
        sponge.absorb(b"c");
        let mut out = [0u8; 32];
        sponge.squeeze(&mut out);
        assert_eq!(out, sha3_256(b"abc"));
    }
}
