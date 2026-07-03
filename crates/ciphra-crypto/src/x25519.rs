//! X25519 (RFC 7748): the classical half of Ciphra's hybrid key
//! exchange. Field arithmetic mod p = 2^255 - 19 on 64-bit limbs, plus
//! the Montgomery ladder. Verified against the RFC 7748 §5.2 vectors.
//!
//! Constant-time-ish: the ladder swaps are branch-free (masked), field
//! ops are data-independent. Not hardened against every microarchitectural
//! channel — the audit checklist owns that (ADR-0002).

pub const KEY_LEN: usize = 32;

/// A field element mod 2^255 - 19 as five 51-bit limbs.
#[derive(Clone, Copy)]
struct Fe([u64; 5]);

const MASK51: u64 = (1u64 << 51) - 1;

impl Fe {
    const ZERO: Fe = Fe([0; 5]);
    const ONE: Fe = Fe([1, 0, 0, 0, 0]);

    fn from_bytes(bytes: &[u8; 32]) -> Fe {
        let load = |i: usize| -> u64 {
            let mut x = 0u64;
            for k in 0..8 {
                x |= (bytes[i + k] as u64) << (8 * k);
            }
            x
        };
        let x0 = load(0);
        let x1 = load(8);
        let x2 = load(16);
        let x3 = load(24);
        // Repack 4x64-bit (top bit cleared) into 5x51-bit.
        Fe([
            x0 & MASK51,
            ((x0 >> 51) | (x1 << 13)) & MASK51,
            ((x1 >> 38) | (x2 << 26)) & MASK51,
            ((x2 >> 25) | (x3 << 39)) & MASK51,
            (x3 >> 12) & MASK51,
        ])
    }

    fn to_bytes(self) -> [u8; 32] {
        let mut t = self;
        t.freeze();
        let l = t.0;
        let packed = [
            l[0] | (l[1] << 51),
            (l[1] >> 13) | (l[2] << 38),
            (l[2] >> 26) | (l[3] << 25),
            (l[3] >> 39) | (l[4] << 12),
        ];
        let mut out = [0u8; 32];
        for (i, word) in packed.iter().enumerate() {
            out[8 * i..8 * i + 8].copy_from_slice(&word.to_le_bytes());
        }
        out
    }

    /// Reduce limbs to under 2^51 + small.
    fn carry(&mut self) {
        let l = &mut self.0;
        let mut carry;
        carry = l[0] >> 51;
        l[0] &= MASK51;
        l[1] += carry;
        carry = l[1] >> 51;
        l[1] &= MASK51;
        l[2] += carry;
        carry = l[2] >> 51;
        l[2] &= MASK51;
        l[3] += carry;
        carry = l[3] >> 51;
        l[3] &= MASK51;
        l[4] += carry;
        carry = l[4] >> 51;
        l[4] &= MASK51;
        l[0] += carry * 19;
    }

    /// Fully reduce into the canonical range [0, p).
    fn freeze(&mut self) {
        self.carry();
        self.carry();
        // Each limb is now < 2^51. Add 19: if the value is >= p this
        // overflows past 2^255 and `q` becomes 1, telling us to keep the
        // reduced form; otherwise q is 0 and we discard the +19.
        let l = &mut self.0;
        let mut q = (l[0] + 19) >> 51;
        q = (l[1] + q) >> 51;
        q = (l[2] + q) >> 51;
        q = (l[3] + q) >> 51;
        q = (l[4] + q) >> 51;
        l[0] += 19 * q;
        l[1] += l[0] >> 51;
        l[0] &= MASK51;
        l[2] += l[1] >> 51;
        l[1] &= MASK51;
        l[3] += l[2] >> 51;
        l[2] &= MASK51;
        l[4] += l[3] >> 51;
        l[3] &= MASK51;
        l[4] &= MASK51;
    }

    fn add(&self, other: &Fe) -> Fe {
        let mut r = Fe::ZERO;
        for i in 0..5 {
            r.0[i] = self.0[i] + other.0[i];
        }
        r
    }

    fn sub(&self, other: &Fe) -> Fe {
        // Add a multiple of p (≡ 0 mod p) large enough that the
        // subtraction never underflows, then carry-reduce. Constants
        // are the standard 51-bit field-arithmetic values.
        let mut r = Fe::ZERO;
        r.0[0] = self.0[0] + 36_028_797_018_963_664 - other.0[0];
        r.0[1] = self.0[1] + 36_028_797_018_963_952 - other.0[1];
        r.0[2] = self.0[2] + 36_028_797_018_963_952 - other.0[2];
        r.0[3] = self.0[3] + 36_028_797_018_963_952 - other.0[3];
        r.0[4] = self.0[4] + 36_028_797_018_963_952 - other.0[4];
        r.carry();
        r
    }

    fn mul(&self, other: &Fe) -> Fe {
        let a = self.0;
        let b = other.0;
        // Schoolbook 5x5 with 19x folding, in u128.
        let m = |x: u64, y: u64| -> u128 { (x as u128) * (y as u128) };
        let r19 = |x: u64| x * 19;
        let t0 = m(a[0], b[0])
            + m(a[1], r19(b[4]))
            + m(a[2], r19(b[3]))
            + m(a[3], r19(b[2]))
            + m(a[4], r19(b[1]));
        let t1 = m(a[0], b[1])
            + m(a[1], b[0])
            + m(a[2], r19(b[4]))
            + m(a[3], r19(b[3]))
            + m(a[4], r19(b[2]));
        let t2 =
            m(a[0], b[2]) + m(a[1], b[1]) + m(a[2], b[0]) + m(a[3], r19(b[4])) + m(a[4], r19(b[3]));
        let t3 = m(a[0], b[3]) + m(a[1], b[2]) + m(a[2], b[1]) + m(a[3], b[0]) + m(a[4], r19(b[4]));
        let t4 = m(a[0], b[4]) + m(a[1], b[3]) + m(a[2], b[2]) + m(a[3], b[1]) + m(a[4], b[0]);
        Fe::reduce_wide([t0, t1, t2, t3, t4])
    }

    fn square(&self) -> Fe {
        self.mul(self)
    }

    #[allow(clippy::needless_range_loop)]
    fn reduce_wide(t: [u128; 5]) -> Fe {
        let mut r = [0u64; 5];
        let mut carry: u128 = 0;
        for i in 0..5 {
            let v = t[i] + carry;
            r[i] = (v as u64) & MASK51;
            carry = v >> 51;
        }
        r[0] += (carry as u64) * 19;
        let mut fe = Fe(r);
        fe.carry();
        fe
    }

    #[allow(clippy::needless_range_loop)]
    fn mul_small(&self, k: u64) -> Fe {
        let mut r = [0u128; 5];
        for i in 0..5 {
            r[i] = (self.0[i] as u128) * (k as u128);
        }
        Fe::reduce_wide(r)
    }

    /// Constant-time conditional swap on `swap` in {0,1}.
    fn cswap(a: &mut Fe, b: &mut Fe, swap: u64) {
        let mask = 0u64.wrapping_sub(swap);
        for i in 0..5 {
            let t = mask & (a.0[i] ^ b.0[i]);
            a.0[i] ^= t;
            b.0[i] ^= t;
        }
    }

    /// x^(p-2) = x^-1 by Fermat, via the standard 255-bit addition chain.
    fn invert(&self) -> Fe {
        let z1 = *self;
        let z2 = z1.square();
        let z8 = z2.square().square();
        let z9 = z1.mul(&z8);
        let z11 = z2.mul(&z9);
        let z22 = z11.square();
        let z_5_0 = z9.mul(&z22);
        let z_10_5 = {
            let mut t = z_5_0;
            for _ in 0..5 {
                t = t.square();
            }
            t
        };
        let z_10_0 = z_10_5.mul(&z_5_0);
        let z_20_10 = {
            let mut t = z_10_0;
            for _ in 0..10 {
                t = t.square();
            }
            t
        };
        let z_20_0 = z_20_10.mul(&z_10_0);
        let z_40_20 = {
            let mut t = z_20_0;
            for _ in 0..20 {
                t = t.square();
            }
            t
        };
        let z_40_0 = z_40_20.mul(&z_20_0);
        let z_50_10 = {
            let mut t = z_40_0;
            for _ in 0..10 {
                t = t.square();
            }
            t
        };
        let z_50_0 = z_50_10.mul(&z_10_0);
        let z_100_50 = {
            let mut t = z_50_0;
            for _ in 0..50 {
                t = t.square();
            }
            t
        };
        let z_100_0 = z_100_50.mul(&z_50_0);
        let z_200_100 = {
            let mut t = z_100_0;
            for _ in 0..100 {
                t = t.square();
            }
            t
        };
        let z_200_0 = z_200_100.mul(&z_100_0);
        let z_250_50 = {
            let mut t = z_200_0;
            for _ in 0..50 {
                t = t.square();
            }
            t
        };
        let z_250_0 = z_250_50.mul(&z_50_0);
        let mut t = z_250_0;
        for _ in 0..5 {
            t = t.square();
        }
        t.mul(&z11)
    }
}

/// The core scalar multiplication: `k * u` on Curve25519.
fn scalarmult(scalar: &[u8; 32], u: &[u8; 32]) -> [u8; 32] {
    // Clamp the scalar per RFC 7748.
    let mut k = *scalar;
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;

    let x1 = Fe::from_bytes(u);
    let mut x2 = Fe::ONE;
    let mut z2 = Fe::ZERO;
    let mut x3 = x1;
    let mut z3 = Fe::ONE;
    let mut swap = 0u64;

    for t in (0..=254).rev() {
        let bit = ((k[t >> 3] >> (t & 7)) & 1) as u64;
        swap ^= bit;
        Fe::cswap(&mut x2, &mut x3, swap);
        Fe::cswap(&mut z2, &mut z3, swap);
        swap = bit;

        let a = x2.add(&z2);
        let aa = a.square();
        let b = x2.sub(&z2);
        let bb = b.square();
        let e = aa.sub(&bb);
        let c = x3.add(&z3);
        let d = x3.sub(&z3);
        let da = d.mul(&a);
        let cb = c.mul(&b);
        x3 = da.add(&cb).square();
        z3 = x1.mul(&da.sub(&cb).square());
        x2 = aa.mul(&bb);
        z2 = e.mul(&aa.add(&e.mul_small(121_665)));
    }

    Fe::cswap(&mut x2, &mut x3, swap);
    Fe::cswap(&mut z2, &mut z3, swap);
    x2.mul(&z2.invert()).to_bytes()
}

/// Base point u = 9.
const BASE_POINT: [u8; 32] = {
    let mut b = [0u8; 32];
    b[0] = 9;
    b
};

/// A freshly generated X25519 secret key.
pub struct SecretKey([u8; 32]);

impl SecretKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        SecretKey(bytes)
    }

    /// The public key `scalar * basepoint`.
    pub fn public_key(&self) -> [u8; 32] {
        scalarmult(&self.0, &BASE_POINT)
    }

    /// The shared secret `scalar * their_public`.
    pub fn diffie_hellman(&self, their_public: &[u8; 32]) -> [u8; 32] {
        scalarmult(&self.0, their_public)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::hex;

    fn arr(hex_str: &str) -> [u8; 32] {
        hex(hex_str).try_into().unwrap()
    }

    #[test]
    fn rfc7748_scalarmult_vectors() {
        // RFC 7748 §5.2, test vector 1.
        let k = arr("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        let u = arr("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        assert_eq!(
            scalarmult(&k, &u).to_vec(),
            hex("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")
        );
        // Test vector 2.
        let k = arr("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d");
        let u = arr("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493");
        assert_eq!(
            scalarmult(&k, &u).to_vec(),
            hex("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957")
        );
    }

    #[test]
    fn rfc7748_diffie_hellman() {
        // RFC 7748 §6.1 Alice/Bob.
        let alice = SecretKey::from_bytes(arr(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
        ));
        let bob = SecretKey::from_bytes(arr(
            "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
        ));
        assert_eq!(
            alice.public_key().to_vec(),
            hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        );
        assert_eq!(
            bob.public_key().to_vec(),
            hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
        );
        let shared = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";
        assert_eq!(
            alice.diffie_hellman(&bob.public_key()).to_vec(),
            hex(shared)
        );
        assert_eq!(
            bob.diffie_hellman(&alice.public_key()).to_vec(),
            hex(shared)
        );
    }

    #[test]
    fn field_roundtrip_and_inverse() {
        let bytes = arr("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
        let fe = Fe::from_bytes(&bytes);
        // (x^-1) * x == 1
        let one = fe.mul(&fe.invert());
        assert_eq!(one.to_bytes(), Fe::ONE.to_bytes());
    }
}
