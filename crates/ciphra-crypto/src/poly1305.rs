//! Poly1305 one-time authenticator (RFC 8439 §2.5).
//!
//! This is a port of the byte-limb reference implementation (as used in
//! TweetNaCl): arithmetic mod 2^130-5 over seventeen 8-bit limbs held
//! in `u32`s. Slow but simple to audit, with no carry subtleties —
//! products are bounded by 17 * 255 * 255 * 320 < 2^32.

/// Compute the 16-byte tag for `message` under the one-time `key`
/// (r || s, 32 bytes). The key must never be reused across messages;
/// the AEAD construction derives it per nonce.
pub fn poly1305(message: &[u8], key: &[u8; 32]) -> [u8; 16] {
    let mut r = [0u32; 17];
    for i in 0..16 {
        r[i] = key[i] as u32;
    }
    // Clamp r per the spec.
    r[3] &= 15;
    r[4] &= 252;
    r[7] &= 15;
    r[8] &= 252;
    r[11] &= 15;
    r[12] &= 252;
    r[15] &= 15;

    let mut h = [0u32; 17];
    let mut rest = message;
    while !rest.is_empty() {
        let take = rest.len().min(16);
        let mut c = [0u32; 17];
        for (i, &byte) in rest[..take].iter().enumerate() {
            c[i] = byte as u32;
        }
        c[take] = 1; // The "append 0x01" from the spec.
        rest = &rest[take..];

        add(&mut h, &c);
        mul_mod(&mut h, &r);
    }

    // Freeze: h = h mod 2^130-5, chosen constant-time between h and h - p.
    let g = h;
    const MINUS_P: [u32; 17] = [5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 252];
    add(&mut h, &MINUS_P);
    let mask = (h[16] >> 7).wrapping_neg(); // all-ones if h < p (borrow), else zero
    for i in 0..17 {
        h[i] ^= mask & (g[i] ^ h[i]);
    }

    // Add s (the second key half) and serialize.
    let mut s = [0u32; 17];
    for i in 0..16 {
        s[i] = key[16 + i] as u32;
    }
    add(&mut h, &s);

    let mut tag = [0u8; 16];
    for i in 0..16 {
        tag[i] = h[i] as u8;
    }
    tag
}

/// h += c over base-256 limbs, carrying as we go.
fn add(h: &mut [u32; 17], c: &[u32; 17]) {
    let mut carry = 0u32;
    for i in 0..17 {
        carry += h[i] + c[i];
        h[i] = carry & 255;
        carry >>= 8;
    }
}

/// h = (h * r) mod 2^130-5.
///
/// Limbs that overflow position 16 wrap around multiplied by
/// 320 = 256 * 5 / 4: shifting down 17 limbs is dividing by 2^136, and
/// 2^136 = 2^130 * 64 ≡ 5 * 64 = 320 (mod 2^130-5) per byte position.
fn mul_mod(h: &mut [u32; 17], r: &[u32; 17]) {
    let mut x = [0u32; 17];
    for i in 0..17 {
        let mut sum = 0u32;
        for j in 0..17 {
            sum += h[j]
                * if j <= i {
                    r[i - j]
                } else {
                    320 * r[i + 17 - j]
                };
        }
        x[i] = sum;
    }
    // Two partial reduction passes bring every limb back under 256.
    for _ in 0..2 {
        let mut carry = 0u32;
        for limb in x.iter_mut().take(16) {
            carry += *limb;
            *limb = carry & 255;
            carry >>= 8;
        }
        carry += x[16];
        x[16] = carry & 3;
        carry = 5 * (carry >> 2);
        x[0] += carry;
    }
    // Propagate the final small carry from x[0].
    let mut carry = 0u32;
    for limb in x.iter_mut() {
        carry += *limb;
        *limb = carry & 255;
        carry >>= 8;
    }
    debug_assert_eq!(carry, 0);
    *h = x;
}

/// Constant-time 16-byte comparison for tag verification.
pub fn tags_equal(a: &[u8; 16], b: &[u8; 16]) -> bool {
    let mut diff = 0u8;
    for i in 0..16 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::hex;

    #[test]
    fn rfc8439_tag_vector() {
        // RFC 8439 §2.5.2
        let key: [u8; 32] = hex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
            .try_into()
            .unwrap();
        let tag = poly1305(b"Cryptographic Forum Research Group", &key);
        assert_eq!(tag.to_vec(), hex("a8061dc1305136c6c22b8baf0c0127a9"));
    }

    #[test]
    fn empty_message() {
        // With an all-zero r, the tag is just s.
        let mut key = [0u8; 32];
        key[16..].copy_from_slice(&[7u8; 16]);
        assert_eq!(poly1305(b"", &key), [7u8; 16]);
    }

    #[test]
    fn tag_depends_on_every_byte() {
        let key: [u8; 32] = hex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
            .try_into()
            .unwrap();
        let base = poly1305(b"hello world, this is poly1305", &key);
        let tweaked = poly1305(b"hello world, this is poly1306", &key);
        assert_ne!(base, tweaked);
    }

    #[test]
    fn tags_equal_is_exact() {
        assert!(tags_equal(&[1; 16], &[1; 16]));
        let mut other = [1u8; 16];
        other[15] = 2;
        assert!(!tags_equal(&[1; 16], &other));
    }
}
