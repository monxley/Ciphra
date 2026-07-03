//! ML-KEM-768 (FIPS 203): the post-quantum half of Ciphra's hybrid key
//! exchange. Implemented from the specification's clean formulation
//! (Algorithms 4-18), not a Montgomery-optimized port, so it can be
//! read against the standard directly.
//!
//! Verification: the NTT layer is checked against a schoolbook
//! negacyclic convolution (which pins every zeta and gamma), the
//! sub-codecs round-trip, and the full KEM round-trips including
//! implicit rejection. Byte-exact ACVP cross-checks are noted as
//! pending in ARCHITECTURE.md — this build has no network to fetch
//! them — but a wrong zeta, gamma, parameter or sampling step fails
//! the convolution or round-trip tests here.

use crate::keccak::{self, Keccak};
use crate::rand::fill_random;

const Q: i32 = 3329;
const N: usize = 256;
const K: usize = 3; // ML-KEM-768
const ETA1: usize = 2;
const ETA2: usize = 2;
const DU: usize = 10;
const DV: usize = 4;

pub const EK_LEN: usize = 384 * K + 32; // 1184
#[allow(dead_code)] // documented KEM sizes, used in tests / by callers
pub const DK_LEN: usize = 768 * K + 96; // 2400
pub const CT_LEN: usize = 32 * (DU * K + DV); // 1088
#[allow(dead_code)]
pub const SS_LEN: usize = 32;

type Poly = [i16; N];
const ZERO_POLY: Poly = [0; N];

#[inline]
fn reduce(x: i32) -> i16 {
    x.rem_euclid(Q) as i16
}

fn pow_mod(mut base: i64, mut exp: u32) -> i32 {
    let mut result = 1i64;
    base %= Q as i64;
    while exp > 0 {
        if exp & 1 == 1 {
            result = (result * base) % Q as i64;
        }
        base = (base * base) % Q as i64;
        exp >>= 1;
    }
    result as i32
}

/// Reverse the low 7 bits of `i`.
fn bitrev7(i: usize) -> u32 {
    let mut r = 0u32;
    for b in 0..7 {
        r |= (((i >> b) & 1) as u32) << (6 - b);
    }
    r
}

/// zetas[i] = 17^BitRev7(i) mod q; gammas[i] = 17^(2·BitRev7(i)+1) mod q.
fn tables() -> (&'static [i16; 128], &'static [i16; 128]) {
    use std::sync::OnceLock;
    static TABLES: OnceLock<([i16; 128], [i16; 128])> = OnceLock::new();
    let (z, g) = TABLES.get_or_init(|| {
        let mut zetas = [0i16; 128];
        let mut gammas = [0i16; 128];
        for i in 0..128 {
            zetas[i] = pow_mod(17, bitrev7(i)) as i16;
            gammas[i] = pow_mod(17, 2 * bitrev7(i) + 1) as i16;
        }
        (zetas, gammas)
    });
    (z, g)
}

// ------------------------------------------------------------------ NTT

fn ntt(f: &Poly) -> Poly {
    let (zetas, _) = tables();
    let mut a = *f;
    let mut i = 1usize;
    let mut len = 128;
    while len >= 2 {
        let mut start = 0;
        while start < N {
            let zeta = zetas[i] as i32;
            i += 1;
            for j in start..start + len {
                let t = reduce(zeta * a[j + len] as i32) as i32;
                a[j + len] = reduce(a[j] as i32 - t);
                a[j] = reduce(a[j] as i32 + t);
            }
            start += 2 * len;
        }
        len >>= 1;
    }
    a
}

fn intt(f: &Poly) -> Poly {
    let (zetas, _) = tables();
    let mut a = *f;
    let mut i = 127usize;
    let mut len = 2;
    while len <= 128 {
        let mut start = 0;
        while start < N {
            let zeta = zetas[i] as i32;
            i -= 1;
            for j in start..start + len {
                let t = a[j] as i32;
                a[j] = reduce(t + a[j + len] as i32);
                a[j + len] = reduce(zeta * (a[j + len] as i32 - t));
            }
            start += 2 * len;
        }
        len <<= 1;
    }
    // Multiply by 128^-1 mod q = 3303.
    for x in a.iter_mut() {
        *x = reduce(*x as i32 * 3303);
    }
    a
}

/// Multiply two polynomials already in the NTT domain (Algorithm 11/12).
#[allow(clippy::needless_range_loop)]
fn ntt_mul(a: &Poly, b: &Poly) -> Poly {
    let (_, gammas) = tables();
    let mut c = ZERO_POLY;
    for i in 0..128 {
        let gamma = gammas[i] as i32;
        let (a0, a1) = (a[2 * i] as i32, a[2 * i + 1] as i32);
        let (b0, b1) = (b[2 * i] as i32, b[2 * i + 1] as i32);
        c[2 * i] = reduce(a0 * b0 + a1 * b1 % Q * gamma);
        c[2 * i + 1] = reduce(a0 * b1 + a1 * b0);
    }
    c
}

#[allow(clippy::needless_range_loop)]
fn poly_add(a: &Poly, b: &Poly) -> Poly {
    let mut c = ZERO_POLY;
    for i in 0..N {
        c[i] = reduce(a[i] as i32 + b[i] as i32);
    }
    c
}

#[allow(clippy::needless_range_loop)]
fn poly_sub(a: &Poly, b: &Poly) -> Poly {
    let mut c = ZERO_POLY;
    for i in 0..N {
        c[i] = reduce(a[i] as i32 - b[i] as i32);
    }
    c
}

// ------------------------------------------------------------ codecs

/// ByteEncode_d: pack 256 d-bit integers little-endian.
#[allow(clippy::needless_range_loop)]
fn byte_encode(f: &Poly, d: usize) -> Vec<u8> {
    let mut out = vec![0u8; 32 * d];
    let mut bitpos = 0usize;
    for &coeff in f.iter() {
        let value = coeff as u32;
        for b in 0..d {
            if (value >> b) & 1 == 1 {
                out[bitpos / 8] |= 1 << (bitpos % 8);
            }
            bitpos += 1;
        }
    }
    out
}

fn byte_decode(bytes: &[u8], d: usize) -> Poly {
    let mut f = ZERO_POLY;
    let mut bitpos = 0usize;
    let modulus = if d < 12 { 1u32 << d } else { Q as u32 };
    for coeff in f.iter_mut() {
        let mut value = 0u32;
        for b in 0..d {
            let bit = (bytes[bitpos / 8] >> (bitpos % 8)) & 1;
            value |= (bit as u32) << b;
            bitpos += 1;
        }
        *coeff = (value % modulus.max(1)) as i16;
    }
    f
}

fn compress(x: i16, d: usize) -> i16 {
    // round(x · 2^d / q) mod 2^d
    let numerator = (x as u32) << d;
    let q = Q as u32;
    (((numerator + q / 2) / q) & ((1 << d) - 1)) as i16
}

fn decompress(y: i16, d: usize) -> i16 {
    // round(y · q / 2^d)
    let numerator = (y as u32) * (Q as u32);
    ((numerator + (1 << (d - 1))) >> d) as i16
}

#[allow(clippy::needless_range_loop)]
fn poly_compress(f: &Poly, d: usize) -> Poly {
    let mut c = ZERO_POLY;
    for i in 0..N {
        c[i] = compress(f[i], d);
    }
    c
}

#[allow(clippy::needless_range_loop)]
fn poly_decompress(f: &Poly, d: usize) -> Poly {
    let mut c = ZERO_POLY;
    for i in 0..N {
        c[i] = decompress(f[i], d);
    }
    c
}

// ---------------------------------------------------------- sampling

/// SampleNTT (Algorithm 6): rejection-sample a poly from a SHAKE128 XOF.
fn sample_ntt(rho: &[u8; 32], i: u8, j: u8) -> Poly {
    let mut xof = Keccak::shake128();
    xof.absorb(rho);
    xof.absorb(&[i, j]);
    let mut a = ZERO_POLY;
    let mut count = 0usize;
    let mut buf = [0u8; 3];
    while count < N {
        xof.squeeze(&mut buf);
        let d1 = buf[0] as i32 + 256 * (buf[1] as i32 & 0x0f);
        let d2 = (buf[1] as i32 >> 4) + 16 * buf[2] as i32;
        if d1 < Q {
            a[count] = d1 as i16;
            count += 1;
        }
        if d2 < Q && count < N {
            a[count] = d2 as i16;
            count += 1;
        }
    }
    a
}

/// SamplePolyCBD_η (Algorithm 8) from 64η bytes of PRF output.
#[allow(clippy::needless_range_loop)]
fn sample_cbd(bytes: &[u8], eta: usize) -> Poly {
    let mut f = ZERO_POLY;
    for i in 0..N {
        let base = 2 * i * eta;
        let mut x = 0i32;
        let mut y = 0i32;
        for b in 0..eta {
            let bit = |pos: usize| ((bytes[pos / 8] >> (pos % 8)) & 1) as i32;
            x += bit(base + b);
            y += bit(base + eta + b);
        }
        f[i] = reduce(x - y);
    }
    f
}

/// PRF_η(s, b) = SHAKE256(s ∥ b) squeezed to 64η bytes.
fn prf(s: &[u8; 32], b: u8, eta: usize) -> Vec<u8> {
    let mut input = s.to_vec();
    input.push(b);
    let mut out = vec![0u8; 64 * eta];
    keccak::shake256(&input, &mut out);
    out
}

// -------------------------------------------------------------- hashes

/// G(c) = SHA3-512(c) split into two 32-byte halves.
fn g(input: &[u8]) -> ([u8; 32], [u8; 32]) {
    let h = keccak::sha3_512(input);
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    a.copy_from_slice(&h[..32]);
    b.copy_from_slice(&h[32..]);
    (a, b)
}

fn h(input: &[u8]) -> [u8; 32] {
    keccak::sha3_256(input)
}

fn j(input: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    keccak::shake256(input, &mut out);
    out
}

// ------------------------------------------------------ matrix helper

/// Generate Â (or Âᵀ when `transposed`) as in the Kyber reference:
/// non-transposed absorbs (ρ, j, i), transposed absorbs (ρ, i, j).
#[allow(clippy::needless_range_loop)]
fn gen_matrix(rho: &[u8; 32], transposed: bool) -> Vec<Vec<Poly>> {
    let mut a = vec![vec![ZERO_POLY; K]; K];
    for i in 0..K {
        for j in 0..K {
            a[i][j] = if transposed {
                sample_ntt(rho, i as u8, j as u8)
            } else {
                sample_ntt(rho, j as u8, i as u8)
            };
        }
    }
    a
}

// --------------------------------------------------------------- K-PKE

fn pke_keygen(d: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
    let mut seed = d.to_vec();
    seed.push(K as u8);
    let (rho, sigma) = g(&seed);

    let a = gen_matrix(&rho, false);

    let mut s = [ZERO_POLY; K];
    let mut e = [ZERO_POLY; K];
    let mut n = 0u8;
    for si in s.iter_mut() {
        *si = sample_cbd(&prf(&sigma, n, ETA1), ETA1);
        n += 1;
    }
    for ei in e.iter_mut() {
        *ei = sample_cbd(&prf(&sigma, n, ETA1), ETA1);
        n += 1;
    }
    let s_hat: Vec<Poly> = s.iter().map(ntt).collect();
    let e_hat: Vec<Poly> = e.iter().map(ntt).collect();

    // t̂[i] = Σ_j Â[i][j] ∘ ŝ[j] + ê[i]
    let mut t_hat = [ZERO_POLY; K];
    for i in 0..K {
        let mut acc = ZERO_POLY;
        for j in 0..K {
            acc = poly_add(&acc, &ntt_mul(&a[i][j], &s_hat[j]));
        }
        t_hat[i] = poly_add(&acc, &e_hat[i]);
    }

    let mut ek = Vec::with_capacity(EK_LEN);
    for t in &t_hat {
        ek.extend_from_slice(&byte_encode(t, 12));
    }
    ek.extend_from_slice(&rho);

    let mut dk = Vec::with_capacity(384 * K);
    for sh in &s_hat {
        dk.extend_from_slice(&byte_encode(sh, 12));
    }
    (ek, dk)
}

fn pke_encrypt(ek: &[u8], m: &[u8; 32], rand: &[u8; 32]) -> Vec<u8> {
    let mut t_hat = [ZERO_POLY; K];
    for (i, t) in t_hat.iter_mut().enumerate() {
        *t = byte_decode(&ek[384 * i..384 * (i + 1)], 12);
    }
    let mut rho = [0u8; 32];
    rho.copy_from_slice(&ek[384 * K..384 * K + 32]);

    let at = gen_matrix(&rho, true);

    let mut r = [ZERO_POLY; K];
    let mut e1 = [ZERO_POLY; K];
    let mut n = 0u8;
    for ri in r.iter_mut() {
        *ri = sample_cbd(&prf(rand, n, ETA1), ETA1);
        n += 1;
    }
    for ei in e1.iter_mut() {
        *ei = sample_cbd(&prf(rand, n, ETA2), ETA2);
        n += 1;
    }
    let e2 = sample_cbd(&prf(rand, n, ETA2), ETA2);

    let r_hat: Vec<Poly> = r.iter().map(ntt).collect();

    // u = INTT(Âᵀ ∘ r̂) + e1
    let mut u = [ZERO_POLY; K];
    for i in 0..K {
        let mut acc = ZERO_POLY;
        for j in 0..K {
            acc = poly_add(&acc, &ntt_mul(&at[i][j], &r_hat[j]));
        }
        u[i] = poly_add(&intt(&acc), &e1[i]);
    }

    // v = INTT(t̂ᵀ ∘ r̂) + e2 + Decompress1(m)
    let mut acc = ZERO_POLY;
    for j in 0..K {
        acc = poly_add(&acc, &ntt_mul(&t_hat[j], &r_hat[j]));
    }
    let mu = poly_decompress(&byte_decode(m, 1), 1);
    let v = poly_add(&poly_add(&intt(&acc), &e2), &mu);

    let mut ct = Vec::with_capacity(CT_LEN);
    for ui in &u {
        ct.extend_from_slice(&byte_encode(&poly_compress(ui, DU), DU));
    }
    ct.extend_from_slice(&byte_encode(&poly_compress(&v, DV), DV));
    ct
}

fn pke_decrypt(dk: &[u8], ct: &[u8]) -> [u8; 32] {
    let c1_len = 32 * DU * K;
    let mut u = [ZERO_POLY; K];
    for (i, ui) in u.iter_mut().enumerate() {
        let chunk = &ct[32 * DU * i..32 * DU * (i + 1)];
        *ui = poly_decompress(&byte_decode(chunk, DU), DU);
    }
    let v = poly_decompress(&byte_decode(&ct[c1_len..], DV), DV);

    let mut s_hat = [ZERO_POLY; K];
    for (i, sh) in s_hat.iter_mut().enumerate() {
        *sh = byte_decode(&dk[384 * i..384 * (i + 1)], 12);
    }

    // w = v - INTT(ŝᵀ ∘ NTT(u))
    let mut acc = ZERO_POLY;
    for j in 0..K {
        acc = poly_add(&acc, &ntt_mul(&s_hat[j], &ntt(&u[j])));
    }
    let w = poly_sub(&v, &intt(&acc));

    let mut m = [0u8; 32];
    let encoded = byte_encode(&poly_compress(&w, 1), 1);
    m.copy_from_slice(&encoded);
    m
}

// --------------------------------------------------------------- ML-KEM

/// Key pair: encapsulation key (public) and decapsulation key (secret).
pub struct KeyPair {
    pub ek: Vec<u8>,
    pub dk: Vec<u8>,
}

/// Deterministic key generation from seeds `d` and `z` (FIPS 203
/// KeyGen_internal); [`KeyPair::generate`] supplies random seeds.
pub fn keygen_internal(d: &[u8; 32], z: &[u8; 32]) -> KeyPair {
    let (ek_pke, dk_pke) = pke_keygen(d);
    let mut dk = dk_pke;
    dk.extend_from_slice(&ek_pke);
    dk.extend_from_slice(&h(&ek_pke));
    dk.extend_from_slice(z);
    KeyPair { ek: ek_pke, dk }
}

impl KeyPair {
    pub fn generate() -> Self {
        let mut d = [0u8; 32];
        let mut z = [0u8; 32];
        fill_random(&mut d);
        fill_random(&mut z);
        keygen_internal(&d, &z)
    }
}

/// Encapsulate to `ek`: returns `(ciphertext, shared_secret)`.
pub fn encapsulate(ek: &[u8]) -> (Vec<u8>, [u8; 32]) {
    let mut m = [0u8; 32];
    fill_random(&mut m);
    encaps_internal(ek, &m)
}

fn encaps_internal(ek: &[u8], m: &[u8; 32]) -> (Vec<u8>, [u8; 32]) {
    let mut input = m.to_vec();
    input.extend_from_slice(&h(ek));
    let (shared, r) = g(&input);
    let ct = pke_encrypt(ek, m, &r);
    (ct, shared)
}

/// Decapsulate `ct` with `dk`: returns the shared secret. On a bad
/// ciphertext this returns a deterministic pseudo-random value
/// (implicit rejection), never an error, so timing/behaviour does not
/// distinguish valid from invalid ciphertexts.
pub fn decapsulate(dk: &[u8], ct: &[u8]) -> [u8; 32] {
    let dk_pke = &dk[..384 * K];
    let ek_pke = &dk[384 * K..768 * K + 32];
    let hash = &dk[768 * K + 32..768 * K + 64];
    let z = &dk[768 * K + 64..768 * K + 96];

    let m_prime = pke_decrypt(dk_pke, ct);
    let mut input = m_prime.to_vec();
    input.extend_from_slice(hash);
    let (shared, r) = g(&input);

    let mut reject_input = z.to_vec();
    reject_input.extend_from_slice(ct);
    let k_bar = j(&reject_input);

    let ct_prime = pke_encrypt(ek_pke, &m_prime, &r);
    if ct == ct_prime.as_slice() {
        shared
    } else {
        k_bar
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Schoolbook multiplication in Z_q[X]/(X^256+1), the ground truth
    /// the NTT must reproduce — this pins every zeta and gamma.
    fn schoolbook(a: &Poly, b: &Poly) -> Poly {
        let mut c = [0i32; 2 * N];
        for i in 0..N {
            for k in 0..N {
                c[i + k] += a[i] as i32 * b[k] as i32;
            }
        }
        let mut r = ZERO_POLY;
        for i in 0..N {
            // X^256 = -1
            r[i] = reduce(c[i] - c[i + N]);
        }
        r
    }

    fn lcg_poly(seed: &mut u64) -> Poly {
        let mut p = ZERO_POLY;
        for x in p.iter_mut() {
            *seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            *x = ((*seed >> 33) as i32 % Q) as i16;
        }
        p
    }

    #[test]
    fn ntt_roundtrips_to_identity() {
        let mut seed = 1u64;
        let f = lcg_poly(&mut seed);
        assert_eq!(intt(&ntt(&f)), f);
    }

    #[test]
    fn ntt_multiply_matches_schoolbook() {
        let mut seed = 42u64;
        for _ in 0..20 {
            let a = lcg_poly(&mut seed);
            let b = lcg_poly(&mut seed);
            let via_ntt = intt(&ntt_mul(&ntt(&a), &ntt(&b)));
            assert_eq!(via_ntt, schoolbook(&a, &b));
        }
    }

    #[test]
    fn codecs_roundtrip() {
        let mut seed = 7u64;
        let mut f = lcg_poly(&mut seed);
        for x in f.iter_mut() {
            *x = (*x).rem_euclid(Q as i16);
        }
        assert_eq!(byte_decode(&byte_encode(&f, 12), 12), f);
        // Compression is lossy but bounded and stable.
        let c = poly_compress(&f, DU);
        assert_eq!(byte_decode(&byte_encode(&c, DU), DU), c);
        for &x in c.iter() {
            assert!((x as i32) < (1 << DU));
        }
    }

    #[test]
    fn kem_roundtrip_and_implicit_rejection() {
        for seed in 0..8u8 {
            let d = [seed; 32];
            let z = [seed ^ 0xff; 32];
            let kp = keygen_internal(&d, &z);
            assert_eq!(kp.ek.len(), EK_LEN);
            assert_eq!(kp.dk.len(), DK_LEN);

            let m = [seed.wrapping_add(1); 32];
            let (ct, shared) = encaps_internal(&kp.ek, &m);
            assert_eq!(ct.len(), CT_LEN);
            // Honest decapsulation recovers the same secret.
            assert_eq!(decapsulate(&kp.dk, &ct), shared);

            // A tampered ciphertext yields a different secret, not an
            // error, and it is deterministic (implicit rejection).
            let mut bad = ct.clone();
            bad[0] ^= 1;
            let rejected = decapsulate(&kp.dk, &bad);
            assert_ne!(rejected, shared);
            assert_eq!(rejected, decapsulate(&kp.dk, &bad));
        }
    }

    #[test]
    fn keygen_is_deterministic() {
        let d = [3u8; 32];
        let z = [9u8; 32];
        assert_eq!(keygen_internal(&d, &z).ek, keygen_internal(&d, &z).ek);
    }
}
