//! ML-DSA-65 (FIPS 204): post-quantum digital signatures, used to sign
//! Ciphra's audit roots so a published root carries a signature anyone
//! can verify offline — and one a quantum adversary cannot forge.
//!
//! Implemented from the specification's clean formulation, not a
//! Montgomery-optimized port: coefficients are kept in `[0, q)` with
//! plain modular arithmetic so the code reads against the standard. The
//! deterministic variant is used (the per-signature randomness `rnd` is
//! all-zero), which makes signatures reproducible for testing.
//!
//! Verification here: the NTT is checked against a schoolbook negacyclic
//! convolution (pinning every zeta), every bit-packing codec round-trips,
//! and full keygen→sign→verify round-trips while tampering with the
//! message, signature or key is rejected. As with ML-KEM, byte-exact
//! ACVP cross-checks are noted as pending in ARCHITECTURE.md — this build
//! has no network to fetch them — but a wrong zeta, parameter, sampling
//! or packing step fails the tests here.

// Coefficient loops routinely index several polynomials in lockstep by
// the same subscript; that reads closer to the FIPS 204 pseudocode than
// zipped iterators would (same choice as the ml_kem module).
#![allow(clippy::needless_range_loop)]

use std::sync::OnceLock;

use crate::keccak::Keccak;

// ------------------------------------------------------------ parameters
// ML-DSA-65 (FIPS 204, security category 3 — matched to ML-KEM-768).

const Q: i32 = 8_380_417;
const N: usize = 256;
const D: usize = 13;
const ROOT: i64 = 1753; // primitive 512th root of unity mod q
const K: usize = 6;
const L: usize = 5;
const ETA: i32 = 4;
const TAU: usize = 49;
const BETA: i32 = (TAU as i32) * ETA; // 196
const GAMMA1: i32 = 1 << 19; // 524288
const GAMMA2: i32 = (Q - 1) / 32; // 261888
const OMEGA: usize = 55;
const LAMBDA: usize = 192;
const C_TILDE_LEN: usize = LAMBDA / 4; // 48

/// Seed length for deterministic key generation.
pub const SEED_LEN: usize = 32;
/// Encoded public key length (ρ ∥ t1).
pub const PUBLIC_KEY_LEN: usize = 32 + K * N * 10 / 8; // 1952
/// Encoded secret key length.
pub const SECRET_KEY_LEN: usize = 32 + 32 + 64 + (L + K) * N * 4 / 8 + K * N * D / 8; // 4032
/// Encoded signature length (c̃ ∥ z ∥ h).
pub const SIGNATURE_LEN: usize = C_TILDE_LEN + L * N * 20 / 8 + OMEGA + K; // 3309

type Poly = [i32; N];
const ZERO: Poly = [0; N];

// ------------------------------------------------------- modular helpers

#[inline]
fn add_mod(a: i32, b: i32) -> i32 {
    let s = a + b;
    if s >= Q { s - Q } else { s }
}

#[inline]
fn sub_mod(a: i32, b: i32) -> i32 {
    let s = a - b;
    if s < 0 { s + Q } else { s }
}

#[inline]
fn mul_mod(a: i32, b: i32) -> i32 {
    (a as i64 * b as i64).rem_euclid(Q as i64) as i32
}

fn pow_mod(mut base: i64, mut exp: u64) -> i64 {
    let mut result = 1i64;
    base = base.rem_euclid(Q as i64);
    while exp > 0 {
        if exp & 1 == 1 {
            result = (result * base) % Q as i64;
        }
        base = (base * base) % Q as i64;
        exp >>= 1;
    }
    result
}

/// Centered representative of a coefficient in `[0, q)`: value in
/// `(-q/2, q/2]`.
#[inline]
fn center(a: i32) -> i32 {
    if a > Q / 2 { a - Q } else { a }
}

/// Infinity norm (centered) of a polynomial.
fn norm_inf(p: &Poly) -> i32 {
    p.iter().map(|&c| center(c).abs()).max().unwrap_or(0)
}

// ---------------------------------------------------------------- the NTT

fn zetas() -> &'static [i32; N] {
    static ZETAS: OnceLock<[i32; N]> = OnceLock::new();
    ZETAS.get_or_init(|| {
        let mut z = [0i32; N];
        for (i, slot) in z.iter_mut().enumerate() {
            // brv8: bit-reverse the 8-bit index.
            let exp = (i as u8).reverse_bits() as u64;
            *slot = pow_mod(ROOT, exp) as i32;
        }
        z
    })
}

fn n_inverse() -> i32 {
    static NINV: OnceLock<i32> = OnceLock::new();
    *NINV.get_or_init(|| pow_mod(N as i64, (Q - 2) as u64) as i32)
}

/// In-place forward NTT (complete: the ring splits into linear factors,
/// so NTT-domain multiplication is coefficient-wise).
fn ntt(a: &mut Poly) {
    let zetas = zetas();
    let mut k = 0usize;
    let mut len = 128;
    while len >= 1 {
        let mut start = 0;
        while start < N {
            k += 1;
            let zeta = zetas[k];
            for j in start..start + len {
                let t = mul_mod(zeta, a[j + len]);
                a[j + len] = sub_mod(a[j], t);
                a[j] = add_mod(a[j], t);
            }
            start += 2 * len;
        }
        len >>= 1;
    }
}

/// In-place inverse NTT, including the final `1/n` scaling.
fn inv_ntt(a: &mut Poly) {
    let zetas = zetas();
    let mut k = N;
    let mut len = 1;
    while len < N {
        let mut start = 0;
        while start < N {
            k -= 1;
            let zeta = Q - zetas[k]; // -zetas[k] mod q
            for j in start..start + len {
                let t = a[j];
                a[j] = add_mod(t, a[j + len]);
                a[j + len] = mul_mod(zeta, sub_mod(t, a[j + len]));
            }
            start += 2 * len;
        }
        len <<= 1;
    }
    let ninv = n_inverse();
    for x in a.iter_mut() {
        *x = mul_mod(*x, ninv);
    }
}

fn poly_add(a: &Poly, b: &Poly) -> Poly {
    let mut r = ZERO;
    for i in 0..N {
        r[i] = add_mod(a[i], b[i]);
    }
    r
}

fn poly_sub(a: &Poly, b: &Poly) -> Poly {
    let mut r = ZERO;
    for i in 0..N {
        r[i] = sub_mod(a[i], b[i]);
    }
    r
}

/// Coefficient-wise product in the NTT domain.
fn poly_pointwise(a: &Poly, b: &Poly) -> Poly {
    let mut r = ZERO;
    for i in 0..N {
        r[i] = mul_mod(a[i], b[i]);
    }
    r
}

// ------------------------------------------------------- rounding / hints

/// Split `r` into `r1·2^d + r0` with `r0 ∈ (-2^{d-1}, 2^{d-1}]`.
fn power2round(r: i32) -> (i32, i32) {
    let r = r.rem_euclid(Q);
    let r1 = (r + (1 << (D - 1)) - 1) >> D;
    let r0 = r - (r1 << D);
    (r1, r0)
}

/// Decompose `r` into high/low parts around `2·γ2`.
fn decompose(r: i32) -> (i32, i32) {
    let r = r.rem_euclid(Q);
    let mut r0 = r % (2 * GAMMA2);
    if r0 > GAMMA2 {
        r0 -= 2 * GAMMA2;
    }
    if r - r0 == Q - 1 {
        (0, r0 - 1)
    } else {
        ((r - r0) / (2 * GAMMA2), r0)
    }
}

fn high_bits(r: i32) -> i32 {
    decompose(r).0
}

fn low_bits(r: i32) -> i32 {
    decompose(r).1
}

/// Whether adding `z` to `r` changes its high bits.
fn make_hint(z: i32, r: i32) -> bool {
    high_bits(r) != high_bits(add_mod(r.rem_euclid(Q), z.rem_euclid(Q)))
}

/// Recover corrected high bits from a hint bit.
fn use_hint(hint: bool, r: i32) -> i32 {
    let m = (Q - 1) / (2 * GAMMA2); // 16
    let (r1, r0) = decompose(r);
    if hint {
        if r0 > 0 {
            (r1 + 1) % m
        } else {
            (r1 - 1).rem_euclid(m)
        }
    } else {
        r1
    }
}

// ---------------------------------------------------------------- hashing

fn shake256_into(parts: &[&[u8]], out: &mut [u8]) {
    let mut sponge = Keccak::shake256();
    for p in parts {
        sponge.absorb(p);
    }
    sponge.squeeze(out);
}

fn h(parts: &[&[u8]], out_len: usize) -> Vec<u8> {
    let mut out = vec![0u8; out_len];
    shake256_into(parts, &mut out);
    out
}

// --------------------------------------------------------------- sampling

/// `SampleInBall`: a challenge polynomial with exactly `TAU` coefficients
/// set to ±1.
fn sample_in_ball(seed: &[u8]) -> Poly {
    let mut c = ZERO;
    let mut sponge = Keccak::shake256();
    sponge.absorb(seed);
    let mut sign_bytes = [0u8; 8];
    sponge.squeeze(&mut sign_bytes);
    let signs = u64::from_le_bytes(sign_bytes);

    for (bit, i) in ((N - TAU)..N).enumerate() {
        let mut j;
        loop {
            let mut b = [0u8; 1];
            sponge.squeeze(&mut b);
            j = b[0] as usize;
            if j <= i {
                break;
            }
        }
        c[i] = c[j];
        c[j] = if (signs >> bit) & 1 == 1 { Q - 1 } else { 1 };
    }
    c
}

/// `RejNTTPoly`: a uniform polynomial in the NTT domain from ρ and a
/// two-byte nonce (used to build the matrix Â).
fn rej_ntt_poly(rho: &[u8], j: u8, i: u8) -> Poly {
    let mut sponge = Keccak::shake128();
    sponge.absorb(rho);
    sponge.absorb(&[j, i]);
    let mut poly = ZERO;
    let mut ctr = 0;
    let mut buf = [0u8; 3];
    while ctr < N {
        sponge.squeeze(&mut buf);
        let t = (buf[0] as i32) | ((buf[1] as i32) << 8) | (((buf[2] as i32) & 0x7f) << 16);
        if t < Q {
            poly[ctr] = t;
            ctr += 1;
        }
    }
    poly
}

/// `RejBoundedPoly`: coefficients in `[-η, η]` from ρ′ and a nonce.
fn rej_bounded_poly(rho_prime: &[u8], nonce: u16) -> Poly {
    let mut sponge = Keccak::shake256();
    sponge.absorb(rho_prime);
    sponge.absorb(&nonce.to_le_bytes());
    let mut poly = ZERO;
    let mut ctr = 0;
    let mut buf = [0u8; 1];
    while ctr < N {
        sponge.squeeze(&mut buf);
        for nibble in [buf[0] & 0x0f, buf[0] >> 4] {
            // η = 4: accept z < 9, coefficient = 4 - z, stored in [0, q).
            if (nibble as i32) < 9 && ctr < N {
                poly[ctr] = (ETA - nibble as i32).rem_euclid(Q);
                ctr += 1;
            }
        }
    }
    poly
}

/// `ExpandMask`: a masking polynomial with coefficients in `(-γ1, γ1]`.
fn expand_mask_poly(rho_pp: &[u8], nonce: u16) -> Poly {
    let mut buf = vec![0u8; N * 20 / 8]; // 640 bytes → 256 coeffs at 20 bits
    let mut sponge = Keccak::shake256();
    sponge.absorb(rho_pp);
    sponge.absorb(&nonce.to_le_bytes());
    sponge.squeeze(&mut buf);
    let vals = unpack_bits(&buf, 20, N);
    let mut poly = ZERO;
    for i in 0..N {
        poly[i] = sub_mod((GAMMA1).rem_euclid(Q), (vals[i] as i32).rem_euclid(Q));
    }
    poly
}

fn expand_a(rho: &[u8]) -> Vec<Vec<Poly>> {
    let mut a = vec![vec![ZERO; L]; K];
    for i in 0..K {
        for j in 0..L {
            a[i][j] = rej_ntt_poly(rho, j as u8, i as u8);
        }
    }
    a
}

fn expand_s(rho_prime: &[u8]) -> (Vec<Poly>, Vec<Poly>) {
    let mut s1 = vec![ZERO; L];
    let mut s2 = vec![ZERO; K];
    for (idx, p) in s1.iter_mut().enumerate() {
        *p = rej_bounded_poly(rho_prime, idx as u16);
    }
    for (idx, p) in s2.iter_mut().enumerate() {
        *p = rej_bounded_poly(rho_prime, (L + idx) as u16);
    }
    (s1, s2)
}

// -------------------------------------------------------- bit-packing

/// Pack fixed-width unsigned values, least-significant-bit first. The
/// total bit count is always a multiple of 8 for our parameter sets.
fn pack_bits(vals: &[u32], bits: usize) -> Vec<u8> {
    let mut out = vec![0u8; vals.len() * bits / 8];
    let mut acc: u64 = 0;
    let mut acc_bits = 0;
    let mut oi = 0;
    for &v in vals {
        acc |= (v as u64) << acc_bits;
        acc_bits += bits;
        while acc_bits >= 8 {
            out[oi] = acc as u8;
            oi += 1;
            acc >>= 8;
            acc_bits -= 8;
        }
    }
    out
}

fn unpack_bits(data: &[u8], bits: usize, count: usize) -> Vec<u32> {
    let mut vals = Vec::with_capacity(count);
    let mask = if bits == 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    };
    let mut acc: u64 = 0;
    let mut acc_bits = 0;
    let mut di = 0;
    for _ in 0..count {
        while acc_bits < bits {
            acc |= (data[di] as u64) << acc_bits;
            di += 1;
            acc_bits += 8;
        }
        vals.push((acc & mask) as u32);
        acc >>= bits;
        acc_bits -= bits;
    }
    vals
}

fn pack_t1(p: &Poly) -> Vec<u8> {
    let vals: Vec<u32> = p.iter().map(|&c| c as u32).collect();
    pack_bits(&vals, 10)
}

fn unpack_t1(data: &[u8]) -> Poly {
    let vals = unpack_bits(data, 10, N);
    let mut p = ZERO;
    for i in 0..N {
        p[i] = vals[i] as i32;
    }
    p
}

fn pack_eta(p: &Poly) -> Vec<u8> {
    let vals: Vec<u32> = p.iter().map(|&c| (ETA - center(c)) as u32).collect();
    pack_bits(&vals, 4)
}

fn unpack_eta(data: &[u8]) -> Poly {
    let vals = unpack_bits(data, 4, N);
    let mut p = ZERO;
    for i in 0..N {
        p[i] = (ETA - vals[i] as i32).rem_euclid(Q);
    }
    p
}

fn pack_t0(p: &Poly) -> Vec<u8> {
    let vals: Vec<u32> = p
        .iter()
        .map(|&c| ((1 << (D - 1)) - center(c)) as u32)
        .collect();
    pack_bits(&vals, D)
}

fn unpack_t0(data: &[u8]) -> Poly {
    let vals = unpack_bits(data, D, N);
    let mut p = ZERO;
    for i in 0..N {
        p[i] = ((1 << (D - 1)) - vals[i] as i32).rem_euclid(Q);
    }
    p
}

fn pack_z(p: &Poly) -> Vec<u8> {
    let vals: Vec<u32> = p.iter().map(|&c| (GAMMA1 - center(c)) as u32).collect();
    pack_bits(&vals, 20)
}

fn unpack_z(data: &[u8]) -> Poly {
    let vals = unpack_bits(data, 20, N);
    let mut p = ZERO;
    for i in 0..N {
        p[i] = (GAMMA1 - vals[i] as i32).rem_euclid(Q);
    }
    p
}

/// `w1Encode`: 4-bit high-bit values, all K polynomials concatenated.
fn w1_encode(w1: &[Poly]) -> Vec<u8> {
    let mut vals = Vec::with_capacity(K * N);
    for p in w1 {
        for &c in p.iter() {
            vals.push(c as u32);
        }
    }
    pack_bits(&vals, 4)
}

// ------------------------------------------------------- key/sig encoding

fn pk_encode(rho: &[u8], t1: &[Poly]) -> Vec<u8> {
    let mut out = Vec::with_capacity(PUBLIC_KEY_LEN);
    out.extend_from_slice(rho);
    for p in t1 {
        out.extend_from_slice(&pack_t1(p));
    }
    out
}

fn pk_decode(pk: &[u8]) -> (Vec<u8>, Vec<Poly>) {
    let rho = pk[..32].to_vec();
    let mut t1 = vec![ZERO; K];
    let stride = N * 10 / 8;
    for (i, p) in t1.iter_mut().enumerate() {
        let off = 32 + i * stride;
        *p = unpack_t1(&pk[off..off + stride]);
    }
    (rho, t1)
}

#[allow(clippy::type_complexity)]
fn sk_decode(sk: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<Poly>, Vec<Poly>, Vec<Poly>) {
    let rho = sk[0..32].to_vec();
    let k_seed = sk[32..64].to_vec();
    let tr = sk[64..128].to_vec();
    let mut off = 128;
    let eta_stride = N * 4 / 8;
    let mut s1 = vec![ZERO; L];
    for p in s1.iter_mut() {
        *p = unpack_eta(&sk[off..off + eta_stride]);
        off += eta_stride;
    }
    let mut s2 = vec![ZERO; K];
    for p in s2.iter_mut() {
        *p = unpack_eta(&sk[off..off + eta_stride]);
        off += eta_stride;
    }
    let t0_stride = N * D / 8;
    let mut t0 = vec![ZERO; K];
    for p in t0.iter_mut() {
        *p = unpack_t0(&sk[off..off + t0_stride]);
        off += t0_stride;
    }
    (rho, k_seed, tr, s1, s2, t0)
}

fn sig_encode(c_tilde: &[u8], z: &[Poly], h: &[Poly]) -> Vec<u8> {
    let mut out = Vec::with_capacity(SIGNATURE_LEN);
    out.extend_from_slice(c_tilde);
    for p in z {
        out.extend_from_slice(&pack_z(p));
    }
    // Hint: positions of set coefficients per polynomial, then per-poly
    // cumulative counts.
    let mut hint = vec![0u8; OMEGA + K];
    let mut idx = 0;
    for (i, p) in h.iter().enumerate() {
        for (j, &c) in p.iter().enumerate() {
            if c != 0 {
                hint[idx] = j as u8;
                idx += 1;
            }
        }
        hint[OMEGA + i] = idx as u8;
    }
    out.extend_from_slice(&hint);
    out
}

fn sig_decode(sig: &[u8]) -> Option<(Vec<u8>, Vec<Poly>, Vec<Poly>)> {
    let c_tilde = sig[..C_TILDE_LEN].to_vec();
    let mut off = C_TILDE_LEN;
    let z_stride = N * 20 / 8;
    let mut z = vec![ZERO; L];
    for p in z.iter_mut() {
        *p = unpack_z(&sig[off..off + z_stride]);
        off += z_stride;
    }
    let hint = &sig[off..off + OMEGA + K];
    let mut h = vec![ZERO; K];
    let mut k = 0usize;
    for i in 0..K {
        let end = hint[OMEGA + i] as usize;
        if end < k || end > OMEGA {
            return None;
        }
        for j in k..end {
            if j > k && hint[j] <= hint[j - 1] {
                return None; // positions must strictly increase
            }
            h[i][hint[j] as usize] = 1;
        }
        k = end;
    }
    for &b in &hint[k..OMEGA] {
        if b != 0 {
            return None; // padding must be zero
        }
    }
    Some((c_tilde, z, h))
}

// ------------------------------------------------------------ public API

/// Deterministically derive a key pair from a 32-byte seed. Returns
/// `(public_key, secret_key)`.
pub fn keypair_from_seed(seed: &[u8; SEED_LEN]) -> (Vec<u8>, Vec<u8>) {
    // (ρ, ρ′, K) ← H(ξ ∥ k ∥ l)
    let expanded = h(&[seed, &[K as u8], &[L as u8]], 128);
    let rho = &expanded[0..32];
    let rho_prime = &expanded[32..96];
    let k_seed = &expanded[96..128];

    let a = expand_a(rho);
    let (s1, s2) = expand_s(rho_prime);

    // t = A·s1 + s2  (A is in the NTT domain)
    let mut s1_hat = s1.clone();
    for p in s1_hat.iter_mut() {
        ntt(p);
    }
    let mut t = vec![ZERO; K];
    for i in 0..K {
        let mut acc = ZERO;
        for j in 0..L {
            acc = poly_add(&acc, &poly_pointwise(&a[i][j], &s1_hat[j]));
        }
        inv_ntt(&mut acc);
        t[i] = poly_add(&acc, &s2[i]);
    }

    let mut t1 = vec![ZERO; K];
    let mut t0 = vec![ZERO; K];
    for i in 0..K {
        for j in 0..N {
            let (hi, lo) = power2round(t[i][j]);
            t1[i][j] = hi;
            t0[i][j] = lo.rem_euclid(Q);
        }
    }

    let pk = pk_encode(rho, &t1);
    let tr = h(&[&pk], 64);

    let mut sk = Vec::with_capacity(SECRET_KEY_LEN);
    sk.extend_from_slice(rho);
    sk.extend_from_slice(k_seed);
    sk.extend_from_slice(&tr);
    for p in &s1 {
        sk.extend_from_slice(&pack_eta(p));
    }
    for p in &s2 {
        sk.extend_from_slice(&pack_eta(p));
    }
    for p in &t0 {
        sk.extend_from_slice(&pack_t0(p));
    }
    (pk, sk)
}

/// Sign `message` with `secret_key` (deterministic variant, empty
/// context). Returns a `SIGNATURE_LEN`-byte signature.
pub fn sign(secret_key: &[u8], message: &[u8]) -> Vec<u8> {
    let (rho, k_seed, tr, s1, s2, t0) = sk_decode(secret_key);
    let a = expand_a(&rho);

    let mut s1_hat = s1.clone();
    let mut s2_hat = s2.clone();
    let mut t0_hat = t0.clone();
    for p in s1_hat.iter_mut() {
        ntt(p);
    }
    for p in s2_hat.iter_mut() {
        ntt(p);
    }
    for p in t0_hat.iter_mut() {
        ntt(p);
    }

    // Pure ML-DSA message representative: 0x00 ∥ |ctx| ∥ ctx ∥ M, ctx empty.
    let m_prime = [&[0u8, 0u8][..], message].concat();
    let mu = h(&[&tr, &m_prime], 64);
    let rnd = [0u8; 32]; // deterministic
    let rho_pp = h(&[&k_seed, &rnd, &mu], 64);

    let mut kappa: u16 = 0;
    loop {
        // y ← ExpandMask(ρ″, κ)
        let mut y = vec![ZERO; L];
        for (r, p) in y.iter_mut().enumerate() {
            *p = expand_mask_poly(&rho_pp, kappa + r as u16);
        }
        kappa += L as u16;

        // w = A·y
        let mut y_hat = y.clone();
        for p in y_hat.iter_mut() {
            ntt(p);
        }
        let mut w = vec![ZERO; K];
        for i in 0..K {
            let mut acc = ZERO;
            for j in 0..L {
                acc = poly_add(&acc, &poly_pointwise(&a[i][j], &y_hat[j]));
            }
            inv_ntt(&mut acc);
            w[i] = acc;
        }

        let mut w1 = vec![ZERO; K];
        for i in 0..K {
            for j in 0..N {
                w1[i][j] = high_bits(w[i][j]);
            }
        }

        let c_tilde = h(&[&mu, &w1_encode(&w1)], C_TILDE_LEN);
        let c = sample_in_ball(&c_tilde);
        let mut c_hat = c;
        ntt(&mut c_hat);

        // cs1, cs2
        let mut cs1 = vec![ZERO; L];
        for j in 0..L {
            let mut p = poly_pointwise(&c_hat, &s1_hat[j]);
            inv_ntt(&mut p);
            cs1[j] = p;
        }
        let mut cs2 = vec![ZERO; K];
        for i in 0..K {
            let mut p = poly_pointwise(&c_hat, &s2_hat[i]);
            inv_ntt(&mut p);
            cs2[i] = p;
        }

        // z = y + cs1
        let mut z = vec![ZERO; L];
        for j in 0..L {
            z[j] = poly_add(&y[j], &cs1[j]);
        }
        // r0 = LowBits(w - cs2)
        let mut r0 = vec![ZERO; K];
        for i in 0..K {
            let diff = poly_sub(&w[i], &cs2[i]);
            for j in 0..N {
                r0[i][j] = low_bits(diff[j]);
            }
        }

        if z.iter().map(norm_inf).max().unwrap_or(0) >= GAMMA1 - BETA
            || r0.iter().map(infinity_low).max().unwrap_or(0) >= GAMMA2 - BETA
        {
            continue;
        }

        // ct0, hint
        let mut ct0 = vec![ZERO; K];
        for i in 0..K {
            let mut p = poly_pointwise(&c_hat, &t0_hat[i]);
            inv_ntt(&mut p);
            ct0[i] = p;
        }

        let mut hint = vec![ZERO; K];
        let mut ones = 0usize;
        for i in 0..K {
            for j in 0..N {
                let minus_ct0 = sub_mod(0, ct0[i][j]);
                let r = add_mod(sub_mod(w[i][j], cs2[i][j]), ct0[i][j]);
                if make_hint(minus_ct0, r) {
                    hint[i][j] = 1;
                    ones += 1;
                }
            }
        }

        if ct0.iter().map(norm_inf).max().unwrap_or(0) >= GAMMA2 || ones > OMEGA {
            continue;
        }

        return sig_encode(&c_tilde, &z, &hint);
    }
}

/// Verify `signature` over `message` under `public_key`.
pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    if public_key.len() != PUBLIC_KEY_LEN || signature.len() != SIGNATURE_LEN {
        return false;
    }
    let (rho, t1) = pk_decode(public_key);
    let Some((c_tilde, z, hint)) = sig_decode(signature) else {
        return false;
    };

    if z.iter().map(norm_inf).max().unwrap_or(0) >= GAMMA1 - BETA {
        return false;
    }

    let a = expand_a(&rho);
    let tr = h(&[public_key], 64);
    let m_prime = [&[0u8, 0u8][..], message].concat();
    let mu = h(&[&tr, &m_prime], 64);

    let c = sample_in_ball(&c_tilde);
    let mut c_hat = c;
    ntt(&mut c_hat);

    // w'Approx = A·z − c·(t1·2^d)
    let mut z_hat = z.clone();
    for p in z_hat.iter_mut() {
        ntt(p);
    }
    let mut t1_hat = vec![ZERO; K];
    for i in 0..K {
        for j in 0..N {
            t1_hat[i][j] = mul_mod(t1[i][j], 1 << D);
        }
        ntt(&mut t1_hat[i]);
    }

    let mut w1 = vec![ZERO; K];
    for i in 0..K {
        let mut az = ZERO;
        for j in 0..L {
            az = poly_add(&az, &poly_pointwise(&a[i][j], &z_hat[j]));
        }
        let ct1 = poly_pointwise(&c_hat, &t1_hat[i]);
        let mut approx = poly_sub(&az, &ct1);
        inv_ntt(&mut approx);
        for j in 0..N {
            w1[i][j] = use_hint(hint[i][j] != 0, approx[j]);
        }
    }

    let c_tilde_prime = h(&[&mu, &w1_encode(&w1)], C_TILDE_LEN);
    c_tilde_prime == c_tilde
}

/// Infinity norm of a low-bits polynomial (already centered in
/// `(-γ2, γ2]`).
fn infinity_low(p: &Poly) -> i32 {
    p.iter().map(|&c| c.abs()).max().unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Multiply two polynomials via NTT and via a schoolbook negacyclic
    /// convolution mod X^256+1; they must agree. This pins the whole NTT
    /// (every zeta, the inverse, and the 1/n scaling).
    #[test]
    fn ntt_matches_schoolbook() {
        let mut a = ZERO;
        let mut b = ZERO;
        for i in 0..N {
            a[i] = ((i as i32 * 7 + 3) % Q).rem_euclid(Q);
            b[i] = ((i as i32 * 5 + 11) % Q).rem_euclid(Q);
        }
        // schoolbook: c_k = Σ_{i+j=k} a_i b_j − Σ_{i+j=k+n} a_i b_j
        let mut school = ZERO;
        for i in 0..N {
            for j in 0..N {
                let prod = mul_mod(a[i], b[j]);
                let k = i + j;
                if k < N {
                    school[k] = add_mod(school[k], prod);
                } else {
                    school[k - N] = sub_mod(school[k - N], prod);
                }
            }
        }
        let mut na = a;
        let mut nb = b;
        ntt(&mut na);
        ntt(&mut nb);
        let mut prod = poly_pointwise(&na, &nb);
        inv_ntt(&mut prod);
        assert_eq!(prod, school);
    }

    #[test]
    fn packing_roundtrips() {
        // eta, t0, z packings round-trip through centered representatives.
        // Inputs must lie in each codec's legal centered range.
        let mut p = ZERO; // η: coefficients in [-η, η]
        for i in 0..N {
            p[i] = ((i as i32 % (2 * ETA + 1)) - ETA).rem_euclid(Q);
        }
        assert_eq!(unpack_eta(&pack_eta(&p)), p);

        let mut t0 = ZERO; // t0: (-2^{d-1}, 2^{d-1}]
        for i in 0..N {
            t0[i] = ((i as i32 % ((1 << D) - 1)) - ((1 << (D - 1)) - 1)).rem_euclid(Q);
        }
        assert_eq!(unpack_t0(&pack_t0(&t0)), t0);

        let mut z = ZERO; // z: (-γ1, γ1]
        for i in 0..N {
            z[i] = ((i as i32 * 4099) % (2 * GAMMA1) - GAMMA1 + 1).rem_euclid(Q);
        }
        assert_eq!(unpack_z(&pack_z(&z)), z);
    }

    #[test]
    fn sign_verify_roundtrip() {
        let seed = [7u8; SEED_LEN];
        let (pk, sk) = keypair_from_seed(&seed);
        assert_eq!(pk.len(), PUBLIC_KEY_LEN);
        assert_eq!(sk.len(), SECRET_KEY_LEN);

        let msg = b"ciphra audit root: 9f86d081...";
        let sig = sign(&sk, msg);
        assert_eq!(sig.len(), SIGNATURE_LEN);
        assert!(verify(&pk, msg, &sig));
    }

    #[test]
    fn deterministic_signature() {
        let seed = [3u8; SEED_LEN];
        let (_, sk) = keypair_from_seed(&seed);
        let msg = b"same message";
        assert_eq!(sign(&sk, msg), sign(&sk, msg));
    }

    #[test]
    fn rejects_tampering() {
        let seed = [42u8; SEED_LEN];
        let (pk, sk) = keypair_from_seed(&seed);
        let msg = b"authentic message";
        let sig = sign(&sk, msg);

        assert!(!verify(&pk, b"different message", &sig));

        let mut bad_sig = sig.clone();
        bad_sig[0] ^= 0x01;
        assert!(!verify(&pk, msg, &bad_sig));

        let mut bad_sig2 = sig.clone();
        let last = bad_sig2.len() - OMEGA - K - 1;
        bad_sig2[last] ^= 0x01;
        assert!(!verify(&pk, msg, &bad_sig2));

        let (other_pk, _) = keypair_from_seed(&[99u8; SEED_LEN]);
        assert!(!verify(&other_pk, msg, &sig));
    }
}
