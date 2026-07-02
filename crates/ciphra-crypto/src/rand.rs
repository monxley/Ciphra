//! Operating-system randomness. Reads the kernel CSPRNG directly so the
//! crate stays dependency-free; getrandom-style syscall wrappers can
//! replace this behind the same function later.

use std::fs::File;
use std::io::Read;

/// Fill `buf` with cryptographically secure random bytes.
///
/// Panics if the OS randomness source is unavailable — proceeding with
/// predictable key material would be strictly worse than crashing.
pub fn fill_random(buf: &mut [u8]) {
    let mut source = File::open("/dev/urandom")
        .expect("cannot open /dev/urandom: no secure randomness available");
    source
        .read_exact(buf)
        .expect("failed to read from /dev/urandom");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fills_and_varies() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        fill_random(&mut a);
        fill_random(&mut b);
        // 2^-256 false-negative probability is acceptable.
        assert_ne!(a, b);
        assert_ne!(a, [0u8; 32]);
    }
}
