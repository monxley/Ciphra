//! Best-effort zeroization of secret material.
//!
//! Secret key bytes are overwritten when their holder is dropped, so a
//! long-lived key does not sit in the heap after its last use. This is
//! **defense in depth, not a guarantee**: Rust may still leave copies the
//! compiler spilled to the stack, moved elsewhere, or reallocated (a
//! `Vec` that grew), and a passphrase `String` handed in from outside is
//! the caller's to manage. The volatile writes below stop the *obvious*
//! long-lived copy from lingering and resist dead-store elimination.

use core::sync::atomic::{Ordering, compiler_fence};

/// Overwrite `buf` with zeros using volatile writes the optimizer may
/// not elide, then a fence so the writes are not reordered past it.
pub(crate) fn secure_zero(buf: &mut [u8]) {
    for byte in buf.iter_mut() {
        // SAFETY: `byte` is a valid, aligned, writable `u8`.
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zeros_the_buffer() {
        let mut secret = [0xa5u8; 64];
        secure_zero(&mut secret);
        assert_eq!(secret, [0u8; 64]);
    }

    #[test]
    fn zeros_an_empty_slice_without_panicking() {
        let mut empty: [u8; 0] = [];
        secure_zero(&mut empty);
    }
}
