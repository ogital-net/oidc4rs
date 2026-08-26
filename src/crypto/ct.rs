//! Constant-time byte-slice equality.
//!
//! Used for the ID-token `nonce` check in `token::verify`. The nonce
//! is a cryptographic secret, so a non-constant-time compare would
//! leak it to a timing oracle one byte at a time. The chosen FFI
//! symbol -- `CRYPTO_memcmp` -- is constant-time over its inputs and
//! is exported by both aws-lc and BoringSSL with identical C
//! signatures:
//!
//! ```c
//! int CRYPTO_memcmp(const void *a, const void *b, size_t len);
//! ```
//!
//! BoringSSL's reference implementation is the classical bitwise-OR
//! accumulator; aws-lc's tracks the same shape. Both treat
//! `len == 0` as returning 0 (equal) without touching memory.

use super::backend::ffi;

/// Returns `true` iff `a` and `b` are byte-for-byte equal, with a
/// running time that does not depend on which byte first differs.
///
/// Slices of different lengths are not equal; the length check is
/// not constant-time but the lengths of the inputs to this function
/// are not secret (the nonce is sent in the auth-request URL and
/// echoed back in the ID token, and the second-leg value is
/// attacker-readable in any well-designed KV).
pub(crate) fn ct_equals(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    // SAFETY: `a` and `b` are valid slices of identical length. The
    // FFI reads exactly `len` bytes from each and never writes
    // through either pointer.
    unsafe { ffi::CRYPTO_memcmp(a.as_ptr().cast(), b.as_ptr().cast(), a.len()) == 0 }
}

#[cfg(test)]
mod tests {
    //! Smoke tests for [`super::ct_equals`].
    //!
    //! These verify the wrapper, not the FFI's constant-time
    //! property -- the upstream aws-lc and BoringSSL implementations
    //! are already audited. We confirm only the bit-level mapping
    //! from FFI return value to `bool` and the length-mismatch
    //! short-circuit.

    use super::ct_equals;

    #[test]
    fn equal_slices_match() {
        let a = b"openid-nonce-abcdefghij";
        let b = b"openid-nonce-abcdefghij";
        assert!(ct_equals(a, b));
    }

    #[test]
    fn first_byte_differs_rejects() {
        let a = b"openid-nonce-abcdefghij";
        let b = b"Openid-nonce-abcdefghij";
        assert!(!ct_equals(a, b));
    }

    #[test]
    fn last_byte_differs_rejects() {
        let a = b"openid-nonce-abcdefghij";
        let b = b"openid-nonce-abcdefghiJ";
        assert!(!ct_equals(a, b));
    }

    #[test]
    fn length_mismatch_rejects() {
        let a = b"openid-nonce-abcdefghij";
        let b = b"openid-nonce-abcdefghi";
        assert!(!ct_equals(a, b));
    }

    #[test]
    fn empty_slices_are_equal() {
        let a: &[u8] = b"";
        let b: &[u8] = b"";
        assert!(ct_equals(a, b));
    }

    #[test]
    fn empty_vs_non_empty_rejects() {
        let a: &[u8] = b"";
        let b = b"\x00";
        assert!(!ct_equals(a, b));
    }
}
