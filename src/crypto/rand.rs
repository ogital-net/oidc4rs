//! Secure random byte generation via the selected FFI backend.

use super::backend::ffi;

/// Fills `dst` with cryptographically secure random bytes.
///
/// `RAND_bytes` in both BoringSSL and aws-lc is documented to return 1
/// on success and to abort the process internally on failure (the OS
/// entropy source is unavailable). The return value is therefore treated
/// as an invariant rather than an error path: if it ever returns
/// something other than 1 the surrounding code is miscompiled.
pub(crate) fn fill_bytes(dst: &mut [u8]) {
    if dst.is_empty() {
        return;
    }

    // SAFETY: `dst` is a valid mutable slice whose length matches the
    // count passed to RAND_bytes. RAND_bytes writes exactly `len` bytes
    // on success and does not read past the buffer.
    let result = unsafe { ffi::RAND_bytes(dst.as_mut_ptr(), dst.len()) };

    // RAND_bytes returns 1 on success, 0 or -1 on failure. Failure is
    // an internal abort in both backends; if we see it here, treat as
    // a contract violation.
    assert!(result == 1, "RAND_bytes returned {result}");
}

#[cfg(test)]
mod tests {
    //! Smoke tests for [`super::fill_bytes`].
    //!
    //! We do not try to validate the cryptographic quality of the
    //! output -- the FFI symbols we wrap are already validated by the
    //! upstream FIPS modules of aws-lc and BoringSSL, and rolling our
    //! own randomness test would just re-derive NIST SP 800-22. The
    //! point of these tests is the much narrower one of catching the
    //! failure mode where the FFI is wired up but the bytes it
    //! produces are zero (or otherwise obviously not random): that
    //! would silently break nonce generation, PKCE verifiers, and the
    //! second-leg state value, all of which depend on the bits being
    //! unique.

    use super::fill_bytes;

    #[test]
    fn fills_requested_length() {
        let mut buf = vec![0u8; 32];
        fill_bytes(&mut buf);
        assert_eq!(buf.len(), 32);
    }

    #[test]
    fn output_is_not_all_zero() {
        // 64 bytes is the size used by PkceCodeVerifier::new_random;
        // checking that length makes this test the canary for the
        // single most security-sensitive caller.
        let mut buf = [0u8; 64];
        fill_bytes(&mut buf);
        assert!(
            buf.iter().any(|b| *b != 0),
            "fill_bytes returned 64 zero bytes -- FFI wiring is broken"
        );
    }

    #[test]
    fn consecutive_calls_differ() {
        // Two back-to-back fills must produce different bytes; a
        // constant seed would make nonces and state values
        // predictable.
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        fill_bytes(&mut a);
        fill_bytes(&mut b);
        assert_ne!(a, b, "two consecutive fills produced identical bytes");
    }

    #[test]
    fn empty_buffer_is_a_noop() {
        let mut buf: [u8; 0] = [];
        fill_bytes(&mut buf); // must not panic, must not assert
        assert_eq!(buf.len(), 0);
    }
}
