//! SHA-2 via the selected FFI backend.
//!
//! Exposes one-shot hash functions for SHA-256, SHA-384, and SHA-512
//! that hash a contiguous buffer in a single FFI call
//!
//! Used for PKCE S256 challenge derivation (RFC 7636) and `at_hash`
//! computation (OIDC Core 1.0, section 3.1.3.6).

use super::backend::ffi;

/// SHA-256 digest size in bytes.
pub(crate) const SHA256_OUTPUT_LEN: usize = 32;
/// SHA-384 digest size in bytes.
pub(crate) const SHA384_OUTPUT_LEN: usize = 48;
/// SHA-512 digest size in bytes.
pub(crate) const SHA512_OUTPUT_LEN: usize = 64;

/// Computes the SHA-256 digest of `data`, returning the 32-byte output.
///
/// Allocates nothing on the Rust heap. The C `SHA256` function
/// internally allocates a stack-local `SHA256_CTX` and dispatches to
/// the pre-compiled SHA-256 compression function.
pub(crate) fn sha256(data: &[u8]) -> [u8; SHA256_OUTPUT_LEN] {
    let mut out = [0u8; SHA256_OUTPUT_LEN];

    // SAFETY: `data` remains readable and `out` remains writable for
    // the call; `SHA256` writes exactly `SHA256_OUTPUT_LEN` bytes.
    let out_ptr = unsafe { ffi::SHA256(data.as_ptr(), data.len(), out.as_mut_ptr()) };
    assert!(!out_ptr.is_null(), "SHA256 returned NULL");

    out
}

/// Computes the SHA-384 digest of `data`.
pub(crate) fn sha384(data: &[u8]) -> [u8; SHA384_OUTPUT_LEN] {
    let mut out = [0u8; SHA384_OUTPUT_LEN];

    // SAFETY: `data` remains readable and `out` remains writable for
    // the call; `SHA384` writes exactly `SHA384_OUTPUT_LEN` bytes.
    let out_ptr = unsafe { ffi::SHA384(data.as_ptr(), data.len(), out.as_mut_ptr()) };
    assert!(!out_ptr.is_null(), "SHA384 returned NULL");

    out
}

/// Computes the SHA-512 digest of `data`.
pub(crate) fn sha512(data: &[u8]) -> [u8; SHA512_OUTPUT_LEN] {
    let mut out = [0u8; SHA512_OUTPUT_LEN];

    // SAFETY: `data` remains readable and `out` remains writable for
    // the call; `SHA512` writes exactly `SHA512_OUTPUT_LEN` bytes.
    let out_ptr = unsafe { ffi::SHA512(data.as_ptr(), data.len(), out.as_mut_ptr()) };
    assert!(!out_ptr.is_null(), "SHA512 returned NULL");

    out
}

#[cfg(test)]
mod tests {
    //! Known-answer tests pinning the exact digest bytes.
    //!
    //! Vectors are from FIPS 180-4 (`Secure Hash Standard`), the
    //! authoritative test set for SHA-256 and the one both aws-lc and
    //! BoringSSL validate their FIPS module against. A future refactor
    //! that swaps or breaks the FFI dispatch will be caught here
    //! before it ships.
    //!
    //! Three inputs exercise the boundary cases that the C
    //! implementation has to handle correctly:
    //!
    //! - empty input: the padding-length code path with no message
    //!   bytes
    //! - 3 bytes ("abc"): single compression block, fits in one chunk
    //!   after padding
    //! - 56 bytes (the FIPS-180-4 `MidSize` example): exercises two
    //!   compression blocks back-to-back without crossing the 64-byte
    //!   block boundary, which is the sharpest edge in the
    //!   length-extension / padding arithmetic

    use super::{sha256, sha384, sha512};

    /// FIPS 180-4 SHA-256 known-answer test vectors:
    ///
    /// - empty string
    /// - ASCII `"abc"`
    /// - 56-byte ASCII message
    ///   (`"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"`)
    const VECTORS: &[(&[u8], &str)] = &[
        (
            b"",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
        (
            b"abc",
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ),
        (
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        ),
    ];

    #[test]
    fn output_len_is_thirty_two() {
        let digest = sha256(b"");
        assert_eq!(digest.len(), 32);
    }

    #[test]
    fn known_answers_match_fips_180_4() {
        for (input, expected_hex) in VECTORS {
            let got = sha256(input);
            assert_eq!(hex(&got), *expected_hex, "input len = {}", input.len());
        }
    }

    #[test]
    fn same_input_produces_same_digest() {
        // Distinct equal-sized buffers must produce identical digests.
        let a = sha256(b"openid email profile");
        let b = sha256(b"openid email profile");
        assert_eq!(a, b);
    }

    #[test]
    fn sha384_known_answer_matches_fips_180_4() {
        assert_eq!(
            hex(&sha384(b"abc")),
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
        );
    }

    #[test]
    fn sha512_known_answer_matches_fips_180_4() {
        assert_eq!(
            hex(&sha512(b"abc")),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
    }

    /// Lowercase hex of a byte slice. Keeps the test self-contained --
    /// adding a `hex` crate for two assertions in one test module is
    /// not worth the dependency.
    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            write!(s, "{b:02x}").expect("writing to String never fails");
        }
        s
    }
}
