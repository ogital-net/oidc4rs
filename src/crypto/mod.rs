//! Cryptography primitives used directly by `oidc4rs`.
//!
//! The JOSE primitives (signatures, encryption, key parsing) come from
//! `jose4rs`. This module covers the two operations `oidc4rs` itself
//! needs but that `jose4rs` does not expose publicly:
//!
//! - Secure random byte generation, used for nonces, state values, PKCE
//!   verifiers, and KV keys.
//! - SHA-256, used for PKCE S256 challenge derivation and `at_hash`
//!   computation.
//!
//! Both operations call into the same FFI backend the consumer selected
//! (`aws-lc-sys` or `boring-sys`), so no extra Rust crypto crate is
//! pulled in. The wrappers are `pub(crate)` so the public API never
//! exposes FFI types. See `docs/SPEC.md` section 3.4 for the verified
//! abort / failure-mode analysis that motivates the infallible wrappers
//! -- in practice the FFI either succeeds or aborts the process, so no
//! `Result` is surfaced.

mod backend;
mod hash;
mod rand;

pub(crate) use hash::sha256;
pub(crate) use rand::fill_bytes;
