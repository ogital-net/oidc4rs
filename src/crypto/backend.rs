//! Backend selection for the FFI primitives.
//!
//! Exactly one of the `aws-lc` or `boring` features is enabled at a time
//! (enforced by `compile_error!` in the crate root). This module re-exports
//! the symbols under a single name so the wrapper modules do not need
//! cfg-gated imports scattered through their bodies.

#[cfg(feature = "aws-lc")]
pub(crate) use aws_lc_sys as ffi;

#[cfg(feature = "boring")]
pub(crate) use boring_sys as ffi;
