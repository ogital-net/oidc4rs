//! oidc4rs -- OpenID Connect relying-party library built on jose4rs.
//!
//! See `docs/SPEC.md` for the design and `AGENTS.md` for conventions.

#![warn(clippy::pedantic)]
// Pedantic lints that produce noise without catching real issues in this
// crate. Kept as a single block so the rationale is colocated.
#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::return_self_not_must_use)]
#![allow(clippy::similar_names)]

// Exactly one cryptography backend must be enabled. The two backends
// provide identical FFI surfaces so enabling both would be ambiguous at
// link time.
#[cfg(all(feature = "aws-lc", feature = "boring"))]
compile_error!("features `aws-lc` and `boring` are mutually exclusive; enable exactly one");

#[cfg(not(any(feature = "aws-lc", feature = "boring")))]
compile_error!(
    "no cryptography backend selected; enable exactly one of `aws-lc` (default) or `boring`"
);

pub mod claims;
pub mod client;
pub mod error;
pub mod flow;
pub mod metadata;
pub mod token;
pub mod transport;
pub mod types;

pub use error::OidcError;

mod crypto;

// Re-exported jose4rs surface commonly needed by callers.
pub use jose4rs;
