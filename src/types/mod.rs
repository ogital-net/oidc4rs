//! Strongly-typed identifiers, URLs, and request knobs.
//!
//! The OIDC protocol has many short-string parameters whose meaning is
//! contextual. Wrapping them in newtypes prevents a `ClientId` from
//! being passed where a `RedirectUrl` is expected, and gives us a
//! single place to validate inputs (HTTPS, non-empty, well-formed).

pub mod identifiers;
pub mod url;

pub use identifiers::*;
pub use url::*;
