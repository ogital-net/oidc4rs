//! Crate-wide error type.

use thiserror::Error;

/// All errors surfaced by `oidc4rs`.
///
/// `From` impls for foreign error types live alongside this enum so the
/// `?` operator works uniformly across modules.
#[derive(Debug, Error)]
pub enum OidcError {
    #[error("discovery failed: {0}")]
    Discovery(String),

    #[error("HTTP transport error: {0}")]
    Http(String),

    #[error("invalid provider metadata: {0}")]
    InvalidMetadata(String),

    #[error("invalid URL: {0}")]
    InvalidUrl(String),

    #[error("ID-token validation failed: {0}")]
    InvalidIdToken(#[from] jose4rs::jwt::InvalidJwtError),

    #[error("token endpoint error (status {status}): {error}")]
    TokenEndpoint {
        status: u16,
        error: String,
        error_description: Option<String>,
    },

    #[error("userinfo error (status {status}): {error}")]
    UserInfo {
        status: u16,
        error: String,
        error_description: Option<String>,
    },

    #[error("JOSE error: {0}")]
    Jose(#[from] jose4rs::error::JoseError),

    #[error("no matching JWK for kid={kid:?}, alg={alg}")]
    NoMatchingJwk { kid: Option<String>, alg: String },

    #[error("at_hash mismatch")]
    AtHashMismatch,

    #[error("unsupported signing algorithm: {0}")]
    UnsupportedAlgorithm(String),

    #[error("key-value store error: {0}")]
    Kv(crate::transport::kv::KvError),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("authorization response error: {0}")]
    AuthorizationResponse(#[from] crate::flow::callback::CallbackError),

    #[error("invalid authorization request: {0}")]
    InvalidAuthorizationRequest(String),

    #[error("missing PKCE verifier in pending request")]
    MissingPkceVerifier,

    #[error("expected PKCE challenge on pending request")]
    UnexpectedPkce,
}

impl From<crate::transport::kv::KvError> for OidcError {
    fn from(err: crate::transport::kv::KvError) -> Self {
        OidcError::Kv(err)
    }
}
