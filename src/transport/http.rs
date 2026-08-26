//! HTTP transport trait used by `oidc4rs`.
//!
//! `oidc4rs` does not pin a runtime or HTTP client. Callers implement
//! `AsyncHttpClient` against their preferred stack (reqwest, hyper,
//! ureq, curl). See `examples/reqwest_adapter.rs` for a reference
//! implementation.

use std::future::Future;
use std::pin::Pin;

use crate::error::OidcError;

/// Runtime-agnostic boxed future. Mirrors `jose4rs::jwk::FetchFuture`.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Post,
}

#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: HttpMethod,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Sends an HTTP request and returns the response.
///
/// Implementations are expected to surface transport-level failures
/// (DNS, TCP, TLS, timeout) as `Err(OidcError::Http(_))`. HTTP status
/// codes are part of the success path -- callers inspect
/// `HttpResponse.status` to detect 4xx / 5xx.
pub trait AsyncHttpClient: Send + Sync {
    fn execute(&self, req: HttpRequest) -> BoxFuture<'_, Result<HttpResponse, OidcError>>;
}
