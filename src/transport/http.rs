//! HTTP transport trait used by `oidc4rs`.
//!
//! `oidc4rs` does not pin a runtime or HTTP client. Callers implement
//! `AsyncHttpClient` against their preferred stack (reqwest, hyper,
//! ureq, curl). See `examples/reqwest_adapter.rs` for a reference
//! implementation.

use std::fmt;
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

#[derive(Clone)]
pub struct HttpRequest {
    pub method: HttpMethod,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
}

/// Headers whose values carry credentials and must be masked in
/// `Debug` output.
fn is_sensitive_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("authorization")
        || name.eq_ignore_ascii_case("proxy-authorization")
        || name.eq_ignore_ascii_case("cookie")
}

impl fmt::Debug for HttpRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The token-request body is form-encoded credentials and the
        // Authorization header is a bearer/basic secret; neither is
        // ever printed verbatim.
        let headers: Vec<(&str, &str)> = self
            .headers
            .iter()
            .map(|(k, v)| {
                (
                    k.as_str(),
                    if is_sensitive_header(k) {
                        "***"
                    } else {
                        v.as_str()
                    },
                )
            })
            .collect();
        f.debug_struct("HttpRequest")
            .field("method", &self.method)
            .field("url", &self.url)
            .field("headers", &headers)
            .field(
                "body",
                &self.body.as_ref().map(|b| format!("<{} bytes>", b.len())),
            )
            .finish()
    }
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
