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
        || name.eq_ignore_ascii_case("set-cookie")
}

fn redacted_headers(headers: &[(String, String)]) -> Vec<(&str, &str)> {
    headers
        .iter()
        .map(|(name, value)| {
            let value = if is_sensitive_header(name) {
                "***"
            } else {
                value.as_str()
            };
            (name.as_str(), value)
        })
        .collect()
}

impl fmt::Debug for HttpRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The token-request body is form-encoded credentials and the
        // Authorization header is a bearer/basic secret; neither is
        // ever printed verbatim.
        f.debug_struct("HttpRequest")
            .field("method", &self.method)
            .field("url", &self.url)
            .field("headers", &redacted_headers(&self.headers))
            .field(
                "body",
                &self.body.as_ref().map(|b| format!("<{} bytes>", b.len())),
            )
            .finish()
    }
}

/// HTTP response with credential-bearing headers and body redacted in `Debug`.
#[derive(Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl fmt::Debug for HttpResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpResponse")
            .field("status", &self.status)
            .field("headers", &redacted_headers(&self.headers))
            .field("body_len", &self.body.len())
            .finish()
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_debug_redacts_body_and_cookie() {
        let response = HttpResponse {
            status: 200,
            headers: vec![
                ("sEt-CoOkIe".into(), "session=secret".into()),
                ("Content-Type".into(), "application/json".into()),
            ],
            body: br#"{"access_token":"secret"}"#.to_vec(),
        };
        let debug = format!("{response:?}");
        assert!(debug.contains("status: 200"));
        assert!(debug.contains("application/json"));
        assert!(debug.contains(&format!("body_len: {}", response.body.len())));
        assert!(!debug.contains("session=secret"));
        assert!(!debug.contains(&format!("{:?}", response.body)));
    }
}
