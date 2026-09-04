//! Optional hyper-based `AsyncHttpClient` implementation.
//!
//! Gated behind the `hyper` feature. Unlike the rest of the crate this
//! module depends on a tokio runtime: `hyper-util`'s connection pool
//! and TCP/TLS connector are built on tokio, and no maintained
//! runtime-agnostic alternative exists. See AGENTS.md's Async section
//! for the rationale.

use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::header::{HeaderName, HeaderValue};
use hyper::{Method, Request, Uri};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client as LegacyClient;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioTimer};

use crate::error::OidcError;
use crate::transport::http::{AsyncHttpClient, BoxFuture, HttpMethod, HttpRequest, HttpResponse};

type Connector = hyper_rustls::HttpsConnector<HttpConnector>;

/// `AsyncHttpClient` backed by hyper, hyper-util's legacy client, and
/// hyper-rustls for TLS. Requires the caller to run a tokio runtime.
///
/// Does not follow HTTP redirects: hyper-util's legacy client sends
/// exactly one request per call and returns the response verbatim, so
/// a `3xx` from an OP is surfaced to the caller as `HttpResponse`
/// rather than silently re-requested against the `Location` target.
/// This is intentional -- discovery, token, and userinfo requests
/// must not be redirected to an origin the caller did not ask for.
///
/// Idle connections are pooled and kept alive for 90 seconds (the
/// `hyper-util` default) and proactively reaped by a `TokioTimer`
/// background task; a `HyperHttpClient` that only ever talks to one
/// host does not leak that connection past the idle timeout.
pub struct HyperHttpClient {
    inner: LegacyClient<Connector, Full<Bytes>>,
}

impl HyperHttpClient {
    /// Builds a client using the platform's native root certificates
    /// and HTTP/1.1. Fails if no native roots could be loaded.
    pub fn new() -> Result<Self, OidcError> {
        let https = HttpsConnectorBuilder::new()
            .with_native_roots()
            .map_err(|err| OidcError::Http(format!("failed to load native roots: {err}")))?
            .https_or_http()
            .enable_http1()
            .build();

        let inner = LegacyClient::builder(TokioExecutor::new())
            .pool_timer(TokioTimer::new())
            .build(https);

        Ok(Self { inner })
    }
}

impl AsyncHttpClient for HyperHttpClient {
    fn execute(&self, req: HttpRequest) -> BoxFuture<'_, Result<HttpResponse, OidcError>> {
        Box::pin(async move {
            let request = build_request(req)?;
            let response = self
                .inner
                .request(request)
                .await
                .map_err(|err| OidcError::Http(err.to_string()))?;

            let status = response.status().as_u16();
            let headers = response
                .headers()
                .iter()
                .map(|(name, value)| {
                    (
                        name.as_str().to_owned(),
                        value.to_str().unwrap_or_default().to_owned(),
                    )
                })
                .collect();
            let body = response
                .into_body()
                .collect()
                .await
                .map_err(|err| OidcError::Http(err.to_string()))?
                .to_bytes()
                .to_vec();

            Ok(HttpResponse {
                status,
                headers,
                body,
            })
        })
    }
}

/// Converts the runtime-agnostic `HttpRequest` into a hyper `Request`.
/// Header names/values are validated here since `HttpRequest` stores
/// them as plain strings.
fn build_request(req: HttpRequest) -> Result<Request<Full<Bytes>>, OidcError> {
    let method = match req.method {
        HttpMethod::Get => Method::GET,
        HttpMethod::Post => Method::POST,
    };
    let uri: Uri = req
        .url
        .parse()
        .map_err(|err| OidcError::Http(format!("invalid request URL: {err}")))?;

    let mut builder = Request::builder().method(method).uri(uri);
    for (name, value) in &req.headers {
        let header_name = HeaderName::try_from(name.as_str())
            .map_err(|err| OidcError::Http(format!("invalid header name {name:?}: {err}")))?;
        let header_value = HeaderValue::try_from(value.as_str())
            .map_err(|err| OidcError::Http(format!("invalid header value for {name:?}: {err}")))?;
        builder = builder.header(header_name, header_value);
    }

    let body = Full::new(Bytes::from(req.body.unwrap_or_default()));
    builder
        .body(body)
        .map_err(|err| OidcError::Http(format!("failed to build request: {err}")))
}

/// Convenience constructor matching the `Arc<dyn AsyncHttpClient>` shape
/// `Client::discover` and `Client::from_parts` expect.
pub fn new_shared() -> Result<Arc<dyn AsyncHttpClient>, OidcError> {
    Ok(Arc::new(HyperHttpClient::new()?))
}
