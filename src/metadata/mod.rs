//! OpenID Provider metadata and discovery.

use std::time::Duration;

/// HTTP response cache policy for discovery metadata.
mod cache;
pub mod provider;

pub(crate) use cache::CachePolicy;
pub use provider::ProviderMetadata;

use crate::error::OidcError;
use crate::transport::http::{AsyncHttpClient, HttpMethod, HttpRequest};
use crate::types::IssuerUrl;

/// Discovery metadata paired with its HTTP response cache policy.
pub(crate) struct DiscoveredMetadata {
    pub(crate) metadata: ProviderMetadata,
    response_headers: Vec<(String, String)>,
}

impl DiscoveredMetadata {
    /// Derives cache policy using the caller's current duration settings.
    pub(crate) fn cache_policy(
        &self,
        default_lifetime: Duration,
        minimum_cache_duration: Duration,
    ) -> CachePolicy {
        let policy = cache::policy_from_headers(&self.response_headers, default_lifetime);
        cache::apply_minimum_cache_duration(policy, minimum_cache_duration)
    }
}

/// Fetches and validates the OP's discovery metadata.
pub async fn discover<C>(issuer: IssuerUrl, http: &C) -> Result<ProviderMetadata, OidcError>
where
    C: AsyncHttpClient + ?Sized,
{
    Ok(discover_with_cache(issuer, http).await?.metadata)
}

/// Fetches discovery metadata and retains its response cache headers.
pub(crate) async fn discover_with_cache<C>(
    issuer: IssuerUrl,
    http: &C,
) -> Result<DiscoveredMetadata, OidcError>
where
    C: AsyncHttpClient + ?Sized,
{
    // Build the discovery URL: issuer + "/.well-known/openid-configuration".
    let mut discovery_url = issuer.as_url().clone();
    {
        let mut segments = discovery_url
            .path_segments_mut()
            .map_err(|()| OidcError::Discovery("issuer URL cannot be a base".into()))?;
        // Trim trailing empty segments so the resulting path is canonical.
        segments.pop_if_empty();
        segments.push(".well-known");
        segments.push("openid-configuration");
    }

    let req = HttpRequest {
        method: HttpMethod::Get,
        url: discovery_url.to_string(),
        headers: vec![("Accept".into(), "application/json".into())],
        body: None,
    };
    let resp = http
        .execute(req)
        .await
        .map_err(|e| OidcError::Discovery(format!("{e}")))?;
    if resp.status != 200 {
        return Err(OidcError::Discovery(format!(
            "metadata HTTP {} from {}",
            resp.status, discovery_url
        )));
    }

    let metadata: ProviderMetadata = serde_json::from_slice(&resp.body)
        .map_err(|e| OidcError::InvalidMetadata(e.to_string()))?;
    metadata.validate()?;

    if metadata.issuer != issuer {
        return Err(OidcError::InvalidMetadata(format!(
            "issuer mismatch: expected {}, got {}",
            issuer, metadata.issuer
        )));
    }

    Ok(DiscoveredMetadata {
        metadata,
        response_headers: resp.headers,
    })
}
