//! OpenID Provider metadata and discovery.

pub mod provider;

pub use provider::ProviderMetadata;

use crate::error::OidcError;
use crate::transport::http::{AsyncHttpClient, HttpMethod, HttpRequest};
use crate::types::IssuerUrl;

/// Fetches and validates the OP's discovery metadata.
pub async fn discover<C>(issuer: IssuerUrl, http: &C) -> Result<ProviderMetadata, OidcError>
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

    Ok(metadata)
}
