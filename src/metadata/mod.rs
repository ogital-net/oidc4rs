//! OpenID Provider metadata and discovery.

pub mod provider;

pub use provider::ProviderMetadata;

use jose4rs::jwk::JsonWebKeySet;

use crate::error::OidcError;
use crate::transport::http::{AsyncHttpClient, HttpMethod, HttpRequest};
use crate::types::IssuerUrl;

/// Performs OIDC discovery: fetches `/.well-known/openid-configuration`
/// and the OP JWKS, validates the issuer, and returns both.
pub async fn discover<C>(
    issuer: IssuerUrl,
    http: &C,
) -> Result<(ProviderMetadata, JsonWebKeySet), OidcError>
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

    if metadata.issuer != issuer {
        return Err(OidcError::InvalidMetadata(format!(
            "issuer mismatch: expected {}, got {}",
            issuer, metadata.issuer
        )));
    }

    let jwks_req = HttpRequest {
        method: HttpMethod::Get,
        url: metadata.jwks_uri.as_str().to_owned(),
        headers: vec![("Accept".into(), "application/json".into())],
        body: None,
    };
    let jwks_resp = http
        .execute(jwks_req)
        .await
        .map_err(|e| OidcError::Discovery(format!("jwks: {e}")))?;
    if jwks_resp.status != 200 {
        return Err(OidcError::Discovery(format!(
            "jwks HTTP {} from {}",
            jwks_resp.status, metadata.jwks_uri
        )));
    }
    let keys = JsonWebKeySet::from_json(&jwks_resp.body)?;

    Ok((metadata, keys))
}
