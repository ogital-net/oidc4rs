//! `ProviderMetadata` -- the deserialized OIDC discovery document.

use serde::{Deserialize, Serialize};

use crate::types::{AuthUrl, EndSessionUrl, IssuerUrl, JwksUrl, Scope, TokenUrl, UserInfoUrl};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderMetadata {
    pub issuer: IssuerUrl,

    pub authorization_endpoint: AuthUrl,

    pub token_endpoint: TokenUrl,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub userinfo_endpoint: Option<UserInfoUrl>,

    pub jwks_uri: JwksUrl,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_session_endpoint: Option<EndSessionUrl>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registration_endpoint: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scopes_supported: Option<Vec<Scope>>,

    #[serde(default = "default_response_types")]
    pub response_types_supported: Vec<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_types_supported: Option<Vec<String>>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id_token_signing_alg_values_supported: Option<Vec<String>>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_types_supported: Option<Vec<String>>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,

    /// JWS `alg` values the OP supports for signing UserInfo responses
    /// (OIDC Core 1.0 section 5.3.2). When the OP advertises this list
    /// callers MAY opt into signed userinfo by sending
    /// `Accept: application/jwt`; the response `Content-Type` is the
    /// operational signal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub userinfo_signing_alg_values_supported: Option<Vec<String>>,

    /// Captures any unknown fields so callers can extend without losing
    /// information on a round-trip.
    #[serde(default, flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

fn default_response_types() -> Vec<String> {
    vec!["code".to_owned()]
}
