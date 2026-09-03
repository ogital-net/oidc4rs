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

    pub response_types_supported: Vec<String>,

    pub subject_types_supported: Vec<String>,

    pub id_token_signing_alg_values_supported: Vec<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_types_supported: Option<Vec<String>>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,

    #[serde(default)]
    pub authorization_response_iss_parameter_supported: bool,

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

impl ProviderMetadata {
    /// Validates required discovery capability lists.
    pub fn validate(&self) -> Result<(), crate::error::OidcError> {
        if self.response_types_supported.is_empty() {
            return Err(crate::error::OidcError::InvalidMetadata(
                "response_types_supported must not be empty".into(),
            ));
        }
        if self.subject_types_supported.is_empty() {
            return Err(crate::error::OidcError::InvalidMetadata(
                "subject_types_supported must not be empty".into(),
            ));
        }
        if !self
            .id_token_signing_alg_values_supported
            .iter()
            .any(|algorithm| algorithm == "RS256")
        {
            return Err(crate::error::OidcError::InvalidMetadata(
                "id_token_signing_alg_values_supported must include RS256".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn valid_metadata() -> serde_json::Value {
        json!({
            "issuer": "https://idp.example.com",
            "authorization_endpoint": "https://idp.example.com/authorize",
            "token_endpoint": "https://idp.example.com/token",
            "jwks_uri": "https://idp.example.com/jwks",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"]
        })
    }

    #[test]
    fn required_capability_fields_must_be_present() {
        for field in [
            "response_types_supported",
            "subject_types_supported",
            "id_token_signing_alg_values_supported",
        ] {
            let mut value = valid_metadata();
            value.as_object_mut().unwrap().remove(field);
            assert!(serde_json::from_value::<ProviderMetadata>(value).is_err());
        }
    }

    #[test]
    fn validation_rejects_empty_or_nonconforming_capabilities() {
        let mut empty_response_types: ProviderMetadata =
            serde_json::from_value(valid_metadata()).unwrap();
        empty_response_types.response_types_supported.clear();
        assert!(empty_response_types.validate().is_err());

        let mut empty_subject_types: ProviderMetadata =
            serde_json::from_value(valid_metadata()).unwrap();
        empty_subject_types.subject_types_supported.clear();
        assert!(empty_subject_types.validate().is_err());

        let mut missing_rs256: ProviderMetadata = serde_json::from_value(valid_metadata()).unwrap();
        missing_rs256.id_token_signing_alg_values_supported = vec!["ES256".into()];
        assert!(missing_rs256.validate().is_err());
    }
}
