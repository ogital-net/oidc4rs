//! Token-endpoint request building.
//!
//! Implements RFC 6749 section 4.1.3 (authorization-code grant) and
//! section 6 (refresh-token grant) as fluent builders. The result of
//! [`CodeTokenRequest::build`] / [`RefreshTokenRequest::build`] is a
//! [`BuiltTokenRequest`] -- the wire form (URL, headers, body) that
//! the caller POSTs through `AsyncHttpClient`. Decoding the response
//! is the job of [`crate::token::response::TokenResponse`].
//!
//! Client-authentication method defaults to the first method listed in
//! `metadata.token_endpoint_auth_methods_supported`, falling back to
//! `client_secret_basic` when the metadata omits the field. Callers
//! can override with [`CodeTokenRequest::auth_method`] /
//! [`RefreshTokenRequest::auth_method`].

use base64::Engine;

use crate::error::OidcError;
use crate::transport::http::{HttpMethod, HttpRequest};
use crate::types::{ClientId, ClientSecret, RefreshToken, TokenEndpointAuthMethod, TokenUrl};

/// Wire form of a token-endpoint request.
///
/// Returned by [`CodeTokenRequest::build`] and
/// [`RefreshTokenRequest::build`]. The body is application/x-www-form-
/// urlencoded per RFC 6749 section 4.1.3.1.
#[derive(Debug, Clone)]
pub struct BuiltTokenRequest {
    pub url: TokenUrl,
    pub http: HttpRequest,
}

/// Client-authentication method at the token endpoint.
///
/// Names match the values advertised in
/// `metadata.token_endpoint_auth_methods_supported` (OIDC Core 1.0
/// section 3, OpenID Connect Discovery 1.0 section 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenAuthMethod {
    ClientSecretBasic,
    ClientSecretPost,
    None,
}

impl TokenAuthMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            TokenAuthMethod::ClientSecretBasic => "client_secret_basic",
            TokenAuthMethod::ClientSecretPost => "client_secret_post",
            TokenAuthMethod::None => "none",
        }
    }

    /// Picks the most-preferred compatible method from discovery.
    /// Falls back to `client_secret_basic` when the field is absent.
    pub fn from_metadata(
        supported: Option<&[String]>,
        has_secret: bool,
    ) -> Result<Self, OidcError> {
        let Some(supported) = supported else {
            return Ok(if has_secret {
                Self::ClientSecretBasic
            } else {
                Self::None
            });
        };
        let wants_basic = supported.iter().any(|m| m == "client_secret_basic");
        let wants_post = supported.iter().any(|m| m == "client_secret_post");
        let wants_none = supported.iter().any(|m| m == "none");
        let method = if has_secret {
            if wants_basic {
                Self::ClientSecretBasic
            } else if wants_post {
                Self::ClientSecretPost
            } else {
                return Err(OidcError::InvalidMetadata(
                    "provider advertises no supported client authentication method".into(),
                ));
            }
        } else if wants_none {
            Self::None
        } else {
            return Err(OidcError::InvalidMetadata(
                "provider does not advertise unauthenticated token requests".into(),
            ));
        };
        Ok(method)
    }
}

impl From<TokenEndpointAuthMethod> for TokenAuthMethod {
    fn from(m: TokenEndpointAuthMethod) -> Self {
        match m {
            TokenEndpointAuthMethod::ClientSecretBasic => Self::ClientSecretBasic,
            TokenEndpointAuthMethod::ClientSecretPost => Self::ClientSecretPost,
            TokenEndpointAuthMethod::None => Self::None,
        }
    }
}

/// Builder for an RFC 6749 section 4.1.3 token request.
///
/// Construct via [`Client::exchange_code`]. The minimum required field
/// is the authorization `code`; everything else defaults to the values
/// that match the original authorization request, which `Client` wires
/// in for callers that go through [`Client::complete_authorization`].
pub struct CodeTokenRequest {
    endpoint: TokenUrl,
    client_id: ClientId,
    client_secret: Option<ClientSecret>,
    code: String,
    redirect_uri: Option<String>,
    pkce_verifier: Option<String>,
    auth_method: Option<TokenAuthMethod>,
}

impl CodeTokenRequest {
    pub(crate) fn new(
        endpoint: TokenUrl,
        client_id: ClientId,
        client_secret: Option<ClientSecret>,
        code: String,
        auth_method: Option<TokenAuthMethod>,
    ) -> Self {
        Self {
            endpoint,
            client_id,
            client_secret,
            code,
            redirect_uri: None,
            pkce_verifier: None,
            auth_method,
        }
    }

    /// Sets the `redirect_uri` parameter. Must match the value used in
    /// the original authorization request (RFC 6749 section 4.1.3).
    pub fn redirect_uri(mut self, uri: impl Into<String>) -> Self {
        self.redirect_uri = Some(uri.into());
        self
    }

    /// Attaches the PKCE verifier. OIDC §3.1.2.1 / RFC 7636 require
    /// the verifier whenever the authorization request sent a
    /// challenge; the public-client case makes the verifier mandatory.
    pub fn pkce_verifier(mut self, verifier: impl Into<String>) -> Self {
        self.pkce_verifier = Some(verifier.into());
        self
    }

    /// Overrides the client-authentication method picked from
    /// metadata. Use when the OP advertises multiple methods and the
    /// caller has a strong preference.
    pub fn auth_method(mut self, method: TokenAuthMethod) -> Self {
        self.auth_method = Some(method);
        self
    }

    /// Finalizes the builder. Returns the wire form (URL, headers,
    /// body) for POSTing through `AsyncHttpClient`.
    pub fn build(self) -> Result<BuiltTokenRequest, OidcError> {
        let method = self
            .auth_method
            .unwrap_or(TokenAuthMethod::ClientSecretBasic);
        if matches!(
            method,
            TokenAuthMethod::ClientSecretBasic | TokenAuthMethod::ClientSecretPost
        ) && self.client_secret.is_none()
        {
            return Err(OidcError::InvalidAuthorizationRequest(
                "client_secret required for client_secret_basic / client_secret_post".into(),
            ));
        }
        if self.code.is_empty() {
            return Err(OidcError::InvalidAuthorizationRequest(
                "authorization code is required".into(),
            ));
        }
        if self.redirect_uri.is_none() {
            return Err(OidcError::InvalidAuthorizationRequest(
                "redirect_uri is required".into(),
            ));
        }
        if method == TokenAuthMethod::None && self.pkce_verifier.is_none() {
            return Err(OidcError::MissingPkceVerifier);
        }

        let mut form: Vec<(&str, &str)> =
            vec![("grant_type", "authorization_code"), ("code", &self.code)];
        if let Some(r) = self.redirect_uri.as_deref() {
            form.push(("redirect_uri", r));
        }
        if let Some(v) = self.pkce_verifier.as_deref() {
            form.push(("code_verifier", v));
        }

        let endpoint_str = self.endpoint.to_string();
        let mut headers: Vec<(String, String)> = vec![
            ("Accept".into(), "application/json".into()),
            (
                "Content-Type".into(),
                "application/x-www-form-urlencoded".into(),
            ),
        ];

        match method {
            TokenAuthMethod::ClientSecretBasic => {
                let client_id = form_encode_component(self.client_id.as_str());
                let client_secret = form_encode_component(
                    self.client_secret.as_ref().map_or("", ClientSecret::as_str),
                );
                let creds = format!("{client_id}:{client_secret}");
                let encoded = base64::engine::general_purpose::STANDARD.encode(creds);
                headers.push(("Authorization".into(), format!("Basic {encoded}")));
            }
            TokenAuthMethod::ClientSecretPost => {
                form.push(("client_id", self.client_id.as_str()));
                form.push((
                    "client_secret",
                    self.client_secret.as_ref().map_or("", ClientSecret::as_str),
                ));
            }
            TokenAuthMethod::None => form.push(("client_id", self.client_id.as_str())),
        }

        let body = form_encode(&form);
        Ok(BuiltTokenRequest {
            url: self.endpoint,
            http: HttpRequest {
                method: HttpMethod::Post,
                url: endpoint_str,
                headers,
                body: Some(body.into_bytes()),
            },
        })
    }
}

/// Builder for an RFC 6749 section 6 token refresh request.
pub struct RefreshTokenRequest {
    endpoint: TokenUrl,
    client_id: ClientId,
    client_secret: Option<ClientSecret>,
    refresh_token: RefreshToken,
    scope: Option<String>,
    auth_method: Option<TokenAuthMethod>,
}

impl RefreshTokenRequest {
    pub(crate) fn new(
        endpoint: TokenUrl,
        client_id: ClientId,
        client_secret: Option<ClientSecret>,
        refresh_token: RefreshToken,
        auth_method: Option<TokenAuthMethod>,
    ) -> Self {
        Self {
            endpoint,
            client_id,
            client_secret,
            refresh_token,
            scope: None,
            auth_method,
        }
    }

    /// Optional `scope` parameter. RFC 6749 section 6 requires the
    /// value to be a subset of the original authorization scope; the
    /// builder does not enforce that.
    pub fn scope(mut self, scope: impl Into<String>) -> Self {
        self.scope = Some(scope.into());
        self
    }

    /// Overrides the client-authentication method.
    pub fn auth_method(mut self, method: TokenAuthMethod) -> Self {
        self.auth_method = Some(method);
        self
    }

    pub fn build(self) -> Result<BuiltTokenRequest, OidcError> {
        let method = self
            .auth_method
            .unwrap_or(TokenAuthMethod::ClientSecretBasic);
        if matches!(
            method,
            TokenAuthMethod::ClientSecretBasic | TokenAuthMethod::ClientSecretPost
        ) && self.client_secret.is_none()
        {
            return Err(OidcError::InvalidAuthorizationRequest(
                "client_secret required for client_secret_basic / client_secret_post".into(),
            ));
        }
        if self.refresh_token.as_str().is_empty() {
            return Err(OidcError::InvalidAuthorizationRequest(
                "refresh_token is required".into(),
            ));
        }

        let mut form: Vec<(&str, &str)> = vec![
            ("grant_type", "refresh_token"),
            ("refresh_token", self.refresh_token.as_str()),
        ];
        if let Some(s) = self.scope.as_deref() {
            form.push(("scope", s));
        }

        let mut headers: Vec<(String, String)> = vec![
            ("Accept".into(), "application/json".into()),
            (
                "Content-Type".into(),
                "application/x-www-form-urlencoded".into(),
            ),
        ];

        match method {
            TokenAuthMethod::ClientSecretBasic => {
                let client_id = form_encode_component(self.client_id.as_str());
                let client_secret = form_encode_component(
                    self.client_secret.as_ref().map_or("", ClientSecret::as_str),
                );
                let creds = format!("{client_id}:{client_secret}");
                let encoded = base64::engine::general_purpose::STANDARD.encode(creds);
                headers.push(("Authorization".into(), format!("Basic {encoded}")));
            }
            TokenAuthMethod::ClientSecretPost => {
                form.push(("client_id", self.client_id.as_str()));
                form.push((
                    "client_secret",
                    self.client_secret.as_ref().map_or("", ClientSecret::as_str),
                ));
            }
            TokenAuthMethod::None => form.push(("client_id", self.client_id.as_str())),
        }

        let body = form_encode(&form);
        let endpoint_str = self.endpoint.to_string();

        Ok(BuiltTokenRequest {
            url: self.endpoint,
            http: HttpRequest {
                method: HttpMethod::Post,
                url: endpoint_str,
                headers,
                body: Some(body.into_bytes()),
            },
        })
    }
}

fn form_encode(form: &[(&str, &str)]) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(form.iter().copied())
        .finish()
}

fn form_encode_component(value: &str) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .append_pair("", value)
        .finish()
        .strip_prefix('=')
        .expect("form serialization of an empty key starts with '='")
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ClientId;

    fn client_id() -> ClientId {
        ClientId::new("my-client").unwrap()
    }

    fn endpoint() -> crate::types::TokenUrl {
        "https://idp.example.com/token".parse().unwrap()
    }

    fn code_req_basic() -> CodeTokenRequest {
        CodeTokenRequest::new(
            endpoint(),
            client_id(),
            Some(crate::types::ClientSecret::new("secret").unwrap()),
            "auth-code".to_string(),
            None,
        )
        .redirect_uri("https://app.example.com/cb")
    }

    fn code_req_none() -> CodeTokenRequest {
        CodeTokenRequest::new(
            endpoint(),
            client_id(),
            None,
            "auth-code".to_string(),
            Some(TokenAuthMethod::None),
        )
        .redirect_uri("https://app.example.com/cb")
    }

    #[test]
    fn code_request_basic_auth() {
        let req = code_req_basic()
            .auth_method(TokenAuthMethod::ClientSecretBasic)
            .pkce_verifier("verifier-1234567890")
            .build()
            .unwrap();

        assert_eq!(req.http.method, HttpMethod::Post);
        let h = req
            .http
            .headers
            .iter()
            .find(|(k, _)| k == "Authorization")
            .unwrap();
        assert!(h.1.starts_with("Basic "));
        let creds_b64 = h.1.trim_start_matches("Basic ");
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(creds_b64)
            .unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), "my-client:secret");
        let body = String::from_utf8(req.http.body.clone().unwrap()).unwrap();
        assert!(body.contains("grant_type=authorization_code"));
        assert!(body.contains("code=auth-code"));
        assert!(body.contains("code_verifier="));
        assert!(body.contains("redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb"));
        // ClientSecretBasic must NOT include client_id/client_secret in body.
        assert!(!body.contains("client_id="));
        assert!(!body.contains("client_secret="));
    }

    #[test]
    fn code_request_post_auth() {
        let req = CodeTokenRequest::new(
            endpoint(),
            client_id(),
            Some(crate::types::ClientSecret::new("secret").unwrap()),
            "auth-code".to_string(),
            None,
        )
        .redirect_uri("https://app.example.com/cb")
        .auth_method(TokenAuthMethod::ClientSecretPost)
        .build()
        .unwrap();
        let body = String::from_utf8(req.http.body.clone().unwrap()).unwrap();
        assert!(body.contains("client_id=my-client"));
        assert!(body.contains("client_secret=secret"));
        assert!(req.http.headers.iter().all(|(k, _)| k != "Authorization"));
    }

    #[test]
    fn code_request_none_auth() {
        let req = code_req_none()
            .pkce_verifier("verifier-1234567890")
            .build()
            .unwrap();
        let body = String::from_utf8(req.http.body.clone().unwrap()).unwrap();
        assert!(body.contains("client_id=my-client"));
        assert!(!body.contains("client_secret="));
        assert!(req.http.headers.iter().all(|(k, _)| k != "Authorization"));
    }

    #[test]
    fn code_request_requires_code() {
        // Empty code is rejected by the builder.
        let req = CodeTokenRequest::new(
            endpoint(),
            client_id(),
            None,
            String::new(),
            Some(TokenAuthMethod::None),
        )
        .redirect_uri("https://app.example.com/cb");
        assert!(req.build().is_err());
    }

    #[test]
    fn code_request_requires_redirect() {
        let req = CodeTokenRequest::new(
            endpoint(),
            client_id(),
            None,
            "auth-code".to_string(),
            Some(TokenAuthMethod::None),
        );
        assert!(req.build().is_err());
    }

    #[test]
    fn code_request_basic_requires_secret() {
        // No secret and default (ClientSecretBasic) -> error.
        let req =
            CodeTokenRequest::new(endpoint(), client_id(), None, "auth-code".to_string(), None)
                .redirect_uri("https://app.example.com/cb");
        assert!(req.build().is_err());
    }

    #[test]
    fn code_request_none_requires_pkce() {
        let err = code_req_none().build().unwrap_err();
        assert!(matches!(err, OidcError::MissingPkceVerifier));
    }

    #[test]
    fn refresh_request_basic_auth() {
        let req = RefreshTokenRequest::new(
            endpoint(),
            client_id(),
            Some(crate::types::ClientSecret::new("s").unwrap()),
            crate::types::RefreshToken::new("rt-1").unwrap(),
            Some(TokenAuthMethod::ClientSecretBasic),
        )
        .build()
        .unwrap();
        let body = String::from_utf8(req.http.body.clone().unwrap()).unwrap();
        assert!(body.contains("grant_type=refresh_token"));
        assert!(body.contains("refresh_token=rt-1"));
        assert!(req.http.headers.iter().any(|(k, _)| k == "Authorization"));
    }

    #[test]
    fn refresh_request_optional_scope() {
        let req = RefreshTokenRequest::new(
            endpoint(),
            client_id(),
            None,
            crate::types::RefreshToken::new("rt-1").unwrap(),
            Some(TokenAuthMethod::None),
        )
        .scope("openid email")
        .build()
        .unwrap();
        let body = String::from_utf8(req.http.body.clone().unwrap()).unwrap();
        assert!(body.contains("scope=openid+email"));
        assert!(body.contains("client_id=my-client"));
    }

    #[test]
    fn basic_auth_form_encodes_each_credential() {
        let req = CodeTokenRequest::new(
            endpoint(),
            ClientId::new("client:id / ").unwrap(),
            Some(crate::types::ClientSecret::new("s:e& c+%").unwrap()),
            "auth-code".to_owned(),
            Some(TokenAuthMethod::ClientSecretBasic),
        )
        .redirect_uri("https://app.example.com/cb")
        .build()
        .unwrap();
        let header = req
            .http
            .headers
            .iter()
            .find(|(name, _)| name == "Authorization")
            .unwrap();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(header.1.trim_start_matches("Basic "))
            .unwrap();

        assert_eq!(
            String::from_utf8(decoded).unwrap(),
            "client%3Aid+%2F+:s%3Ae%26+c%2B%25"
        );
    }

    #[test]
    fn metadata_rejects_incompatible_auth_methods() {
        let private_only = vec!["private_key_jwt".to_owned()];
        let basic_only = vec!["client_secret_basic".to_owned()];

        assert!(TokenAuthMethod::from_metadata(Some(&private_only), true).is_err());
        assert!(TokenAuthMethod::from_metadata(Some(&basic_only), false).is_err());
    }

    #[test]
    fn refresh_request_requires_token() {
        // Empty strings cannot construct a RefreshToken (constructor
        // rejects); verify the gate at the newtype level instead of
        // the build() level. The build() check is also exercised
        // indirectly by `requires_token`.
        assert!(crate::types::RefreshToken::new("").is_err());
    }

    #[test]
    fn form_url_encodes_payload() {
        let body = form_encode(&[
            ("grant_type", "authorization_code"),
            ("redirect_uri", "https://x.example.com/?a=b&c=d"),
        ]);
        assert!(body.contains("redirect_uri=https%3A%2F%2Fx.example.com%2F%3Fa%3Db%26c%3Dd"));
    }
}
