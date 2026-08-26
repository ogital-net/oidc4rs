//! RP-initiated logout URL construction.
//!
//! Implements the OIDC RP-Initiated Logout 1.0 spec
//! (<https://openid.net/specs/openid-connect-rpinitiated-1_0.html>).
//! The relying party redirects the end-user's browser to the OP's
//! `end_session_endpoint` with one or more of the standard parameters:
//!
//! - `id_token_hint` (REQUIRED for most OPs to identify the session
//!   to be logged out; RECOMMENDED in the spec)
//! - `post_logout_redirect_uri` (where to send the user after
//!   logout; must be pre-registered with the OP)
//! - `state` (opaque value echoed back to the RP; recommended when
//!   `post_logout_redirect_uri` is used)
//! - `client_id` (the OP's cross-check on the hint; some providers
//!   require it explicitly)
//! - `logout_hint` (OP-specific identity hint, often a username or
//!   email; not standardized)
//! - `ui_locales` (preferred languages for the OP's confirmation
//!   UI; RFC 5646 BCP47 tags, space-separated per OIDC Core 2.0)
//!
//! Reached via [`Client::build_end_session_url`](crate::client::Client::build_end_session_url).

use crate::client::Client;
use crate::error::OidcError;
use crate::types::{ClientId, EndSessionUrl, LogoutHint, PostLogoutRedirectUrl, State};

/// Builder for the OIDC RP-initiated logout request URL.
///
/// Constructed via
/// [`Client::build_end_session_url`](crate::client::Client::build_end_session_url).
/// Every field is optional; the only one callers will typically set
/// in practice is `id_token_hint`.
pub struct EndSessionUrlBuilder<'c> {
    client: &'c Client,
    id_token_hint: Option<String>,
    post_logout_redirect_uri: Option<PostLogoutRedirectUrl>,
    state: Option<State>,
    client_id: Option<ClientId>,
    logout_hint: Option<LogoutHint>,
    ui_locales: Vec<String>,
}

impl<'c> EndSessionUrlBuilder<'c> {
    pub fn new(client: &'c Client) -> Self {
        Self {
            client,
            id_token_hint: None,
            post_logout_redirect_uri: None,
            state: None,
            client_id: None,
            logout_hint: None,
            ui_locales: Vec::new(),
        }
    }

    /// Sets the `id_token_hint` parameter. The OP uses this to identify
    /// the session to log out; almost every OP requires it.
    pub fn id_token_hint(mut self, hint: impl Into<String>) -> Self {
        self.id_token_hint = Some(hint.into());
        self
    }

    /// Sets the `post_logout_redirect_uri` parameter. Must be a URI
    /// pre-registered with the OP.
    pub fn post_logout_redirect_uri(mut self, uri: PostLogoutRedirectUrl) -> Self {
        self.post_logout_redirect_uri = Some(uri);
        self
    }

    /// Sets the `state` parameter. An opaque value the OP echoes back
    /// to the RP; lets the RP correlate the post-logout redirect with
    /// the originating user session.
    ///
    /// When the caller does not supply a value, the builder
    /// auto-generates a fresh random one whenever
    /// `post_logout_redirect_uri` is set -- the two together are
    /// what makes the post-logout redirect safe to consume.
    pub fn state(mut self, s: State) -> Self {
        self.state = Some(s);
        self
    }

    /// Sets the `client_id` parameter. The OP may verify it matches
    /// the `aud` of the hinted ID token.
    pub fn client_id(mut self, id: ClientId) -> Self {
        self.client_id = Some(id);
        self
    }

    /// Sets the `logout_hint` parameter. OP-specific; not required by
    /// the spec.
    pub fn logout_hint(mut self, hint: LogoutHint) -> Self {
        self.logout_hint = Some(hint);
        self
    }

    /// Adds a `ui_locales` entry. May be called multiple times; the
    /// values are joined with a single space per OIDC Core 2.0.
    /// Order matters -- OPs honor the left-most tag they support.
    pub fn add_ui_locale(mut self, locale: impl Into<String>) -> Self {
        self.ui_locales.push(locale.into());
        self
    }

    /// Finishes building and returns the end-session URL plus the
    /// `state` value the OP will echo back.
    ///
    /// If the caller set `post_logout_redirect_uri` but not `state`,
    /// a random `state` is generated so the post-logout redirect is
    /// CSRF-defended by default.
    pub fn build(self) -> Result<(EndSessionUrl, Option<State>), OidcError> {
        let endpoint = self
            .client
            .metadata()
            .end_session_endpoint
            .clone()
            .ok_or_else(|| {
                OidcError::InvalidMetadata("end_session_endpoint not advertised".into())
            })?;

        // Auto-generate `state` when post_logout_redirect_uri is set
        // and the caller did not supply one. See the doc comment on
        // `state` for why the two are coupled.
        let state = match (self.state, self.post_logout_redirect_uri.as_ref()) {
            (Some(s), _) => Some(s),
            (None, Some(_)) => Some(State::new_random()),
            (None, None) => None,
        };

        let mut url = endpoint.into_inner();
        // `url::form_urlencoded` always emits a trailing `?` even
        // when no pairs are appended. We strip it so the empty
        // builder case produces a clean URL with no query string.
        {
            let mut q = url.query_pairs_mut();
            if let Some(hint) = &self.id_token_hint {
                q.append_pair("id_token_hint", hint);
            }
            if let Some(redirect) = &self.post_logout_redirect_uri {
                q.append_pair("post_logout_redirect_uri", redirect.as_str());
            }
            if let Some(s) = &state {
                q.append_pair("state", s.as_str());
            }
            if let Some(id) = &self.client_id {
                q.append_pair("client_id", id.as_str());
            }
            if let Some(hint) = &self.logout_hint {
                q.append_pair("logout_hint", hint.as_str());
            }
            if !self.ui_locales.is_empty() {
                q.append_pair("ui_locales", &self.ui_locales.join(" "));
            }
        }
        if url.query() == Some("") {
            url.set_query(None);
        }

        let parsed: EndSessionUrl = url
            .as_str()
            .parse()
            .map_err(|e: OidcError| OidcError::InvalidMetadata(format!("end_session URL: {e}")))?;
        Ok((parsed, state))
    }
}

#[cfg(test)]
mod tests {
    //! Verifies the parameter wiring of [`EndSessionUrlBuilder`] by
    //! parsing the produced URL back into its components. The builder
    //! itself does not hit the network.

    use std::collections::HashMap;
    use std::str::FromStr;
    use std::sync::Arc;

    use super::*;
    use crate::metadata::ProviderMetadata;
    use crate::transport::http::{AsyncHttpClient, HttpRequest, HttpResponse};
    use crate::types::{AuthUrl, ClientId, IssuerUrl, JwksUrl, TokenUrl, UserInfoUrl};

    struct NoopHttp;

    impl AsyncHttpClient for NoopHttp {
        fn execute(
            &self,
            _req: HttpRequest,
        ) -> crate::transport::http::BoxFuture<'_, Result<HttpResponse, OidcError>> {
            Box::pin(async {
                Ok(HttpResponse {
                    status: 200,
                    headers: vec![],
                    body: vec![],
                })
            })
        }
    }

    fn test_metadata() -> ProviderMetadata {
        ProviderMetadata {
            issuer: IssuerUrl::from_str("https://op.example.com").unwrap(),
            authorization_endpoint: AuthUrl::from_str("https://op.example.com/authorize").unwrap(),
            token_endpoint: TokenUrl::from_str("https://op.example.com/token").unwrap(),
            userinfo_endpoint: Some(
                UserInfoUrl::from_str("https://op.example.com/userinfo").unwrap(),
            ),
            jwks_uri: JwksUrl::from_str("https://op.example.com/jwks").unwrap(),
            end_session_endpoint: Some(
                EndSessionUrl::from_str("https://op.example.com/logout").unwrap(),
            ),
            registration_endpoint: None,
            scopes_supported: None,
            response_types_supported: vec!["code".into()],
            subject_types_supported: None,
            id_token_signing_alg_values_supported: None,
            grant_types_supported: None,
            token_endpoint_auth_methods_supported: None,
            userinfo_signing_alg_values_supported: None,
            extra: serde_json::Map::new(),
        }
    }

    fn test_client() -> Arc<Client> {
        let http: Arc<dyn AsyncHttpClient> = Arc::new(NoopHttp);
        Arc::new(
            Client::from_parts(
                test_metadata(),
                ClientId::new("test-client").unwrap(),
                None,
                http,
            )
            .unwrap(),
        )
    }

    /// Parses the query string out of a URL for easier assertions.
    fn query_pairs(url: &url::Url) -> HashMap<String, String> {
        url.query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect()
    }

    #[test]
    fn empty_builder_produces_endpoint_with_no_query() {
        let client = test_client();
        let (url, state) = EndSessionUrlBuilder::new(&client).build().unwrap();
        assert_eq!(url.as_str(), "https://op.example.com/logout");
        assert!(state.is_none());
    }

    #[test]
    fn id_token_hint_only() {
        let client = test_client();
        let (url, state) = EndSessionUrlBuilder::new(&client)
            .id_token_hint("eyJhbGciOiJSUzI1NiJ9.payload.sig")
            .build()
            .unwrap();
        let q = query_pairs(url.as_url());
        assert_eq!(
            q.get("id_token_hint").map(String::as_str),
            Some("eyJhbGciOiJSUzI1NiJ9.payload.sig")
        );
        assert!(!q.contains_key("post_logout_redirect_uri"));
        assert!(!q.contains_key("state"));
        assert!(!q.contains_key("client_id"));
        assert!(!q.contains_key("logout_hint"));
        assert!(!q.contains_key("ui_locales"));
        assert!(state.is_none());
    }

    #[test]
    fn post_logout_redirect_uri_auto_generates_state() {
        let client = test_client();
        let redirect = PostLogoutRedirectUrl::from_str("https://rp.example.com/goodbye").unwrap();
        let (url, state) = EndSessionUrlBuilder::new(&client)
            .post_logout_redirect_uri(redirect.clone())
            .build()
            .unwrap();
        let q = query_pairs(url.as_url());
        assert_eq!(
            q.get("post_logout_redirect_uri").map(String::as_str),
            Some(redirect.as_str())
        );
        let s = q.get("state").expect("state must be auto-generated");
        // Random 32 bytes -> 43 url-safe base64 chars (no padding).
        assert_eq!(s.len(), 43);
        assert!(state.is_some(), "state must round-trip back to the caller");
    }

    #[test]
    fn explicit_state_overrides_auto_generation() {
        let client = test_client();
        let redirect = PostLogoutRedirectUrl::from_str("https://rp.example.com/goodbye").unwrap();
        let explicit = State::new_random();
        let expected = explicit.as_str().to_owned();
        let (_url, state) = EndSessionUrlBuilder::new(&client)
            .post_logout_redirect_uri(redirect)
            .state(explicit)
            .build()
            .unwrap();
        assert_eq!(state.as_ref().map(State::as_str), Some(expected.as_str()));
    }

    #[test]
    fn client_id_logout_hint_and_ui_locales() {
        let client = test_client();
        let (url, _) = EndSessionUrlBuilder::new(&client)
            .client_id(ClientId::new("rp-1").unwrap())
            .logout_hint(LogoutHint::new("alice@example.com").unwrap())
            .add_ui_locale("en-US")
            .add_ui_locale("fr-FR")
            .build()
            .unwrap();
        let q = query_pairs(url.as_url());
        assert_eq!(q.get("client_id").map(String::as_str), Some("rp-1"));
        assert_eq!(
            q.get("logout_hint").map(String::as_str),
            Some("alice@example.com")
        );
        // OIDC Core 2.0 specifies space separation for ui_locales;
        // url::form_urlencoded encodes a literal space as + on the
        // wire, and `query_pairs` decodes it back to a space.
        assert_eq!(q.get("ui_locales").map(String::as_str), Some("en-US fr-FR"));
    }

    #[test]
    fn missing_endpoint_is_an_error() {
        let mut metadata = test_metadata();
        metadata.end_session_endpoint = None;
        let http: Arc<dyn AsyncHttpClient> = Arc::new(NoopHttp);
        let client = Arc::new(
            Client::from_parts(metadata, ClientId::new("test-client").unwrap(), None, http)
                .unwrap(),
        );
        let err = EndSessionUrlBuilder::new(&client).build().unwrap_err();
        assert!(matches!(err, OidcError::InvalidMetadata(_)));
    }

    #[test]
    fn all_parameters_together() {
        let client = test_client();
        let redirect = PostLogoutRedirectUrl::from_str("https://rp.example.com/goodbye").unwrap();
        let (url, state) = EndSessionUrlBuilder::new(&client)
            .id_token_hint("id-token")
            .post_logout_redirect_uri(redirect.clone())
            .client_id(ClientId::new("rp-1").unwrap())
            .logout_hint(LogoutHint::new("alice").unwrap())
            .add_ui_locale("en")
            .build()
            .unwrap();
        let q = query_pairs(url.as_url());
        assert_eq!(q.get("id_token_hint").map(String::as_str), Some("id-token"));
        assert_eq!(
            q.get("post_logout_redirect_uri").map(String::as_str),
            Some(redirect.as_str())
        );
        assert_eq!(q.get("client_id").map(String::as_str), Some("rp-1"));
        assert_eq!(q.get("logout_hint").map(String::as_str), Some("alice"));
        assert_eq!(q.get("ui_locales").map(String::as_str), Some("en"));
        assert!(q.contains_key("state"));
        assert!(state.is_some());
    }

    #[test]
    fn client_method_returns_same_builder() {
        let client = test_client();
        let (url, _state) = client
            .build_end_session_url()
            .id_token_hint("id-token")
            .build()
            .unwrap();
        assert_eq!(
            query_pairs(url.as_url())
                .get("id_token_hint")
                .map(String::as_str),
            Some("id-token")
        );
    }
}
