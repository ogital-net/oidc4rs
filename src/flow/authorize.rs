//! Authorization-code flow: URL construction and state generation.
//!
//! Constructs an OIDC authorization request URL per OIDC Core 1.0
//! section 3.1.2 and RFC 6749 section 4.1.1. The builder pattern lets
//! callers add optional parameters (PKCE, prompt, max_age, acr_values,
//! login_hint, ui_locales, id_token_hint, response_mode, custom
//! params) without combinatorial method signatures.
//!
//! The companion [`AuthRequestState`] carries the URL plus the
//! `state`, `nonce`, and (optional) PKCE verifier that the relying
//! party must persist across the authorization redirect. See
//! [`AuthRequestState::to_pending`] for the serializable form stored
//! in the second-leg KV.

use std::fmt;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use url::Url;

use crate::client::Client;
use crate::error::OidcError;
use crate::types::{
    AuthPrompt, Nonce, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, ResponseMode, Scope, State,
};

/// Snapshot of the values a relying party must persist across the
/// authorization redirect.
///
/// `state`, `nonce`, and `pkce_verifier` are all cryptographically
/// random; `state` doubles as the lookup key for `to_pending`.
#[derive(Debug, Clone)]
pub struct AuthRequestState {
    pub state: State,
    pub nonce: Nonce,
    pub pkce_verifier: Option<PkceCodeVerifier>,
    pub max_age: Option<Duration>,
    pub redirect_uri: RedirectUrl,
    pub scopes: Scope,
    pub authorization_url: Url,
}

impl AuthRequestState {
    /// Storage key for the second-leg KV. Format is opaque to callers
    /// but stable so test fixtures and external observers can match it.
    pub fn storage_key(&self) -> String {
        format!("oidc4rs:pending:{}", self.state.as_str())
    }

    /// Serializes the state for storage. The caller is responsible for
    /// inserting the result into the `AsyncKvStore` under
    /// [`storage_key`](Self::storage_key) before redirecting the user.
    pub fn to_pending(&self) -> PendingAuthRequest {
        PendingAuthRequest {
            state: self.state.as_str().to_owned(),
            nonce: self.nonce.as_str().to_owned(),
            pkce_verifier: self.pkce_verifier.as_ref().map(|v| v.as_str().to_owned()),
            max_age: self.max_age,
            redirect_uri: Some(self.redirect_uri.as_str().to_owned()),
            scopes: self.scopes.iter().map(str::to_owned).collect(),
            created_at: std::time::SystemTime::now(),
        }
    }
}

/// Serializable form of [`AuthRequestState`] for the second-leg KV.
///
/// Stored under [`Self::key_for`]; the same `state` value the OP
/// echoes back on the callback is the lookup key.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct PendingAuthRequest {
    pub state: String,
    pub nonce: String,
    pub pkce_verifier: Option<String>,
    #[serde(default)]
    pub max_age: Option<Duration>,
    pub redirect_uri: Option<String>,
    pub scopes: Vec<String>,
    pub created_at: std::time::SystemTime,
}

impl fmt::Debug for PendingAuthRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingAuthRequest")
            .field("state", &self.state)
            .field("nonce", &"***")
            .field("pkce_verifier", &self.pkce_verifier.as_ref().map(|_| "***"))
            .field("max_age", &self.max_age)
            .field("redirect_uri", &self.redirect_uri)
            .field("scopes", &self.scopes)
            .field("created_at", &self.created_at)
            .finish()
    }
}

impl PendingAuthRequest {
    pub const DEFAULT_TTL: Duration = Duration::from_secs(10 * 60);

    pub fn key_for(state: &str) -> String {
        format!("oidc4rs:pending:{state}")
    }

    pub(crate) fn validate_created_at(&self, now: SystemTime) -> Result<(), OidcError> {
        let age = now
            .duration_since(self.created_at)
            .map_err(|_| OidcError::PendingAuthorizationFromFuture)?;
        if age > Self::DEFAULT_TTL {
            return Err(OidcError::PendingAuthorizationExpired);
        }
        Ok(())
    }
}

/// Builder for an OIDC authorization request URL.
///
/// Constructed via [`Client::authorize`]. Every standard OIDC
/// authorization request parameter is reachable through a typed
/// method; non-standard parameters use [`extra_param`](Self::extra_param).
pub struct AuthorizeUrlBuilder {
    client: Arc<Client>,
    url: Url,
    state: State,
    nonce: Nonce,
    pkce_verifier: Option<PkceCodeVerifier>,
    pkce_challenge: Option<PkceCodeChallenge>,
    response_mode: Option<ResponseMode>,
    prompt: Option<AuthPrompt>,
    max_age: Option<Duration>,
    id_token_hint: Option<String>,
    extra: Vec<(String, String)>,
    redirect_uri: RedirectUrl,
    scopes: Scope,
}

impl AuthorizeUrlBuilder {
    /// Constructs a builder pre-populated with the required parameters
    /// (`response_type`, `client_id`, `redirect_uri`, `scope`).
    /// `state` and `nonce` are randomized and applied in [`build`].
    ///
    /// `scope` must include `openid` per OIDC Core 1.0 section 3.1.2.
    pub(crate) fn new(
        client: Arc<Client>,
        redirect_uri: RedirectUrl,
        scope: Scope,
    ) -> Result<Self, OidcError> {
        if !scope.iter().any(|s| s == "openid") {
            return Err(OidcError::InvalidAuthorizationRequest(
                "scope must include `openid` per OIDC Core 1.0 section 3.1.2".into(),
            ));
        }

        let mut url = client.metadata().authorization_endpoint.as_url().clone();
        {
            let mut q = url.query_pairs_mut();
            q.append_pair("response_type", "code");
            q.append_pair("client_id", client.client_id().as_str());
            q.append_pair("redirect_uri", redirect_uri.as_str());
            q.append_pair("scope", scope.as_str());
        }

        let (pkce_verifier, pkce_challenge) = if client.client_secret.is_none() {
            let verifier = PkceCodeVerifier::new_random();
            let challenge = PkceCodeChallenge::s256_from_verifier(&verifier);
            (Some(verifier), Some(challenge))
        } else {
            (None, None)
        };

        Ok(Self {
            client,
            url,
            state: State::new_random(),
            nonce: Nonce::new_random(),
            pkce_verifier,
            pkce_challenge,
            response_mode: None,
            prompt: None,
            max_age: None,
            id_token_hint: None,
            extra: Vec::new(),
            redirect_uri,
            scopes: scope,
        })
    }

    /// Sets `state` to a caller-supplied value instead of a fresh
    /// random one. Test-only escape hatch; production code should
    /// rely on the default random generation.
    #[cfg(test)]
    pub fn state_for_testing(mut self, state: State) -> Self {
        self.state = state;
        self
    }

    /// Adds PKCE using the S256 method. Public clients use S256 by
    /// default; calling this method replaces the generated verifier.
    pub fn pkce_s256(mut self) -> Self {
        let verifier = PkceCodeVerifier::new_random();
        let challenge = PkceCodeChallenge::s256_from_verifier(&verifier);
        self.pkce_verifier = Some(verifier);
        self.pkce_challenge = Some(challenge);
        self
    }

    /// Sets the `prompt` parameter. The OIDC Core 1.0 specification
    /// forbids combining `none` with other values; the builder does
    /// not enforce this -- callers that need that guarantee must do
    /// their own validation or skip `prompt` entirely.
    pub fn prompt(mut self, prompt: AuthPrompt) -> Self {
        self.prompt = Some(prompt);
        self
    }

    /// Sets the `max_age` parameter (seconds since the user's last
    /// authentication). `Duration::ZERO` is valid and means "force
    /// re-authentication".
    pub fn max_age(mut self, max_age: Duration) -> Self {
        self.max_age = Some(max_age);
        self
    }

    /// Sets the `acr_values` parameter (space-separated Authentication
    /// Context Class References).
    pub fn acr_values(mut self, acr_values: impl Into<String>) -> Self {
        self.extra.push(("acr_values".into(), acr_values.into()));
        self
    }

    /// Sets the `login_hint` parameter.
    pub fn login_hint(mut self, login_hint: impl Into<String>) -> Self {
        self.extra.push(("login_hint".into(), login_hint.into()));
        self
    }

    /// Sets the `ui_locales` parameter (space-separated BCP47 tags).
    pub fn ui_locales(mut self, ui_locales: impl Into<String>) -> Self {
        self.extra.push(("ui_locales".into(), ui_locales.into()));
        self
    }

    /// Sets the `id_token_hint` parameter (a previously-issued ID
    /// token, used for re-authentication).
    pub fn id_token_hint(mut self, id_token_hint: impl Into<String>) -> Self {
        self.id_token_hint = Some(id_token_hint.into());
        self
    }

    /// Sets the `response_mode` parameter. OIDC auto-detects `query`
    /// for `response_type=code`; explicit override is needed only for
    /// `form_post` or to force `fragment`.
    pub fn response_mode(mut self, response_mode: ResponseMode) -> Self {
        self.response_mode = Some(response_mode);
        self
    }

    /// Adds an arbitrary custom parameter. Use for OP-specific
    /// extensions. The key is sent verbatim; the value is encoded as
    /// a single form value (no internal newlines).
    pub fn extra_param(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.extra.push((key.into(), value.into()));
        self
    }

    /// Returns the relying party's [`Client`] handle so callers can
    /// chain follow-up operations after the callback.
    #[allow(dead_code)]
    pub(crate) fn client(&self) -> &Client {
        &self.client
    }

    /// Finishes building and returns the persisted state plus the
    /// authorization URL to redirect the user to.
    pub fn build(self) -> AuthRequestState {
        let mut url = self.url;

        {
            let mut q = url.query_pairs_mut();
            q.append_pair("state", self.state.as_str());
            q.append_pair("nonce", self.nonce.as_str());

            if let Some(challenge) = &self.pkce_challenge {
                q.append_pair("code_challenge", challenge.as_str());
                q.append_pair("code_challenge_method", "S256");
            }
            if let Some(mode) = self.response_mode {
                q.append_pair("response_mode", mode.as_str());
            }
            if let Some(prompt) = self.prompt {
                q.append_pair("prompt", prompt.as_str());
            }
            if let Some(max_age) = self.max_age {
                // `as_secs` returns u64; OIDC's `max_age` is an
                // unconstrained JSON Number per RFC 8259. Callers
                // that need to bound it must clamp upstream.
                q.append_pair("max_age", &max_age.as_secs().to_string());
            }
            if let Some(hint) = &self.id_token_hint {
                q.append_pair("id_token_hint", hint);
            }
            for (k, v) in &self.extra {
                q.append_pair(k, v);
            }
        }

        AuthRequestState {
            state: self.state,
            nonce: self.nonce,
            pkce_verifier: self.pkce_verifier,
            max_age: self.max_age,
            redirect_uri: self.redirect_uri,
            scopes: self.scopes,
            authorization_url: url,
        }
    }
}

impl Client {
    /// Begins an authorization-code flow and returns a builder for the
    /// request URL. `redirect_uri` and `scope` are required; `scope`
    /// must contain `openid`.
    ///
    /// ```ignore
    /// let state = client
    ///     .authorize(redirect_uri, scope)?
    ///     .pkce_s256()
    ///     .prompt(AuthPrompt::Login)
    ///     .build();
    /// kv.put(&state.storage_key(), &state.to_pending()).await?;
    /// redirect_to(state.authorization_url);
    /// ```
    pub fn authorize(
        self: &Arc<Self>,
        redirect_uri: RedirectUrl,
        scope: Scope,
    ) -> Result<AuthorizeUrlBuilder, OidcError> {
        AuthorizeUrlBuilder::new(Arc::clone(self), redirect_uri, scope)
    }

    /// Computes a PKCE S256 challenge from a verifier. Convenience
    /// wrapper around [`PkceCodeChallenge::s256_from_verifier`] for
    /// callers that already generated the verifier externally.
    #[allow(dead_code)]
    pub fn pkce_s256(&self, verifier: &PkceCodeVerifier) -> PkceCodeChallenge {
        PkceCodeChallenge::s256_from_verifier(verifier)
    }
}

#[cfg(test)]
mod tests {
    //! Tests construct a `Client` via `from_parts` with a hand-built
    //! `ProviderMetadata` and a no-op HTTP client. They exercise the
    //! builder's required-parameter injection and the optional
    //! parameter coverage listed in SPEC §8.7.
    //!
    //! Verification of the wire format (OIDC compliance) is done at
    //! the URL level via `Url::query_pairs`, which is the same
    //! representation the OP receives.

    use std::str::FromStr;
    use std::sync::Arc;

    use super::*;
    use crate::metadata::ProviderMetadata;
    use crate::transport::http::{AsyncHttpClient, HttpRequest, HttpResponse};
    use crate::types::{
        AuthUrl, ClientId, ClientSecret, EndSessionUrl, IssuerUrl, JwksUrl, TokenUrl, UserInfoUrl,
    };

    /// No-op HTTP client. Never executed in these tests because
    /// `Client::authorize` is purely synchronous.
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
            subject_types_supported: vec!["public".into()],
            id_token_signing_alg_values_supported: vec!["RS256".into()],
            grant_types_supported: None,
            token_endpoint_auth_methods_supported: None,
            authorization_response_iss_parameter_supported: false,
            userinfo_signing_alg_values_supported: None,
            extra: serde_json::Map::new(),
        }
    }

    fn test_client() -> Arc<Client> {
        let http: Arc<dyn AsyncHttpClient> = Arc::new(NoopHttp);
        let secret: Option<ClientSecret> = None;
        // from_parts returns Self, not Arc<Self>; wrap it.
        Arc::new(
            Client::from_parts(
                test_metadata(),
                ClientId::new("test-client").unwrap(),
                secret,
                http,
            )
            .unwrap(),
        )
    }

    fn test_redirect_uri() -> RedirectUrl {
        // RedirectUrl allows custom schemes (native apps), so an http
        // loopback is the test-friendly choice.
        RedirectUrl::from_str("http://localhost:8080/callback").unwrap()
    }

    fn test_scope() -> Scope {
        Scope::new("openid email profile")
    }

    #[test]
    fn builder_injects_required_params() {
        let client = test_client();
        let state = client
            .authorize(test_redirect_uri(), test_scope())
            .unwrap()
            .build();

        let pairs: std::collections::HashMap<_, _> =
            state.authorization_url.query_pairs().into_owned().collect();

        assert_eq!(pairs.get("response_type"), Some(&"code".to_owned()));
        assert_eq!(pairs.get("client_id"), Some(&"test-client".to_owned()));
        assert_eq!(
            pairs.get("redirect_uri"),
            Some(&"http://localhost:8080/callback".to_owned())
        );
        assert_eq!(pairs.get("scope"), Some(&"openid email profile".to_owned()));
        assert!(pairs.contains_key("state"));
        assert!(pairs.contains_key("nonce"));
        assert_eq!(
            state.nonce.as_str().len(),
            43,
            "nonce should be ~256 bits b64url"
        );
        assert_eq!(
            state.state.as_str().len(),
            43,
            "state should be ~256 bits b64url"
        );
    }

    #[test]
    fn builder_rejects_scope_without_openid() {
        let client = test_client();
        let scope = Scope::new("email profile");
        let err = client
            .authorize(test_redirect_uri(), scope)
            .err()
            .expect("must reject scope without openid");
        assert!(matches!(err, OidcError::InvalidAuthorizationRequest(_)));
    }

    #[test]
    fn pkce_s256_adds_challenge_pair() {
        let client = test_client();
        let state = client
            .authorize(test_redirect_uri(), test_scope())
            .unwrap()
            .pkce_s256()
            .build();

        let pairs: std::collections::HashMap<_, _> =
            state.authorization_url.query_pairs().into_owned().collect();

        assert_eq!(pairs.get("code_challenge_method"), Some(&"S256".to_owned()));
        assert!(pairs.contains_key("code_challenge"));
        let verifier = state.pkce_verifier.as_ref().expect("verifier stored");
        // RFC 7636: 43..128 chars url-safe base64.
        let len = verifier.as_str().len();
        assert!(
            (43..=128).contains(&len),
            "verifier length {len} out of RFC 7636 range"
        );
    }

    #[test]
    fn public_client_uses_pkce_by_default() {
        let state = test_client()
            .authorize(test_redirect_uri(), test_scope())
            .unwrap()
            .build();
        let pairs: std::collections::HashMap<_, _> =
            state.authorization_url.query_pairs().into_owned().collect();

        assert_eq!(pairs.get("code_challenge_method"), Some(&"S256".to_owned()));
        assert!(pairs.contains_key("code_challenge"));
        assert!(state.pkce_verifier.is_some());
    }

    #[test]
    fn pkce_challenge_matches_verifier() {
        let client = test_client();
        let state = client
            .authorize(test_redirect_uri(), test_scope())
            .unwrap()
            .pkce_s256()
            .build();

        let verifier = state.pkce_verifier.as_ref().unwrap();
        let derived = PkceCodeChallenge::s256_from_verifier(verifier);
        let pairs: std::collections::HashMap<_, _> =
            state.authorization_url.query_pairs().into_owned().collect();
        let url_challenge = pairs.get("code_challenge").unwrap();
        assert_eq!(url_challenge, &derived.as_str());
    }

    #[test]
    fn prompt_and_max_age_added() {
        let client = test_client();
        let state = client
            .authorize(test_redirect_uri(), test_scope())
            .unwrap()
            .prompt(AuthPrompt::Login)
            .max_age(Duration::from_secs(300))
            .build();

        let pairs: std::collections::HashMap<_, _> =
            state.authorization_url.query_pairs().into_owned().collect();
        assert_eq!(pairs.get("prompt"), Some(&"login".to_owned()));
        assert_eq!(pairs.get("max_age"), Some(&"300".to_owned()));
        assert_eq!(state.max_age, Some(Duration::from_secs(300)));
        assert_eq!(state.to_pending().max_age, state.max_age);
    }

    #[test]
    fn max_age_zero_is_valid() {
        let client = test_client();
        let state = client
            .authorize(test_redirect_uri(), test_scope())
            .unwrap()
            .max_age(Duration::ZERO)
            .build();
        let pairs: std::collections::HashMap<_, _> =
            state.authorization_url.query_pairs().into_owned().collect();
        assert_eq!(pairs.get("max_age"), Some(&"0".to_owned()));
        assert_eq!(state.max_age, Some(Duration::ZERO));
    }

    #[test]
    fn optional_typed_params_added() {
        let client = test_client();
        let state = client
            .authorize(test_redirect_uri(), test_scope())
            .unwrap()
            .acr_values("urn:mace:incommon:iap:silver")
            .login_hint("alice@example.com")
            .ui_locales("fr-CA fr-FR")
            .id_token_hint("eyJhbGciOiJIUzI1NiJ9.payload.sig")
            .response_mode(ResponseMode::FormPost)
            .build();

        let pairs: std::collections::HashMap<_, _> =
            state.authorization_url.query_pairs().into_owned().collect();
        assert_eq!(
            pairs.get("acr_values"),
            Some(&"urn:mace:incommon:iap:silver".to_owned())
        );
        assert_eq!(
            pairs.get("login_hint"),
            Some(&"alice@example.com".to_owned())
        );
        assert_eq!(pairs.get("ui_locales"), Some(&"fr-CA fr-FR".to_owned()));
        assert_eq!(
            pairs.get("id_token_hint"),
            Some(&"eyJhbGciOiJIUzI1NiJ9.payload.sig".to_owned())
        );
        assert_eq!(pairs.get("response_mode"), Some(&"form_post".to_owned()));
    }

    #[test]
    fn extra_param_passes_through() {
        let client = test_client();
        let state = client
            .authorize(test_redirect_uri(), test_scope())
            .unwrap()
            .extra_param("prompt", "consent")
            .extra_param("custom", "value")
            .build();

        let pairs: std::collections::HashMap<_, _> =
            state.authorization_url.query_pairs().into_owned().collect();
        // `prompt` added via extra_param should be present (last write wins
        // because the typed `.prompt()` method runs first; `extra_param`
        // runs after).
        assert_eq!(pairs.get("prompt"), Some(&"consent".to_owned()));
        assert_eq!(pairs.get("custom"), Some(&"value".to_owned()));
    }

    #[test]
    fn to_pending_round_trips_via_json() {
        let client = test_client();
        let state = client
            .authorize(test_redirect_uri(), test_scope())
            .unwrap()
            .pkce_s256()
            .build();

        let pending = state.to_pending();
        assert_eq!(pending.state, state.state.as_str());
        assert_eq!(pending.nonce, state.nonce.as_str());
        assert_eq!(
            pending.pkce_verifier.as_deref(),
            Some(state.pkce_verifier.as_ref().unwrap().as_str())
        );
        assert_eq!(
            pending.redirect_uri.as_deref(),
            Some("http://localhost:8080/callback")
        );
        assert_eq!(pending.scopes, vec!["openid", "email", "profile"]);

        // JSON round-trip (this is what gets persisted in the KV).
        let json = serde_json::to_string(&pending).unwrap();
        let restored: PendingAuthRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.state, pending.state);
        assert_eq!(restored.nonce, pending.nonce);
        assert_eq!(restored.pkce_verifier, pending.pkce_verifier);
        assert_eq!(restored.redirect_uri, pending.redirect_uri);
        assert_eq!(restored.scopes, pending.scopes);

        // The storage key format must be stable.
        assert_eq!(
            PendingAuthRequest::key_for(&pending.state),
            state.storage_key()
        );
    }

    #[test]
    fn pending_default_ttl_is_ten_minutes() {
        assert_eq!(PendingAuthRequest::DEFAULT_TTL, Duration::from_secs(600));
    }

    #[test]
    fn state_for_testing_overrides_random() {
        let client = test_client();
        let fixed = State::new_random();
        let state = client
            .authorize(test_redirect_uri(), test_scope())
            .unwrap()
            .state_for_testing(fixed.clone())
            .build();
        assert_eq!(state.state.as_str(), fixed.as_str());

        let pairs: std::collections::HashMap<_, _> =
            state.authorization_url.query_pairs().into_owned().collect();
        assert_eq!(pairs.get("state"), Some(&fixed.as_str().to_owned()));
    }

    #[test]
    fn nonce_is_distinct_per_call() {
        let client = test_client();
        let s1 = client
            .authorize(test_redirect_uri(), test_scope())
            .unwrap()
            .build();
        let s2 = client
            .authorize(test_redirect_uri(), test_scope())
            .unwrap()
            .build();
        assert_ne!(s1.state.as_str(), s2.state.as_str());
        assert_ne!(s1.nonce.as_str(), s2.nonce.as_str());
    }
}
