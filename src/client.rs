//! `Client` -- the high-level entry point for an OIDC relying party.

use std::sync::Arc;

use jose4rs::jwk::{AsyncHttpsJwks, AsyncJwksFetcher, FetchResponse};

use crate::error::OidcError;
use crate::flow::authorize::PendingAuthRequest;
use crate::flow::callback::parse_authorization_response;
use crate::flow::token::{BuiltTokenRequest, CodeTokenRequest, RefreshTokenRequest};
use crate::metadata::ProviderMetadata;
use crate::token::response::{IdToken, TokenResponse};
use crate::transport::http::{AsyncHttpClient, HttpMethod, HttpRequest};
use crate::transport::kv::AsyncKvStore;
use crate::types::{AccessToken, ClientId, ClientSecret, RefreshToken};

/// OIDC relying-party client.
#[allow(clippy::struct_field_names)] // `Client.client_id` / `Client.client_secret` are the standard names.
pub struct Client {
    pub(crate) metadata: ProviderMetadata,
    pub(crate) client_id: ClientId,
    pub(crate) client_secret: Option<ClientSecret>,
    pub(crate) jwks: AsyncHttpsJwks,
    pub(crate) http: Arc<dyn AsyncHttpClient>,
}

impl Client {
    /// Performs discovery from `issuer` and returns a fully wired
    /// `Client`. Wires the JWKS cache through a `reqwest`-style
    /// `AsyncJwksFetcher` backed by the supplied HTTP client.
    pub async fn discover<C>(
        issuer: crate::types::IssuerUrl,
        client_id: ClientId,
        client_secret: Option<ClientSecret>,
        http: Arc<C>,
    ) -> Result<Self, OidcError>
    where
        C: AsyncHttpClient + 'static,
    {
        let (metadata, _keys) = crate::metadata::discover(issuer, http.as_ref()).await?;
        let fetcher: Arc<dyn AsyncJwksFetcher> = Arc::new(HttpJwksFetcher { http: http.clone() });
        let jwks = AsyncHttpsJwks::new(metadata.jwks_uri.as_url().as_str(), fetcher);

        Ok(Self {
            metadata,
            client_id,
            client_secret,
            jwks,
            http,
        })
    }

    /// Manual construction for tests or for callers that load metadata
    /// via a non-HTTP path. The caller is responsible for ensuring the
    /// JWKS endpoint is reachable; the cache will populate on first use.
    pub fn from_parts(
        metadata: ProviderMetadata,
        client_id: ClientId,
        client_secret: Option<ClientSecret>,
        http: Arc<dyn AsyncHttpClient>,
    ) -> Result<Self, OidcError> {
        metadata.validate()?;
        let fetcher: Arc<dyn AsyncJwksFetcher> = Arc::new(HttpJwksFetcher { http: http.clone() });
        let jwks = AsyncHttpsJwks::new(metadata.jwks_uri.as_url().as_str(), fetcher);

        Ok(Self {
            metadata,
            client_id,
            client_secret,
            jwks,
            http,
        })
    }

    pub fn metadata(&self) -> &ProviderMetadata {
        &self.metadata
    }

    pub fn client_id(&self) -> &ClientId {
        &self.client_id
    }

    /// Borrows the JWKS cache used to verify this OP's ID tokens.
    ///
    /// The cache is shared across all ID-token / userinfo / token
    /// verifications performed by this `Client`; callers performing
    /// bearer-access-token verification (or any other JWS check)
    /// against the same OP should pass this same cache to
    /// `jose4rs::jwk::AsyncHttpsJwks::select_verification_key` so
    /// key fetches, `kid` lookups, and `Cache-Control` honoring are
    /// amortized across the process.
    ///
    /// Returning `&AsyncHttpsJwks` (not the inner `JsonWebKeySet`)
    /// keeps the cache hot: passing the borrowed handle to the next
    /// verify call still hits jose4rs's internal `Arc` and avoids a
    /// second HTTP fetch when the JWKS is already cached.
    pub fn jwks(&self) -> &AsyncHttpsJwks {
        &self.jwks
    }

    /// Completes the OIDC authorization-code flow.
    ///
    /// Inputs:
    /// - `callback_query`: the query (or fragment) string from the
    ///   OP redirect, e.g. `"code=...&state=..."`. Leading `?` / `#`
    ///   are not stripped automatically; pass the part after.
    /// - `kv`: the shared store backing the second leg (Redis, etc.).
    ///
    /// Behavior:
    /// 1. Parses the callback.
    /// 2. Atomically consumes the pending request by `state`.
    /// 3. Verifies the `state` matches (CSRF defense).
    /// 4. Rejects stale or future-dated pending requests.
    /// 5. POSTs the token request, including PKCE verifier if any.
    /// 6. Returns the parsed [`TokenResponse`] plus the pending request
    ///    snapshot for downstream logic (e.g. nonce verification).
    ///
    /// The ID-token verification step is *not* performed here. Callers
    /// must run [`crate::token::verify::IdTokenVerifier::verify`] on
    /// `token_response.id_token()` before trusting any claim. Use
    /// [`CompleteAuthorization::verify_id_token`] as a convenience.
    pub async fn complete_authorization(
        &self,
        callback_query: &str,
        kv: &dyn AsyncKvStore,
    ) -> Result<CompleteAuthorization, OidcError> {
        let response = parse_authorization_response(callback_query)?;
        let expected_issuer = self.metadata.issuer.as_str();
        match response.iss.as_deref() {
            Some(actual) if actual != expected_issuer => {
                return Err(crate::flow::callback::CallbackError::IssuerMismatch {
                    expected: expected_issuer.to_owned(),
                    actual: actual.to_owned(),
                }
                .into());
            }
            None if self.metadata.authorization_response_iss_parameter_supported => {
                return Err(crate::flow::callback::CallbackError::Missing("iss").into());
            }
            Some(_) | None => {}
        }
        let key = PendingAuthRequest::key_for(&response.state);

        let raw = kv
            .take(&key)
            .await?
            .ok_or(OidcError::AuthorizationResponse(
                crate::flow::callback::CallbackError::Missing("state"),
            ))?;
        let pending: PendingAuthRequest = serde_json::from_slice(&raw)?;

        if pending.state != response.state {
            return Err(OidcError::AuthorizationResponse(
                crate::flow::callback::CallbackError::Parse(
                    "state mismatch between callback and pending entry".into(),
                ),
            ));
        }
        pending.validate_created_at(std::time::SystemTime::now())?;

        let mut builder: CodeTokenRequest = self.exchange_code(response.code.clone())?;
        if let Some(uri) = pending.redirect_uri.as_deref() {
            builder = builder.redirect_uri(uri);
        }
        if let Some(verifier) = pending.pkce_verifier.as_deref() {
            builder = builder.pkce_verifier(verifier);
        }
        let built = builder.build()?;
        let token_response = post_token_request(&*self.http, &built).await?;

        Ok(CompleteAuthorization {
            token_response,
            pending,
            callback_state: response.state,
        })
    }

    /// Begins an authorization-code token exchange. `code` is the
    /// short-lived authorization code from the OP callback.
    pub fn exchange_code(&self, code: String) -> Result<CodeTokenRequest, OidcError> {
        let supported = self
            .metadata()
            .token_endpoint_auth_methods_supported
            .as_deref();
        let method = crate::flow::token::TokenAuthMethod::from_metadata(
            supported,
            self.client_secret.is_some(),
        )?;
        Ok(CodeTokenRequest::new(
            self.metadata().token_endpoint.clone(),
            self.client_id().clone(),
            self.client_secret.clone(),
            code,
            Some(method),
        ))
    }

    /// Fetches the OIDC userinfo claims for `access_token`.
    ///
    /// Sends a GET to the OP userinfo endpoint with
    /// `Authorization: Bearer <token>` and
    /// `Accept: application/json, application/jwt;q=0.9`. The
    /// response format is selected by the OP's `Content-Type`
    /// header:
    ///
    /// - `application/json` -- claims parsed directly into
    ///   [`UserInfo`].
    /// - `application/jwt` -- a signed JWT. Signature, issuer,
    ///   audience, and the provider's UserInfo algorithm policy are
    ///   enforced.
    ///
    /// OIDC Core 1.0 section 5.4. The endpoint URL comes from
    /// `metadata.userinfo_endpoint`; returns an error if the OP
    /// did not advertise one.
    pub async fn fetch_userinfo(
        &self,
        access_token: &AccessToken,
        expected_subject: &str,
    ) -> Result<crate::token::userinfo::UserInfo, OidcError> {
        let endpoint = self.metadata().userinfo_endpoint.as_ref().ok_or_else(|| {
            OidcError::InvalidMetadata("provider metadata missing userinfo_endpoint".into())
        })?;
        let req = HttpRequest {
            method: HttpMethod::Get,
            url: endpoint.as_url().to_string(),
            headers: vec![
                (
                    "Accept".into(),
                    "application/json, application/jwt;q=0.9".into(),
                ),
                (
                    "Authorization".into(),
                    format!("Bearer {}", access_token.as_str()),
                ),
            ],
            body: None,
        };
        let resp = self.http.execute(req).await?;
        if resp.status != 200 {
            return Err(parse_userinfo_error(&resp));
        }
        let content_type = resp
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
            .map_or("application/json", |(_, v)| v.as_str());
        let userinfo = if content_type_essence_is(content_type, "application/jwt") {
            let compact = std::str::from_utf8(&resp.body).map_err(|_| {
                OidcError::InvalidAuthorizationRequest(
                    "userinfo JWT body is not valid UTF-8".into(),
                )
            })?;
            let verifier = crate::token::userinfo::UserInfoVerifier::from_metadata(
                &self.metadata,
                self.client_id.as_str(),
            );
            crate::token::userinfo::UserInfo::from_signed_jwt(compact, &verifier, &self.jwks)
                .await?
        } else if content_type_essence_is(content_type, "application/json") {
            crate::token::userinfo::UserInfo::from_json(&resp.body)?
        } else {
            return Err(OidcError::InvalidAuthorizationRequest(format!(
                "unexpected userinfo Content-Type: {content_type:?}"
            )));
        };
        userinfo.verify_subject(expected_subject)?;
        Ok(userinfo)
    }

    /// Begins a refresh-token grant. See [`RefreshTokenRequest`] for
    /// customization (scope, auth method).
    pub fn exchange_refresh_token(
        &self,
        refresh_token: RefreshToken,
    ) -> Result<RefreshTokenRequest, OidcError> {
        let supported = self
            .metadata()
            .token_endpoint_auth_methods_supported
            .as_deref();
        let method = crate::flow::token::TokenAuthMethod::from_metadata(
            supported,
            self.client_secret.is_some(),
        )?;
        Ok(RefreshTokenRequest::new(
            self.metadata().token_endpoint.clone(),
            self.client_id().clone(),
            self.client_secret.clone(),
            refresh_token,
            Some(method),
        ))
    }

    /// Builds an [`IdTokenVerifier`](crate::token::verify::IdTokenVerifier)
    /// pre-wired for this relying party:
    /// - `expected_issuer` is taken from the discovery document.
    /// - `expected_audience` is `self.client_id().as_str()`.
    /// - The `allowed_algs` list is narrowed to whatever the OP
    ///   advertised in `id_token_signing_alg_values_supported`, so
    ///   the verifier cannot be tricked into accepting a `none` or
    ///   weaker algorithm the OP has stopped using.
    ///
    /// Callers can further narrow or widen the list with
    /// `IdTokenVerifier::allow_alg` /
    /// `IdTokenVerifier::with_allowed_algs` before passing the
    /// verifier to `verify` / `verify_id_token`.
    pub fn verifier(&self) -> crate::token::verify::IdTokenVerifier {
        crate::token::verify::IdTokenVerifier::from_metadata(
            self.metadata(),
            self.client_id().as_str(),
        )
    }

    /// Begins building an RP-initiated logout URL (OIDC RP-Initiated
    /// Logout 1.0). The returned
    /// [`EndSessionUrlBuilder`](crate::flow::logout::EndSessionUrlBuilder)
    /// accepts the standard parameters (`id_token_hint`,
    /// `post_logout_redirect_uri`, `state`, `client_id`,
    /// `logout_hint`, `ui_locales`).
    ///
    /// `build()` returns the URL plus the `state` value the OP will
    /// echo back (or `None` if neither `state` nor
    /// `post_logout_redirect_uri` were set). Errors if the OP did not
    /// advertise an `end_session_endpoint` in its discovery
    /// document.
    pub fn build_end_session_url(&self) -> crate::flow::logout::EndSessionUrlBuilder<'_> {
        crate::flow::logout::EndSessionUrlBuilder::new(self)
    }
}

/// Result of [`Client::complete_authorization`].
#[derive(Debug, Clone)]
pub struct CompleteAuthorization {
    pub token_response: TokenResponse,
    pub pending: PendingAuthRequest,
    pub callback_state: String,
}

impl CompleteAuthorization {
    /// Parses the `id_token` field of `token_response` into a typed
    /// [`IdToken`] with header + claims. Does not verify the
    /// signature; callers must run an [`IdTokenVerifier`](crate::token::verify::IdTokenVerifier)
    /// before trusting claims.
    pub fn parse_id_token(&self) -> Result<Option<IdToken>, OidcError> {
        let Some(raw) = self.token_response.id_token.as_deref() else {
            return Ok(None);
        };
        let id_token = IdToken::parse(raw)?;
        Ok(Some(id_token))
    }

    /// Convenience: parse + verify the id_token in one call. Wires
    /// the access token (for `at_hash`) and the second-leg nonce from
    /// the pending request.
    ///
    /// `client_id` and `jwks` are taken from the calling `Client` via
    /// the [`crate::token::verify::IdTokenVerifier`].
    pub async fn verify_id_token(
        &self,
        verifier: &crate::token::verify::IdTokenVerifier,
        client_id: &str,
        jwks: &jose4rs::jwk::AsyncHttpsJwks,
    ) -> Result<jose4rs::jwt::JwtClaims, OidcError> {
        let id_token = self.parse_id_token()?.ok_or_else(|| {
            OidcError::InvalidAuthorizationRequest("no id_token in token_response".into())
        })?;
        let ctx = crate::token::verify::VerifyContext {
            expected_nonce: Some(self.pending.nonce.clone()),
            access_token: Some(self.token_response.access_token.as_str().to_owned()),
            client_id: Some(client_id.to_owned()),
            clock_skew: None,
            expected_max_age: self.pending.max_age,
        };
        verifier.verify(&id_token, jwks, &ctx).await
    }
}

/// POSTs a built token request and parses the JSON response.
pub(crate) async fn post_token_request(
    http: &dyn AsyncHttpClient,
    built: &BuiltTokenRequest,
) -> Result<TokenResponse, OidcError> {
    let req = HttpRequest {
        method: HttpMethod::Post,
        url: built.http.url.clone(),
        headers: built.http.headers.clone(),
        body: built.http.body.clone(),
    };
    let resp = http.execute(req).await?;
    if resp.status != 200 {
        return Err(parse_token_error(&resp));
    }
    serde_json::from_slice(&resp.body).map_err(OidcError::from)
}

fn parse_token_error(resp: &crate::transport::http::HttpResponse) -> OidcError {
    #[derive(serde::Deserialize)]
    struct ErrBody {
        error: String,
        #[serde(default)]
        error_description: Option<String>,
    }
    match serde_json::from_slice::<ErrBody>(&resp.body) {
        Ok(body) => OidcError::TokenEndpoint {
            status: resp.status,
            error: body.error,
            error_description: body.error_description,
        },
        Err(_) => OidcError::TokenEndpoint {
            status: resp.status,
            error: "invalid_response".into(),
            error_description: None,
        },
    }
}

fn parse_userinfo_error(resp: &crate::transport::http::HttpResponse) -> OidcError {
    #[derive(serde::Deserialize)]
    struct ErrBody {
        error: Option<String>,
        #[serde(default)]
        error_description: Option<String>,
    }
    match serde_json::from_slice::<ErrBody>(&resp.body) {
        Ok(body) => OidcError::UserInfo {
            status: resp.status,
            error: body.error.unwrap_or_else(|| "userinfo_error".into()),
            error_description: body.error_description,
        },
        Err(_) => OidcError::UserInfo {
            status: resp.status,
            error: "invalid_response".into(),
            error_description: None,
        },
    }
}

/// Returns true when the MIME essence (the type/subtype, ignoring
/// parameters) of `content_type` matches `essence`. Case-insensitive
/// on the type and subtype; whitespace around `;` is tolerated.
fn content_type_essence_is(content_type: &str, essence: &str) -> bool {
    let (head, _params) = match content_type.split_once(';') {
        Some((h, p)) => (h, p),
        None => (content_type, ""),
    };
    head.trim().eq_ignore_ascii_case(essence)
}

struct HttpJwksFetcher {
    http: Arc<dyn AsyncHttpClient>,
}

impl AsyncJwksFetcher for HttpJwksFetcher {
    fn fetch<'a>(&'a self, url: &'a str) -> jose4rs::jwk::FetchFuture<'a> {
        Box::pin(async move {
            let req = HttpRequest {
                method: HttpMethod::Get,
                url: url.to_owned(),
                headers: vec![("Accept".into(), "application/json".into())],
                body: None,
            };
            let resp = self.http.execute(req).await.map_err(|e| {
                jose4rs::error::JoseError::JwksFetch(format!("jwks fetch failed: {e}"))
            })?;
            if resp.status != 200 {
                return Err(jose4rs::error::JoseError::JwksFetch(format!(
                    "jwks fetch status {}",
                    resp.status
                )));
            }
            let cache_control = resp
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("cache-control"))
                .map(|(_, v)| v.clone());
            let expires = resp
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("expires"))
                .map(|(_, v)| v.clone());
            Ok(FetchResponse {
                body: resp.body,
                cache_control,
                expires,
            })
        })
    }
}

// AsyncHttpsJwks does not currently expose a public seed method. The
// discover path intentionally re-fetches the JWKS on first validation.
// Pre-seeding from the discovery response is tracked under SPEC §8.5.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::authorize::PendingAuthRequest;
    use crate::metadata::ProviderMetadata;
    use crate::transport::http::{BoxFuture as HttpBoxFuture, HttpMethod, HttpResponse};
    use crate::transport::kv::{AsyncKvStore, BoxFuture as KvBoxFuture, KvError};
    use std::collections::HashMap;
    use std::sync::Mutex;

    struct MockHttp {
        responses: Mutex<Vec<HttpResponse>>,
        last_request: Mutex<Option<HttpRequest>>,
    }

    impl MockHttp {
        fn new(responses: Vec<HttpResponse>) -> Self {
            Self {
                responses: Mutex::new(responses),
                last_request: Mutex::new(None),
            }
        }
    }

    impl AsyncHttpClient for MockHttp {
        fn execute(&self, req: HttpRequest) -> HttpBoxFuture<'_, Result<HttpResponse, OidcError>> {
            let mut responses = self.responses.lock().unwrap();
            let resp = responses.remove(0);
            *self.last_request.lock().unwrap() = Some(req);
            Box::pin(async move { Ok(resp) })
        }
    }

    struct MockKv {
        data: Mutex<HashMap<String, Vec<u8>>>,
    }

    impl MockKv {
        fn new() -> Self {
            Self {
                data: Mutex::new(HashMap::new()),
            }
        }

        fn contains(&self, key: &str) -> bool {
            self.data.lock().unwrap().contains_key(key)
        }
    }

    impl AsyncKvStore for MockKv {
        fn put_if_absent(
            &self,
            key: &str,
            value: Vec<u8>,
            _ttl: std::time::Duration,
        ) -> KvBoxFuture<'_, Result<bool, KvError>> {
            let inserted = match self.data.lock().unwrap().entry(key.to_owned()) {
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert(value);
                    true
                }
                std::collections::hash_map::Entry::Occupied(_) => false,
            };
            Box::pin(async move { Ok(inserted) })
        }

        fn take(&self, key: &str) -> KvBoxFuture<'_, Result<Option<Vec<u8>>, KvError>> {
            let value = self.data.lock().unwrap().remove(key);
            Box::pin(async move { Ok(value) })
        }
    }

    fn provider_metadata() -> ProviderMetadata {
        let json = serde_json::json!({
            "issuer": "https://idp.example.com",
            "authorization_endpoint": "https://idp.example.com/auth",
            "token_endpoint": "https://idp.example.com/token",
            "jwks_uri": "https://idp.example.com/jwks",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
        });
        serde_json::from_value(json).unwrap()
    }

    fn provider_metadata_with_userinfo() -> ProviderMetadata {
        let json = serde_json::json!({
            "issuer": "https://idp.example.com",
            "authorization_endpoint": "https://idp.example.com/auth",
            "token_endpoint": "https://idp.example.com/token",
            "userinfo_endpoint": "https://idp.example.com/userinfo",
            "jwks_uri": "https://idp.example.com/jwks",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "userinfo_signing_alg_values_supported": ["RS256"],
        });
        serde_json::from_value(json).unwrap()
    }

    #[tokio::test]
    async fn complete_authorization_exchanges_code_and_consumes_pending() {
        let token_resp = serde_json::json!({
            "access_token": "AT-1",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "RT-1",
            "id_token": "header.payload.signature",
        })
        .to_string()
        .into_bytes();
        let http = Arc::new(MockHttp::new(vec![HttpResponse {
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())],
            body: token_resp,
        }]));
        let client = Client::from_parts(
            provider_metadata(),
            ClientId::new("my-client").unwrap(),
            Some(ClientSecret::new("secret").unwrap()),
            http.clone() as Arc<dyn AsyncHttpClient>,
        )
        .unwrap();

        let kv = MockKv::new();
        let state = "state-xyz";
        let pending = PendingAuthRequest {
            state: state.to_string(),
            nonce: "nonce-abc".to_string(),
            pkce_verifier: Some("verifier-1234567890".to_string()),
            max_age: None,
            redirect_uri: Some("https://app.example.com/cb".to_string()),
            scopes: vec!["openid".into()],
            created_at: std::time::SystemTime::now(),
        };
        assert!(
            kv.put_if_absent(
                &PendingAuthRequest::key_for(state),
                serde_json::to_vec(&pending).unwrap(),
                PendingAuthRequest::DEFAULT_TTL,
            )
            .await
            .unwrap()
        );

        let query = format!("code=AUTH-CODE&state={state}");
        let result = client.complete_authorization(&query, &kv).await.unwrap();

        // Response parsed.
        assert_eq!(result.token_response.access_token.as_str(), "AT-1");
        assert_eq!(
            result
                .token_response
                .refresh_token
                .as_ref()
                .map(AsRef::as_ref),
            Some("RT-1")
        );
        assert_eq!(result.callback_state, state);
        assert_eq!(result.pending.nonce, "nonce-abc");

        // Pending entry consumed.
        assert!(!kv.contains(&PendingAuthRequest::key_for(state)));

        // Last request was a POST with form body containing grant_type=authorization_code.
        let last = http.last_request.lock().unwrap().clone().unwrap();
        assert_eq!(last.method, HttpMethod::Post);
        let body = String::from_utf8(last.body.unwrap()).unwrap();
        assert!(body.contains("grant_type=authorization_code"));
        assert!(body.contains("code=AUTH-CODE"));
        assert!(body.contains("code_verifier=verifier-1234567890"));
        assert!(body.contains("redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb"));
        // client_secret_basic puts creds in header, not body.
        assert!(last.headers.iter().any(|(k, _)| k == "Authorization"));
    }

    #[tokio::test]
    async fn concurrent_completion_consumes_pending_once() {
        let token_resp = serde_json::json!({
            "access_token": "AT-1",
            "token_type": "Bearer",
            "id_token": "header.payload.signature",
        })
        .to_string()
        .into_bytes();
        let http = Arc::new(MockHttp::new(vec![HttpResponse {
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())],
            body: token_resp,
        }]));
        let client = Client::from_parts(
            provider_metadata(),
            ClientId::new("my-client").unwrap(),
            Some(ClientSecret::new("secret").unwrap()),
            http as Arc<dyn AsyncHttpClient>,
        )
        .unwrap();
        let kv = MockKv::new();
        let state = "single-use-state";
        let pending = PendingAuthRequest {
            state: state.into(),
            nonce: "nonce".into(),
            pkce_verifier: None,
            max_age: None,
            redirect_uri: Some("https://app.example.com/cb".into()),
            scopes: vec!["openid".into()],
            created_at: std::time::SystemTime::now(),
        };
        assert!(
            kv.put_if_absent(
                &PendingAuthRequest::key_for(state),
                serde_json::to_vec(&pending).unwrap(),
                PendingAuthRequest::DEFAULT_TTL,
            )
            .await
            .unwrap()
        );
        let query = format!("code=AUTH-CODE&state={state}");

        let (first, second) = futures::join!(
            client.complete_authorization(&query, &kv),
            client.complete_authorization(&query, &kv),
        );

        assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
        assert!(!kv.contains(&PendingAuthRequest::key_for(state)));
    }

    #[tokio::test]
    async fn complete_authorization_rejects_state_mismatch() {
        let http = Arc::new(MockHttp::new(vec![]));
        let client = Client::from_parts(
            provider_metadata(),
            ClientId::new("my-client").unwrap(),
            None,
            http as Arc<dyn AsyncHttpClient>,
        )
        .unwrap();

        let kv = MockKv::new();
        let pending = PendingAuthRequest {
            state: "real-state".into(),
            nonce: "nonce-1".into(),
            pkce_verifier: None,
            max_age: None,
            redirect_uri: Some("https://app.example.com/cb".into()),
            scopes: vec!["openid".into()],
            created_at: std::time::SystemTime::now(),
        };
        assert!(
            kv.put_if_absent(
                &PendingAuthRequest::key_for("real-state"),
                serde_json::to_vec(&pending).unwrap(),
                PendingAuthRequest::DEFAULT_TTL,
            )
            .await
            .unwrap()
        );

        let query = "code=AUTH-CODE&state=other-state";
        let err = client.complete_authorization(query, &kv).await.unwrap_err();
        let _ = err; // expect AuthorizationResponse variant; we just confirm it errors
    }

    #[tokio::test]
    async fn complete_authorization_rejects_invalid_pending_age() {
        let http = Arc::new(MockHttp::new(vec![]));
        let client = Client::from_parts(
            provider_metadata(),
            ClientId::new("my-client").unwrap(),
            Some(ClientSecret::new("secret").unwrap()),
            http as Arc<dyn AsyncHttpClient>,
        )
        .unwrap();
        let kv = MockKv::new();
        let now = std::time::SystemTime::now();
        let cases = [
            (
                "stale-state",
                now - PendingAuthRequest::DEFAULT_TTL - std::time::Duration::from_secs(1),
                OidcError::PendingAuthorizationExpired,
            ),
            (
                "future-state",
                now + std::time::Duration::from_secs(60),
                OidcError::PendingAuthorizationFromFuture,
            ),
        ];

        for (state, created_at, expected) in cases {
            let pending = PendingAuthRequest {
                state: state.into(),
                nonce: "nonce".into(),
                pkce_verifier: None,
                max_age: None,
                redirect_uri: Some("https://app.example.com/cb".into()),
                scopes: vec!["openid".into()],
                created_at,
            };
            let key = PendingAuthRequest::key_for(state);
            assert!(
                kv.put_if_absent(
                    &key,
                    serde_json::to_vec(&pending).unwrap(),
                    PendingAuthRequest::DEFAULT_TTL,
                )
                .await
                .unwrap()
            );

            let query = format!("code=AUTH-CODE&state={state}");
            let error = client
                .complete_authorization(&query, &kv)
                .await
                .unwrap_err();
            assert_eq!(
                std::mem::discriminant(&error),
                std::mem::discriminant(&expected)
            );
            assert!(!kv.contains(&key));
        }
    }

    #[tokio::test]
    async fn complete_authorization_rejects_wrong_callback_issuer() {
        let http = Arc::new(MockHttp::new(vec![]));
        let mut metadata = provider_metadata();
        metadata.authorization_response_iss_parameter_supported = true;
        let client = Client::from_parts(
            metadata,
            ClientId::new("my-client").unwrap(),
            None,
            http as Arc<dyn AsyncHttpClient>,
        )
        .unwrap();

        let err = client
            .complete_authorization(
                "code=AUTH-CODE&state=state-1&iss=https%3A%2F%2Fattacker.example.com",
                &MockKv::new(),
            )
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            OidcError::AuthorizationResponse(
                crate::flow::callback::CallbackError::IssuerMismatch { .. }
            )
        ));
    }

    #[tokio::test]
    async fn complete_authorization_requires_advertised_callback_issuer() {
        let http = Arc::new(MockHttp::new(vec![]));
        let mut metadata = provider_metadata();
        metadata.authorization_response_iss_parameter_supported = true;
        let client = Client::from_parts(
            metadata,
            ClientId::new("my-client").unwrap(),
            None,
            http as Arc<dyn AsyncHttpClient>,
        )
        .unwrap();

        let err = client
            .complete_authorization("code=AUTH-CODE&state=state-1", &MockKv::new())
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            OidcError::AuthorizationResponse(crate::flow::callback::CallbackError::Missing("iss"))
        ));
    }

    #[tokio::test]
    async fn complete_authorization_errors_on_token_endpoint_failure() {
        let err_body = serde_json::json!({
            "error": "invalid_grant",
            "error_description": "authorization code expired",
        })
        .to_string()
        .into_bytes();
        let http = Arc::new(MockHttp::new(vec![HttpResponse {
            status: 400,
            headers: vec![],
            body: err_body,
        }]));
        let client = Client::from_parts(
            provider_metadata(),
            ClientId::new("my-client").unwrap(),
            Some(ClientSecret::new("secret").unwrap()),
            http as Arc<dyn AsyncHttpClient>,
        )
        .unwrap();
        let kv = MockKv::new();
        let state = "st";
        let pending = PendingAuthRequest {
            state: state.into(),
            nonce: "n".into(),
            pkce_verifier: None,
            max_age: None,
            redirect_uri: Some("https://app.example.com/cb".into()),
            scopes: vec!["openid".into()],
            created_at: std::time::SystemTime::now(),
        };
        assert!(
            kv.put_if_absent(
                &PendingAuthRequest::key_for(state),
                serde_json::to_vec(&pending).unwrap(),
                PendingAuthRequest::DEFAULT_TTL,
            )
            .await
            .unwrap()
        );

        let query = format!("code=CODE&state={state}");
        let err = client
            .complete_authorization(&query, &kv)
            .await
            .unwrap_err();
        match err {
            OidcError::TokenEndpoint {
                status,
                error,
                error_description,
            } => {
                assert_eq!(status, 400);
                assert_eq!(error, "invalid_grant");
                assert_eq!(
                    error_description.as_deref(),
                    Some("authorization code expired")
                );
            }
            other => panic!("expected TokenEndpoint, got {other:?}"),
        }
    }

    #[test]
    fn exchange_code_picks_basic_when_secret_present() {
        let http = Arc::new(MockHttp::new(vec![]));
        let client = Client::from_parts(
            provider_metadata(),
            ClientId::new("c").unwrap(),
            Some(ClientSecret::new("s").unwrap()),
            http as Arc<dyn AsyncHttpClient>,
        )
        .unwrap();
        let req = client
            .exchange_code("code".into())
            .unwrap()
            .redirect_uri("https://app.example.com/cb")
            .pkce_verifier("verifier-1234567890");
        let built = req.build().unwrap();
        assert!(built.http.headers.iter().any(|(k, _)| k == "Authorization"));
    }

    #[test]
    fn exchange_code_picks_none_when_no_secret() {
        let http = Arc::new(MockHttp::new(vec![]));
        let client = Client::from_parts(
            provider_metadata(),
            ClientId::new("c").unwrap(),
            None,
            http as Arc<dyn AsyncHttpClient>,
        )
        .unwrap();
        let req = client
            .exchange_code("code".into())
            .unwrap()
            .redirect_uri("https://app.example.com/cb")
            .pkce_verifier("verifier-1234567890");
        let built = req.build().unwrap();
        assert!(built.http.headers.iter().all(|(k, _)| k != "Authorization"));
        let body = String::from_utf8(built.http.body.unwrap()).unwrap();
        assert!(body.contains("client_id=c"));
        assert!(body.contains("code_verifier=verifier-1234567890"));
    }

    #[tokio::test]
    async fn fetch_userinfo_parses_unsigned_json() {
        let body = serde_json::json!({
            "sub": "user-1",
            "email": "user@example.com",
            "email_verified": true,
        })
        .to_string()
        .into_bytes();
        let resp = HttpResponse {
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())],
            body: body.clone(),
        };
        let http = Arc::new(MockHttp::new(vec![resp]));
        let client = Client::from_parts(
            provider_metadata_with_userinfo(),
            ClientId::new("c").unwrap(),
            None,
            http as Arc<dyn AsyncHttpClient>,
        )
        .unwrap();
        let access_token = crate::types::AccessToken::new("AT-1").unwrap();
        let info = client
            .fetch_userinfo(&access_token, "user-1")
            .await
            .unwrap();
        assert_eq!(info.sub, "user-1");
        assert_eq!(info.email.as_deref(), Some("user@example.com"));
        assert_eq!(info.email_verified, Some(true));
    }

    #[tokio::test]
    async fn fetch_userinfo_sends_bearer_and_accept_header() {
        // Empty response body with status 200 so we can inspect the
        // outgoing request without parsing.
        let resp = HttpResponse {
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())],
            body: b"{\"sub\":\"x\"}".to_vec(),
        };
        let http = Arc::new(MockHttp::new(vec![resp]));
        let client = Client::from_parts(
            provider_metadata_with_userinfo(),
            ClientId::new("c").unwrap(),
            None,
            http.clone() as Arc<dyn AsyncHttpClient>,
        )
        .unwrap();
        let access_token = crate::types::AccessToken::new("AT-7").unwrap();
        client.fetch_userinfo(&access_token, "x").await.unwrap();

        let last = http.last_request.lock().unwrap().clone().unwrap();
        assert_eq!(last.method, HttpMethod::Get);
        assert_eq!(last.url, "https://idp.example.com/userinfo");
        let auth = last
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("authorization"))
            .map(|(_, v)| v.as_str());
        assert_eq!(auth, Some("Bearer AT-7"));
        let accept = last
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("accept"))
            .map(|(_, v)| v.as_str());
        assert_eq!(accept, Some("application/json, application/jwt;q=0.9"));
    }

    #[tokio::test]
    async fn fetch_userinfo_returns_error_when_endpoint_missing() {
        let http = Arc::new(MockHttp::new(vec![]));
        let client = Client::from_parts(
            provider_metadata(),
            ClientId::new("c").unwrap(),
            None,
            http as Arc<dyn AsyncHttpClient>,
        )
        .unwrap();
        let access_token = crate::types::AccessToken::new("AT-1").unwrap();
        let err = client
            .fetch_userinfo(&access_token, "user-1")
            .await
            .unwrap_err();
        assert!(matches!(err, OidcError::InvalidMetadata(_)));
    }

    #[tokio::test]
    async fn fetch_userinfo_maps_non_200_to_userinfo_error() {
        let resp = HttpResponse {
            status: 401,
            headers: vec![("content-type".into(), "application/json".into())],
            body: serde_json::json!({
                "error": "invalid_token",
                "error_description": "access token expired",
            })
            .to_string()
            .into_bytes(),
        };
        let http = Arc::new(MockHttp::new(vec![resp]));
        let client = Client::from_parts(
            provider_metadata_with_userinfo(),
            ClientId::new("c").unwrap(),
            None,
            http as Arc<dyn AsyncHttpClient>,
        )
        .unwrap();
        let access_token = crate::types::AccessToken::new("AT-1").unwrap();
        let err = client
            .fetch_userinfo(&access_token, "user-1")
            .await
            .unwrap_err();
        match err {
            OidcError::UserInfo {
                status,
                error,
                error_description,
            } => {
                assert_eq!(status, 401);
                assert_eq!(error, "invalid_token");
                assert_eq!(error_description.as_deref(), Some("access token expired"));
            }
            other => panic!("expected UserInfo variant, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn fetch_userinfo_rejects_unexpected_content_type() {
        let resp = HttpResponse {
            status: 200,
            headers: vec![("content-type".into(), "text/html".into())],
            body: b"<html>oops</html>".to_vec(),
        };
        let http = Arc::new(MockHttp::new(vec![resp]));
        let client = Client::from_parts(
            provider_metadata_with_userinfo(),
            ClientId::new("c").unwrap(),
            None,
            http as Arc<dyn AsyncHttpClient>,
        )
        .unwrap();
        let access_token = crate::types::AccessToken::new("AT-1").unwrap();
        let err = client
            .fetch_userinfo(&access_token, "user-1")
            .await
            .unwrap_err();
        assert!(matches!(err, OidcError::InvalidAuthorizationRequest(_)));
    }

    #[tokio::test]
    async fn fetch_userinfo_rejects_subject_mismatch() {
        let resp = HttpResponse {
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())],
            body: br#"{"sub":"other-user","name":"Mallory"}"#.to_vec(),
        };
        let http = Arc::new(MockHttp::new(vec![resp]));
        let client = Client::from_parts(
            provider_metadata_with_userinfo(),
            ClientId::new("c").unwrap(),
            None,
            http as Arc<dyn AsyncHttpClient>,
        )
        .unwrap();
        let access_token = crate::types::AccessToken::new("AT-1").unwrap();

        let err = client
            .fetch_userinfo(&access_token, "verified-user")
            .await
            .unwrap_err();
        assert!(matches!(err, OidcError::UserInfoSubjectMismatch));
    }

    #[test]
    fn jwks_accessor_returns_shared_cache() {
        // The same `AsyncHttpsJwks` should be returned across
        // repeated calls so resource-server code can cache it in a
        // per-request closure without losing the kid / Cache-Control
        // state that jose4rs keeps internally.
        let http = Arc::new(MockHttp::new(vec![]));
        let client = Client::from_parts(
            provider_metadata(),
            ClientId::new("c").unwrap(),
            None,
            http as Arc<dyn AsyncHttpClient>,
        )
        .unwrap();
        let a: *const AsyncHttpsJwks = client.jwks();
        let b: *const AsyncHttpsJwks = client.jwks();
        assert!(std::ptr::eq(a, b));
        // The metadata URL the cache was constructed with must match
        // the well-known jwks_uri so a caller pulling the JWKS via
        // `client.jwks().select_verification_key(...)` looks keys up
        // against the right OP.
        assert_eq!(
            client.metadata().jwks_uri.as_url().as_str(),
            "https://idp.example.com/jwks"
        );
    }
}
