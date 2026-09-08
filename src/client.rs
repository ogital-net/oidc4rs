//! `Client` -- the high-level entry point for an OIDC relying party.

use std::sync::{Arc, PoisonError, RwLock};
use std::time::{Duration, Instant};

use futures_util::lock::Mutex as AsyncMutex;
use jose4rs::jwk::{AsyncHttpsJwks, AsyncJwksFetcher, FetchResponse};

use crate::error::OidcError;
use crate::flow::authorize::PendingAuthRequest;
use crate::flow::callback::{AuthorizationResponse, CallbackError, parse_authorization_response};
use crate::flow::token::{BuiltTokenRequest, CodeTokenRequest, RefreshTokenRequest};
use crate::metadata::{CachePolicy, ProviderMetadata};
use crate::token::response::{IdToken, TokenResponse};
use crate::transport::http::{AsyncHttpClient, HttpMethod, HttpRequest};
use crate::transport::kv::AsyncKvStore;
use crate::types::{AccessToken, ClientId, ClientSecret, RefreshToken};

/// Default metadata freshness when discovery supplies no cache lifetime.
pub const DEFAULT_METADATA_REFRESH_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// Default minimum time a successful discovery response is reused.
pub const DEFAULT_METADATA_MINIMUM_CACHE_DURATION: Duration = Duration::from_secs(60);

/// Default time stale metadata remains usable after an automatic refresh failure.
pub const DEFAULT_METADATA_RETAIN_ON_ERROR: Duration = Duration::from_secs(24 * 60 * 60);

/// Suppresses repeated automatic refresh attempts during a provider outage.
const METADATA_REFRESH_RETRY_INTERVAL: Duration = Duration::from_secs(30);

/// OIDC relying-party client.
#[allow(clippy::struct_field_names)] // `Client.client_id` / `Client.client_secret` are the standard names.
pub struct Client {
    provider: RwLock<ProviderState>,
    metadata_refresh_lock: AsyncMutex<()>,
    pub(crate) client_id: ClientId,
    pub(crate) client_secret: Option<ClientSecret>,
    pub(crate) http: Arc<dyn AsyncHttpClient>,
}

/// Metadata and keys must change as one snapshot when `jwks_uri` changes.
#[derive(Clone)]
struct ProviderState {
    metadata: Arc<ProviderMetadata>,
    jwks: AsyncHttpsJwks,
    refresh_after: Option<Instant>,
    stale_until: Option<Instant>,
    retry_after: Option<Instant>,
    /// Whether the response policy permits use after freshness expires.
    stale_on_error: bool,
    metadata_refresh_interval: Option<Duration>,
    metadata_minimum_cache_duration: Duration,
    metadata_retain_on_error: Duration,
}

impl ProviderState {
    fn metadata_needs_refresh(&self) -> bool {
        let now = Instant::now();
        self.refresh_after.is_some_and(|deadline| now >= deadline)
            && self.retry_after.is_none_or(|deadline| now >= deadline)
    }
}

/// An unrepresentable deadline is treated as immediately stale.
fn metadata_refresh_deadline(interval: Duration) -> Instant {
    let now = Instant::now();
    now.checked_add(interval).unwrap_or(now)
}

fn metadata_stale_deadline(
    refresh_after: Instant,
    stale_on_error: bool,
    retain_on_error: Duration,
) -> Option<Instant> {
    if !stale_on_error || retain_on_error.is_zero() {
        return None;
    }
    refresh_after.checked_add(retain_on_error)
}

/// Converts response freshness policy into monotonic cache deadlines.
fn metadata_cache_deadlines(
    policy: CachePolicy,
    retain_on_error: Duration,
) -> (Option<Instant>, Option<Instant>, bool) {
    match policy {
        CachePolicy::CacheFor {
            lifetime,
            must_revalidate,
        } => {
            let refresh_after = metadata_refresh_deadline(lifetime);
            let stale_until =
                metadata_stale_deadline(refresh_after, !must_revalidate, retain_on_error);
            (Some(refresh_after), stale_until, !must_revalidate)
        }
        CachePolicy::Revalidate | CachePolicy::DoNotStore => (Some(Instant::now()), None, false),
    }
}

impl Client {
    /// Performs discovery from `issuer` and returns a fully wired
    /// `Client`. Fetches the initial JWKS through the same cache used
    /// for future refreshes. Provider metadata freshness follows its HTTP
    /// response, with [`DEFAULT_METADATA_REFRESH_INTERVAL`] as the fallback.
    /// Successful responses are reused for at least
    /// [`DEFAULT_METADATA_MINIMUM_CACHE_DURATION`] because OIDC implementations
    /// commonly treat discovery as long-lived configuration. Stale metadata is
    /// refreshed by async client operations or an explicit stale check.
    pub async fn discover<C>(
        issuer: crate::types::IssuerUrl,
        client_id: ClientId,
        client_secret: Option<ClientSecret>,
        http: Arc<C>,
    ) -> Result<Self, OidcError>
    where
        C: AsyncHttpClient + 'static,
    {
        let discovered = crate::metadata::discover_with_cache(issuer, http.as_ref()).await?;
        let (refresh_after, stale_until, stale_on_error) = metadata_cache_deadlines(
            discovered.cache_policy(
                DEFAULT_METADATA_REFRESH_INTERVAL,
                DEFAULT_METADATA_MINIMUM_CACHE_DURATION,
            ),
            DEFAULT_METADATA_RETAIN_ON_ERROR,
        );
        let metadata = discovered.metadata;
        let fetcher: Arc<dyn AsyncJwksFetcher> = Arc::new(HttpJwksFetcher { http: http.clone() });
        let jwks = AsyncHttpsJwks::new(metadata.jwks_uri.as_url().as_str(), fetcher);
        jwks.keys().await?;

        Ok(Self {
            provider: RwLock::new(ProviderState {
                metadata: Arc::new(metadata),
                jwks,
                refresh_after,
                stale_until,
                retry_after: None,
                stale_on_error,
                metadata_refresh_interval: Some(DEFAULT_METADATA_REFRESH_INTERVAL),
                metadata_minimum_cache_duration: DEFAULT_METADATA_MINIMUM_CACHE_DURATION,
                metadata_retain_on_error: DEFAULT_METADATA_RETAIN_ON_ERROR,
            }),
            metadata_refresh_lock: AsyncMutex::new(()),
            client_id,
            client_secret,
            http,
        })
    }

    /// Manual construction for tests or for callers that load metadata
    /// via a non-HTTP path. Automatic metadata refresh starts disabled;
    /// callers can enable it with
    /// [`set_metadata_refresh_interval`](Self::set_metadata_refresh_interval).
    /// The caller is responsible for ensuring the JWKS endpoint is reachable;
    /// the key cache will populate on first use.
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
            provider: RwLock::new(ProviderState {
                metadata: Arc::new(metadata),
                jwks,
                refresh_after: None,
                stale_until: None,
                retry_after: None,
                stale_on_error: true,
                metadata_refresh_interval: None,
                metadata_minimum_cache_duration: DEFAULT_METADATA_MINIMUM_CACHE_DURATION,
                metadata_retain_on_error: DEFAULT_METADATA_RETAIN_ON_ERROR,
            }),
            metadata_refresh_lock: AsyncMutex::new(()),
            client_id,
            client_secret,
            http,
        })
    }

    fn provider(&self) -> ProviderState {
        self.provider
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Returns the latest successfully fetched provider metadata snapshot.
    ///
    /// This accessor performs no I/O. Call
    /// [`refresh_metadata_if_stale`](Self::refresh_metadata_if_stale) before
    /// synchronous operations when they must use a current snapshot.
    pub fn metadata(&self) -> Arc<ProviderMetadata> {
        self.provider
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .metadata
            .clone()
    }

    pub fn client_id(&self) -> &ClientId {
        &self.client_id
    }

    /// Returns the JWKS cache used to verify this OP's ID tokens.
    ///
    /// The cache is shared across all ID-token / userinfo / token
    /// verifications performed by this `Client`; callers performing
    /// bearer-access-token verification (or any other JWS check)
    /// against the same OP should pass this same cache to
    /// `jose4rs::jwk::AsyncHttpsJwks::select_verification_key` so
    /// key fetches, `kid` lookups, and `Cache-Control` honoring are
    /// amortized across the process.
    ///
    /// `AsyncHttpsJwks` is cheap to clone and shares its cache internally.
    /// Reacquire this handle after refreshing metadata so a changed
    /// `jwks_uri` is reflected.
    pub fn jwks(&self) -> AsyncHttpsJwks {
        self.provider
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .jwks
            .clone()
    }

    /// Sets fallback freshness for discovery responses without a cache lifetime.
    ///
    /// The current snapshot is rescheduled relative to this call. Subsequent
    /// responses with `Cache-Control: max-age` or `Expires` override this
    /// fallback. The effective interval is also bounded by the configured
    /// metadata minimum cache duration.
    pub fn set_metadata_refresh_interval(&self, interval: Duration) {
        let mut provider = self
            .provider
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        provider.metadata_refresh_interval = Some(interval);
        let refresh_after =
            metadata_refresh_deadline(interval.max(provider.metadata_minimum_cache_duration));
        provider.refresh_after = Some(refresh_after);
        provider.stale_until = metadata_stale_deadline(
            refresh_after,
            provider.stale_on_error,
            provider.metadata_retain_on_error,
        );
        provider.retry_after = None;
    }

    /// Sets the minimum time a successful discovery response is reused.
    ///
    /// This OIDC-specific local policy prevents providers with missing,
    /// ineffective, or strict HTTP freshness directives from causing discovery
    /// on every client operation. A strict directive still disables stale use
    /// after the minimum expires. Forced refreshes bypass the minimum. Set it
    /// to zero so subsequent responses follow HTTP freshness strictly.
    /// Increasing the minimum extends the current snapshot; reducing it applies
    /// after the next successful metadata fetch.
    pub fn set_metadata_minimum_cache_duration(&self, duration: Duration) {
        let mut provider = self
            .provider
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        provider.metadata_minimum_cache_duration = duration;
        provider.retry_after = None;
        if provider.metadata_refresh_interval.is_none() {
            return;
        }

        let minimum_refresh_after = metadata_refresh_deadline(duration);
        if provider
            .refresh_after
            .is_none_or(|refresh_after| refresh_after < minimum_refresh_after)
        {
            provider.refresh_after = Some(minimum_refresh_after);
            provider.stale_until = metadata_stale_deadline(
                minimum_refresh_after,
                provider.stale_on_error,
                provider.metadata_retain_on_error,
            );
        }
    }

    /// Sets how long eligible stale metadata remains usable after an automatic
    /// refresh failure.
    ///
    /// Zero disables stale fallback. Responses requiring revalidation remain
    /// ineligible, and forced refreshes always report failures. The current
    /// snapshot is rescheduled relative to its existing freshness deadline.
    pub fn set_metadata_retain_on_error(&self, duration: Duration) {
        let mut provider = self
            .provider
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        provider.metadata_retain_on_error = duration;
        provider.stale_until = provider.refresh_after.and_then(|refresh_after| {
            metadata_stale_deadline(refresh_after, provider.stale_on_error, duration)
        });
        provider.retry_after = None;
    }

    /// Disables automatic stale checks while retaining explicit refreshes.
    pub fn disable_metadata_refresh(&self) {
        let mut provider = self
            .provider
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        provider.metadata_refresh_interval = None;
        provider.refresh_after = None;
        provider.stale_until = None;
        provider.retry_after = None;
    }

    /// Refreshes provider metadata when its configured interval has elapsed.
    ///
    /// Concurrent stale checks share one refresh. On failure, the last
    /// successful snapshot remains usable for a bounded period unless the
    /// response required revalidation. If the `jwks_uri` changes, the
    /// replacement JWKS cache is populated before the new provider snapshot
    /// becomes visible. The runtime-independent client does not create a
    /// background task; call this before synchronous builders when freshness
    /// is required. Async authorization completion and UserInfo operations
    /// call it automatically.
    pub async fn refresh_metadata_if_stale(&self) -> Result<Arc<ProviderMetadata>, OidcError> {
        let provider = self.provider();
        if !provider.metadata_needs_refresh() {
            return Ok(provider.metadata);
        }

        let _guard = self.metadata_refresh_lock.lock().await;
        let provider = self.provider();
        if !provider.metadata_needs_refresh() {
            return Ok(provider.metadata);
        }
        match self.refresh_metadata_from(provider).await {
            Ok(metadata) => Ok(metadata),
            Err(error) => self.metadata_after_refresh_error(error),
        }
    }

    /// Forces an immediate provider metadata refresh and reports any failure.
    pub async fn refresh_metadata(&self) -> Result<Arc<ProviderMetadata>, OidcError> {
        let _guard = self.metadata_refresh_lock.lock().await;
        self.refresh_metadata_from(self.provider()).await
    }

    /// Retains an eligible stale snapshot and defers the next automatic retry.
    fn metadata_after_refresh_error(
        &self,
        error: OidcError,
    ) -> Result<Arc<ProviderMetadata>, OidcError> {
        let now = Instant::now();
        let mut provider = self
            .provider
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        let Some(stale_until) = provider.stale_until.filter(|deadline| now < *deadline) else {
            return Err(error);
        };
        let retry_after = now
            .checked_add(METADATA_REFRESH_RETRY_INTERVAL)
            .map_or(stale_until, |deadline| deadline.min(stale_until));
        provider.retry_after = Some(retry_after);
        Ok(provider.metadata.clone())
    }

    /// Fetches a complete replacement before publishing any of it.
    async fn refresh_metadata_from(
        &self,
        current: ProviderState,
    ) -> Result<Arc<ProviderMetadata>, OidcError> {
        let discovered = crate::metadata::discover_with_cache(
            current.metadata.issuer.clone(),
            self.http.as_ref(),
        )
        .await?;
        let jwks = if discovered.metadata.jwks_uri == current.metadata.jwks_uri {
            current.jwks
        } else {
            let fetcher: Arc<dyn AsyncJwksFetcher> = Arc::new(HttpJwksFetcher {
                http: self.http.clone(),
            });
            let jwks = AsyncHttpsJwks::new(discovered.metadata.jwks_uri.as_url().as_str(), fetcher);
            jwks.keys().await?;
            jwks
        };
        let mut provider = self
            .provider
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        let metadata_refresh_interval = provider.metadata_refresh_interval;
        let metadata_minimum_cache_duration = provider.metadata_minimum_cache_duration;
        let metadata_retain_on_error = provider.metadata_retain_on_error;
        let cache_policy = discovered.cache_policy(
            metadata_refresh_interval.unwrap_or(DEFAULT_METADATA_REFRESH_INTERVAL),
            metadata_minimum_cache_duration,
        );
        let (policy_refresh_after, policy_stale_until, stale_on_error) =
            metadata_cache_deadlines(cache_policy, metadata_retain_on_error);
        let (refresh_after, stale_until) = if metadata_refresh_interval.is_some() {
            (policy_refresh_after, policy_stale_until)
        } else {
            (None, None)
        };
        let metadata = Arc::new(discovered.metadata);
        *provider = ProviderState {
            metadata: metadata.clone(),
            jwks,
            refresh_after,
            stale_until,
            retry_after: None,
            stale_on_error,
            metadata_refresh_interval,
            metadata_minimum_cache_duration,
            metadata_retain_on_error,
        };
        Ok(metadata)
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
    /// 3. Verifies the `state` matches and the request is current.
    /// 4. Returns a provider error after consuming its pending request.
    /// 5. Otherwise delegates to
    ///    [`complete_authorization_from_pending`](Self::complete_authorization_from_pending).
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
        let pending = take_pending_request(kv, response.state()).await?;
        self.complete_authorization_from_pending(response, pending)
            .await
    }

    /// Completes an authorization-code flow from state the caller has already
    /// consumed atomically.
    ///
    /// Use this entry point when the stored transaction contains application
    /// context needed to select the client, such as a tenant or provider ID.
    /// The caller consumes and decodes its transaction, resolves this client,
    /// then passes the embedded [`PendingAuthRequest`] here. This method still
    /// validates the callback issuer, state binding, and pending-request age
    /// before making the token request.
    pub async fn complete_authorization_from_pending(
        &self,
        response: AuthorizationResponse,
        pending: PendingAuthRequest,
    ) -> Result<CompleteAuthorization, OidcError> {
        let metadata = self.refresh_metadata_if_stale().await?;
        let callback_state = response.state().to_owned();
        validate_pending_request(&pending, &callback_state)?;
        let expected_issuer = metadata.issuer.as_str();
        match response.issuer() {
            Some(actual) if actual != expected_issuer => {
                return Err(crate::flow::callback::CallbackError::IssuerMismatch {
                    expected: expected_issuer.to_owned(),
                    actual: actual.to_owned(),
                }
                .into());
            }
            None if metadata.authorization_response_iss_parameter_supported => {
                return Err(crate::flow::callback::CallbackError::Missing("iss").into());
            }
            Some(_) | None => {}
        }

        let code = match response {
            AuthorizationResponse::Success { code, .. } => code,
            AuthorizationResponse::Error {
                error,
                description,
                error_uri,
                iss,
                ..
            } => {
                return Err(CallbackError::ProviderError {
                    error,
                    description,
                    error_uri,
                    state: callback_state,
                    iss,
                }
                .into());
            }
        };

        let mut builder: CodeTokenRequest = self.exchange_code_with_metadata(code, &metadata)?;
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
            callback_state,
        })
    }

    /// Begins an authorization-code token exchange. `code` is the
    /// short-lived authorization code from the OP callback.
    pub fn exchange_code(&self, code: String) -> Result<CodeTokenRequest, OidcError> {
        let metadata = self.metadata();
        self.exchange_code_with_metadata(code, &metadata)
    }

    fn exchange_code_with_metadata(
        &self,
        code: String,
        metadata: &ProviderMetadata,
    ) -> Result<CodeTokenRequest, OidcError> {
        let supported = metadata.token_endpoint_auth_methods_supported.as_deref();
        let method = crate::flow::token::TokenAuthMethod::from_metadata(
            supported,
            self.client_secret.is_some(),
        )?;
        Ok(CodeTokenRequest::new(
            metadata.token_endpoint.clone(),
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
        self.refresh_metadata_if_stale().await?;
        let provider = self.provider();
        let endpoint = provider
            .metadata
            .userinfo_endpoint
            .as_ref()
            .ok_or_else(|| {
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
                &provider.metadata,
                self.client_id.as_str(),
            );
            crate::token::userinfo::UserInfo::from_signed_jwt(compact, &verifier, &provider.jwks)
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
        let metadata = self.metadata();
        let supported = metadata.token_endpoint_auth_methods_supported.as_deref();
        let method = crate::flow::token::TokenAuthMethod::from_metadata(
            supported,
            self.client_secret.is_some(),
        )?;
        Ok(RefreshTokenRequest::new(
            metadata.token_endpoint.clone(),
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
        let metadata = self.metadata();
        crate::token::verify::IdTokenVerifier::from_metadata(&metadata, self.client_id().as_str())
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

async fn take_pending_request(
    kv: &dyn AsyncKvStore,
    state: &str,
) -> Result<PendingAuthRequest, OidcError> {
    let key = PendingAuthRequest::key_for(state);
    let raw = kv
        .take(&key)
        .await?
        .ok_or(OidcError::AuthorizationResponse(CallbackError::Missing(
            "state",
        )))?;
    serde_json::from_slice(&raw).map_err(Into::into)
}

fn validate_pending_request(
    pending: &PendingAuthRequest,
    callback_state: &str,
) -> Result<(), OidcError> {
    if pending.state != callback_state {
        return Err(OidcError::AuthorizationResponse(CallbackError::Parse(
            "state mismatch between callback and pending entry".into(),
        )));
    }
    pending.validate_created_at(std::time::SystemTime::now())
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
            let age = resp
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("age"))
                .and_then(|(_, v)| v.parse().ok())
                .map(std::time::Duration::from_secs);
            Ok(FetchResponse {
                body: resp.body,
                cache_control,
                expires,
                age,
            })
        })
    }
}

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
            Box::pin(async move {
                let mut yielded = false;
                std::future::poll_fn(|context| {
                    if yielded {
                        std::task::Poll::Ready(())
                    } else {
                        yielded = true;
                        context.waker().wake_by_ref();
                        std::task::Poll::Pending
                    }
                })
                .await;
                Ok(resp)
            })
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

    fn discovery_metadata(token_endpoint: &str, jwks_uri: &str) -> serde_json::Value {
        serde_json::json!({
            "issuer": "https://idp.example.com",
            "authorization_endpoint": "https://idp.example.com/auth",
            "token_endpoint": token_endpoint,
            "jwks_uri": jwks_uri,
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
        })
    }

    fn json_response(value: &serde_json::Value) -> HttpResponse {
        HttpResponse {
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())],
            body: value.to_string().into_bytes(),
        }
    }

    fn json_response_with_headers(
        value: &serde_json::Value,
        headers: Vec<(String, String)>,
    ) -> HttpResponse {
        let mut response = json_response(value);
        response.headers.extend(headers);
        response
    }

    fn empty_jwks_response() -> HttpResponse {
        HttpResponse {
            status: 200,
            headers: vec![("cache-control".into(), "max-age=3600".into())],
            body: br#"{"keys":[]}"#.to_vec(),
        }
    }

    fn expire_metadata(client: &Client) {
        client.set_metadata_minimum_cache_duration(Duration::ZERO);
        client.set_metadata_refresh_interval(Duration::ZERO);
    }

    #[tokio::test]
    async fn jwks_discovery_populates_cache() {
        let metadata = discovery_metadata(
            "https://idp.example.com/token",
            "https://idp.example.com/jwks",
        );
        let http = Arc::new(MockHttp::new(vec![
            json_response(&metadata),
            empty_jwks_response(),
        ]));

        let client = Client::discover(
            "https://idp.example.com".parse().unwrap(),
            ClientId::new("c").unwrap(),
            None,
            http.clone(),
        )
        .await
        .unwrap();

        assert!(client.jwks().keys().await.unwrap().is_empty());
        assert!(http.responses.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn default_metadata_minimum_cache_duration_throttles_strict_directives() {
        let initial = discovery_metadata(
            "https://idp.example.com/token-v1",
            "https://idp.example.com/jwks",
        );
        let http = Arc::new(MockHttp::new(vec![
            json_response_with_headers(
                &initial,
                vec![("cache-control".into(), "no-cache, no-store".into())],
            ),
            empty_jwks_response(),
        ]));
        let client = Client::discover(
            "https://idp.example.com".parse().unwrap(),
            ClientId::new("c").unwrap(),
            None,
            http.clone(),
        )
        .await
        .unwrap();
        client.set_metadata_refresh_interval(Duration::ZERO);

        let metadata = client.refresh_metadata_if_stale().await.unwrap();

        assert_eq!(
            metadata.token_endpoint.as_url().as_str(),
            "https://idp.example.com/token-v1"
        );
        assert!(http.responses.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn zero_metadata_minimum_cache_duration_honors_no_cache() {
        let initial = discovery_metadata(
            "https://idp.example.com/token-v1",
            "https://idp.example.com/jwks",
        );
        let refreshed = discovery_metadata(
            "https://idp.example.com/token-v2",
            "https://idp.example.com/jwks",
        );
        let http = Arc::new(MockHttp::new(vec![
            json_response(&initial),
            empty_jwks_response(),
            json_response_with_headers(
                &refreshed,
                vec![("cache-control".into(), "no-cache".into())],
            ),
            HttpResponse {
                status: 503,
                headers: vec![],
                body: vec![],
            },
        ]));
        let client = Client::discover(
            "https://idp.example.com".parse().unwrap(),
            ClientId::new("c").unwrap(),
            None,
            http,
        )
        .await
        .unwrap();
        client.set_metadata_minimum_cache_duration(Duration::ZERO);

        client.refresh_metadata().await.unwrap();

        assert!(client.refresh_metadata_if_stale().await.is_err());
        assert_eq!(
            client.metadata().token_endpoint.as_url().as_str(),
            "https://idp.example.com/token-v2"
        );
    }

    #[tokio::test]
    async fn stale_metadata_refresh_reuses_unchanged_jwks_cache() {
        let initial = discovery_metadata(
            "https://idp.example.com/token-v1",
            "https://idp.example.com/jwks",
        );
        let refreshed = discovery_metadata(
            "https://idp.example.com/token-v2",
            "https://idp.example.com/jwks",
        );
        let http = Arc::new(MockHttp::new(vec![
            json_response(&initial),
            empty_jwks_response(),
        ]));
        let client = Client::discover(
            "https://idp.example.com".parse().unwrap(),
            ClientId::new("c").unwrap(),
            None,
            http.clone(),
        )
        .await
        .unwrap();
        let original_jwks = client.jwks();
        expire_metadata(&client);
        http.responses
            .lock()
            .unwrap()
            .push(json_response(&refreshed));

        let metadata = client.refresh_metadata_if_stale().await.unwrap();

        assert_eq!(
            metadata.token_endpoint.as_url().as_str(),
            "https://idp.example.com/token-v2"
        );
        assert!(original_jwks.keys().await.unwrap().is_empty());
        assert!(client.jwks().keys().await.unwrap().is_empty());
        assert!(http.responses.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn concurrent_stale_checks_share_one_metadata_refresh() {
        let initial = discovery_metadata(
            "https://idp.example.com/token-v1",
            "https://idp.example.com/jwks",
        );
        let refreshed = discovery_metadata(
            "https://idp.example.com/token-v2",
            "https://idp.example.com/jwks",
        );
        let http = Arc::new(MockHttp::new(vec![
            json_response(&initial),
            empty_jwks_response(),
            json_response(&refreshed),
        ]));
        let client = Client::discover(
            "https://idp.example.com".parse().unwrap(),
            ClientId::new("c").unwrap(),
            None,
            http.clone(),
        )
        .await
        .unwrap();
        client.set_metadata_refresh_interval(DEFAULT_METADATA_REFRESH_INTERVAL);
        client.provider.write().unwrap().refresh_after = Some(Instant::now());

        let (first, second) = tokio::join!(
            client.refresh_metadata_if_stale(),
            client.refresh_metadata_if_stale(),
        );

        assert_eq!(
            first.unwrap().token_endpoint.as_url().as_str(),
            "https://idp.example.com/token-v2"
        );
        assert_eq!(
            second.unwrap().token_endpoint.as_url().as_str(),
            "https://idp.example.com/token-v2"
        );
        assert!(http.responses.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn metadata_refresh_replaces_changed_jwks_cache() {
        let initial = discovery_metadata(
            "https://idp.example.com/token",
            "https://idp.example.com/jwks-v1",
        );
        let refreshed = discovery_metadata(
            "https://idp.example.com/token",
            "https://idp.example.com/jwks-v2",
        );
        let http = Arc::new(MockHttp::new(vec![
            json_response(&initial),
            empty_jwks_response(),
            json_response(&refreshed),
            empty_jwks_response(),
        ]));
        let client = Client::discover(
            "https://idp.example.com".parse().unwrap(),
            ClientId::new("c").unwrap(),
            None,
            http.clone(),
        )
        .await
        .unwrap();
        expire_metadata(&client);

        client.refresh_metadata_if_stale().await.unwrap();

        assert_eq!(
            client.metadata().jwks_uri.as_url().as_str(),
            "https://idp.example.com/jwks-v2"
        );
        assert_eq!(
            http.last_request.lock().unwrap().as_ref().unwrap().url,
            "https://idp.example.com/jwks-v2"
        );
        assert!(client.jwks().keys().await.unwrap().is_empty());
        assert!(http.responses.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn failed_automatic_metadata_refresh_retains_previous_snapshot() {
        let initial = discovery_metadata(
            "https://idp.example.com/token-v1",
            "https://idp.example.com/jwks",
        );
        let http = Arc::new(MockHttp::new(vec![
            json_response(&initial),
            empty_jwks_response(),
            HttpResponse {
                status: 503,
                headers: vec![],
                body: vec![],
            },
        ]));
        let client = Client::discover(
            "https://idp.example.com".parse().unwrap(),
            ClientId::new("c").unwrap(),
            None,
            http,
        )
        .await
        .unwrap();
        expire_metadata(&client);

        let metadata = client.refresh_metadata_if_stale().await.unwrap();
        assert_eq!(
            metadata.token_endpoint.as_url().as_str(),
            "https://idp.example.com/token-v1"
        );
        assert_eq!(
            client.metadata().token_endpoint.as_url().as_str(),
            "https://idp.example.com/token-v1"
        );
        assert!(client.jwks().keys().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn zero_metadata_retain_on_error_disables_stale_fallback() {
        let initial = discovery_metadata(
            "https://idp.example.com/token-v1",
            "https://idp.example.com/jwks",
        );
        let http = Arc::new(MockHttp::new(vec![
            json_response(&initial),
            empty_jwks_response(),
            HttpResponse {
                status: 503,
                headers: vec![],
                body: vec![],
            },
        ]));
        let client = Client::discover(
            "https://idp.example.com".parse().unwrap(),
            ClientId::new("c").unwrap(),
            None,
            http,
        )
        .await
        .unwrap();
        expire_metadata(&client);
        client.set_metadata_retain_on_error(Duration::ZERO);

        assert!(client.refresh_metadata_if_stale().await.is_err());
        let provider = client.provider.read().unwrap();
        assert_eq!(provider.metadata_retain_on_error, Duration::ZERO);
        assert!(provider.stale_until.is_none());
    }

    #[tokio::test]
    async fn metadata_retain_on_error_survives_successful_refresh() {
        let initial = discovery_metadata(
            "https://idp.example.com/token-v1",
            "https://idp.example.com/jwks",
        );
        let refreshed = discovery_metadata(
            "https://idp.example.com/token-v2",
            "https://idp.example.com/jwks",
        );
        let http = Arc::new(MockHttp::new(vec![
            json_response(&initial),
            empty_jwks_response(),
            json_response(&refreshed),
        ]));
        let client = Client::discover(
            "https://idp.example.com".parse().unwrap(),
            ClientId::new("c").unwrap(),
            None,
            http,
        )
        .await
        .unwrap();
        let retain_on_error = Duration::from_secs(17 * 60);
        client.set_metadata_retain_on_error(retain_on_error);

        client.refresh_metadata().await.unwrap();

        let provider = client.provider.read().unwrap();
        assert_eq!(provider.metadata_retain_on_error, retain_on_error);
        assert_eq!(
            provider
                .stale_until
                .unwrap()
                .duration_since(provider.refresh_after.unwrap()),
            retain_on_error
        );
    }

    #[tokio::test]
    async fn must_revalidate_disables_stale_metadata_fallback() {
        let initial = discovery_metadata(
            "https://idp.example.com/token-v1",
            "https://idp.example.com/jwks",
        );
        let http = Arc::new(MockHttp::new(vec![
            json_response_with_headers(
                &initial,
                vec![("cache-control".into(), "max-age=0, must-revalidate".into())],
            ),
            empty_jwks_response(),
            HttpResponse {
                status: 503,
                headers: vec![],
                body: vec![],
            },
        ]));
        let client = Client::discover(
            "https://idp.example.com".parse().unwrap(),
            ClientId::new("c").unwrap(),
            None,
            http,
        )
        .await
        .unwrap();
        expire_metadata(&client);

        assert!(client.refresh_metadata_if_stale().await.is_err());
        assert_eq!(
            client.metadata().token_endpoint.as_url().as_str(),
            "https://idp.example.com/token-v1"
        );
    }

    #[tokio::test]
    async fn stale_metadata_retry_is_deferred_and_bounded() {
        let initial = discovery_metadata(
            "https://idp.example.com/token-v1",
            "https://idp.example.com/jwks",
        );
        let unavailable = || HttpResponse {
            status: 503,
            headers: vec![],
            body: vec![],
        };
        let http = Arc::new(MockHttp::new(vec![
            json_response(&initial),
            empty_jwks_response(),
            unavailable(),
            unavailable(),
        ]));
        let client = Client::discover(
            "https://idp.example.com".parse().unwrap(),
            ClientId::new("c").unwrap(),
            None,
            http.clone(),
        )
        .await
        .unwrap();
        expire_metadata(&client);
        let original_stale_until = client.provider.read().unwrap().stale_until;

        client.refresh_metadata_if_stale().await.unwrap();
        client.refresh_metadata_if_stale().await.unwrap();

        assert_eq!(
            client.provider.read().unwrap().stale_until,
            original_stale_until
        );
        assert_eq!(http.responses.lock().unwrap().len(), 1);

        {
            let mut provider = client.provider.write().unwrap();
            provider.stale_until = Some(Instant::now());
            provider.retry_after = None;
        }
        assert!(client.refresh_metadata_if_stale().await.is_err());
        assert!(http.responses.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn forced_metadata_refresh_reports_failure() {
        let initial = discovery_metadata(
            "https://idp.example.com/token-v1",
            "https://idp.example.com/jwks",
        );
        let http = Arc::new(MockHttp::new(vec![
            json_response(&initial),
            empty_jwks_response(),
            HttpResponse {
                status: 503,
                headers: vec![],
                body: vec![],
            },
        ]));
        let client = Client::discover(
            "https://idp.example.com".parse().unwrap(),
            ClientId::new("c").unwrap(),
            None,
            http,
        )
        .await
        .unwrap();

        assert!(client.refresh_metadata().await.is_err());
        assert_eq!(
            client.metadata().token_endpoint.as_url().as_str(),
            "https://idp.example.com/token-v1"
        );
    }

    #[tokio::test]
    async fn disabling_metadata_refresh_wins_during_in_flight_refresh() {
        let initial = discovery_metadata(
            "https://idp.example.com/token-v1",
            "https://idp.example.com/jwks",
        );
        let refreshed = discovery_metadata(
            "https://idp.example.com/token-v2",
            "https://idp.example.com/jwks",
        );
        let http = Arc::new(MockHttp::new(vec![
            json_response(&initial),
            empty_jwks_response(),
            json_response_with_headers(
                &refreshed,
                vec![("cache-control".into(), "max-age=0".into())],
            ),
        ]));
        let client = Client::discover(
            "https://idp.example.com".parse().unwrap(),
            ClientId::new("c").unwrap(),
            None,
            http,
        )
        .await
        .unwrap();

        let (refresh, ()) = tokio::join!(
            biased;
            client.refresh_metadata(),
            async { client.disable_metadata_refresh() },
        );

        assert_eq!(
            refresh.unwrap().token_endpoint.as_url().as_str(),
            "https://idp.example.com/token-v2"
        );
        let provider = client.provider.read().unwrap();
        assert!(provider.metadata_refresh_interval.is_none());
        assert!(provider.refresh_after.is_none());
        assert!(!provider.metadata_needs_refresh());
    }

    #[tokio::test]
    async fn setting_metadata_refresh_interval_wins_during_in_flight_refresh() {
        let initial = discovery_metadata(
            "https://idp.example.com/token-v1",
            "https://idp.example.com/jwks",
        );
        let refreshed = discovery_metadata(
            "https://idp.example.com/token-v2",
            "https://idp.example.com/jwks",
        );
        let http = Arc::new(MockHttp::new(vec![
            json_response(&initial),
            empty_jwks_response(),
            json_response(&refreshed),
        ]));
        let client = Client::discover(
            "https://idp.example.com".parse().unwrap(),
            ClientId::new("c").unwrap(),
            None,
            http,
        )
        .await
        .unwrap();
        client.disable_metadata_refresh();
        client.set_metadata_minimum_cache_duration(Duration::ZERO);

        let (refresh, ()) = tokio::join!(
            biased;
            client.refresh_metadata(),
            async { client.set_metadata_refresh_interval(Duration::ZERO) },
        );

        assert_eq!(
            refresh.unwrap().token_endpoint.as_url().as_str(),
            "https://idp.example.com/token-v2"
        );
        let provider = client.provider.read().unwrap();
        assert_eq!(provider.metadata_refresh_interval, Some(Duration::ZERO));
        assert!(provider.metadata_needs_refresh());
    }

    #[tokio::test]
    async fn setting_metadata_minimum_cache_duration_wins_during_in_flight_refresh() {
        let initial = discovery_metadata(
            "https://idp.example.com/token-v1",
            "https://idp.example.com/jwks",
        );
        let refreshed = discovery_metadata(
            "https://idp.example.com/token-v2",
            "https://idp.example.com/jwks",
        );
        let http = Arc::new(MockHttp::new(vec![
            json_response(&initial),
            empty_jwks_response(),
            json_response_with_headers(
                &refreshed,
                vec![("cache-control".into(), "max-age=0".into())],
            ),
        ]));
        let client = Client::discover(
            "https://idp.example.com".parse().unwrap(),
            ClientId::new("c").unwrap(),
            None,
            http,
        )
        .await
        .unwrap();
        let minimum = Duration::from_secs(3600);

        let (refresh, ()) = tokio::join!(
            biased;
            client.refresh_metadata(),
            async { client.set_metadata_minimum_cache_duration(minimum) },
        );

        assert_eq!(
            refresh.unwrap().token_endpoint.as_url().as_str(),
            "https://idp.example.com/token-v2"
        );
        let provider = client.provider.read().unwrap();
        assert_eq!(provider.metadata_minimum_cache_duration, minimum);
        assert!(!provider.metadata_needs_refresh());
    }

    #[tokio::test]
    async fn jwks_fetcher_forwards_age_header() {
        let http = Arc::new(MockHttp::new(vec![HttpResponse {
            status: 200,
            headers: vec![("AGE".into(), "120".into())],
            body: br#"{"keys":[]}"#.to_vec(),
        }]));
        let fetcher = HttpJwksFetcher { http };

        let response = fetcher.fetch("https://idp.example.com/jwks").await.unwrap();

        assert_eq!(response.age, Some(std::time::Duration::from_secs(120)));
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
    async fn complete_authorization_from_pending_exchanges_without_store() {
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
            http,
        )
        .unwrap();
        let response = AuthorizationResponse::Success {
            code: "AUTH-CODE".into(),
            state: "consumed-state".into(),
            iss: None,
        };
        let pending = PendingAuthRequest {
            state: "consumed-state".into(),
            nonce: "nonce".into(),
            pkce_verifier: None,
            max_age: None,
            redirect_uri: Some("https://app.example.com/cb".into()),
            scopes: vec!["openid".into()],
            created_at: std::time::SystemTime::now(),
        };

        let result = client
            .complete_authorization_from_pending(response, pending)
            .await
            .unwrap();

        assert_eq!(result.callback_state, "consumed-state");
        assert_eq!(result.token_response.access_token.as_str(), "AT-1");
    }

    #[tokio::test]
    async fn provider_error_consumes_pending_state() {
        let http = Arc::new(MockHttp::new(vec![]));
        let client = Client::from_parts(
            provider_metadata(),
            ClientId::new("my-client").unwrap(),
            Some(ClientSecret::new("secret").unwrap()),
            http,
        )
        .unwrap();
        let kv = MockKv::new();
        let state = "denied-state";
        let key = PendingAuthRequest::key_for(state);
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
                &key,
                serde_json::to_vec(&pending).unwrap(),
                PendingAuthRequest::DEFAULT_TTL,
            )
            .await
            .unwrap()
        );

        let error = client
            .complete_authorization(
                "error=access_denied&error_uri=https%3A%2F%2Fop.example.com%2Fdenied&state=denied-state&iss=https%3A%2F%2Fidp.example.com",
                &kv,
            )
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            OidcError::AuthorizationResponse(CallbackError::ProviderError {
                error,
                error_uri: Some(error_uri),
                state,
                iss: Some(iss),
                ..
            }) if error == "access_denied"
                && error_uri == "https://op.example.com/denied"
                && state == "denied-state"
                && iss == "https://idp.example.com"
        ));
        assert!(!kv.contains(&key));
    }

    #[tokio::test]
    async fn provider_error_rejects_wrong_callback_issuer_after_consuming_state() {
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
        let kv = MockKv::new();
        let state = "denied-state";
        let key = PendingAuthRequest::key_for(state);
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
                &key,
                serde_json::to_vec(&pending).unwrap(),
                PendingAuthRequest::DEFAULT_TTL,
            )
            .await
            .unwrap()
        );

        let error = client
            .complete_authorization(
                "error=access_denied&state=denied-state&iss=https%3A%2F%2Fattacker.example.com",
                &kv,
            )
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            OidcError::AuthorizationResponse(CallbackError::IssuerMismatch { .. })
        ));
        assert!(!kv.contains(&key));
    }

    #[tokio::test]
    async fn provider_error_requires_advertised_callback_issuer_after_consuming_state() {
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
        let kv = MockKv::new();
        let state = "denied-state";
        let key = PendingAuthRequest::key_for(state);
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
                &key,
                serde_json::to_vec(&pending).unwrap(),
                PendingAuthRequest::DEFAULT_TTL,
            )
            .await
            .unwrap()
        );

        let error = client
            .complete_authorization("error=access_denied&state=denied-state", &kv)
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            OidcError::AuthorizationResponse(CallbackError::Missing("iss"))
        ));
        assert!(!kv.contains(&key));
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
        let kv = MockKv::new();
        let key = PendingAuthRequest::key_for("state-1");
        let pending = PendingAuthRequest {
            state: "state-1".into(),
            nonce: "nonce".into(),
            pkce_verifier: None,
            max_age: None,
            redirect_uri: Some("https://app.example.com/cb".into()),
            scopes: vec!["openid".into()],
            created_at: std::time::SystemTime::now(),
        };
        assert!(
            kv.put_if_absent(
                &key,
                serde_json::to_vec(&pending).unwrap(),
                PendingAuthRequest::DEFAULT_TTL,
            )
            .await
            .unwrap()
        );

        let err = client
            .complete_authorization(
                "code=AUTH-CODE&state=state-1&iss=https%3A%2F%2Fattacker.example.com",
                &kv,
            )
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            OidcError::AuthorizationResponse(
                crate::flow::callback::CallbackError::IssuerMismatch { .. }
            )
        ));
        assert!(!kv.contains(&key));
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
        let kv = MockKv::new();
        let key = PendingAuthRequest::key_for("state-1");
        let pending = PendingAuthRequest {
            state: "state-1".into(),
            nonce: "nonce".into(),
            pkce_verifier: None,
            max_age: None,
            redirect_uri: Some("https://app.example.com/cb".into()),
            scopes: vec!["openid".into()],
            created_at: std::time::SystemTime::now(),
        };
        assert!(
            kv.put_if_absent(
                &key,
                serde_json::to_vec(&pending).unwrap(),
                PendingAuthRequest::DEFAULT_TTL,
            )
            .await
            .unwrap()
        );

        let err = client
            .complete_authorization("code=AUTH-CODE&state=state-1", &kv)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            OidcError::AuthorizationResponse(crate::flow::callback::CallbackError::Missing("iss"))
        ));
        assert!(!kv.contains(&key));
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

    #[tokio::test]
    async fn jwks_accessor_returns_shared_cache() {
        let http = Arc::new(MockHttp::new(vec![empty_jwks_response()]));
        let client = Client::from_parts(
            provider_metadata(),
            ClientId::new("c").unwrap(),
            None,
            http.clone() as Arc<dyn AsyncHttpClient>,
        )
        .unwrap();
        let first = client.jwks();
        let second = client.jwks();

        assert!(first.keys().await.unwrap().is_empty());
        assert!(second.keys().await.unwrap().is_empty());
        assert!(http.responses.lock().unwrap().is_empty());
        assert_eq!(
            client.metadata().jwks_uri.as_url().as_str(),
            "https://idp.example.com/jwks"
        );
    }
}
