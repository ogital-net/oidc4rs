# oidc4rs Specification

Status: living document. Update the checklist as items land; do not edit
historical entries.

## 1. Goals

Provide a Rust OpenID Connect relying-party library on top of the `jose4rs`
JOSE crate. The library must:

- Run as multiple instances behind a load balancer without session affinity.
- Validate ID tokens per RFC 7519 and OIDC Core 1.0.
- Be runtime-agnostic (no tokio / async-std in the public API).
- Have no transitive dependency on `ring`, `sha2`, `rand_core`, or
  `aws-lc-rs` in the type signature of our public API. All randomness and
  hashing go through `aws-lc-sys` / `boring-sys` FFI, reusing the
  cryptography backend selected by the consumer.

## 2. Non-Goals (v1)

- DPoP (RFC 9445)
- Backchannel logout (RP receiver)
- Client-initiated backchannel authentication (CIBA)
- Dynamic client registration
- FAPI profile
- Resource-server (introspection-only) mode
- Acting as an OpenID Provider

Note: "Resource-server (introspection-only) mode" refers specifically
to RFC 7662 token introspection. Verifying a JWT bearer access token
at a resource server is *not* a non-goal: the library exposes
`Client::jwks()` so the same per-OP JWKS cache can be reused by
resource-server code that performs the JWS check via `jose4rs`
directly. The library deliberately does not ship its own access-token
verifier struct or claim-extraction helpers; the resource-server
shape is "handles, not opinions".

## 3. Cryptography

### 3.1 Backend selection

Mirror `jose4rs`: a single backend feature must be enabled. The mutually
exclusive pair is `aws-lc` (default) and `boring`. Compile-time errors fire
if neither or both are enabled. Both features are passed through to the
`jose4rs` dependency.

### 3.2 Direct FFI surface

We call into the backend via `aws-lc-sys` / `boring-sys` directly, behind
our own thin wrappers in `src/crypto`. The wrappers live in `pub(crate)`
modules so the type signatures of public API never expose FFI types.

| Wrapper | Backing function | Used for |
|---|---|---|
| `crypto::rand::fill_bytes` | `RAND_bytes` | Nonces, state, PKCE verifier, opaque session ids |
| `crypto::hash::sha256` | `SHA256` | PKCE S256 challenge, `at_hash` computation |
| `crypto::ct::ct_equals` | `CRYPTO_memcmp` | Constant-time nonce equality in `IdTokenVerifier::verify` |

The raw `SHA256` one-shot C symbol is chosen over `EVP_Digest` because:

- Under the hood both aws-lc and BoringSSL resolve `SHA256` to the
  same `EVP_DigestInit_ex` + `EVP_DigestUpdate` + `EVP_DigestFinal_ex`
  chain. Calling the raw symbol skips the per-call `EVP_MD_CTX`
  allocation, method-table dispatch, and function-pointer overhead
  that `EVP_Digest` adds.
- Matches the fast-path used by jose4rs's own
  `crypto::digest::digest_buf`.
- Both backends expose the `SHA256` symbol through their FFI crates
  with the same signature: `uint8_t *SHA256(const uint8_t *data,
  size_t len, uint8_t out[SHA256_DIGEST_LENGTH])`.

Streaming hashers can be added in the future by wrapping
`EVP_DigestInit_ex` / `EVP_DigestUpdate` / `EVP_DigestFinal_ex` in a
`Send + Sync` newtype, the same shape jose4rs uses internally.

### 3.3 Why direct FFI

- `jose4rs` keeps its `crypto` module `pub(crate)`. Reusing it requires
  forking.
- Pulling `ring`, `sha2`, `rand_core`, or `aws-lc-rs` would either duplicate
  the audited primitives or expose them in our public types. Both are
  unacceptable per Goal 4.
- `aws-lc-sys` and `boring-sys` are pure FFI bindings; they do not pull a
  Rust-side crypto abstraction into our public API. Cargo unifies the
  version with `jose4rs`'s, so we share one compiled libcrypto.

### 3.4 Error handling in FFI wrappers

Verified against aws-lc (`crypto/fipsmodule/rand/rand.c`,
`crypto/fipsmodule/sha/sha256.c`) and BoringSSL FIPS
(`deps/boringssl-fips/crypto/fipsmodule/sha/sha256.c`):

- `RAND_bytes` returns 1 unconditionally; the *real* failure mode is an
  internal `abort()` from `rand_bytes_impl` on thread-local RNG state
  initialization failure or OOM. This is not catchable from Rust, so
  the wrapper uses `assert!(result == 1)` for documentation and lets
  the `abort()` propagate.
- The raw `SHA256(data, len, out)` one-shot:
  - BoringSSL: does not take the FIPS service-indicator lock, never
    aborts, never returns NULL.
  - aws-lc: takes the FIPS lock. The lock overflow path aborts but
    the source itself calls it "impossible on a 64-bit system". Same
    theoretical abort risk as `RAND_bytes`. NULL return is asserted
    on, per [`AGENTS.md`](AGENTS.md).
- No `unwrap`, `expect`, or `panic!` on attacker-controlled paths.

## 4. Module Layout

```
src/
  lib.rs                 crate-root re-exports
  error.rs               OidcError enum
  crypto/
    mod.rs               pub(crate) re-exports
    backend.rs           cfg-gated selection of aws-lc vs boring
    rand.rs              fill_bytes wrapper
    hash.rs              sha256 wrapper
    ct.rs                ct_equals wrapper
  types/
    mod.rs
    url.rs               newtype URLs with FromStr
    identifiers.rs       ClientId, Scope, Nonce, State, ...
  transport/
    mod.rs
    http.rs              AsyncHttpClient trait + request/response types
    hyper_client.rs      optional hyper + hyper-rustls AsyncHttpClient (`hyper` feature)
    kv.rs                AsyncKvStore trait for second-leg state
  metadata/
    mod.rs
    provider.rs          ProviderMetadata
    discovery.rs         async discover()
  claims.rs              OidcClaims extension trait on jose4rs JwtClaims
  flow/
    mod.rs
    authorize.rs         AuthorizeUrlBuilder, AuthRequestState
    callback.rs          parse_authorization_response
    token.rs             CodeTokenRequest, RefreshTokenRequest
    logout.rs            build_end_session_url
  token/
    mod.rs
    response.rs          TokenResponse, AccessToken, RefreshToken
    verify.rs            IdTokenVerifier
    userinfo.rs          UserInfo + signed-JWT support
  client.rs              Client struct
```

## 5. Validation Responsibilities

ID-token verification (in `token::verify::IdTokenVerifier::verify`):

| Check | Source of truth |
|---|---|
| Signature | `jose4rs::jws::JsonWebSignature::verify_signature` |
| `alg` matches verifier's allowed list | verifier config |
| `iss` equals expected issuer | verifier config |
| `aud` contains expected client id | verifier config |
| `azp` equals client id if `aud` has multiple values | verifier config |
| `exp` is in the future (with configurable skew) | `JwtConsumerBuilder` |
| `iat` is in the past (with configurable skew) | `JwtConsumerBuilder` |
| `nbf` is in the past (with configurable skew) | `JwtConsumerBuilder` |
| `nonce` matches second-leg state | second-leg flow |
| `at_hash` (hybrid flow) | computed via `crypto::hash::sha256` |
| JWKS `kid` lookup | `jose4rs::jwk::VerificationJwkSelector` |
| JWKS refresh on unknown `kid` | `jose4rs::jwk::AsyncHttpsJwks` |

Nonce comparison is performed via constant-time equality on the
SHA-256 digests of the two strings (rather than the strings
themselves) to defeat timing oracles that recover the secret
byte-by-byte. The convention follows `openidconnect-rs`; the secret
being compared is the cryptographic nonce, not user input.

## 6. HTTP / KV Transport

Both are traits with `BoxFuture<'_, T>` returns. `AsyncKvStore` exposes
create-if-absent with a TTL and atomic take operations. The built-in
`InMemoryKvStore` uses a mutex-protected hash map for single-instance
applications. Multi-instance applications provide a shared implementation;
for example, Redis-compatible stores map the operations to `SET NX EX` and
`GETDEL`.

Examples provide `reqwest` adapters for `AsyncHttpClient`. An optional
`AsyncHttpClient` implementation,
`transport::hyper_client::HyperHttpClient`, ships behind the `hyper`
feature for callers who want a built-in client instead of wiring
`reqwest` themselves. It depends on a tokio runtime at call sites;
see AGENTS.md's Async section for why this is an accepted exception
to the crate's no-tokio-in-dependencies rule.

## 7. Coding Conventions

See `AGENTS.md` at the repository root.

## 8. Progress Checklist

Mark items `[x]` when merged to `main`. Sub-items under a heading become
children once their parent is done.

### 8.1 Crate skeleton

- [x] Cargo.toml with `jose4rs` git-rev dep + optional `aws-lc-sys`/`boring-sys`
- [x] `src/lib.rs` re-exports
- [x] `src/error.rs` with `OidcError`
- [x] Build cleanly with `cargo build` and `cargo build --no-default-features --features boring`
- [x] `cargo clippy --all-targets --all-features -- -D warnings` passes

  Run separately per backend (`aws-lc` and `boring`) because the
  `compile_error!` guard rejects enabling both at once.
- [x] `cargo fmt --check` passes

### 8.2 Cryptography layer

- [x] `crypto::backend` cfg module selecting `aws-lc-sys` or `boring-sys`
- [x] `crypto::rand::fill_bytes` wrapper with `RAND_bytes`
- [x] `crypto::hash::sha256` wrapper with `SHA256`
- [x] `crypto::ct::ct_equals` wrapper with `CRYPTO_memcmp`
- [x] Unit tests for `fill_bytes` (length, non-zero, two consecutive calls differ) and `sha256` (FIPS 180-4 known-answer vectors) and `ct_equals` (equal, first-byte mismatch, last-byte mismatch, length mismatch, empty-vs-empty, empty-vs-non-empty)

### 8.3 Types

- [x] `types::url` newtypes: `IssuerUrl`, `AuthUrl`, `TokenUrl`, `UserInfoUrl`, `EndSessionUrl`, `JwksUrl`, `RedirectUrl`
- [x] `types::identifiers`: `ClientId`, `ClientSecret`, `Scope`, `Nonce`, `State`, `PkceCodeVerifier`, `PkceCodeChallenge`, `ResponseType`, `GrantType`, `AuthPrompt`, `ResponseMode`, `TokenEndpointAuthMethod`

### 8.4 Transport

- [x] `transport::http::AsyncHttpClient` trait + `HttpRequest` / `HttpResponse`
- [x] `transport::kv::AsyncKvStore` trait + `KvError` + `InMemoryKvStore`
- [x] `transport::hyper_client::HyperHttpClient` -- optional hyper + hyper-rustls `AsyncHttpClient` behind the `hyper` feature

### 8.5 Metadata and discovery

- [x] `metadata::ProviderMetadata` with all OIDC Discovery fields as `Option<...>`
- [x] `metadata::discover()` returns `(ProviderMetadata, JsonWebKeySet)`
- [x] Issuer equality check against input

### 8.6 Claims

- [x] `claims::OidcClaims` extension trait on `jose4rs::jwt::JwtClaims` with typed accessors for `at_hash`, `c_hash`, `auth_time`, `acr`, `amr`, `azp`, `nonce`

### 8.7 Client and flows

- [x] `client::Client::discover` end-to-end
- [x] `client::Client::from_parts` for manual setup
- [x] `flow::authorize::AuthorizeUrlBuilder` (scope, prompt, max_age, acr, login_hint, ui_locales, PKCE, extra params)
- [ ] `flow::authorize::AuthorizeUrlBuilder` -- add `display`, `claims_locales` (parity with `temp/openid` and `temp/openidconnect-rs`; see section 9.1)
- [x] `flow::callback::parse_authorization_response` (query and fragment modes)
- [ ] `flow::callback::parse_authorization_response` auto-detects leading `?` / `#` so callers do not strip (see section 9.9)
- [x] `flow::token::CodeTokenRequest` (Basic + body auth, PKCE verifier)
- [x] `flow::token::RefreshTokenRequest`
- [x] `flow::logout` -- expose `Client::build_end_session_url` wrapping `EndSessionUrlBuilder` (see section 9.7)
- [x] `flow::logout::EndSessionUrlBuilder` -- add `client_id`, `logout_hint`, `ui_locales` (see section 9.7)
- [x] `Client::complete_authorization` second-leg helper
- [x] `Client::exchange_refresh_token`

### 8.8 Token verification

- [x] `token::verify::IdTokenVerifier` with all checks in section 5
- [x] `token::verify::IdTokenVerifier::verify` -- constant-time `nonce` comparison via `CRYPTO_memcmp` (see section 5 footnote)
- [x] `IdTokenVerifier::from_metadata` narrows `allowed_algs` from `metadata.id_token_signing_alg_values_supported`; `Client::verifier()` is the convenience constructor (issuer from discovery, audience from `client_id`, trailing slash stripped from issuer so it compares byte-equal to the OP's `iss` claim)
- [x] `Client::jwks()` exposes the per-Client `AsyncHttpsJwks` cache so resource-server code that verifies bearer JWT access tokens with `jose4rs` directly shares the same key fetches, `kid` lookups, and `Cache-Control` state. `AsyncHttpsJwks` and `AsyncJwksFetcher` are re-exported at the crate root for that purpose.
- [x] `token::response::TokenResponse` with `AccessToken`, `RefreshToken`, `IdToken`
- [ ] `token::response::TokenResponse` -- record `expires_in` as `Option<Instant>` for downstream refresh logic
- [x] `token::userinfo::UserInfo` with signed-JWT body support
- [x] `Client::fetch_userinfo` with `Accept: application/json, application/jwt;q=0.9` and Content-Type dispatch
- [ ] `Client::fetch_userinfo` -- assert `sub` matches the verified ID token when supplied (see section 9.5)
- [ ] `claims::OidcClaims` -- `AdditionalClaims` trait so callers can decode typed custom fields (see section 9.8)

### 8.9 Examples and docs

- [ ] `examples/authorization_code.rs` (single-instance, no KV)
- [ ] `examples/authorization_code_multi_instance.rs` (with in-memory KV adapter)
- [ ] `examples/reqwest_adapter.rs` showing the HTTP / KV trait impls
- [ ] `examples/refresh_token.rs`
- [x] `examples/logout.rs`
- [x] `examples/hyper_adapter.rs` showing the `hyper` feature's `AsyncHttpClient`
- [ ] `examples/custom_claims.rs`
- [ ] Top-level `README.md` with quickstart

### 8.10 Testing

- [x] Unit tests for all wrapper functions
- [ ] Integration test against a mock OIDC server (e.g. `oidc-testprovider` from mozilla-django-oidc) behind a feature flag
- [ ] Snapshot tests for `parse_authorization_response`

## 9. Parity Status (vs. `temp/openid` and `temp/openidconnect-rs`)

Two reference clones were audited in 2026-08 against this spec.
Items below classify the gaps as **Add** (work pending for v1.1),
**Defer** (intentionally out of scope per section 2), or **Already**
(present).

### 9.1 Authorization request parameters

| Parameter | Status | Notes |
|---|---|---|
| `scope` (must include `openid`) | Already | `Client::authorize` enforces |
| `state`, `nonce` | Already | Random, persisted in `AuthRequestState` |
| PKCE S256 | Already | `AuthorizeUrlBuilder::pkce_s256` |
| `prompt` | Already | `AuthPrompt` enum (None/Login/Consent/SelectAccount) |
| `max_age` | Already | `Duration` |
| `id_token_hint` | Already | builder method |
| `login_hint` | Already | builder method |
| `acr_values` | Already | builder method |
| `ui_locales` | Already | builder method |
| `response_mode` (Query/Fragment/FormPost) | Already | enum |
| `claims_locales` | Add | Both clones support; builder has no method |
| `display` (page/popup/touch/wap) | Add | Both clones support; not in v1 builder |
| Extra params | Already | `extra_param` covers JAR-style `request` and PAR-style `request_uri` |

### 9.2 Token request

| Feature | Status | Notes |
|---|---|---|
| Authorization-code exchange | Already | `Client::exchange_code` + `CodeTokenRequest` |
| Refresh-token exchange | Already | `Client::exchange_refresh_token` + `RefreshTokenRequest` |
| Basic and body client auth | Already | `TokenAuthMethod::from_metadata` |
| PKCE verifier on the wire | Already | wired through `complete_authorization` |
| ROPC / Client Credentials / Device Code | Defer | Spec section 2 |
| Token Exchange (RFC 8693) | Defer | Spec section 2 |

### 9.3 Token response

| Feature | Status | Notes |
|---|---|---|
| `access_token`, `refresh_token`, `id_token` parsing | Already | `TokenResponse` |
| `expires_in` / clock-skewed expiry tracking | Add | openid has `TemporalBearerGuard`; we ignore `expires_in` after parse |
| `auto-refresh` helper (`ensure_token`) | Defer | Convenience, not protocol |

### 9.4 ID-token verification

| Feature | Status | Notes |
|---|---|---|
| All SPEC section 5 checks | Already | Single call site in `IdTokenVerifier::verify` |
| JWKS kid refresh on miss | Already | `AsyncHttpsJwks::select_verification_key` |
| Constant-time nonce compare | Already | `crypto::ct::ct_equals` wrapping `CRYPTO_memcmp`; called from `check_nonce` |
| Algorithm allow-list seeded from discovery | Already | `IdTokenVerifier::from_metadata` and `Client::verifier()` thread `metadata.id_token_signing_alg_values_supported`; `Some(empty)` is honored as "reject all" to surface misconfigured OPs loudly; `None` falls back to the OIDC Core default `id_token` `alg` set |
| Insecure verify (skip signature) | Defer | OpenSSF discourages; documentation only |

### 9.5 UserInfo

| Feature | Status | Notes |
|---|---|---|
| JSON body | Already | `UserInfo::from_json` |
| Signed-JWT body | Already | `UserInfo::from_signed_jwt` |
| `Accept` negotiation (`application/json, application/jwt;q=0.9`) | Already | `Client::fetch_userinfo` |
| `sub` mismatch with ID token | Add | openid has `Userinfo::MismatchSubject` |
| Custom claim decoding into typed structs | Add | See section 9.8 |

### 9.6 Discovery

| Feature | Status | Notes |
|---|---|---|
| Standard fields (`ProviderMetadata`) | Already | `metadata::ProviderMetadata` |
| Issuer equality check | Already | `metadata::discover` |
| JWKS fetch | Already | `AsyncHttpsJwks`; `Client::jwks()` accessor lets resource-server code reuse the same cache for bearer-JWT verification via `jose4rs` directly |
| Forward-compatible unknown-field capture | Already | `extra: serde_json::Map` flatten |
| `AdditionalProviderMetadata` trait | Add | openidconnect-rs has; we keep the flat map |
| JWKS TTL / refresh hint caching | Already | `AsyncHttpsJwks` honors `cache-control` |
| `IssuerUrl::join(".well-known/openid-configuration")` | Already | `metadata::discover` does it |

### 9.7 Logout

| Feature | Status | Notes |
|---|---|---|
| RP-initiated logout URL builder | Already | `Client::build_end_session_url()` returns `EndSessionUrlBuilder` |
| `id_token_hint` | Already | builder |
| `post_logout_redirect_uri` | Already | builder; typed `PostLogoutRedirectUrl` |
| `state` | Already | builder; auto-generated when `post_logout_redirect_uri` is set |
| `client_id` | Already | builder |
| `logout_hint` | Already | builder; typed `LogoutHint` |
| `ui_locales` (repeated) | Already | builder; `add_ui_locale` joins with space |
| Backchannel logout (RP) | Defer | Spec section 2 |
| Front-channel logout (RP) | Defer | Spec section 2 (browser iframe is the OP's job; we do not deliver frames) |

### 9.8 Custom claims (extension surface)

| Feature | Status | Notes |
|---|---|---|
| Extra fields on `UserInfo` | Already | `UserInfo.extra: HashMap<String, Value>` |
| Extra fields on ID-token claims | Add | openid has `CustomClaims` trait; openidconnect-rs has `AdditionalClaims`. SPEC §8.6 only covers typed accessors, not extension fields |
| Custom token response fields | Already | `TokenResponse` round-trips unknown keys via `extra` flatten |

### 9.9 Callback parsing

| Feature | Status | Notes |
|---|---|---|
| `code` / `state` / `iss` | Already | `parse_authorization_response` |
| `error` / `error_description` | Already | `CallbackError::ProviderError` |
| Auto-detect query vs fragment at the string level | Add | Both clones accept either; we require the caller to strip the leading `?`/`#` |
| Snapshot tests | Add | SPEC §8.10 already calls this out |

### 9.10 Transport and crypto

| Feature | Status | Notes |
|---|---|---|
| `AsyncHttpClient` trait | Already | `transport::http` |
| `AsyncKvStore` trait | Already | Atomic create and take; built-in process-local adapter |
| Examples wiring reqwest + Redis-like adapters | Partial | SPEC §8.9 pending |
| Direct FFI to aws-lc / boring, no `ring`/`sha2`/`rand_core` in public types | Already | Unique to oidc4rs |

### 9.11 Error model

| Feature | Status | Notes |
|---|---|---|
| Single crate-wide `OidcError` | Already | openidconnect-rs has 5+ per-feature enums; we have one |
| `From<jose4rs::error::JoseError>` and `From<InvalidJwtError>` | Already | wired in `error.rs` |

### 9.12 Testing

| Feature | Status | Notes |
|---|---|---|
| Unit tests for all wrapper functions | Already | 78 tests passing on both backends |
| Integration test against a mock OP | Add | SPEC §8.10 calls this out |
| Snapshot tests for callback parsing | Add | SPEC §8.10 |

## 10. v1.1 Roadmap (post-1.0)

Items marked **Add** in section 9 are candidates. Ordered roughly
by impact and dependency order:

1. **Custom claims trait** (`AdditionalClaims`). Pairs with
   `IdTokenVerifier::verify` returning a typed `IdTokenClaims<AC>`
   instead of bare `JwtClaims`. Closes the largest ergonomic gap
   with `openidconnect-rs`.
2. **`Client::build_end_session_url`** wrapping the existing
   `EndSessionUrlBuilder`. Required for SPEC §8.7 conformance and
   the logout example. (Done -- returns the builder directly, no
   intermediate wrapper.)
3. **Logout extension params** (`client_id`, `logout_hint`,
   `ui_locales`) added to the builder. (Done -- typed `LogoutHint`
   and `PostLogoutRedirectUrl` newtypes; `add_ui_locale` is
   repeatable and joins with space per OIDC Core 2.0.)
4. **Auth-request extension params** (`display`, `claims_locales`)
   added to the builder.
5. **Constant-time nonce comparison** in `IdTokenVerifier`. See
   section 5 footnote. (Done -- `crypto::ct::ct_equals` wrapping
   `CRYPTO_memcmp`; called from `token::verify::check_nonce`.)
6. **Auto-`sub` check** in `Client::fetch_userinfo`: compare the
   `sub` claim against the ID-token's `sub` when a verifier is
   supplied.
7. **Algorithm allow-list from discovery**: `Client::discover`
   auto-narrows `IdTokenVerifier::allowed_algs` to
   `metadata.id_token_signing_alg_values_supported`. New convenience
   constructor `Client::verifier()` that returns the narrowed
   verifier. (Done -- `IdTokenVerifier::from_metadata` plus
   `Client::verifier`; issuer pulled from discovery with the
   trailing slash stripped so it byte-matches the OP's `iss`
   claim; `Some(empty)` is honored as "reject every alg" to
   surface a misconfigured OP, `None` falls back to
   `DEFAULT_ALLOWED_ALGS`. Six new tests in `token::verify::tests`.)
8. **`parse_authorization_response`** accepts either a query string
   or a leading-`#`-stripped fragment unchanged. SPEC §8.10
   snapshot tests added at the same time.
9. **Examples** (SPEC §8.9) and **integration tests** (SPEC §8.10).
   Pulled from the same reference clones so the examples double as
   compatibility documentation.
10. **`expires_in` parsing**: `TokenResponse` records expiry as
    `Option<Instant>`; `TemporalBearerGuard`-style convenience is
    deferred until requested.

## 11. Open Questions

- Mock OP for integration tests: pure-Rust (`wiremock` + `axum`,
  CI stays Rust-only) vs Python `oidc-testprovider`. Same question
  as in [oidc4rs-roadmap-2026-08.md](../memories/repo/oidc4rs-roadmap-2026-08.md).
- Should `AdditionalClaims` be required or optional at the API
  level? `openidconnect-rs` uses a 17-parameter typestate; we
  prefer one generic on `IdTokenClaims<AC>` to keep `Client`
  unparameterized.
- Snapshot tests: `insta` (dev-dep) vs hand-rolled string compare.
