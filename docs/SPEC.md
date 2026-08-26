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
  types/
    mod.rs
    url.rs               newtype URLs with FromStr
    identifiers.rs       ClientId, Scope, Nonce, State, ...
  transport/
    mod.rs
    http.rs              AsyncHttpClient trait + request/response types
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

## 6. HTTP / KV Transport

Both are traits with `BoxFuture<'_, T>` returns. The crate ships no
default implementation; examples provide `reqwest` adapters.

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
- [x] Unit tests for `fill_bytes` (length, non-zero, two consecutive calls differ) and `sha256` (FIPS 180-4 known-answer vectors)

### 8.3 Types

- [x] `types::url` newtypes: `IssuerUrl`, `AuthUrl`, `TokenUrl`, `UserInfoUrl`, `EndSessionUrl`, `JwksUrl`, `RedirectUrl`
- [x] `types::identifiers`: `ClientId`, `ClientSecret`, `Scope`, `Nonce`, `State`, `PkceCodeVerifier`, `PkceCodeChallenge`, `ResponseType`, `GrantType`, `AuthPrompt`, `ResponseMode`, `TokenEndpointAuthMethod`

### 8.4 Transport

- [x] `transport::http::AsyncHttpClient` trait + `HttpRequest` / `HttpResponse`
- [x] `transport::kv::AsyncKvStore` trait + `KvError`

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
- [x] `flow::callback::parse_authorization_response` (query and fragment modes)
- [x] `flow::token::CodeTokenRequest` (Basic + body auth, PKCE verifier)
- [x] `flow::token::RefreshTokenRequest`
- [x] `flow::logout::build_end_session_url` (id_token_hint, post_logout_redirect_uri, state)
- [x] `Client::complete_authorization` second-leg helper
- [x] `Client::exchange_refresh_token`

### 8.8 Token verification

- [x] `token::verify::IdTokenVerifier` with all checks in section 5
- [x] `token::response::TokenResponse` with `AccessToken`, `RefreshToken`, `IdToken`
- [x] `token::userinfo::UserInfo` with signed-JWT body support
- [x] `Client::fetch_userinfo` with `Accept: application/json, application/jwt;q=0.9` and Content-Type dispatch

### 8.9 Examples and docs

- [ ] `examples/authorization_code.rs` (single-instance, no KV)
- [ ] `examples/authorization_code_multi_instance.rs` (with in-memory KV adapter)
- [ ] `examples/reqwest_adapter.rs` showing the HTTP / KV trait impls
- [ ] `examples/refresh_token.rs`
- [ ] `examples/logout.rs`
- [ ] `examples/custom_claims.rs`
- [ ] Top-level `README.md` with quickstart

### 8.10 Testing

- [x] Unit tests for all wrapper functions
- [ ] Integration test against a mock OIDC server (e.g. `oidc-testprovider` from mozilla-django-oidc) behind a feature flag
- [ ] Snapshot tests for `parse_authorization_response`
