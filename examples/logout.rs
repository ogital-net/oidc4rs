//! RP-initiated logout example.
//!
//! Builds an OIDC end-session URL for a previously-authenticated
//! user. Demonstrates every parameter the builder supports and
//! prints the result.
//!
//! The example uses `Client::from_parts` so no network or HTTP
//! client is required -- it is a pure builder exercise. To plug it
//! into a real relying party, swap the metadata source for
//! `Client::discover(...)` and pass the ID token you received from
//! the token endpoint.
//!
//! Run with:
//!
//! ```text
//! cargo run --example logout
//! ```
//!
//! Expected output (the random `state` value will differ on every
//! run):
//!
//! ```text
//! end_session_url = https://op.example.com/logout?id_token_hint=...&state=...
//! echoed_state = <random>
//! ```

use std::str::FromStr;
use std::sync::Arc;

use oidc4rs::OidcError;
use oidc4rs::client::Client;
use oidc4rs::metadata::ProviderMetadata;
use oidc4rs::transport::http::{AsyncHttpClient, HttpRequest, HttpResponse};
use oidc4rs::types::{
    AuthUrl, ClientId, EndSessionUrl, IssuerUrl, JwksUrl, LogoutHint, PostLogoutRedirectUrl,
    TokenUrl, UserInfoUrl,
};

/// No-op HTTP client. `Client::from_parts` accepts any
/// `AsyncHttpClient` even though this example never hits the
/// network.
struct NoopHttp;

impl AsyncHttpClient for NoopHttp {
    fn execute(
        &self,
        _req: HttpRequest,
    ) -> oidc4rs::transport::http::BoxFuture<'_, Result<HttpResponse, OidcError>> {
        Box::pin(async {
            Ok(HttpResponse {
                status: 200,
                headers: vec![],
                body: vec![],
            })
        })
    }
}

fn main() -> Result<(), OidcError> {
    let metadata = ProviderMetadata {
        issuer: IssuerUrl::from_str("https://op.example.com")?,
        authorization_endpoint: AuthUrl::from_str("https://op.example.com/authorize")?,
        token_endpoint: TokenUrl::from_str("https://op.example.com/token")?,
        userinfo_endpoint: Some(UserInfoUrl::from_str("https://op.example.com/userinfo")?),
        jwks_uri: JwksUrl::from_str("https://op.example.com/jwks")?,
        end_session_endpoint: Some(EndSessionUrl::from_str("https://op.example.com/logout")?),
        registration_endpoint: None,
        scopes_supported: None,
        response_types_supported: vec!["code".into()],
        subject_types_supported: None,
        id_token_signing_alg_values_supported: None,
        grant_types_supported: None,
        token_endpoint_auth_methods_supported: None,
        userinfo_signing_alg_values_supported: None,
        extra: serde_json::Map::new(),
    };

    let client = Arc::new(Client::from_parts(
        metadata,
        ClientId::new("rp-example")?,
        None,
        Arc::new(NoopHttp),
    )?);

    // In a real relying party this string comes from the
    // `id_token` field of the token response.
    let id_token = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImRlYWQtYmVlZiJ9.payload.sig";

    let post_logout_redirect = PostLogoutRedirectUrl::from_str("https://rp.example.com/goodbye")?;

    let (url, state) = client
        .build_end_session_url()
        .id_token_hint(id_token)
        .post_logout_redirect_uri(post_logout_redirect)
        .client_id(ClientId::new("rp-example")?)
        .logout_hint(LogoutHint::new("alice@example.com")?)
        .add_ui_locale("en-US")
        .add_ui_locale("fr-FR")
        .build()?;

    println!("end_session_url = {url}");
    println!(
        "echoed_state = {}",
        state.as_ref().map(|s| s.as_str()).unwrap_or("<none>")
    );

    Ok(())
}
