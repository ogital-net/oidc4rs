//! `AsyncHttpClient` wiring for `transport::hyper_client::HyperHttpClient`.
//!
//! Unlike the other examples this one needs a tokio runtime, because
//! `HyperHttpClient` depends on `hyper-util`'s tokio-based connector
//! (see AGENTS.md's Async section). It requires the `hyper` feature.
//!
//! Run with:
//!
//! ```text
//! cargo run --example hyper_adapter --features hyper
//! ```
//!
//! This performs real discovery against the issuer given as the first
//! CLI argument (default: `https://accounts.google.com`) and prints
//! the resolved token endpoint.

use std::env;
use std::str::FromStr;
use std::sync::Arc;

use oidc4rs::OidcError;
use oidc4rs::client::Client;
use oidc4rs::transport::hyper_client::HyperHttpClient;
use oidc4rs::types::{ClientId, IssuerUrl};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), OidcError> {
    let issuer = env::args()
        .nth(1)
        .unwrap_or_else(|| "https://accounts.google.com".to_owned());

    let http = Arc::new(HyperHttpClient::new()?);

    let client = Client::discover(
        IssuerUrl::from_str(&issuer)?,
        ClientId::new("rp-example")?,
        None,
        http,
    )
    .await?;

    println!("token_endpoint = {}", client.metadata().token_endpoint);

    Ok(())
}
