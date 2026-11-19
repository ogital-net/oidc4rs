//! Test-only relying party for the browser interop harness.

use std::collections::HashMap;
use std::convert::Infallible;
use std::env;
use std::error::Error;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, header};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use oidc4rs::client::Client;
use oidc4rs::flow::authorize::PendingAuthRequest;
use oidc4rs::flow::callback::parse_authorization_response;
use oidc4rs::transport::hyper_client::HyperHttpClient;
use oidc4rs::types::{ClientId, ClientSecret, RedirectUrl, Scope};

type Body = Full<Bytes>;
type HarnessError = Box<dyn Error + Send + Sync>;

struct RelyingParty {
    client: Arc<Client>,
    redirect_uri: RedirectUrl,
    pending: Mutex<HashMap<String, PendingAuthRequest>>,
}

impl RelyingParty {
    async fn route(&self, request: Request<Incoming>) -> Result<Response<Body>, HarnessError> {
        match (request.method(), request.uri().path()) {
            (&Method::GET, "/health") => Ok(Response::new(Full::from("ready"))),
            (&Method::GET, "/login") => {
                let authorization = self
                    .client
                    .authorize(
                        self.redirect_uri.clone(),
                        Scope::new("openid profile email"),
                    )?
                    .pkce_s256()
                    .build();
                self.pending
                    .lock()
                    .map_err(|_| "pending state lock poisoned")?
                    .insert(
                        authorization.state.as_str().to_owned(),
                        authorization.to_pending(),
                    );
                Ok(Response::builder()
                    .status(StatusCode::FOUND)
                    .header(header::LOCATION, authorization.authorization_url.as_str())
                    .body(Full::default())?)
            }
            (&Method::GET, "/callback") => {
                let callback = parse_authorization_response(
                    request.uri().query().ok_or("missing callback query")?,
                )?;
                let pending = self
                    .pending
                    .lock()
                    .map_err(|_| "pending state lock poisoned")?
                    .remove(callback.state())
                    .ok_or("unknown callback state")?;
                let completed = self
                    .client
                    .complete_authorization_from_pending(callback, pending)
                    .await?;
                let claims = completed
                    .verify_id_token(
                        &self.client.verifier(),
                        self.client.client_id().as_str(),
                        &self.client.jwks(),
                    )
                    .await?;
                let subject = claims.subject().ok_or("missing verified subject")?;
                let userinfo = self
                    .client
                    .fetch_userinfo(&completed.token_response.access_token, subject)
                    .await?;
                let body = serde_json::json!({
                    "subject": subject,
                    "userinfo_subject": userinfo.sub,
                    "name": userinfo.name,
                    "email": userinfo.email,
                    "email_verified": userinfo.email_verified,
                    "middle_name": userinfo.middle_name,
                });
                Ok(Response::builder()
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Full::from(serde_json::to_vec(&body)?))?)
            }
            _ => {
                let mut response = Response::new(Full::default());
                *response.status_mut() = StatusCode::NOT_FOUND;
                Ok(response)
            }
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), HarnessError> {
    let client = Client::discover(
        env::var("OIDC_ISSUER")?.parse()?,
        ClientId::new(env::var("OIDC_CLIENT_ID")?)?,
        Some(ClientSecret::new(env::var("OIDC_CLIENT_SECRET")?)?),
        Arc::new(HyperHttpClient::new()?),
    )
    .await?;
    let relying_party = Arc::new(RelyingParty {
        client: Arc::new(client),
        redirect_uri: env::var("OIDC_REDIRECT_URI")?.parse()?,
        pending: Mutex::default(),
    });
    let listener = TcpListener::bind("0.0.0.0:8080").await?;
    loop {
        let (stream, _) = listener.accept().await?;
        let relying_party = Arc::clone(&relying_party);
        tokio::spawn(async move {
            let service = service_fn(|request| async {
                let response = relying_party.route(request).await.unwrap_or_else(|error| {
                    eprintln!("Interop RP failed: {error}");
                    let mut response = Response::new(Full::from("Interop RP failed"));
                    *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                    response
                });
                Ok::<_, Infallible>(response)
            });
            if let Err(error) = http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await
            {
                eprintln!("Interop HTTP connection failed: {error}");
            }
        });
    }
}
