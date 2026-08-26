//! RP-initiated logout URL builder. Stub.

use crate::client::Client;
use crate::error::OidcError;
use crate::types::{EndSessionUrl, State};

#[allow(dead_code)]
pub struct EndSessionUrlBuilder<'c> {
    client: &'c Client,
    id_token_hint: Option<String>,
    post_logout_redirect_uri: Option<String>,
    state: Option<State>,
}

impl<'c> EndSessionUrlBuilder<'c> {
    pub fn new(client: &'c Client) -> Self {
        Self {
            client,
            id_token_hint: None,
            post_logout_redirect_uri: None,
            state: None,
        }
    }

    pub fn id_token_hint(mut self, hint: impl Into<String>) -> Self {
        self.id_token_hint = Some(hint.into());
        self
    }

    pub fn post_logout_redirect_uri(mut self, uri: impl Into<String>) -> Self {
        self.post_logout_redirect_uri = Some(uri.into());
        self
    }

    pub fn state(mut self, s: State) -> Self {
        self.state = Some(s);
        self
    }

    pub fn build(self) -> Result<(EndSessionUrl, Option<State>), OidcError> {
        let endpoint = self
            .client
            .metadata()
            .end_session_endpoint
            .clone()
            .ok_or_else(|| {
                OidcError::InvalidMetadata("end_session_endpoint not advertised".into())
            })?;
        let mut url = endpoint.into_inner();
        {
            let mut q = url.query_pairs_mut();
            if let Some(hint) = self.id_token_hint {
                q.append_pair("id_token_hint", &hint);
            }
            if let Some(redirect) = self.post_logout_redirect_uri {
                q.append_pair("post_logout_redirect_uri", &redirect);
            }
            if let Some(state) = &self.state {
                q.append_pair("state", state.as_str());
            }
        }
        let parsed: EndSessionUrl = url
            .as_str()
            .parse()
            .map_err(|e: OidcError| OidcError::InvalidMetadata(format!("end_session URL: {e}")))?;
        Ok((parsed, self.state))
    }
}
