//! Parsing of the OIDC redirect-URI query (or fragment).

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CallbackError {
    #[error("missing required parameter: {0}")]
    Missing(&'static str),

    #[error("provider returned an error: {error} - {description:?}")]
    ProviderError {
        error: String,
        description: Option<String>,
    },

    #[error("authorization response issuer mismatch: expected {expected}, got {actual}")]
    IssuerMismatch { expected: String, actual: String },

    #[error("failed to parse redirect: {0}")]
    Parse(String),
}

#[derive(Debug, Clone)]
pub struct AuthorizationResponse {
    pub code: String,
    pub state: String,
    #[allow(dead_code)]
    pub iss: Option<String>,
}

/// Parses an authorization response from a query string of the form
/// `?code=...&state=...&iss=...` (or an error variant).
///
/// `raw` should be the part after `?` in the redirect URL -- not the
/// fragment, not the full URL. For `response_mode=fragment`, the caller
/// is responsible for stripping the leading `#` first.
pub fn parse_authorization_response(raw: &str) -> Result<AuthorizationResponse, CallbackError> {
    let params: Vec<(String, String)> = url::form_urlencoded::parse(raw.as_bytes())
        .into_owned()
        .collect();

    if let Some((_, error)) = params.iter().find(|(k, _)| k == "error") {
        let description = params
            .iter()
            .find(|(k, _)| k == "error_description")
            .map(|(_, v)| v.clone());
        return Err(CallbackError::ProviderError {
            error: error.clone(),
            description,
        });
    }

    let mut code: Option<String> = None;
    let mut state: Option<String> = None;
    let mut iss: Option<String> = None;
    for (k, v) in &params {
        match k.as_str() {
            "code" => code = Some(v.clone()),
            "state" => state = Some(v.clone()),
            "iss" => iss = Some(v.clone()),
            _ => {}
        }
    }

    let code = code.ok_or(CallbackError::Missing("code"))?;
    let state = state.ok_or(CallbackError::Missing("state"))?;

    Ok(AuthorizationResponse { code, state, iss })
}
