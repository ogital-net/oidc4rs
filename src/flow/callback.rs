//! Parsing of OIDC authorization responses from a redirect-URI query or
//! fragment.
//!
//! The parser enforces RFC 6749 sections 3.1 and 4.1.2 and OIDC Core
//! sections 3.1.2.5 through 3.1.2.7. It rejects duplicate parameters and
//! mixed success/error responses, treats empty values as omitted, validates
//! the OAuth parameter character sets, and ignores unknown parameters.
//! RFC 9207 issuer and pending-request validation require provider context
//! and are performed by `Client::complete_authorization` or
//! `Client::complete_authorization_from_pending`.

use std::collections::HashSet;

use thiserror::Error;

/// A malformed, unbound, or rejected authorization response.
#[derive(Debug, Error)]
pub enum CallbackError {
    /// A parameter required for this authorization transaction is absent.
    #[error("missing required parameter: {0}")]
    Missing(&'static str),

    /// A validated error response returned by the authorization server.
    #[error("provider returned an error: {error} - {description:?}")]
    ProviderError {
        error: String,
        description: Option<String>,
        error_uri: Option<String>,
        state: String,
        iss: Option<String>,
    },

    /// A response parameter name occurs more than once.
    #[error("authorization response parameter appears more than once: {0}")]
    DuplicateParameter(String),

    /// Success and error response parameters occur in the same response.
    #[error("authorization response contains both success and error parameters")]
    AmbiguousResponse,

    /// A parameter value violates its OAuth ABNF character set.
    #[error("authorization response parameter has an invalid value: {0}")]
    InvalidParameter(&'static str),

    /// The RFC 9207 issuer does not exactly match the expected issuer.
    #[error("authorization response issuer mismatch: expected {expected}, got {actual}")]
    IssuerMismatch { expected: String, actual: String },

    /// The form-encoded response or pending-request binding is malformed.
    #[error("failed to parse redirect: {0}")]
    Parse(String),
}

/// A syntactically valid authorization-code response.
///
/// This value is not trusted until it is bound to the pending request and its
/// optional RFC 9207 issuer is validated by one of the `Client` completion
/// methods.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizationResponse {
    /// Successful authorization-code response.
    Success {
        code: String,
        state: String,
        iss: Option<String>,
    },
    /// Error response returned by the authorization server.
    Error {
        error: String,
        description: Option<String>,
        error_uri: Option<String>,
        state: String,
        iss: Option<String>,
    },
}

impl AuthorizationResponse {
    /// Returns the state that binds the response to its authorization request.
    pub fn state(&self) -> &str {
        match self {
            Self::Success { state, .. } | Self::Error { state, .. } => state,
        }
    }

    /// Returns the authorization server issuer included in the response.
    pub fn issuer(&self) -> Option<&str> {
        match self {
            Self::Success { iss, .. } | Self::Error { iss, .. } => iss.as_deref(),
        }
    }
}

/// Parses an authorization response from a query string of the form
/// `?code=...&state=...&iss=...` (or an error variant).
///
/// `raw` should be the part after `?` in the redirect URL -- not the
/// fragment, not the full URL. For `response_mode=fragment`, the caller
/// is responsible for stripping the leading `#` first.
///
/// This crate always sends `state`, so both successful and error responses
/// require a non-empty `state` value. Unknown parameters are ignored, but all
/// parameter names must be unique as required by RFC 6749 section 3.1.
pub fn parse_authorization_response(raw: &str) -> Result<AuthorizationResponse, CallbackError> {
    validate_form_encoding(raw)?;
    let params: Vec<(String, String)> = url::form_urlencoded::parse(raw.as_bytes())
        .into_owned()
        .collect();

    let mut names = HashSet::with_capacity(params.len());
    for (name, _) in &params {
        if !names.insert(name.as_str()) {
            return Err(CallbackError::DuplicateParameter(name.clone()));
        }
    }

    let code = parameter(&params, "code");
    let error = parameter(&params, "error");
    let description = parameter(&params, "error_description");
    let error_uri = parameter(&params, "error_uri");
    let state = parameter(&params, "state");
    let iss = parameter(&params, "iss");

    if code.is_some() && (error.is_some() || description.is_some() || error_uri.is_some()) {
        return Err(CallbackError::AmbiguousResponse);
    }

    if let Some(error) = error {
        validate_nqschar("error", &error)?;
        if let Some(value) = description.as_deref() {
            validate_nqschar("error_description", value)?;
        }
        if let Some(value) = error_uri.as_deref() {
            validate_uri_reference_chars("error_uri", value)?;
        }
        let state = state.ok_or(CallbackError::Missing("state"))?;
        validate_vschar("state", &state)?;
        return Ok(AuthorizationResponse::Error {
            error,
            description,
            state,
            error_uri,
            iss,
        });
    }

    if description.is_some() || error_uri.is_some() {
        return Err(CallbackError::Missing("error"));
    }

    let code = code.ok_or(CallbackError::Missing("code"))?;
    let state = state.ok_or(CallbackError::Missing("state"))?;
    validate_vschar("code", &code)?;
    validate_vschar("state", &state)?;

    Ok(AuthorizationResponse::Success { code, state, iss })
}

fn parameter(params: &[(String, String)], name: &str) -> Option<String> {
    params
        .iter()
        .find(|(key, _)| key == name)
        .and_then(|(_, value)| (!value.is_empty()).then(|| value.clone()))
}

fn validate_form_encoding(raw: &str) -> Result<(), CallbackError> {
    for field in raw.split('&') {
        let (name, value) = field.split_once('=').unwrap_or((field, ""));
        validate_encoded_component(name)?;
        validate_encoded_component(value)?;
    }
    Ok(())
}

fn validate_encoded_component(component: &str) -> Result<(), CallbackError> {
    let encoded = component.as_bytes();
    let mut decoded = Vec::with_capacity(encoded.len());
    let mut index = 0;
    while index < encoded.len() {
        match encoded[index] {
            b'%' => {
                let Some(hex) = encoded.get(index + 1..index + 3) else {
                    return Err(invalid_form_encoding());
                };
                let Some(high) = hex_value(hex[0]) else {
                    return Err(invalid_form_encoding());
                };
                let Some(low) = hex_value(hex[1]) else {
                    return Err(invalid_form_encoding());
                };
                decoded.push((high << 4) | low);
                index += 3;
            }
            b'+' => {
                decoded.push(b' ');
                index += 1;
            }
            byte => {
                decoded.push(byte);
                index += 1;
            }
        }
    }

    std::str::from_utf8(&decoded)
        .map(|_| ())
        .map_err(|_| invalid_form_encoding())
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn invalid_form_encoding() -> CallbackError {
    CallbackError::Parse("authorization response is not valid form encoding".into())
}

fn validate_vschar(name: &'static str, value: &str) -> Result<(), CallbackError> {
    validate_chars(name, value, |byte| (0x20..=0x7e).contains(&byte))
}

fn validate_nqschar(name: &'static str, value: &str) -> Result<(), CallbackError> {
    validate_chars(
        name,
        value,
        |byte| matches!(byte, 0x20..=0x21 | 0x23..=0x5b | 0x5d..=0x7e),
    )
}

fn validate_uri_reference_chars(name: &'static str, value: &str) -> Result<(), CallbackError> {
    validate_chars(
        name,
        value,
        |byte| matches!(byte, 0x21 | 0x23..=0x5b | 0x5d..=0x7e),
    )
}

fn validate_chars(
    name: &'static str,
    value: &str,
    allowed: impl Fn(u8) -> bool,
) -> Result<(), CallbackError> {
    if value.bytes().all(allowed) {
        Ok(())
    } else {
        Err(CallbackError::InvalidParameter(name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_error_retains_standard_parameters() {
        let response = parse_authorization_response(
            "error=access_denied&error_description=cancelled&error_uri=https%3A%2F%2Fop.example.com%2Ferrors%2Fdenied&state=pending-state&iss=https%3A%2F%2Fop.example.com",
        )
        .unwrap();

        match response {
            AuthorizationResponse::Error {
                error,
                description,
                error_uri,
                state,
                iss,
            } => {
                assert_eq!(error, "access_denied");
                assert_eq!(description.as_deref(), Some("cancelled"));
                assert_eq!(
                    error_uri.as_deref(),
                    Some("https://op.example.com/errors/denied")
                );
                assert_eq!(state, "pending-state");
                assert_eq!(iss.as_deref(), Some("https://op.example.com"));
            }
            other @ AuthorizationResponse::Success { .. } => {
                panic!("expected provider error response, got {other:?}");
            }
        }
    }

    #[test]
    fn rejects_duplicate_parameters() {
        let error = parse_authorization_response("code=first&code=second&state=state").unwrap_err();

        assert!(matches!(
            error,
            CallbackError::DuplicateParameter(name) if name == "code"
        ));
    }

    #[test]
    fn rejects_duplicate_unknown_parameters() {
        let error = parse_authorization_response("code=code&state=state&extension=1&extension=2")
            .unwrap_err();

        assert!(matches!(
            error,
            CallbackError::DuplicateParameter(name) if name == "extension"
        ));
    }

    #[test]
    fn rejects_duplicates_after_parameter_name_decoding() {
        let error =
            parse_authorization_response("code=code&state=first&%73tate=second").unwrap_err();

        assert!(matches!(
            error,
            CallbackError::DuplicateParameter(name) if name == "state"
        ));
    }

    #[test]
    fn rejects_mixed_success_and_error_parameters() {
        let error =
            parse_authorization_response("code=code&error=access_denied&state=state").unwrap_err();

        assert!(matches!(error, CallbackError::AmbiguousResponse));
    }

    #[test]
    fn treats_empty_values_as_omitted() {
        let response = parse_authorization_response(
            "code=code&error=&error_description=&error_uri=&state=state&iss=",
        )
        .unwrap();

        assert_eq!(
            response,
            AuthorizationResponse::Success {
                code: "code".into(),
                state: "state".into(),
                iss: None,
            }
        );
    }

    #[test]
    fn rejects_error_details_without_error() {
        let error =
            parse_authorization_response("error_description=authorization+failed&state=state")
                .unwrap_err();

        assert!(matches!(error, CallbackError::Missing("error")));
    }

    #[test]
    fn provider_error_requires_state() {
        let error = parse_authorization_response("error=access_denied").unwrap_err();

        assert!(matches!(error, CallbackError::Missing("state")));
    }

    #[test]
    fn ignores_unknown_parameters() {
        let response =
            parse_authorization_response("code=code&state=state&extension=value").unwrap();

        assert!(matches!(response, AuthorizationResponse::Success { .. }));
    }

    #[test]
    fn rejects_invalid_form_encoding() {
        for raw in [
            "code=%GG&state=state",
            "code=%A&state=state",
            "code=%FF&state=state",
        ] {
            assert!(matches!(
                parse_authorization_response(raw),
                Err(CallbackError::Parse(_))
            ));
        }
    }

    #[test]
    fn rejects_values_outside_oauth_syntax() {
        let error = parse_authorization_response("code=code%0Avalue&state=state").unwrap_err();
        assert!(matches!(error, CallbackError::InvalidParameter("code")));

        let error =
            parse_authorization_response("error=invalid%22request&state=state").unwrap_err();
        assert!(matches!(error, CallbackError::InvalidParameter("error")));

        let error = parse_authorization_response(
            "error=access_denied&error_description=bad%5Cvalue&state=state",
        )
        .unwrap_err();
        assert!(matches!(
            error,
            CallbackError::InvalidParameter("error_description")
        ));

        let error = parse_authorization_response(
            "error=access_denied&error_uri=https%3A%2F%2Fop.example.com%2Fbad+path&state=state",
        )
        .unwrap_err();
        assert!(matches!(
            error,
            CallbackError::InvalidParameter("error_uri")
        ));
    }
}
