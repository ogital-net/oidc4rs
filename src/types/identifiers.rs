//! Strongly-typed identifiers, scopes, and request knobs.

use std::fmt;

use crate::crypto::fill_bytes;
use crate::error::OidcError;

/// Implements a `Debug` that hides the wrapped value. Applied to every
/// credential- or token-grade newtype so `{:?}` in a log or error path
/// cannot leak the secret.
macro_rules! redacted_debug {
    ($name:ident) => {
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_tuple(stringify!($name)).field(&"***").finish()
            }
        }
    };
}

macro_rules! nonempty_string_newtype {
    // Secret-bearing newtype: identical API but a redacting `Debug`.
    (secret $(#[$meta:meta])* $name:ident) => {
        nonempty_string_newtype!(@build $(#[$meta])* $name);
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_tuple(stringify!($name)).field(&"***").finish()
            }
        }
    };
    // Non-secret newtype: `Debug` shows the wrapped value.
    ($(#[$meta:meta])* $name:ident) => {
        nonempty_string_newtype!(@build $(#[$meta])* $name);
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_tuple(stringify!($name)).field(&self.0).finish()
            }
        }
    };
    (@build $(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, PartialEq, Eq, Hash)]
        pub struct $name(String);

        impl $name {
            pub fn new(s: impl Into<String>) -> Result<Self, OidcError> {
                let s = s.into();
                if s.is_empty() {
                    return Err(OidcError::InvalidMetadata(format!(
                        "{} must not be empty",
                        stringify!($name)
                    )));
                }
                Ok(Self(s))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0, f)
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }
    };
}

nonempty_string_newtype!(
    /// OIDC client identifier issued by the OP.
    ClientId
);

nonempty_string_newtype!(secret
    /// OIDC client secret. Optional for public clients.
    ClientSecret
);

/// Space-separated scope list per RFC 6749 section 3.3.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Scope(String);

impl Scope {
    pub fn openid() -> Self {
        Self("openid".into())
    }

    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn iter(&self) -> impl Iterator<Item = &str> + '_ {
        // Filter empty splits so trailing spaces do not produce a blank entry.
        self.0.split(' ').filter(|s| !s.is_empty())
    }
}

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl serde::Serialize for Scope {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<'de> serde::Deserialize<'de> for Scope {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Ok(Self(s))
    }
}

/// Cryptographically random nonce for replay defense on the ID token.
#[derive(Clone, PartialEq, Eq)]
pub struct Nonce(String);

redacted_debug!(Nonce);

impl Nonce {
    pub fn new_random() -> Self {
        Self(random_url_safe(32))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Cryptographically random state value for CSRF defense on the
/// authorization callback.
#[derive(Clone, PartialEq, Eq)]
pub struct State(String);

redacted_debug!(State);

impl State {
    pub fn new_random() -> Self {
        Self(random_url_safe(32))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// PKCE code verifier per RFC 7636 section 4.1.
#[derive(Clone, PartialEq, Eq)]
pub struct PkceCodeVerifier(String);

redacted_debug!(PkceCodeVerifier);

impl PkceCodeVerifier {
    pub fn new_random() -> Self {
        // 64 random bytes -> 86 url-safe base64 chars (no padding), within the
        // RFC 7636 43..128 character range.
        Self(random_url_safe(64))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PkceCodeChallengeMethod {
    S256,
    #[allow(dead_code)]
    Plain,
}

/// PKCE code challenge sent on the authorization request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PkceCodeChallenge {
    method: PkceCodeChallengeMethod,
    value: String,
}

impl PkceCodeChallenge {
    pub fn s256_from_verifier(v: &PkceCodeVerifier) -> Self {
        use base64::Engine;

        // RFC 7636 section 4.2: challenge = BASE64URL-ENCODE(SHA256(verifier))
        // with no padding. SHA-256 here is infallible (see crypto::hash).
        let digest = crate::crypto::sha256(v.as_str().as_bytes());
        let value = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest);
        Self {
            method: PkceCodeChallengeMethod::S256,
            value,
        }
    }

    pub fn method(&self) -> PkceCodeChallengeMethod {
        self.method
    }

    pub fn as_str(&self) -> &str {
        &self.value
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseType {
    Code,
    #[allow(dead_code)]
    IdToken,
    #[allow(dead_code)]
    Token,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantType {
    AuthorizationCode,
    RefreshToken,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthPrompt {
    None,
    #[allow(dead_code)]
    Login,
    #[allow(dead_code)]
    Consent,
    #[allow(dead_code)]
    SelectAccount,
}

impl AuthPrompt {
    pub fn as_str(&self) -> &'static str {
        match self {
            AuthPrompt::None => "none",
            AuthPrompt::Login => "login",
            AuthPrompt::Consent => "consent",
            AuthPrompt::SelectAccount => "select_account",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseMode {
    #[allow(dead_code)]
    Query,
    Fragment,
    #[allow(dead_code)]
    FormPost,
}

impl ResponseMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            ResponseMode::Query => "query",
            ResponseMode::Fragment => "fragment",
            ResponseMode::FormPost => "form_post",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenEndpointAuthMethod {
    ClientSecretBasic,
    #[allow(dead_code)]
    ClientSecretPost,
    #[allow(dead_code)]
    None,
}

/// OAuth 2.0 / OIDC access token. Opaque bearer string issued by the OP.
///
/// This is a thin newtype around `String`; the OIDC Core 1.0
/// specification (section 5.3) does not require the RP to parse the
/// access-token value, and RFC 6750 forbids using it as a URL
/// parameter or as a form-encoded body field unless the access-token
/// type permits it. Callers should treat the inner value as opaque.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct AccessToken(String);

redacted_debug!(AccessToken);

impl AccessToken {
    /// Wraps a raw access-token string. Empty strings are rejected:
    /// RFC 6749 section 5.1 requires a successful token response to
    /// include the token, and an empty value would silently break
    /// userinfo and resource-server calls.
    pub fn new(s: impl Into<String>) -> Result<Self, OidcError> {
        let s = s.into();
        if s.is_empty() {
            return Err(OidcError::InvalidMetadata(
                "AccessToken must not be empty".into(),
            ));
        }
        Ok(Self(s))
    }

    /// Borrows the inner string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AccessToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl AsRef<str> for AccessToken {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// OAuth 2.0 refresh token (RFC 6749 section 6).
///
/// Opaque bearer string issued by the OP. Empty strings are rejected
/// for the same reason as [`AccessToken`].
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct RefreshToken(String);

redacted_debug!(RefreshToken);

impl RefreshToken {
    pub fn new(s: impl Into<String>) -> Result<Self, OidcError> {
        let s = s.into();
        if s.is_empty() {
            return Err(OidcError::InvalidMetadata(
                "RefreshToken must not be empty".into(),
            ));
        }
        Ok(Self(s))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RefreshToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl AsRef<str> for RefreshToken {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

nonempty_string_newtype!(
    /// Hint to the OP about which end-user is logging out
    /// (OIDC RP-Initiated Logout 1.0 section 2.1).
    ///
    /// The OP is free to interpret the value; the spec does not
    /// require any particular encoding. Callers that want to send a
    /// known-stable user identifier (e.g. login name, email) wrap
    /// it here so the wire parameter is type-safe at the Rust
    /// boundary.
    LogoutHint
);

/// Generates a url-safe base64 (no padding) string from `n` random bytes.
fn random_url_safe(n: usize) -> String {
    use base64::Engine;

    let mut bytes = vec![0u8; n];
    fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_newtypes_redact_debug_output() {
        let secret = ClientSecret::new("super-secret-value").unwrap();
        let access = AccessToken::new("access-token-value").unwrap();
        let refresh = RefreshToken::new("refresh-token-value").unwrap();
        let verifier = PkceCodeVerifier::new_random();
        let nonce = Nonce::new_random();
        let state = State::new_random();

        for rendered in [
            format!("{secret:?}"),
            format!("{access:?}"),
            format!("{refresh:?}"),
            format!("{verifier:?}"),
            format!("{nonce:?}"),
            format!("{state:?}"),
        ] {
            assert!(
                rendered.contains("***"),
                "expected redaction, got {rendered}"
            );
        }

        // The wrapped value must not leak.
        assert!(!format!("{secret:?}").contains("super-secret-value"));
        assert!(!format!("{access:?}").contains("access-token-value"));
        assert!(!format!("{refresh:?}").contains("refresh-token-value"));
        assert!(!format!("{verifier:?}").contains(verifier.as_str()));
    }

    #[test]
    fn non_secret_newtype_debug_shows_value() {
        let id = ClientId::new("public-client-id").unwrap();
        assert!(format!("{id:?}").contains("public-client-id"));
    }
}
