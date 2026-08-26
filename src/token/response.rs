//! Token response shape and id_token parsing.

use serde::{Deserialize, Deserializer};

use jose4rs::error::JoseError;
use jose4rs::jws::JsonWebSignature;
use jose4rs::jwt::JwtClaims;
use jose4rs::jwx::{HeaderParameter, JsonWebStructure as _};

use crate::types::{AccessToken, RefreshToken};

/// Parsed RFC 6749 section 5.1 token response.
///
/// `access_token` and `refresh_token` are deserialized into newtype
/// wrappers via the `RefreshToken` and `AccessToken` newtypes -- the
/// wire format stays a plain string, but downstream APIs see typed
/// values that cannot accidentally be passed where a `ClientId` or
/// `Scope` is expected.
#[derive(Debug, Clone, Deserialize)]
pub struct TokenResponse {
    #[serde(deserialize_with = "deserialize_access_token")]
    pub access_token: AccessToken,
    pub token_type: String,
    #[serde(default)]
    pub expires_in: Option<u64>,
    #[serde(default, deserialize_with = "deserialize_refresh_token")]
    pub refresh_token: Option<RefreshToken>,
    #[serde(default)]
    pub id_token: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
}

fn deserialize_access_token<'de, D>(d: D) -> Result<AccessToken, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(d)?;
    AccessToken::new(s).map_err(serde::de::Error::custom)
}

fn deserialize_refresh_token<'de, D>(d: D) -> Result<Option<RefreshToken>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt = Option::<String>::deserialize(d)?;
    match opt {
        None => Ok(None),
        Some(s) if s.is_empty() => Ok(None),
        Some(s) => RefreshToken::new(s)
            .map(Some)
            .map_err(serde::de::Error::custom),
    }
}

/// Parsed ID-token structure.
///
/// `raw` is the original compact serialization for downstream
/// re-verification by [`crate::token::verify::IdTokenVerifier`]. The
/// `claims` are parsed but **not yet cryptographically verified**.
#[derive(Debug, Clone)]
pub struct IdToken {
    pub raw: String,
    pub claims: JwtClaims,
    pub header_alg: String,
    pub header_kid: Option<String>,
}

impl IdToken {
    /// Parses a compact-serialized ID token into header + claims.
    ///
    /// Does not verify the signature; callers must run an
    /// [`IdTokenVerifier`](crate::token::verify::IdTokenVerifier) before
    /// trusting any claim.
    pub fn parse(raw: impl Into<String>) -> Result<Self, JoseError> {
        let raw = raw.into();
        let jws = JsonWebSignature::from_compact_serialization(&raw)?;
        let alg = jws.algorithm().unwrap_or("").to_owned();
        let kid = jws.header(HeaderParameter::KeyId).map(str::to_owned);
        // Use unverified_payload here; verification is the verifier's job.
        let payload_bytes = jws.unverified_payload()?;
        let claims_json = std::str::from_utf8(payload_bytes)
            .map_err(|_| JoseError::MalformedToken("id_token payload is not UTF-8".into()))?;
        let claims = JwtClaims::parse(claims_json)?;
        Ok(Self {
            raw,
            claims,
            header_alg: alg,
            header_kid: kid,
        })
    }
}

impl TokenResponse {
    pub fn id_token(&self) -> Option<&str> {
        self.id_token.as_deref()
    }
}
