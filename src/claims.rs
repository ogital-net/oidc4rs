//! OIDC-specific typed accessors on `jose4rs::jwt::JwtClaims`.
//!
//! Implemented as an extension trait so callers can write
//! `claims.auth_time()?` against the `JwtClaims` they already hold
//! after signature verification.

use jose4rs::jwt::JwtClaims;

use crate::error::OidcError;

/// OIDC-specific typed accessors layered on top of `jose4rs::jwt::JwtClaims`.
pub trait OidcClaims {
    fn at_hash(&self) -> Result<Option<Vec<u8>>, OidcError>;
    fn c_hash(&self) -> Result<Option<Vec<u8>>, OidcError>;
    fn auth_time(&self) -> Result<Option<i64>, OidcError>;
    fn acr(&self) -> Result<Option<String>, OidcError>;
    fn amr(&self) -> Result<Option<Vec<String>>, OidcError>;
    fn azp(&self) -> Result<Option<String>, OidcError>;
    fn nonce(&self) -> Result<Option<String>, OidcError>;
}

impl OidcClaims for JwtClaims {
    fn at_hash(&self) -> Result<Option<Vec<u8>>, OidcError> {
        decode_hash_claim(self, "at_hash")
    }

    fn c_hash(&self) -> Result<Option<Vec<u8>>, OidcError> {
        decode_hash_claim(self, "c_hash")
    }

    fn auth_time(&self) -> Result<Option<i64>, OidcError> {
        // `JwtClaims` does not expose a typed integer accessor publicly,
        // so we round-trip via `to_json` + `serde_json` to read a single
        // integer. `time_int` returns `None` for missing or non-integer
        // values.
        Ok(self.time_int("auth_time"))
    }

    fn acr(&self) -> Result<Option<String>, OidcError> {
        Ok(self.string_claim("acr").map(str::to_owned))
    }

    fn amr(&self) -> Result<Option<Vec<String>>, OidcError> {
        Ok(self.string_array_claim("amr"))
    }

    fn azp(&self) -> Result<Option<String>, OidcError> {
        Ok(self.string_claim("azp").map(str::to_owned))
    }

    fn nonce(&self) -> Result<Option<String>, OidcError> {
        Ok(self.string_claim("nonce").map(str::to_owned))
    }
}

fn decode_hash_claim(claims: &JwtClaims, name: &str) -> Result<Option<Vec<u8>>, OidcError> {
    use base64::Engine;

    let Some(s) = claims.string_claim(name) else {
        return Ok(None);
    };
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .map_err(OidcError::Base64)?;
    Ok(Some(bytes))
}

// Private extension to fetch integer claims without expanding the public
// surface of jose4rs. Re-parses the claim JSON; fine because these claims
// are short integers.
trait TimeInt {
    fn time_int(&self, name: &str) -> Option<i64>;
}

impl TimeInt for JwtClaims {
    fn time_int(&self, name: &str) -> Option<i64> {
        // JwtClaims does not expose a typed integer accessor publicly.
        // Round-trip through the JSON serialization of just the claim.
        let json = self.to_json();
        let value: serde_json::Value = serde_json::from_str(&json).ok()?;
        value.get(name)?.as_i64()
    }
}
