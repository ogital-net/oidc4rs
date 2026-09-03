//! Userinfo response shape and verification.
//!
//! Covers OIDC Core 1.0 section 5.4 (UserInfo). Two response formats
//! are supported:
//!
//! - **Unsigned JSON**: claims serialized as a plain JSON object.
//! - **Signed JWT**: claims serialized as a JWS in compact form and
//!   checked using the provider's UserInfo signing policy.

use std::collections::HashMap;

use jose4rs::jwk::AsyncHttpsJwks;
use jose4rs::jws::{AlgorithmIdentifier, JsonWebSignature};
use jose4rs::jwt::{InvalidJwtError, JwtConsumerBuilder};
use serde::{Deserialize, Serialize};

use crate::error::OidcError;
use crate::metadata::ProviderMetadata;
use crate::token::verify::DEFAULT_ALLOWED_ALGS;

/// Validation policy for signed UserInfo responses.
pub struct UserInfoVerifier {
    expected_issuer: String,
    expected_audience: String,
    allowed_algs: Vec<String>,
}

impl UserInfoVerifier {
    /// Creates a verifier with the crate's conservative asymmetric
    /// signing algorithm defaults.
    pub fn new(expected_issuer: impl Into<String>, expected_audience: impl Into<String>) -> Self {
        Self {
            expected_issuer: expected_issuer.into(),
            expected_audience: expected_audience.into(),
            allowed_algs: DEFAULT_ALLOWED_ALGS
                .iter()
                .map(|alg| (*alg).to_owned())
                .collect(),
        }
    }

    /// Creates a verifier from the provider's UserInfo algorithm list.
    pub fn from_metadata(metadata: &ProviderMetadata, audience: impl Into<String>) -> Self {
        let default_algs = DEFAULT_ALLOWED_ALGS
            .iter()
            .map(|alg| (*alg).to_owned())
            .collect();
        Self {
            expected_issuer: metadata.issuer.as_str().to_owned(),
            expected_audience: audience.into(),
            allowed_algs: metadata
                .userinfo_signing_alg_values_supported
                .clone()
                .unwrap_or(default_algs),
        }
    }

    /// Replaces the accepted signing algorithm list.
    pub fn with_allowed_algs(mut self, algs: impl IntoIterator<Item = String>) -> Self {
        self.allowed_algs = algs.into_iter().collect();
        self
    }

    /// Returns the accepted signing algorithms.
    pub fn allowed_algs(&self) -> &[String] {
        &self.allowed_algs
    }

    async fn verify(
        &self,
        compact_jws: &str,
        jwks: &AsyncHttpsJwks,
    ) -> Result<UserInfo, OidcError> {
        let token = crate::token::response::IdToken::parse(compact_jws)?;
        if !self
            .allowed_algs
            .iter()
            .any(|allowed| allowed == &token.header_alg)
        {
            return Err(OidcError::UnsupportedAlgorithm(token.header_alg));
        }
        AlgorithmIdentifier::try_from(token.header_alg.as_str())
            .map_err(|error| OidcError::UnsupportedAlgorithm(error.to_string()))?;
        let key = crate::token::verify::resolve_key(jwks, &token).await?;
        let jws = JsonWebSignature::from_compact_serialization(compact_jws)?;
        if !jws.verify_signature(&key)? {
            return Err(OidcError::InvalidUserInfoJwt(InvalidJwtError::new(
                "JWS signature is invalid",
            )));
        }
        let payload = jws.payload(&key)?;
        let payload = std::str::from_utf8(payload).map_err(|_| {
            OidcError::InvalidUserInfoJwt(InvalidJwtError::new("JWT payload is not valid UTF-8"))
        })?;
        JwtConsumerBuilder::new()
            .set_expected_issuer(&self.expected_issuer)
            .set_expected_audience(true, false, &[self.expected_audience.as_str()])
            .build()
            .process_to_claims(payload)
            .map_err(OidcError::InvalidUserInfoJwt)?;
        serde_json::from_str(payload).map_err(OidcError::from)
    }
}

/// Standard Claims from OIDC Core 1.0 section 5.4 plus the §5.1.1
/// profile (email / phone / address) claims that the userinfo
/// endpoint MAY return.
///
/// All fields except `sub` are optional; the `extra` map captures
/// anything else (custom claims, `groups`, `roles`, `gender`, etc.)
/// without forcing the type system to model every op-specific
/// extension.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    /// REQUIRED. Locally unique identifier for the end-user at the OP.
    pub sub: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub given_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub middle_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nickname: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preferred_username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub website: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phone_number: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phone_number_verified: Option<bool>,

    /// Compound `address` claim from OIDC Core 5.1.1. Captured
    /// as raw JSON because the localized form is op-specific.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<serde_json::Value>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zoneinfo: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,

    /// `updated_at` is a JSON number (seconds since epoch).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<i64>,

    /// Non-standard and op-specific claims land here. The standard
    /// fields above are not duplicated: serde's `flatten` matches
    /// known field names to the struct and routes the rest here.
    #[serde(default, flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

impl UserInfo {
    /// Parses an unsigned JSON userinfo response.
    pub fn from_json(bytes: &[u8]) -> Result<Self, OidcError> {
        serde_json::from_slice(bytes).map_err(OidcError::from)
    }

    /// Verifies that this response describes the ID-token subject.
    pub fn verify_subject(&self, expected_subject: &str) -> Result<(), OidcError> {
        if self.sub != expected_subject {
            return Err(OidcError::UserInfoSubjectMismatch);
        }
        Ok(())
    }

    /// Parses and verifies a signed (JWS compact) userinfo response.
    ///
    /// Validates the signature, required `iss` and `aud` claims, and
    /// any time claims that are present. UserInfo does not require an
    /// `exp` or `iat` claim.
    pub async fn from_signed_jwt(
        compact_jws: &str,
        verifier: &UserInfoVerifier,
        jwks: &AsyncHttpsJwks,
    ) -> Result<Self, OidcError> {
        verifier.verify(compact_jws, jwks).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jose4rs::jwk::{
        AsyncHttpsJwks, AsyncJwksFetcher, FetchResponse, JsonWebKey, JsonWebKeySet,
    };
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use rsa::RsaPrivateKey;
    use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
    use serde_json::json;
    use std::sync::Arc;

    const KID: &str = "test-userinfo-key-1";
    const ISS: &str = "https://idp.example.com";
    const AUD: &str = "my-client";

    fn make_keypair() -> (RsaPrivateKey, JsonWebKey) {
        let mut rng = rand::thread_rng();
        let priv_key = RsaPrivateKey::new(&mut rng, 2048).expect("rsa keygen");
        let pub_pem = priv_key
            .to_public_key()
            .to_public_key_pem(LineEnding::LF)
            .expect("pub pem");
        let mut jwk = JsonWebKey::from_pem(&pub_pem).expect("jwk from pem");
        jwk.set_key_id(KID);
        (priv_key, jwk)
    }

    fn jwks_body(jwk: &JsonWebKey) -> Vec<u8> {
        let set = JsonWebKeySet::from_keys(vec![jwk.clone()]);
        let mut json: serde_json::Value =
            serde_json::from_str(&set.to_json(jose4rs::jwk::OutputControlLevel::PublicOnly))
                .unwrap();
        if let Some(keys) = json.get_mut("keys").and_then(|k| k.as_array_mut()) {
            for k in keys.iter_mut() {
                if let Some(obj) = k.as_object_mut() {
                    obj.insert("kid".into(), json!(KID));
                    obj.insert("alg".into(), json!("RS256"));
                    obj.insert("use".into(), json!("sig"));
                    if !obj.contains_key("kty") {
                        obj.insert("kty".into(), json!("RSA"));
                    }
                }
            }
        }
        serde_json::to_vec(&json).unwrap()
    }

    struct StaticJwks {
        body: Vec<u8>,
    }

    impl AsyncJwksFetcher for StaticJwks {
        fn fetch<'a>(&'a self, _url: &'a str) -> jose4rs::jwk::FetchFuture<'a> {
            let body = self.body.clone();
            Box::pin(async move { Ok(FetchResponse::new(body)) })
        }
    }

    fn build_jwks(jwk: &JsonWebKey) -> AsyncHttpsJwks {
        let fetcher: Arc<dyn AsyncJwksFetcher> = Arc::new(StaticJwks {
            body: jwks_body(jwk),
        });
        AsyncHttpsJwks::new("https://idp.example.com/jwks", fetcher)
    }

    fn sign(priv_key: &RsaPrivateKey, claims: &serde_json::Value) -> String {
        let pem = priv_key.to_pkcs8_pem(LineEnding::LF).expect("priv pem");
        let key = EncodingKey::from_rsa_pem(pem.as_bytes()).expect("enc key");
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(KID.to_owned());
        encode(&header, claims, &key).expect("encode")
    }

    fn verifier() -> UserInfoVerifier {
        UserInfoVerifier::new(ISS, AUD)
    }

    fn now() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .cast_signed()
    }

    #[test]
    fn from_json_parses_full_claims() {
        let body = json!({
            "sub": "user-1",
            "name": "Ada Lovelace",
            "given_name": "Ada",
            "family_name": "Lovelace",
            "email": "ada@example.com",
            "email_verified": true,
            "picture": "https://example.com/ada.png",
            "groups": ["admin", "users"],
        });
        let bytes = serde_json::to_vec(&body).unwrap();
        let info = UserInfo::from_json(&bytes).unwrap();
        assert_eq!(info.sub, "user-1");
        assert_eq!(info.name.as_deref(), Some("Ada Lovelace"));
        assert_eq!(info.given_name.as_deref(), Some("Ada"));
        assert_eq!(info.email.as_deref(), Some("ada@example.com"));
        assert_eq!(info.email_verified, Some(true));
        // Non-standard claims land in `extra`.
        assert_eq!(
            info.extra.get("groups").unwrap(),
            &json!(["admin", "users"])
        );
    }

    #[test]
    fn from_json_minimal_only_requires_sub() {
        let body = json!({"sub": "user-2"});
        let info = UserInfo::from_json(body.to_string().as_bytes()).unwrap();
        assert_eq!(info.sub, "user-2");
        assert!(info.email.is_none());
        assert!(info.extra.is_empty());
    }

    #[test]
    fn from_json_rejects_missing_sub() {
        let body = json!({"name": "no sub"});
        let err = UserInfo::from_json(body.to_string().as_bytes()).unwrap_err();
        assert!(matches!(err, OidcError::Json(_)));
    }

    #[tokio::test]
    async fn from_signed_jwt_accepts_well_formed_token() {
        let (priv_key, jwk) = make_keypair();
        let iat = now();
        let claims = json!({
            "iss": ISS,
            "aud": AUD,
            "sub": "user-42",
            "exp": iat + 3600,
            "iat": iat,
            "name": "Ada",
            "email": "ada@example.com",
            "groups": ["admin"],
        });
        let jwt = sign(&priv_key, &claims);
        let jwks = build_jwks(&jwk);
        let info = UserInfo::from_signed_jwt(&jwt, &verifier(), &jwks)
            .await
            .unwrap();
        assert_eq!(info.sub, "user-42");
        assert_eq!(info.name.as_deref(), Some("Ada"));
        assert_eq!(info.extra.get("groups").unwrap(), &json!(["admin"]));
    }

    #[tokio::test]
    async fn from_signed_jwt_accepts_response_without_time_claims() {
        let (priv_key, jwk) = make_keypair();
        let claims = json!({
            "iss": ISS,
            "aud": AUD,
            "sub": "user-42",
            "name": "Ada",
        });
        let jwt = sign(&priv_key, &claims);
        let jwks = build_jwks(&jwk);

        let info = UserInfo::from_signed_jwt(&jwt, &verifier(), &jwks)
            .await
            .unwrap();
        assert_eq!(info.sub, "user-42");
    }

    #[tokio::test]
    async fn from_signed_jwt_rejects_bad_issuer() {
        let (priv_key, jwk) = make_keypair();
        let iat = now();
        let claims = json!({
            "iss": "https://attacker.example.com",
            "aud": AUD,
            "sub": "user-1",
            "exp": iat + 3600,
            "iat": iat,
        });
        let jwt = sign(&priv_key, &claims);
        let jwks = build_jwks(&jwk);
        let err = UserInfo::from_signed_jwt(&jwt, &verifier(), &jwks)
            .await
            .unwrap_err();
        assert!(matches!(err, OidcError::InvalidUserInfoJwt(_)));
    }

    #[tokio::test]
    async fn from_signed_jwt_rejects_bad_audience() {
        let (priv_key, jwk) = make_keypair();
        let iat = now();
        let claims = json!({
            "iss": ISS,
            "aud": "other-client",
            "sub": "user-1",
            "exp": iat + 3600,
            "iat": iat,
        });
        let jwt = sign(&priv_key, &claims);
        let jwks = build_jwks(&jwk);
        let err = UserInfo::from_signed_jwt(&jwt, &verifier(), &jwks)
            .await
            .unwrap_err();
        assert!(matches!(err, OidcError::InvalidUserInfoJwt(_)));
    }

    #[tokio::test]
    async fn from_signed_jwt_rejects_expired() {
        let (priv_key, jwk) = make_keypair();
        let iat = now();
        let claims = json!({
            "iss": ISS,
            "aud": AUD,
            "sub": "user-1",
            "exp": iat - 3600,
            "iat": iat,
        });
        let jwt = sign(&priv_key, &claims);
        let jwks = build_jwks(&jwk);
        let err = UserInfo::from_signed_jwt(&jwt, &verifier(), &jwks)
            .await
            .unwrap_err();
        assert!(matches!(err, OidcError::InvalidUserInfoJwt(_)));
    }

    #[tokio::test]
    async fn from_signed_jwt_rejects_bad_signature() {
        // Sign with one key, advertise a different one.
        let (other_priv, _other_jwk) = make_keypair();
        let (_priv, jwk) = make_keypair();
        let iat = now();
        let claims = json!({
            "iss": ISS,
            "aud": AUD,
            "sub": "user-1",
            "exp": iat + 3600,
            "iat": iat,
        });
        let jwt = sign(&other_priv, &claims);
        let jwks = build_jwks(&jwk);
        let err = UserInfo::from_signed_jwt(&jwt, &verifier(), &jwks)
            .await
            .unwrap_err();
        assert!(matches!(err, OidcError::InvalidUserInfoJwt(_)));
    }

    #[tokio::test]
    async fn from_signed_jwt_rejects_disallowed_alg() {
        // Sign with RS384; default verifier only allows the standard
        // set which jose4rs may further narrow to RS256-only JWKs.
        let (priv_key, jwk) = make_keypair();
        let iat = now();
        let pem = priv_key.to_pkcs8_pem(LineEnding::LF).unwrap();
        let key = EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap();
        let mut header = Header::new(Algorithm::RS384);
        header.kid = Some(KID.to_owned());
        let jwt = encode(
            &header,
            &json!({
                "iss": ISS,
                "aud": AUD,
                "sub": "user-1",
                "exp": iat + 3600,
                "iat": iat,
            }),
            &key,
        )
        .unwrap();
        let jwks = build_jwks(&jwk);
        let verifier = verifier().with_allowed_algs(["RS256".to_owned()]);
        let err = UserInfo::from_signed_jwt(&jwt, &verifier, &jwks)
            .await
            .unwrap_err();
        assert!(matches!(err, OidcError::UnsupportedAlgorithm(ref alg) if alg == "RS384"));
    }
}
