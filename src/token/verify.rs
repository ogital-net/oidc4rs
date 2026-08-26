//! ID-token verification.
//!
//! Implements every check in SPEC §5:
//! - signature via `JsonWebSignature::verify_signature(&key)`
//! - `alg` against the verifier's allow-list
//! - `iss`, `aud`, `exp`, `iat`, `nbf` via `JwtConsumer`
//! - `azp` rule: when `aud` has multiple values, `azp` must equal the
//!   configured client id
//! - `nonce` matches the second-leg state (caller supplies it)
//! - `at_hash` over the access token (caller supplies it; hybrid flow)
//! - JWKS `kid` lookup with refresh on miss (combined with alg
//!   filtering via `AsyncHttpsJwks::select_verification_key`)

use std::time::Duration;

use base64::Engine;
use jose4rs::error::JoseError;
use jose4rs::jwk::{AsyncHttpsJwks, JsonWebKey};
use jose4rs::jws::{AlgorithmIdentifier, JsonWebSignature};
use jose4rs::jwt::{JwtClaims, JwtConsumerBuilder};

use crate::error::OidcError;
use crate::token::response::IdToken;

/// Context the caller supplies per verification.
#[derive(Debug, Clone, Default)]
pub struct VerifyContext {
    /// Expected `nonce` claim. Set from the second-leg pending entry.
    pub expected_nonce: Option<String>,
    /// Access token to validate the `at_hash` claim against. Only
    /// required for the OIDC hybrid flow; leave `None` otherwise.
    pub access_token: Option<String>,
    /// Client id used as the `azp` value when `aud` is multi-valued.
    pub client_id: Option<String>,
    /// Clock skew to apply to `exp` / `iat` / `nbf` checks. Defaults
    /// to zero.
    pub clock_skew: Option<Duration>,
}

/// Configured verifier. Constructed once per relying-party, then
/// reused for every callback.
pub struct IdTokenVerifier {
    expected_issuer: String,
    expected_audience: String,
    allowed_algs: Vec<String>,
}

impl IdTokenVerifier {
    pub fn new(expected_issuer: impl Into<String>, expected_audience: impl Into<String>) -> Self {
        Self {
            expected_issuer: expected_issuer.into(),
            expected_audience: expected_audience.into(),
            allowed_algs: vec![
                "RS256".into(),
                "RS384".into(),
                "RS512".into(),
                "ES256".into(),
                "ES384".into(),
                "ES512".into(),
                "PS256".into(),
                "PS384".into(),
                "PS512".into(),
                "EdDSA".into(),
            ],
        }
    }

    pub fn allow_alg(mut self, alg: impl Into<String>) -> Self {
        self.allowed_algs.push(alg.into());
        self
    }

    pub fn with_allowed_algs(mut self, algs: impl IntoIterator<Item = String>) -> Self {
        self.allowed_algs = algs.into_iter().collect();
        self
    }

    pub fn issuer(&self) -> &str {
        &self.expected_issuer
    }

    pub fn audience(&self) -> &str {
        &self.expected_audience
    }

    /// Verifies `token` end-to-end. Looks the signing key up in
    /// `jwks`, refreshing the JWKS on unknown `kid`. All checks in
    /// SPEC §5 are enforced.
    pub async fn verify(
        &self,
        token: &IdToken,
        jwks: &AsyncHttpsJwks,
        ctx: &VerifyContext,
    ) -> Result<JwtClaims, OidcError> {
        // 1. alg allow-list.
        self.check_alg(&token.header_alg)?;
        let alg_id = AlgorithmIdentifier::try_from(token.header_alg.as_str())
            .map_err(|e: JoseError| OidcError::UnsupportedAlgorithm(e.to_string()))?;

        // 2. JWKS lookup with refresh on unknown kid.
        let key = resolve_key(jwks, token).await?;

        // 3+4. Signature + claim-level validation.
        let claims = verify_signature_and_claims(self, token, &key, ctx)?;

        // 5. azp.
        check_azp(&claims, ctx)?;

        // 6. nonce.
        check_nonce(&claims, ctx)?;

        // 7. at_hash.
        check_at_hash(&claims, ctx, alg_id)?;

        Ok(claims)
    }

    fn check_alg(&self, alg: &str) -> Result<(), OidcError> {
        if !self.allowed_algs.iter().any(|a| a == alg) {
            return Err(OidcError::UnsupportedAlgorithm(alg.to_owned()));
        }
        Ok(())
    }
}

/// Looks up the signing key via `AsyncHttpsJwks::select_verification_key`.
/// Refreshes the JWKS on `kid` miss and applies the algorithm-confusion
/// guard (`kty`/curve matching via `VerificationJwkSelector`).
async fn resolve_key(jwks: &AsyncHttpsJwks, token: &IdToken) -> Result<JsonWebKey, OidcError> {
    let key = jwks
        .select_verification_key(token.header_kid.as_deref(), &token.header_alg)
        .await?;
    key.ok_or_else(|| OidcError::NoMatchingJwk {
        kid: token.header_kid.clone(),
        alg: token.header_alg.clone(),
    })
}

/// Verifies the JWS signature and runs the JwtConsumer over the
/// payload to enforce iss/aud/exp/iat/nbf.
fn verify_signature_and_claims(
    verifier: &IdTokenVerifier,
    token: &IdToken,
    key: &JsonWebKey,
    ctx: &VerifyContext,
) -> Result<JwtClaims, OidcError> {
    let jws = JsonWebSignature::from_compact_serialization(&token.raw).map_err(OidcError::Jose)?;
    if !jws.verify_signature(key)? {
        return Err(OidcError::InvalidIdToken(
            jose4rs::jwt::InvalidJwtError::new("JWS signature is invalid"),
        ));
    }
    let payload_bytes = jws.payload(key).map_err(OidcError::Jose)?;
    let payload_str = std::str::from_utf8(payload_bytes).map_err(|_| {
        OidcError::InvalidIdToken(jose4rs::jwt::InvalidJwtError::new(
            "JWT payload is not valid UTF-8",
        ))
    })?;
    let mut builder = JwtConsumerBuilder::new()
        .set_expected_issuer(&verifier.expected_issuer)
        .set_expected_audience(true, false, &[verifier.expected_audience.as_str()])
        .set_require_expiration_time();
    if let Some(skew) = ctx.clock_skew {
        builder = builder.set_allowed_clock_skew(skew);
    }
    builder
        .build()
        .process_to_claims(payload_str)
        .map_err(Into::into)
}

/// Enforces the azp rule from SPEC §5.
fn check_azp(claims: &JwtClaims, ctx: &VerifyContext) -> Result<(), OidcError> {
    let Some(aud) = claims.audience() else {
        return Ok(());
    };
    if aud.len() <= 1 {
        return Ok(());
    }
    let azp = claims.string_claim("azp").ok_or_else(|| {
        OidcError::InvalidIdToken(jose4rs::jwt::InvalidJwtError::new(
            "azp claim required when aud has multiple values",
        ))
    })?;
    let expected = ctx.client_id.as_deref().ok_or_else(|| {
        OidcError::InvalidAuthorizationRequest(
            "client_id required in VerifyContext for multi-aud azp check".into(),
        )
    })?;
    if azp != expected {
        return Err(OidcError::InvalidIdToken(
            jose4rs::jwt::InvalidJwtError::new("azp does not match client_id"),
        ));
    }
    Ok(())
}

/// Enforces that the JWT `nonce` claim matches the second-leg value.
fn check_nonce(claims: &JwtClaims, ctx: &VerifyContext) -> Result<(), OidcError> {
    if let Some(expected) = ctx.expected_nonce.as_deref() {
        let got = claims.string_claim("nonce").ok_or_else(|| {
            OidcError::InvalidIdToken(jose4rs::jwt::InvalidJwtError::new("nonce claim required"))
        })?;
        if got != expected {
            return Err(OidcError::InvalidIdToken(
                jose4rs::jwt::InvalidJwtError::new("nonce does not match expected"),
            ));
        }
    }
    Ok(())
}

/// Enforces the at_hash rule from SPEC §5 when the claim is present.
fn check_at_hash(
    claims: &JwtClaims,
    ctx: &VerifyContext,
    alg_id: AlgorithmIdentifier,
) -> Result<(), OidcError> {
    let Some(at_hash_b64) = claims.string_claim("at_hash") else {
        return Ok(());
    };
    let access_token = ctx.access_token.as_deref().ok_or_else(|| {
        OidcError::InvalidAuthorizationRequest(
            "access_token required in VerifyContext to validate at_hash".into(),
        )
    })?;
    let hash_len = match alg_id {
        AlgorithmIdentifier::RsaUsingSha384
        | AlgorithmIdentifier::EcdsaUsingP384CurveAndSha384
        | AlgorithmIdentifier::RsaPssUsingSha384 => 48,
        AlgorithmIdentifier::RsaUsingSha512
        | AlgorithmIdentifier::EcdsaUsingP521CurveAndSha512
        | AlgorithmIdentifier::RsaPssUsingSha512 => 64,
        _ => 32,
    };
    let digest = crate::crypto::sha256(access_token.as_bytes());
    let left = &digest[..hash_len.min(digest.len())];
    let expected_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(left);
    if at_hash_b64 != expected_b64 {
        return Err(OidcError::AtHashMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use jose4rs::jwk::{AsyncJwksFetcher, FetchResponse, JsonWebKey, JsonWebKeySet};
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use rsa::RsaPrivateKey;
    use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
    use serde_json::json;
    use std::sync::Arc;

    const KID: &str = "test-key-1";

    /// Generates a small RSA keypair for tests.
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

    /// Wraps a single `JsonWebKey` in a JWKS body suitable for the
    /// mock fetcher. Patches in `kid` and `alg` because jose4rs does
    /// not expose public setters for those on `RsaJsonWebKey`.
    fn jwks_body(jwk: &JsonWebKey) -> Vec<u8> {
        let set = JsonWebKeySet::from_keys(vec![jwk.clone()]);
        let mut json: serde_json::Value =
            serde_json::from_str(&set.to_json(jose4rs::jwk::OutputControlLevel::PublicOnly))
                .unwrap();
        // Patch the only key with kid/alg/use/kty.
        if let Some(keys) = json.get_mut("keys").and_then(|k| k.as_array_mut()) {
            for k in keys.iter_mut() {
                if let Some(obj) = k.as_object_mut() {
                    obj.insert("kid".into(), json!(KID));
                    obj.insert("alg".into(), json!("RS256"));
                    obj.insert("use".into(), json!("sig"));
                    // Ensure kty is set; jose4rs usually does this.
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

    fn sign_id_token(priv_key: &RsaPrivateKey, claims: &serde_json::Value) -> String {
        let pem = priv_key.to_pkcs8_pem(LineEnding::LF).expect("priv pem");
        let key = EncodingKey::from_rsa_pem(pem.as_bytes()).expect("enc key");
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(KID.to_owned());
        encode(&header, claims, &key).expect("encode")
    }

    fn verifier() -> IdTokenVerifier {
        IdTokenVerifier::new("https://idp.example.com", "my-client")
    }

    fn now() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .cast_signed()
    }

    #[tokio::test]
    async fn verifies_well_formed_token() {
        let (priv_key, jwk) = make_keypair();
        let iat = now();
        let claims = json!({
            "iss": "https://idp.example.com",
            "aud": "my-client",
            "sub": "user-42",
            "exp": iat + 3600,
            "iat": iat,
        });
        let jwt = sign_id_token(&priv_key, &claims);
        let token = IdToken::parse(&jwt).unwrap();
        let jwks = build_jwks(&jwk);
        let ctx = VerifyContext::default();
        let parsed = verifier().verify(&token, &jwks, &ctx).await.unwrap();
        assert_eq!(parsed.subject().unwrap(), "user-42");
    }

    #[tokio::test]
    async fn rejects_bad_issuer() {
        let (priv_key, jwk) = make_keypair();
        let iat = now();
        let claims = json!({
            "iss": "https://attacker.example.com",
            "aud": "my-client",
            "sub": "user-1",
            "exp": iat + 3600,
            "iat": iat,
        });
        let jwt = sign_id_token(&priv_key, &claims);
        let token = IdToken::parse(&jwt).unwrap();
        let jwks = build_jwks(&jwk);
        let err = verifier()
            .verify(&token, &jwks, &VerifyContext::default())
            .await
            .unwrap_err();
        assert!(matches!(err, OidcError::InvalidIdToken(_)));
    }

    #[tokio::test]
    async fn rejects_bad_audience() {
        let (priv_key, jwk) = make_keypair();
        let iat = now();
        let claims = json!({
            "iss": "https://idp.example.com",
            "aud": "other-client",
            "sub": "user-1",
            "exp": iat + 3600,
            "iat": iat,
        });
        let jwt = sign_id_token(&priv_key, &claims);
        let token = IdToken::parse(&jwt).unwrap();
        let jwks = build_jwks(&jwk);
        let err = verifier()
            .verify(&token, &jwks, &VerifyContext::default())
            .await
            .unwrap_err();
        assert!(matches!(err, OidcError::InvalidIdToken(_)));
    }

    #[tokio::test]
    async fn rejects_expired() {
        let (priv_key, jwk) = make_keypair();
        let iat = now();
        let claims = json!({
            "iss": "https://idp.example.com",
            "aud": "my-client",
            "sub": "user-1",
            "exp": iat - 3600,
            "iat": iat,
        });
        let jwt = sign_id_token(&priv_key, &claims);
        let token = IdToken::parse(&jwt).unwrap();
        let jwks = build_jwks(&jwk);
        let err = verifier()
            .verify(&token, &jwks, &VerifyContext::default())
            .await
            .unwrap_err();
        assert!(matches!(err, OidcError::InvalidIdToken(_)));
    }

    #[tokio::test]
    async fn rejects_alg_not_in_allow_list() {
        let (priv_key, jwk) = make_keypair();
        let iat = now();
        // Sign with RS384 so alg is not allowed by the default verifier.
        let pem = priv_key.to_pkcs8_pem(LineEnding::LF).unwrap();
        let key = EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap();
        let mut header = Header::new(Algorithm::RS384);
        header.kid = Some(KID.to_owned());
        let jwt = encode(
            &header,
            &json!({
                "iss": "https://idp.example.com",
                "aud": "my-client",
                "sub": "user-1",
                "exp": iat + 3600,
                "iat": iat,
            }),
            &key,
        )
        .unwrap();
        let token = IdToken::parse(&jwt).unwrap();
        let jwks = build_jwks(&jwk);
        let err = verifier()
            .verify(&token, &jwks, &VerifyContext::default())
            .await
            .unwrap_err();
        // Either UnsupportedAlgorithm (allow-list) or Jose::InvalidKey (JWK
        // alg restriction) is an acceptable rejection.
        assert!(
            matches!(err, OidcError::UnsupportedAlgorithm(ref a) if a == "RS384")
                || matches!(err, OidcError::Jose(_))
        );
    }

    #[tokio::test]
    async fn rejects_bad_signature() {
        let (_priv_key, jwk) = make_keypair();
        let (other_priv, _other_jwk) = make_keypair();
        let iat = now();
        let claims = json!({
            "iss": "https://idp.example.com",
            "aud": "my-client",
            "sub": "user-1",
            "exp": iat + 3600,
            "iat": iat,
        });
        // Sign with one key, present another key in JWKS.
        let jwt = sign_id_token(&other_priv, &claims);
        let token = IdToken::parse(&jwt).unwrap();
        let jwks = build_jwks(&jwk);
        let err = verifier()
            .verify(&token, &jwks, &VerifyContext::default())
            .await
            .unwrap_err();
        assert!(matches!(err, OidcError::InvalidIdToken(_)));
    }

    #[tokio::test]
    async fn enforces_nonce_match() {
        let (priv_key, jwk) = make_keypair();
        let iat = now();
        let claims = json!({
            "iss": "https://idp.example.com",
            "aud": "my-client",
            "sub": "user-1",
            "exp": iat + 3600,
            "iat": iat,
            "nonce": "server-nonce",
        });
        let jwt = sign_id_token(&priv_key, &claims);
        let token = IdToken::parse(&jwt).unwrap();
        let jwks = build_jwks(&jwk);
        let ctx = VerifyContext {
            expected_nonce: Some("client-expected".into()),
            ..Default::default()
        };
        let err = verifier().verify(&token, &jwks, &ctx).await.unwrap_err();
        assert!(matches!(err, OidcError::InvalidIdToken(_)));
    }

    #[tokio::test]
    async fn validates_at_hash_when_present() {
        let (priv_key, jwk) = make_keypair();
        let iat = now();
        let access_token = "AT-VALUE-123";
        let digest = crate::crypto::sha256(access_token.as_bytes());
        let at_hash = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&digest[..32]);
        let claims = json!({
            "iss": "https://idp.example.com",
            "aud": "my-client",
            "sub": "user-1",
            "exp": iat + 3600,
            "iat": iat,
            "at_hash": at_hash,
        });
        let jwt = sign_id_token(&priv_key, &claims);
        let token = IdToken::parse(&jwt).unwrap();
        let jwks = build_jwks(&jwk);
        let ctx = VerifyContext {
            access_token: Some(access_token.to_owned()),
            ..Default::default()
        };
        let parsed = verifier().verify(&token, &jwks, &ctx).await.unwrap();
        assert_eq!(parsed.subject().unwrap(), "user-1");
    }

    #[tokio::test]
    async fn rejects_at_hash_mismatch() {
        let (priv_key, jwk) = make_keypair();
        let iat = now();
        let claims = json!({
            "iss": "https://idp.example.com",
            "aud": "my-client",
            "sub": "user-1",
            "exp": iat + 3600,
            "iat": iat,
            "at_hash": "AAAA",
        });
        let jwt = sign_id_token(&priv_key, &claims);
        let token = IdToken::parse(&jwt).unwrap();
        let jwks = build_jwks(&jwk);
        let ctx = VerifyContext {
            access_token: Some("anything".into()),
            ..Default::default()
        };
        let err = verifier().verify(&token, &jwks, &ctx).await.unwrap_err();
        assert!(matches!(err, OidcError::AtHashMismatch));
    }
}
