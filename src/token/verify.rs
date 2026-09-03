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
//! - `auth_time` freshness when the request used `max_age`
//! - JWKS `kid` lookup with refresh on miss (combined with alg
//!   filtering via `AsyncHttpsJwks::select_verification_key`)

use std::time::Duration;

use base64::Engine;
use jose4rs::error::JoseError;
use jose4rs::jwk::{AsyncHttpsJwks, JsonWebKey};
use jose4rs::jws::{AlgorithmIdentifier, JsonWebSignature};
use jose4rs::jwt::{JwtClaims, JwtConsumerBuilder};

use crate::error::OidcError;
use crate::metadata::ProviderMetadata;
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
    /// Clock skew to apply to `exp`, `iat`, `nbf`, and `auth_time`
    /// checks. Defaults to zero.
    pub clock_skew: Option<Duration>,
    /// Requested `max_age`. When set, the ID token must contain a
    /// valid `auth_time` no older than this duration.
    pub expected_max_age: Option<Duration>,
}

/// The default algorithm allow-list used by [`IdTokenVerifier::new`].
/// Mirrors the supported asymmetric JWS families.
/// HS* are deliberately excluded because symmetric algorithms
/// require a shared secret distribution the RP cannot assume.
pub const DEFAULT_ALLOWED_ALGS: &[&str] = &[
    "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "EdDSA",
];

/// Algorithms that must never seed an ID-token or UserInfo allow-list:
/// `none` (unsecured JWS) and the HS* family (symmetric; this RP has no
/// path to supply the shared secret as a verification key).
pub(crate) fn is_forbidden_alg(alg: &str) -> bool {
    alg.eq_ignore_ascii_case("none") || matches!(alg, "HS256" | "HS384" | "HS512")
}

/// Configured verifier. Constructed once per relying-party, then
/// reused for every callback.
pub struct IdTokenVerifier {
    expected_issuer: String,
    expected_audience: String,
    allowed_algs: Vec<String>,
}

impl IdTokenVerifier {
    /// Builds a verifier with the OIDC Core 1.0 default
    /// `id_token` allow-list. Use [`IdTokenVerifier::from_metadata`]
    /// when the relying party has access to a discovery document;
    /// it narrows the list to the algorithms the OP actually
    /// advertises.
    pub fn new(expected_issuer: impl Into<String>, expected_audience: impl Into<String>) -> Self {
        Self {
            expected_issuer: expected_issuer.into(),
            expected_audience: expected_audience.into(),
            allowed_algs: DEFAULT_ALLOWED_ALGS
                .iter()
                .map(|s| (*s).to_owned())
                .collect(),
        }
    }

    /// Builds a verifier whose allow-list is sourced from the OP's
    /// discovery document, closing the algorithm-confusion gap that
    /// comes from a default-permissive verifier accepting any Core
    /// `alg` the OP happens to rotate to.
    ///
    /// `audience` is the relying party's client id (the `aud` value
    /// the OP is expected to put in the ID token).
    ///
    /// The expected issuer preserves the exact `metadata.issuer`
    /// serialization because OIDC requires a byte-for-byte match.
    pub fn from_metadata(metadata: &ProviderMetadata, audience: impl Into<String>) -> Self {
        Self {
            expected_issuer: metadata.issuer.as_str().to_owned(),
            expected_audience: audience.into(),
            allowed_algs: metadata
                .id_token_signing_alg_values_supported
                .iter()
                .filter(|alg| !is_forbidden_alg(alg))
                .cloned()
                .collect(),
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

    /// Returns the configured allow-list as a borrowed slice of
    /// `String`. Intended for inspection and tests; the verifier
    /// itself owns the canonical list.
    pub fn allowed_algs(&self) -> &[String] {
        &self.allowed_algs
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
        check_azp(&claims, ctx, &self.expected_audience)?;

        // 6. nonce.
        check_nonce(&claims, ctx)?;

        // 7. at_hash.
        check_at_hash(&claims, ctx, alg_id, &key)?;

        // 8. auth_time when max_age was requested.
        check_auth_time(&claims, ctx)?;

        Ok(claims)
    }

    fn check_alg(&self, alg: &str) -> Result<(), OidcError> {
        // `none` is never acceptable, even if a caller widened the
        // allow-list: an unsecured JWS carries no signature to verify.
        if alg.eq_ignore_ascii_case("none") {
            return Err(OidcError::UnsupportedAlgorithm(
                "the `none` algorithm is never accepted for ID tokens".into(),
            ));
        }
        if !self.allowed_algs.iter().any(|a| a == alg) {
            return Err(OidcError::UnsupportedAlgorithm(alg.to_owned()));
        }
        Ok(())
    }
}

/// Looks up the signing key via `AsyncHttpsJwks::select_verification_key`.
/// Refreshes the JWKS on `kid` miss and applies the algorithm-confusion
/// guard (`kty`/curve matching via `VerificationJwkSelector`).
pub(crate) async fn resolve_key(
    jwks: &AsyncHttpsJwks,
    token: &IdToken,
) -> Result<JsonWebKey, OidcError> {
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
        .set_require_subject()
        .set_require_issued_at()
        .set_require_expiration_time();
    if let Some(skew) = ctx.clock_skew {
        builder = builder.set_allowed_clock_skew(skew);
    }
    builder
        .build()
        .process_to_claims(payload_str)
        .map_err(Into::into)
}

/// Enforces the azp rules from OIDC Core 1.0 section 3.1.3.7: azp is
/// required when `aud` is multi-valued, and whenever azp is present it
/// must equal the relying party's client id.
fn check_azp(
    claims: &JwtClaims,
    ctx: &VerifyContext,
    expected_audience: &str,
) -> Result<(), OidcError> {
    let azp = claims.string_claim("azp");
    let multi_aud = claims.audience().is_some_and(|aud| aud.len() > 1);
    if multi_aud && azp.is_none() {
        return Err(OidcError::InvalidIdToken(
            jose4rs::jwt::InvalidJwtError::new("azp claim required when aud has multiple values"),
        ));
    }
    let Some(azp) = azp else {
        return Ok(());
    };
    // The client id is the expected audience; ctx.client_id overrides
    // it only when the caller supplies a different value.
    let expected = ctx.client_id.as_deref().unwrap_or(expected_audience);
    if azp != expected {
        return Err(OidcError::InvalidIdToken(
            jose4rs::jwt::InvalidJwtError::new("azp does not match client_id"),
        ));
    }
    Ok(())
}

/// Enforces that the JWT `nonce` claim matches the second-leg value.
///
/// Comparison uses `crypto::ct::ct_equals` (constant-time byte
/// equality via `CRYPTO_memcmp`) so the comparison does not leak the
/// nonce byte-by-byte through a timing oracle. See SPEC section 5.
fn check_nonce(claims: &JwtClaims, ctx: &VerifyContext) -> Result<(), OidcError> {
    if let Some(expected) = ctx.expected_nonce.as_deref() {
        let got = claims.string_claim("nonce").ok_or_else(|| {
            OidcError::InvalidIdToken(jose4rs::jwt::InvalidJwtError::new("nonce claim required"))
        })?;
        if !crate::crypto::ct_equals(got.as_bytes(), expected.as_bytes()) {
            return Err(OidcError::InvalidIdToken(
                jose4rs::jwt::InvalidJwtError::new("nonce does not match expected"),
            ));
        }
    }
    Ok(())
}

/// Enforces the `auth_time` requirement implied by an authorization
/// request's `max_age` parameter.
fn check_auth_time(claims: &JwtClaims, ctx: &VerifyContext) -> Result<(), OidcError> {
    let Some(max_age) = ctx.expected_max_age else {
        return Ok(());
    };
    let value: serde_json::Value = serde_json::from_str(&claims.to_json()).map_err(|_| {
        OidcError::InvalidIdToken(jose4rs::jwt::InvalidJwtError::new(
            "JWT claims could not be inspected",
        ))
    })?;
    let auth_time = value.get("auth_time").ok_or_else(|| {
        OidcError::InvalidIdToken(jose4rs::jwt::InvalidJwtError::new(
            "auth_time claim required when max_age was requested",
        ))
    })?;
    let seconds = auth_time.as_u64().ok_or_else(|| {
        OidcError::InvalidIdToken(jose4rs::jwt::InvalidJwtError::new(
            "auth_time claim must be a non-negative integer",
        ))
    })?;
    let auth_time = std::time::UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .ok_or_else(|| {
            OidcError::InvalidIdToken(jose4rs::jwt::InvalidJwtError::new(
                "auth_time claim is out of range",
            ))
        })?;
    let now = std::time::SystemTime::now();
    let skew = ctx.clock_skew.unwrap_or_default();

    if now
        .checked_add(skew)
        .is_some_and(|latest| auth_time > latest)
    {
        return Err(OidcError::InvalidIdToken(
            jose4rs::jwt::InvalidJwtError::new("auth_time claim is in the future"),
        ));
    }
    if auth_time
        .checked_add(max_age)
        .and_then(|deadline| deadline.checked_add(skew))
        .is_some_and(|deadline| now > deadline)
    {
        return Err(OidcError::InvalidIdToken(
            jose4rs::jwt::InvalidJwtError::new("authentication exceeds requested max_age"),
        ));
    }
    Ok(())
}

/// Enforces the at_hash rule from SPEC §5 when the claim is present.
fn check_at_hash(
    claims: &JwtClaims,
    ctx: &VerifyContext,
    alg_id: AlgorithmIdentifier,
    key: &JsonWebKey,
) -> Result<(), OidcError> {
    let Some(at_hash_b64) = claims.string_claim("at_hash") else {
        return Ok(());
    };
    let access_token = ctx.access_token.as_deref().ok_or_else(|| {
        OidcError::InvalidAuthorizationRequest(
            "access_token required in VerifyContext to validate at_hash".into(),
        )
    })?;
    let expected_b64 = calculate_at_hash(access_token, alg_id, key.curve_name())?;
    if at_hash_b64 != expected_b64 {
        return Err(OidcError::AtHashMismatch);
    }
    Ok(())
}

fn calculate_at_hash(
    access_token: &str,
    alg_id: AlgorithmIdentifier,
    key_curve: Option<&str>,
) -> Result<String, OidcError> {
    let token = access_token.as_bytes();
    let encoded = match alg_id {
        AlgorithmIdentifier::HmacSha256
        | AlgorithmIdentifier::RsaUsingSha256
        | AlgorithmIdentifier::EcdsaUsingP256CurveAndSha256
        | AlgorithmIdentifier::RsaPssUsingSha256 => {
            let digest = crate::crypto::sha256(token);
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&digest[..digest.len() / 2])
        }
        #[cfg(not(feature = "boring"))]
        AlgorithmIdentifier::EcdsaUsingSecp256k1CurveAndSha256 => {
            let digest = crate::crypto::sha256(token);
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&digest[..digest.len() / 2])
        }
        AlgorithmIdentifier::HmacSha384
        | AlgorithmIdentifier::RsaUsingSha384
        | AlgorithmIdentifier::EcdsaUsingP384CurveAndSha384
        | AlgorithmIdentifier::RsaPssUsingSha384 => {
            let digest = crate::crypto::sha384(token);
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&digest[..digest.len() / 2])
        }
        AlgorithmIdentifier::HmacSha512
        | AlgorithmIdentifier::RsaUsingSha512
        | AlgorithmIdentifier::EcdsaUsingP521CurveAndSha512
        | AlgorithmIdentifier::RsaPssUsingSha512 => {
            let digest = crate::crypto::sha512(token);
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&digest[..digest.len() / 2])
        }
        AlgorithmIdentifier::EdDsa if key_curve == Some("Ed25519") => {
            let digest = crate::crypto::sha512(token);
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&digest[..digest.len() / 2])
        }
        AlgorithmIdentifier::None | AlgorithmIdentifier::EdDsa => {
            return Err(OidcError::UnsupportedAlgorithm(format!(
                "{} does not identify an at_hash digest",
                alg_id.name()
            )));
        }
    };
    Ok(encoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::ProviderMetadata;
    use crate::types::{AuthUrl, IssuerUrl, JwksUrl, TokenUrl};
    use jose4rs::jwk::{AsyncJwksFetcher, FetchResponse, JsonWebKey, JsonWebKeySet};
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use rsa::RsaPrivateKey;
    use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
    use serde_json::json;
    use sha2::Digest as _;
    use std::str::FromStr;
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
    async fn rejects_missing_subject() {
        let (priv_key, jwk) = make_keypair();
        let iat = now();
        let claims = json!({
            "iss": "https://idp.example.com",
            "aud": "my-client",
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
    async fn rejects_missing_issued_at() {
        let (priv_key, jwk) = make_keypair();
        let iat = now();
        let claims = json!({
            "iss": "https://idp.example.com",
            "aud": "my-client",
            "sub": "user-42",
            "exp": iat + 3600,
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
    async fn enforces_auth_time_when_max_age_requested() {
        let (priv_key, jwk) = make_keypair();
        let iat = now();
        let jwks = build_jwks(&jwk);
        let ctx = VerifyContext {
            expected_max_age: Some(Duration::from_secs(300)),
            clock_skew: Some(Duration::from_secs(30)),
            ..Default::default()
        };
        let base = json!({
            "iss": "https://idp.example.com",
            "aud": "my-client",
            "sub": "user-1",
            "exp": iat + 3600,
            "iat": iat,
        });

        for auth_time in [
            None,
            Some(json!("invalid")),
            Some(json!(iat - 3600)),
            Some(json!(iat + 3600)),
        ] {
            let mut claims = base.clone();
            if let Some(auth_time) = auth_time {
                claims["auth_time"] = auth_time;
            }
            let token = IdToken::parse(sign_id_token(&priv_key, &claims)).unwrap();
            let err = verifier().verify(&token, &jwks, &ctx).await.unwrap_err();
            assert!(matches!(err, OidcError::InvalidIdToken(_)));
        }

        let mut claims = base;
        claims["auth_time"] = json!(iat - 120);
        let token = IdToken::parse(sign_id_token(&priv_key, &claims)).unwrap();
        verifier().verify(&token, &jwks, &ctx).await.unwrap();
    }

    #[tokio::test]
    async fn validates_at_hash_when_present() {
        let (priv_key, jwk) = make_keypair();
        let iat = now();
        let access_token = "AT-VALUE-123";
        let digest = sha2::Sha256::digest(access_token.as_bytes());
        let at_hash =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&digest[..digest.len() / 2]);
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

    #[test]
    fn at_hash_uses_jws_hash_family_and_left_half() {
        let access_token = "AT-VALUE-123";
        let sha256 = sha2::Sha256::digest(access_token.as_bytes());
        let sha384 = sha2::Sha384::digest(access_token.as_bytes());
        let sha512 = sha2::Sha512::digest(access_token.as_bytes());
        let encode_left = |digest: &[u8]| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&digest[..digest.len() / 2])
        };

        assert_eq!(
            calculate_at_hash(access_token, AlgorithmIdentifier::RsaUsingSha256, None).unwrap(),
            encode_left(&sha256)
        );
        assert_eq!(
            calculate_at_hash(access_token, AlgorithmIdentifier::RsaUsingSha384, None).unwrap(),
            encode_left(&sha384)
        );
        assert_eq!(
            calculate_at_hash(access_token, AlgorithmIdentifier::RsaUsingSha512, None).unwrap(),
            encode_left(&sha512)
        );
        assert_eq!(
            calculate_at_hash(access_token, AlgorithmIdentifier::EdDsa, Some("Ed25519")).unwrap(),
            encode_left(&sha512)
        );
        assert!(
            calculate_at_hash(access_token, AlgorithmIdentifier::EdDsa, Some("Ed448")).is_err()
        );
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

    fn metadata_with_algs(algs: Vec<String>) -> ProviderMetadata {
        ProviderMetadata {
            issuer: IssuerUrl::from_str("https://idp.example.com").unwrap(),
            authorization_endpoint: AuthUrl::from_str("https://idp.example.com/authorize").unwrap(),
            token_endpoint: TokenUrl::from_str("https://idp.example.com/token").unwrap(),
            userinfo_endpoint: None,
            jwks_uri: JwksUrl::from_str("https://idp.example.com/jwks").unwrap(),
            end_session_endpoint: None,
            registration_endpoint: None,
            scopes_supported: None,
            response_types_supported: vec!["code".into()],
            subject_types_supported: vec!["public".into()],
            id_token_signing_alg_values_supported: algs,
            grant_types_supported: None,
            token_endpoint_auth_methods_supported: None,
            authorization_response_iss_parameter_supported: false,
            userinfo_signing_alg_values_supported: None,
            extra: serde_json::Map::new(),
        }
    }

    #[test]
    fn from_metadata_narrows_to_advertised_subset() {
        let meta = metadata_with_algs(vec!["RS256".into(), "ES256".into()]);
        let v = IdTokenVerifier::from_metadata(&meta, "my-client");
        assert_eq!(v.allowed_algs(), &["RS256".to_owned(), "ES256".to_owned()]);
        assert_eq!(v.issuer(), "https://idp.example.com");
        assert_eq!(v.audience(), "my-client");
    }

    #[test]
    fn from_metadata_preserves_issuer_with_path() {
        let meta = metadata_with_algs(vec!["RS256".into()]);
        // Issuer with a non-trivial path -- no slash stripping needed.
        let meta = ProviderMetadata {
            issuer: IssuerUrl::from_str("https://idp.example.com/op").unwrap(),
            ..meta
        };
        let v = IdTokenVerifier::from_metadata(&meta, "my-client");
        assert_eq!(v.issuer(), "https://idp.example.com/op");
    }

    #[test]
    fn from_metadata_preserves_trailing_slash() {
        let meta = metadata_with_algs(vec!["RS256".into()]);
        let meta = ProviderMetadata {
            issuer: IssuerUrl::from_str("https://idp.example.com/").unwrap(),
            ..meta
        };
        let v = IdTokenVerifier::from_metadata(&meta, "my-client");
        assert_eq!(v.issuer(), "https://idp.example.com/");
    }

    #[test]
    fn from_metadata_preserves_op_advertised_empty_list() {
        // An empty list means the OP explicitly advertised nothing;
        // honor that as "reject every alg" so a misconfigured OP
        // surfaces as a hard verification failure rather than
        // silently passing.
        let meta = metadata_with_algs(vec![]);
        let v = IdTokenVerifier::from_metadata(&meta, "my-client");
        assert!(v.allowed_algs().is_empty());
    }

    #[test]
    fn from_metadata_keeps_unknown_alg_strings_verbatim() {
        // OPs can advertise algs jose4rs does not recognize; the
        // allow-list is opaque strings, so we do not validate each
        // entry against the jose4rs enum. The downstream
        // `AlgorithmIdentifier::try_from` in `check_alg` is what
        // surfaces an unsupported alg to the caller.
        let meta = metadata_with_algs(vec!["RS256".into(), "ZZ999".into()]);
        let v = IdTokenVerifier::from_metadata(&meta, "my-client");
        assert_eq!(v.allowed_algs(), &["RS256".to_owned(), "ZZ999".to_owned()]);
    }

    #[test]
    fn from_metadata_filters_none_and_symmetric_algs() {
        let meta = metadata_with_algs(vec![
            "none".into(),
            "RS256".into(),
            "HS256".into(),
            "ES256".into(),
            "HS512".into(),
        ]);
        let v = IdTokenVerifier::from_metadata(&meta, "my-client");
        assert_eq!(v.allowed_algs(), &["RS256".to_owned(), "ES256".to_owned()]);
    }

    #[test]
    fn check_alg_hard_rejects_none_even_when_allowlisted() {
        let v = IdTokenVerifier::new("https://idp.example.com", "my-client")
            .with_allowed_algs(vec!["none".to_owned()]);
        let err = v.check_alg("none").unwrap_err();
        assert!(matches!(err, OidcError::UnsupportedAlgorithm(_)));
    }

    #[tokio::test]
    async fn rejects_multi_aud_without_azp() {
        let (priv_key, jwk) = make_keypair();
        let iat = now();
        let claims = json!({
            "iss": "https://idp.example.com",
            "aud": ["my-client", "other-client"],
            "sub": "user-1",
            "exp": iat + 3600,
            "iat": iat,
        });
        let token = IdToken::parse(sign_id_token(&priv_key, &claims)).unwrap();
        let jwks = build_jwks(&jwk);
        let err = verifier()
            .verify(&token, &jwks, &VerifyContext::default())
            .await
            .unwrap_err();
        assert!(matches!(err, OidcError::InvalidIdToken(_)));
    }

    #[tokio::test]
    async fn accepts_multi_aud_with_matching_azp() {
        let (priv_key, jwk) = make_keypair();
        let iat = now();
        let claims = json!({
            "iss": "https://idp.example.com",
            "aud": ["my-client", "other-client"],
            "azp": "my-client",
            "sub": "user-1",
            "exp": iat + 3600,
            "iat": iat,
        });
        let token = IdToken::parse(sign_id_token(&priv_key, &claims)).unwrap();
        let jwks = build_jwks(&jwk);
        let parsed = verifier()
            .verify(&token, &jwks, &VerifyContext::default())
            .await
            .unwrap();
        assert_eq!(parsed.subject().unwrap(), "user-1");
    }

    #[tokio::test]
    async fn rejects_multi_aud_with_mismatched_azp() {
        let (priv_key, jwk) = make_keypair();
        let iat = now();
        let claims = json!({
            "iss": "https://idp.example.com",
            "aud": ["my-client", "other-client"],
            "azp": "other-client",
            "sub": "user-1",
            "exp": iat + 3600,
            "iat": iat,
        });
        let token = IdToken::parse(sign_id_token(&priv_key, &claims)).unwrap();
        let jwks = build_jwks(&jwk);
        let err = verifier()
            .verify(&token, &jwks, &VerifyContext::default())
            .await
            .unwrap_err();
        assert!(matches!(err, OidcError::InvalidIdToken(_)));
    }

    #[tokio::test]
    async fn rejects_single_aud_with_mismatched_azp() {
        let (priv_key, jwk) = make_keypair();
        let iat = now();
        let claims = json!({
            "iss": "https://idp.example.com",
            "aud": "my-client",
            "azp": "attacker",
            "sub": "user-1",
            "exp": iat + 3600,
            "iat": iat,
        });
        let token = IdToken::parse(sign_id_token(&priv_key, &claims)).unwrap();
        let jwks = build_jwks(&jwk);
        let err = verifier()
            .verify(&token, &jwks, &VerifyContext::default())
            .await
            .unwrap_err();
        assert!(matches!(err, OidcError::InvalidIdToken(_)));
    }
}
