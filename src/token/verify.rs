//! ID-token verification.
//!
//! Implements every check in SPEC §5:
//! - signature via `JsonWebSignature::verify_signature(&key)`
//! - `alg` against the verifier's allow-list
//! - `iss`, `aud`, `exp`, `iat`, `nbf` via `JwtConsumer`
//! - additional `aud` values must be explicitly trusted
//! - `azp` rule: when `aud` has multiple values, `azp` must equal the
//!   configured client id
//! - `nonce` matches the second-leg state (caller supplies it)
//! - `at_hash` over the access token (caller supplies it; hybrid flow)
//! - `auth_time` freshness when the request used `max_age`
//! - JWKS `kid` lookup with refresh on miss (combined with alg
//!   filtering via `AsyncHttpsJwks::select_verification_key`)

use std::time::Duration;

use jose4rs::error::JoseError;
use jose4rs::jwk::{AsyncHttpsJwks, JsonWebKey};
use jose4rs::jws::{AlgorithmIdentifier, JsonWebSignature};
use jose4rs::jwt::{JwtClaims, JwtConsumerBuilder};
use jose4rs::jwx::{HeaderParameter, JsonWebStructure as _};

use crate::error::OidcError;
use crate::metadata::ProviderMetadata;
use crate::token::response::{IdToken, TokenResponse};

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
    /// valid `auth_time`. A zero value requires fresh authentication
    /// for the current request rather than a zero-second callback delay.
    pub expected_max_age: Option<Duration>,
    /// Time the authorization request was created. Required when
    /// `expected_max_age` is zero.
    pub authorization_started_at: Option<std::time::SystemTime>,
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
    trusted_additional_audiences: Vec<String>,
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
            trusted_additional_audiences: Vec::new(),
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
            trusted_additional_audiences: Vec::new(),
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

    /// Replaces the trusted list of additional ID-token audiences.
    /// By default, only the configured client ID is trusted. It must
    /// still appear in `aud` even when additional audiences are trusted.
    pub fn with_trusted_additional_audiences(
        mut self,
        audiences: impl IntoIterator<Item = String>,
    ) -> Self {
        self.trusted_additional_audiences = audiences.into_iter().collect();
        self
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
        let jws = JsonWebSignature::from_compact_serialization(&token.raw)?;
        let alg = jws.algorithm().unwrap_or("");
        self.check_alg(alg)?;
        let alg_id = AlgorithmIdentifier::try_from(alg)
            .map_err(|e: JoseError| OidcError::UnsupportedAlgorithm(e.to_string()))?;

        // 2. JWKS lookup with refresh on unknown kid.
        let key = resolve_key(jwks, jws.header(HeaderParameter::KeyId), alg).await?;

        // 3+4. Signature + claim-level validation.
        let claims = verify_signature_and_claims(self, &jws, &key, ctx)?;

        // 5. Additional audiences and azp.
        check_azp(
            &claims,
            ctx,
            &self.expected_audience,
            &self.trusted_additional_audiences,
        )?;

        // 6. nonce.
        check_nonce(&claims, ctx)?;

        // 7. at_hash.
        check_at_hash(&claims, ctx, alg_id, &key)?;

        // 8. auth_time when max_age was requested.
        check_auth_time(&claims, ctx)?;

        Ok(claims)
    }

    /// Validates any ID token in a refresh response against the verified ID
    /// token claims from the original authentication (OIDC Core section 12.2).
    /// Pass the original claims, not those from a previous refresh.
    /// A response without an ID token returns `Ok(None)` and does not change
    /// the authenticated identity. If the refreshed token includes `auth_time`,
    /// the original token must also have recorded it to establish continuity.
    pub async fn verify_refresh_response(
        &self,
        response: &TokenResponse,
        original: &JwtClaims,
        jwks: &AsyncHttpsJwks,
    ) -> Result<Option<JwtClaims>, OidcError> {
        let Some(raw) = response.id_token() else {
            return Ok(None);
        };
        let token = IdToken::parse(raw)?;
        let context = VerifyContext {
            access_token: Some(response.access_token.as_str().to_owned()),
            ..VerifyContext::default()
        };
        let refreshed = self.verify(&token, jwks, &context).await?;
        check_refresh_continuity(original, &refreshed)?;
        Ok(Some(refreshed))
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

fn refresh_claim_mismatch(claim: &str) -> OidcError {
    OidcError::InvalidIdToken(jose4rs::jwt::InvalidJwtError::new(format!(
        "refreshed ID token has inconsistent {claim}"
    )))
}

fn check_refresh_continuity(original: &JwtClaims, refreshed: &JwtClaims) -> Result<(), OidcError> {
    if refreshed.issuer() != original.issuer() {
        return Err(refresh_claim_mismatch("iss"));
    }
    if refreshed.subject() != original.subject() {
        return Err(refresh_claim_mismatch("sub"));
    }
    let audience_set = |claims: &JwtClaims| {
        let mut audiences = claims.audience().unwrap_or_default();
        audiences.sort_unstable();
        audiences.dedup();
        audiences
    };
    if audience_set(refreshed) != audience_set(original) {
        return Err(refresh_claim_mismatch("aud"));
    }
    if refreshed
        .issued_at()
        .zip(original.issued_at())
        .is_none_or(|(refreshed_at, original_at)| refreshed_at < original_at)
    {
        return Err(refresh_claim_mismatch("iat"));
    }
    if refreshed.has_claim("nonce") {
        let matches = refreshed
            .string_claim("nonce")
            .zip(original.string_claim("nonce"))
            .is_some_and(|(actual, expected)| {
                crate::crypto::ct_equals(actual.as_bytes(), expected.as_bytes())
            });
        if !matches {
            return Err(refresh_claim_mismatch("nonce"));
        }
    }
    if refreshed.has_claim("auth_time") {
        let original_json: serde_json::Value = serde_json::from_str(&original.to_json())?;
        let refreshed_json: serde_json::Value = serde_json::from_str(&refreshed.to_json())?;
        let auth_time = refreshed_json
            .get("auth_time")
            .and_then(serde_json::Value::as_number);
        if auth_time.is_none()
            || auth_time
                != original_json
                    .get("auth_time")
                    .and_then(serde_json::Value::as_number)
        {
            return Err(refresh_claim_mismatch("auth_time"));
        }
    }
    Ok(())
}

/// Refreshes the JWKS on a `kid` miss. Without a `kid`, requires a unique
/// candidate after applying the same key selection rules.
pub(crate) async fn resolve_key(
    jwks: &AsyncHttpsJwks,
    kid: Option<&str>,
    alg: &str,
) -> Result<JsonWebKey, OidcError> {
    let key = if kid.is_some() {
        jwks.select_verification_key(kid, alg).await?
    } else {
        let keys = jwks.keys_with_refresh(None).await?;
        let candidates = jose4rs::jwk::VerificationJwkSelector::new().select_list(None, alg, &keys);
        match candidates.as_slice() {
            [key] => Some((*key).clone()),
            _ => None,
        }
    };
    key.ok_or_else(|| OidcError::NoMatchingJwk {
        kid: kid.map(str::to_owned),
        alg: alg.to_owned(),
    })
}

/// Verifies the JWS signature and runs the JwtConsumer over the
/// payload to enforce iss/aud/exp/iat/nbf.
fn verify_signature_and_claims(
    verifier: &IdTokenVerifier,
    jws: &JsonWebSignature,
    key: &JsonWebKey,
    ctx: &VerifyContext,
) -> Result<JwtClaims, OidcError> {
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

/// Enforces audience trust and the azp rules from OIDC Core 1.0 section 3.1.3.7: azp is
/// required when `aud` is multi-valued, and whenever azp is present it
/// must equal the relying party's client id.
fn check_azp(
    claims: &JwtClaims,
    ctx: &VerifyContext,
    expected_audience: &str,
    trusted_additional_audiences: &[String],
) -> Result<(), OidcError> {
    let audiences = claims.audience().unwrap_or_default();
    if audiences.iter().any(|audience| {
        *audience != expected_audience
            && !trusted_additional_audiences
                .iter()
                .any(|trusted| trusted == audience)
    }) {
        return Err(OidcError::InvalidIdToken(
            jose4rs::jwt::InvalidJwtError::new("aud contains an untrusted additional audience"),
        ));
    }
    let azp = claims.string_claim("azp");
    if audiences.len() > 1 && azp.is_none() {
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
    let too_old = if max_age.is_zero() {
        let started_at = ctx.authorization_started_at.ok_or_else(|| {
            OidcError::InvalidAuthorizationRequest(
                "authorization start time is required for max_age=0".into(),
            )
        })?;
        let earliest = started_at
            .checked_sub(skew)
            .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
            .unwrap_or_default();
        seconds < earliest.as_secs()
    } else {
        auth_time
            .checked_add(max_age)
            .and_then(|deadline| deadline.checked_add(skew))
            .is_some_and(|deadline| now > deadline)
    };
    if too_old {
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
            base64_simd::URL_SAFE_NO_PAD.encode_to_string(&digest[..digest.len() / 2])
        }
        #[cfg(not(feature = "boring"))]
        AlgorithmIdentifier::EcdsaUsingSecp256k1CurveAndSha256 => {
            let digest = crate::crypto::sha256(token);
            base64_simd::URL_SAFE_NO_PAD.encode_to_string(&digest[..digest.len() / 2])
        }
        AlgorithmIdentifier::HmacSha384
        | AlgorithmIdentifier::RsaUsingSha384
        | AlgorithmIdentifier::EcdsaUsingP384CurveAndSha384
        | AlgorithmIdentifier::RsaPssUsingSha384 => {
            let digest = crate::crypto::sha384(token);
            base64_simd::URL_SAFE_NO_PAD.encode_to_string(&digest[..digest.len() / 2])
        }
        AlgorithmIdentifier::HmacSha512
        | AlgorithmIdentifier::RsaUsingSha512
        | AlgorithmIdentifier::EcdsaUsingP521CurveAndSha512
        | AlgorithmIdentifier::RsaPssUsingSha512 => {
            let digest = crate::crypto::sha512(token);
            base64_simd::URL_SAFE_NO_PAD.encode_to_string(&digest[..digest.len() / 2])
        }
        AlgorithmIdentifier::EdDsa if key_curve == Some("Ed25519") => {
            let digest = crate::crypto::sha512(token);
            base64_simd::URL_SAFE_NO_PAD.encode_to_string(&digest[..digest.len() / 2])
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

    /// Builds a JWKS body with explicit signing metadata for the mock fetcher.
    fn jwks_body(keys: &[JsonWebKey]) -> Vec<u8> {
        let set = JsonWebKeySet::from_keys(keys.to_vec());
        let mut json: serde_json::Value =
            serde_json::from_str(&set.to_json(jose4rs::jwk::OutputControlLevel::PublicOnly))
                .unwrap();
        if let Some(keys) = json.get_mut("keys").and_then(|k| k.as_array_mut()) {
            for k in keys.iter_mut() {
                if let Some(obj) = k.as_object_mut() {
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
        build_jwks_from_keys(std::slice::from_ref(jwk))
    }

    fn build_jwks_from_keys(keys: &[JsonWebKey]) -> AsyncHttpsJwks {
        let fetcher: Arc<dyn AsyncJwksFetcher> = Arc::new(StaticJwks {
            body: jwks_body(keys),
        });
        AsyncHttpsJwks::new("https://idp.example.com/jwks", fetcher)
    }

    fn sign_id_token(priv_key: &RsaPrivateKey, claims: &serde_json::Value) -> String {
        sign_id_token_with_kid(priv_key, claims, Some(KID))
    }

    fn sign_id_token_with_kid(
        priv_key: &RsaPrivateKey,
        claims: &serde_json::Value,
        kid: Option<&str>,
    ) -> String {
        let pem = priv_key.to_pkcs8_pem(LineEnding::LF).expect("priv pem");
        let key = EncodingKey::from_rsa_pem(pem.as_bytes()).expect("enc key");
        let mut header = Header::new(Algorithm::RS256);
        header.kid = kid.map(str::to_owned);
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
    async fn token_without_kid_requires_one_eligible_key() -> Result<(), OidcError> {
        let (signing_key, signing_jwk) = make_keypair();
        let (_, mut other_jwk) = make_keypair();
        other_jwk.set_key_id("test-key-2");
        let issued_at = now();
        let claims = json!({
            "iss": "https://idp.example.com",
            "aud": "my-client",
            "sub": "user-42",
            "exp": issued_at + 3600,
            "iat": issued_at,
        });
        let token = IdToken::parse(sign_id_token_with_kid(&signing_key, &claims, None))?;
        let verifier = verifier();
        let context = VerifyContext::default();
        let verified = verifier
            .verify(&token, &build_jwks(&signing_jwk), &context)
            .await?;
        assert_eq!(verified.subject(), Some("user-42"));

        for keys in [
            [signing_jwk.clone(), other_jwk.clone()],
            [other_jwk, signing_jwk],
        ] {
            let result = verifier
                .verify(&token, &build_jwks_from_keys(&keys), &context)
                .await;
            assert!(matches!(
                result,
                Err(OidcError::NoMatchingJwk { kid: None, .. })
            ));
        }
        Ok(())
    }

    #[tokio::test]
    async fn refresh_response_preserves_the_original_authentication() {
        let (priv_key, jwk) = make_keypair();
        let issued_at = now();
        let original_claims = json!({
            "iss": "https://idp.example.com",
            "aud": ["my-client", "trusted-client"],
            "azp": "my-client",
            "sub": "user-1",
            "exp": issued_at + 3600,
            "iat": issued_at - 60,
            "auth_time": issued_at - 120,
            "nonce": "original-nonce",
        });
        let jwks = build_jwks(&jwk);
        let verifier = verifier().with_trusted_additional_audiences(["trusted-client".into()]);
        let token = IdToken::parse(sign_id_token(&priv_key, &original_claims)).unwrap();
        let original = verifier
            .verify(&token, &jwks, &VerifyContext::default())
            .await
            .unwrap();
        let mut response: TokenResponse = serde_json::from_value(json!({
            "access_token": "refreshed-access-token",
            "token_type": "Bearer",
        }))
        .unwrap();
        assert!(
            verifier
                .verify_refresh_response(&response, &original, &jwks)
                .await
                .unwrap()
                .is_none()
        );

        let mut claims = original_claims;
        claims["iat"] = json!(issued_at);
        claims["aud"] = json!(["trusted-client", "my-client"]);
        response.id_token = Some(sign_id_token(&priv_key, &claims));
        assert!(
            verifier
                .verify_refresh_response(&response, &original, &jwks)
                .await
                .unwrap()
                .is_some()
        );

        claims.as_object_mut().unwrap().remove("nonce");
        response.id_token = Some(sign_id_token(&priv_key, &claims));
        assert!(
            verifier
                .verify_refresh_response(&response, &original, &jwks)
                .await
                .unwrap()
                .is_some()
        );

        for (claim, value) in [
            ("sub", json!("another-user")),
            ("aud", json!("my-client")),
            ("auth_time", json!(issued_at)),
            ("nonce", json!("different-nonce")),
            ("iat", json!(issued_at - 61)),
        ] {
            let mut inconsistent = claims.clone();
            inconsistent[claim] = value;
            response.id_token = Some(sign_id_token(&priv_key, &inconsistent));
            let error = verifier
                .verify_refresh_response(&response, &original, &jwks)
                .await
                .unwrap_err();
            assert!(error.to_string().contains(&format!("inconsistent {claim}")));
        }
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
        let mut token = IdToken::parse(&jwt).unwrap();
        token.header_alg = "unrelated-cache-value".to_owned();
        let jwks = build_jwks(&jwk);
        let err = verifier()
            .with_allowed_algs(["RS256".to_owned()])
            .verify(&token, &jwks, &VerifyContext::default())
            .await
            .unwrap_err();
        assert!(matches!(err, OidcError::UnsupportedAlgorithm(ref a) if a == "RS384"));
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
    async fn max_age_zero_requires_authentication_during_the_request() {
        let (priv_key, jwk) = make_keypair();
        let issued_at = now();
        let started_at = issued_at - 60;
        let ctx = VerifyContext {
            expected_max_age: Some(Duration::ZERO),
            authorization_started_at: Some(
                std::time::UNIX_EPOCH
                    + Duration::from_secs(u64::try_from(started_at).unwrap())
                    + Duration::from_millis(500),
            ),
            ..Default::default()
        };
        let jwks = build_jwks(&jwk);
        let mut claims = json!({
            "iss": "https://idp.example.com",
            "aud": "my-client",
            "sub": "user-1",
            "exp": issued_at + 3600,
            "iat": issued_at,
        });
        let token = IdToken::parse(sign_id_token(&priv_key, &claims)).unwrap();
        assert!(verifier().verify(&token, &jwks, &ctx).await.is_err());

        claims["auth_time"] = json!(started_at - 1);
        let token = IdToken::parse(sign_id_token(&priv_key, &claims)).unwrap();
        assert!(verifier().verify(&token, &jwks, &ctx).await.is_err());

        claims["auth_time"] = json!(started_at);
        let token = IdToken::parse(sign_id_token(&priv_key, &claims)).unwrap();
        verifier().verify(&token, &jwks, &ctx).await.unwrap();
    }

    #[tokio::test]
    async fn validates_at_hash_when_present() {
        let (priv_key, jwk) = make_keypair();
        let iat = now();
        let access_token = "AT-VALUE-123";
        let digest = sha2::Sha256::digest(access_token.as_bytes());
        let at_hash = base64_simd::URL_SAFE_NO_PAD.encode_to_string(&digest[..digest.len() / 2]);
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
            base64_simd::URL_SAFE_NO_PAD.encode_to_string(&digest[..digest.len() / 2])
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
        assert_eq!(v.allowed_algs(), &[] as &[String]);
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
            .with_trusted_additional_audiences(["other-client".to_owned()])
            .verify(&token, &jwks, &VerifyContext::default())
            .await
            .unwrap_err();
        assert!(matches!(err, OidcError::InvalidIdToken(_)));
    }

    #[tokio::test]
    async fn requires_trusted_additional_audience_even_with_matching_azp() {
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
        let err = verifier()
            .verify(&token, &jwks, &VerifyContext::default())
            .await
            .unwrap_err();
        assert!(matches!(err, OidcError::InvalidIdToken(_)));
        let parsed = verifier()
            .with_trusted_additional_audiences(["other-client".to_owned()])
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
            .with_trusted_additional_audiences(["other-client".to_owned()])
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
