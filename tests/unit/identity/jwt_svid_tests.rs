//! SPIFFE JWT-SVID mint / validate / bundle tests (issue #3617).
//!
//! Covers the library surface (`identity::jwt_svid`) and the three Workload
//! API JWT RPCs. Forged tokens are produced with `ring` directly rather than
//! through the library, so an attack case exercises the validator instead of
//! Ferrum's own minting rules.

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ferrum_edge::identity::attestation::{AttestError, Attestor, PeerInfo, WorkloadIdentity};
use ferrum_edge::identity::ca::{
    CaError, CertificateAuthority, IssuanceRequest, PublishedJwtAuthority, PublishedTrustBundle,
    SignedSvid,
};
use ferrum_edge::identity::jwt_svid::{
    JwtSvidSigner, LocalJwtAuthority, LocalJwtAuthorityConfig, SharedJwtSvidSigner, jwks_document,
    validate_jwt_svid,
};
use ferrum_edge::identity::spiffe::{SpiffeId, TrustDomain};
use ferrum_edge::identity::workload_api::server::WorkloadApiService;
use std::collections::BTreeMap;
use std::sync::Arc;
use tonic::Request;

// ── fixtures ─────────────────────────────────────────────────────────────

fn td() -> TrustDomain {
    TrustDomain::new("td.test").expect("test trust domain is valid")
}

fn workload_id() -> SpiffeId {
    SpiffeId::from_parts(&td(), "ns/test/sa/foo").expect("test SPIFFE ID is valid")
}

fn authority() -> Arc<LocalJwtAuthority> {
    Arc::new(
        LocalJwtAuthority::new(LocalJwtAuthorityConfig::new(td()))
            .expect("local JWT authority builds"),
    )
}

fn bundles_of(signer: &Arc<LocalJwtAuthority>) -> BTreeMap<TrustDomain, Vec<PublishedJwtAuthority>> {
    let mut bundles = BTreeMap::new();
    bundles.insert(td(), signer.authorities());
    bundles
}

fn workload_request<T>(payload: T) -> Request<T> {
    let mut req = Request::new(payload);
    req.metadata_mut().insert(
        "workload.spiffe.io",
        tonic::metadata::AsciiMetadataValue::from_static("true"),
    );
    req
}

/// CA backend that owns a JWT signing authority (the `internal` posture).
struct JwtCapableCa {
    trust_domain: TrustDomain,
    jwt: Arc<LocalJwtAuthority>,
}

#[async_trait]
impl CertificateAuthority for JwtCapableCa {
    async fn issue_svid(&self, req: IssuanceRequest) -> Result<SignedSvid, CaError> {
        let (spiffe_id, ttl_secs) = match req {
            IssuanceRequest::Generate {
                spiffe_id,
                ttl_secs,
            }
            | IssuanceRequest::Csr {
                spiffe_id,
                ttl_secs,
                ..
            } => (spiffe_id, ttl_secs),
        };
        Ok(SignedSvid {
            spiffe_id,
            cert_chain_der: vec![b"stub-cert".to_vec()],
            private_key_pkcs8_der: b"stub-key".to_vec().into(),
            not_after: chrono::Utc::now() + chrono::Duration::seconds(ttl_secs as i64),
        })
    }

    async fn trust_bundle(&self, domain: &TrustDomain) -> Result<PublishedTrustBundle, CaError> {
        if domain != &self.trust_domain {
            return Err(CaError::UnknownTrustDomain(domain.to_string()));
        }
        Ok(PublishedTrustBundle {
            trust_domain: self.trust_domain.clone(),
            roots_der: vec![b"stub-root".to_vec()],
            refresh_hint_secs: None,
        })
    }

    async fn jwt_authorities(
        &self,
        domain: &TrustDomain,
    ) -> Result<Vec<PublishedJwtAuthority>, CaError> {
        if domain != &self.trust_domain {
            return Err(CaError::UnknownTrustDomain(domain.to_string()));
        }
        Ok(self.jwt.authorities())
    }

    fn jwt_signer(&self) -> Option<SharedJwtSvidSigner> {
        Some(Arc::clone(&self.jwt) as SharedJwtSvidSigner)
    }
}

/// CA backend with no JWT authority at all (the `spire` posture).
struct JwtlessCa {
    trust_domain: TrustDomain,
}

#[async_trait]
impl CertificateAuthority for JwtlessCa {
    async fn issue_svid(&self, req: IssuanceRequest) -> Result<SignedSvid, CaError> {
        let (spiffe_id, ttl_secs) = match req {
            IssuanceRequest::Generate {
                spiffe_id,
                ttl_secs,
            }
            | IssuanceRequest::Csr {
                spiffe_id,
                ttl_secs,
                ..
            } => (spiffe_id, ttl_secs),
        };
        Ok(SignedSvid {
            spiffe_id,
            cert_chain_der: vec![b"stub-cert".to_vec()],
            private_key_pkcs8_der: b"stub-key".to_vec().into(),
            not_after: chrono::Utc::now() + chrono::Duration::seconds(ttl_secs as i64),
        })
    }

    async fn trust_bundle(&self, domain: &TrustDomain) -> Result<PublishedTrustBundle, CaError> {
        if domain != &self.trust_domain {
            return Err(CaError::UnknownTrustDomain(domain.to_string()));
        }
        Ok(PublishedTrustBundle {
            trust_domain: self.trust_domain.clone(),
            roots_der: vec![b"stub-root".to_vec()],
            refresh_hint_secs: None,
        })
    }

    async fn jwt_authorities(
        &self,
        _domain: &TrustDomain,
    ) -> Result<Vec<PublishedJwtAuthority>, CaError> {
        Ok(Vec::new())
    }
}

struct StubAttestor {
    id: SpiffeId,
}

#[async_trait]
impl Attestor for StubAttestor {
    fn kind(&self) -> &'static str {
        "stub"
    }

    async fn attest(&self, _peer: &PeerInfo) -> Result<WorkloadIdentity, AttestError> {
        Ok(WorkloadIdentity {
            spiffe_id: self.id.clone(),
            selectors: Default::default(),
            attestor_kind: "stub".to_string(),
        })
    }
}

fn jwt_capable_service() -> (WorkloadApiService, Arc<LocalJwtAuthority>) {
    let jwt = authority();
    let ca: Arc<dyn CertificateAuthority> = Arc::new(JwtCapableCa {
        trust_domain: td(),
        jwt: Arc::clone(&jwt),
    });
    let attestor: Arc<dyn Attestor> = Arc::new(StubAttestor { id: workload_id() });
    (
        WorkloadApiService::new(vec![attestor], ca, td(), 600),
        jwt,
    )
}

// ── forged-token machinery ───────────────────────────────────────────────

/// DER prefix of a P-256 `SubjectPublicKeyInfo`: `SEQUENCE { AlgorithmIdentifier
/// { id-ecPublicKey, prime256v1 }, BIT STRING (0 unused bits) }`. The 65-byte
/// uncompressed point follows.
const P256_SPKI_PREFIX: &[u8] = &[
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

/// An attacker-controlled (or independently generated) ES256 key we can forge
/// arbitrary headers and claim sets with.
struct ForgeKey {
    pkcs8: Vec<u8>,
    public_key_pem: String,
}

fn forge_key() -> ForgeKey {
    use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};

    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
        .expect("ring generates a P-256 key");
    let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
        .expect("generated PKCS#8 parses");

    let mut spki = P256_SPKI_PREFIX.to_vec();
    spki.extend_from_slice(key_pair.public_key().as_ref());

    let mut pem = String::from("-----BEGIN PUBLIC KEY-----\n");
    let encoded = STANDARD.encode(&spki);
    for chunk in encoded.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
        pem.push('\n');
    }
    pem.push_str("-----END PUBLIC KEY-----\n");

    ForgeKey {
        pkcs8: pkcs8.as_ref().to_vec(),
        public_key_pem: pem,
    }
}

/// Sign an arbitrary header/claims pair into a JWS compact serialization.
fn sign_compact(key: &ForgeKey, header_json: &str, claims_json: &str) -> String {
    use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};

    let rng = ring::rand::SystemRandom::new();
    let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &key.pkcs8, &rng)
        .expect("forge key parses");
    let signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header_json.as_bytes()),
        URL_SAFE_NO_PAD.encode(claims_json.as_bytes())
    );
    let signature = key_pair
        .sign(&rng, signing_input.as_bytes())
        .expect("forge key signs");
    format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature.as_ref())
    )
}

/// A bundle holding exactly one forged authority under `kid`.
fn forged_bundles(
    key: &ForgeKey,
    kid: &str,
) -> BTreeMap<TrustDomain, Vec<PublishedJwtAuthority>> {
    let mut bundles = BTreeMap::new();
    bundles.insert(
        td(),
        vec![PublishedJwtAuthority {
            trust_domain: td(),
            key_id: kid.to_string(),
            public_key_pem: key.public_key_pem.clone(),
        }],
    );
    bundles
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn claims_of(validated_json: &[u8]) -> serde_json::Value {
    serde_json::from_slice(validated_json).expect("claims are JSON")
}

// ── mint ─────────────────────────────────────────────────────────────────

#[test]
fn mint_and_validate_round_trip() {
    let signer = authority();
    let minted = signer
        .mint(&workload_id(), &["spiffe://td.test/api".to_string()], 0)
        .expect("mint succeeds");

    let validated = validate_jwt_svid(
        &minted.token,
        "spiffe://td.test/api",
        &bundles_of(&signer),
    )
    .expect("round trip validates");

    assert_eq!(validated.spiffe_id, workload_id());
    let claims = claims_of(&validated.claims_json);
    assert_eq!(claims["sub"], workload_id().as_str());
    assert_eq!(claims["aud"][0], "spiffe://td.test/api");
    assert!(claims["exp"].is_number(), "exp must be present");
    assert!(claims["iat"].is_number(), "iat must be present");
    assert!(
        claims["jti"].as_str().is_some_and(|jti| !jti.is_empty()),
        "each token needs a unique identity"
    );
}

#[test]
fn minted_tokens_have_distinct_token_ids() {
    let signer = authority();
    let first = signer
        .mint(&workload_id(), &["aud".to_string()], 0)
        .expect("first mint");
    let second = signer
        .mint(&workload_id(), &["aud".to_string()], 0)
        .expect("second mint");
    assert_ne!(
        first.token, second.token,
        "two mints must not produce byte-identical bearer tokens"
    );
}

#[test]
fn mint_rejects_an_empty_audience_list() {
    let signer = authority();
    let err = signer
        .mint(&workload_id(), &[], 0)
        .expect_err("an audience is required");
    assert!(err.to_string().contains("at least one audience"));
}

#[test]
fn mint_rejects_an_empty_audience_entry() {
    let signer = authority();
    assert!(
        signer
            .mint(&workload_id(), &[String::new()], 0)
            .is_err(),
        "an empty audience string must not reach a signed token"
    );
    assert!(
        signer
            .mint(&workload_id(), &["   ".to_string()], 0)
            .is_err(),
        "a whitespace-only audience must not reach a signed token"
    );
}

#[test]
fn mint_rejects_too_many_or_oversized_audiences() {
    let signer = authority();
    let many: Vec<String> = (0..64).map(|index| format!("aud-{index}")).collect();
    assert!(signer.mint(&workload_id(), &many, 0).is_err());

    let huge = vec!["a".repeat(4096)];
    assert!(signer.mint(&workload_id(), &huge, 0).is_err());
}

#[test]
fn mint_rejects_a_control_character_audience() {
    let signer = authority();
    assert!(
        signer
            .mint(&workload_id(), &["good\u{0000}evil".to_string()], 0)
            .is_err()
    );
}

#[test]
fn mint_collapses_duplicate_audiences_preserving_order() {
    let signer = authority();
    let minted = signer
        .mint(
            &workload_id(),
            &["b".to_string(), "a".to_string(), "b".to_string()],
            0,
        )
        .expect("mint succeeds");
    let validated =
        validate_jwt_svid(&minted.token, "a", &bundles_of(&signer)).expect("validates");
    let claims = claims_of(&validated.claims_json);
    assert_eq!(claims["aud"], serde_json::json!(["b", "a"]));
}

#[test]
fn mint_refuses_a_subject_from_another_trust_domain() {
    let signer = authority();
    let foreign = SpiffeId::new("spiffe://other.test/ns/x/sa/y").expect("valid SPIFFE ID");
    let err = signer
        .mint(&foreign, &["aud".to_string()], 0)
        .expect_err("cross-trust-domain mint must be refused");
    assert!(err.to_string().contains("trust domain"));
}

#[test]
fn mint_clamps_the_lifetime_to_the_authority_ceiling() {
    let signer = authority();
    let minted = signer
        .mint(&workload_id(), &["aud".to_string()], u64::MAX)
        .expect("mint succeeds");
    let lifetime = (minted.expires_at - minted.issued_at).num_seconds();
    assert!(
        lifetime <= 3600,
        "a caller must not be able to raise the JWT-SVID ceiling (got {lifetime}s)"
    );
    assert!(lifetime > 0);
}

// ── validate: audience / subject ─────────────────────────────────────────

#[test]
fn validate_rejects_a_different_audience() {
    let signer = authority();
    let minted = signer
        .mint(&workload_id(), &["intended".to_string()], 0)
        .expect("mint succeeds");
    let err = validate_jwt_svid(&minted.token, "attacker", &bundles_of(&signer))
        .expect_err("audience mismatch must fail");
    assert!(err.to_string().contains("audience"));
}

#[test]
fn validate_rejects_an_empty_audience_argument() {
    let signer = authority();
    let minted = signer
        .mint(&workload_id(), &["aud".to_string()], 0)
        .expect("mint succeeds");
    assert!(validate_jwt_svid(&minted.token, "", &bundles_of(&signer)).is_err());
}

#[test]
fn validate_rejects_a_non_spiffe_subject() {
    let key = forge_key();
    let token = sign_compact(
        &key,
        r#"{"alg":"ES256","kid":"k1","typ":"JWT"}"#,
        &format!(
            r#"{{"sub":"not-a-spiffe-id","aud":["aud"],"exp":{}}}"#,
            now() + 300
        ),
    );
    let err = validate_jwt_svid(&token, "aud", &forged_bundles(&key, "k1"))
        .expect_err("a non-SPIFFE subject must fail");
    assert!(err.to_string().contains("SPIFFE ID"));
}

#[test]
fn validate_rejects_an_issuer_from_another_trust_domain() {
    let key = forge_key();
    let token = sign_compact(
        &key,
        r#"{"alg":"ES256","kid":"k1","typ":"JWT"}"#,
        &format!(
            r#"{{"sub":"spiffe://td.test/ns/test/sa/foo","iss":"spiffe://evil.test","aud":["aud"],"exp":{}}}"#,
            now() + 300
        ),
    );
    let err = validate_jwt_svid(&token, "aud", &forged_bundles(&key, "k1"))
        .expect_err("a cross-domain issuer must fail");
    assert!(err.to_string().contains("issuer"));
}

// ── validate: key / algorithm ────────────────────────────────────────────

#[test]
fn validate_rejects_an_unknown_trust_domain() {
    let signer = authority();
    let minted = signer
        .mint(&workload_id(), &["aud".to_string()], 0)
        .expect("mint succeeds");

    let mut bundles = BTreeMap::new();
    let other = TrustDomain::new("other.test").expect("valid trust domain");
    bundles.insert(
        other.clone(),
        vec![PublishedJwtAuthority {
            trust_domain: other,
            key_id: "k1".to_string(),
            public_key_pem: forge_key().public_key_pem,
        }],
    );

    let err = validate_jwt_svid(&minted.token, "aud", &bundles)
        .expect_err("a token from an untrusted domain must fail");
    assert!(err.to_string().contains("trust domain"));
}

#[test]
fn validate_rejects_an_unknown_key_id() {
    let signer = authority();
    let minted = signer
        .mint(&workload_id(), &["aud".to_string()], 0)
        .expect("mint succeeds");
    let err = validate_jwt_svid(&minted.token, "aud", &forged_bundles(&forge_key(), "unrelated"))
        .expect_err("an unknown kid must fail");
    assert!(err.to_string().contains("key id"));
}

#[test]
fn validate_rejects_a_signature_from_a_different_key_under_the_same_key_id() {
    // The classic key-substitution attempt: keep the `kid` the verifier
    // expects, but sign with a key the verifier does not hold.
    let signer = authority();
    let minted = signer
        .mint(&workload_id(), &["aud".to_string()], 0)
        .expect("mint succeeds");
    let real_kid = signer.authorities()[0].key_id.clone();

    let err = validate_jwt_svid(&minted.token, "aud", &forged_bundles(&forge_key(), &real_kid))
        .expect_err("a mismatched key must fail");
    assert!(err.to_string().contains("signature"));
}

#[test]
fn validate_rejects_the_unsecured_none_algorithm() {
    let claims = format!(
        r#"{{"sub":"spiffe://td.test/ns/test/sa/foo","aud":["aud"],"exp":{}}}"#,
        now() + 300
    );
    let token = format!(
        "{}.{}.",
        URL_SAFE_NO_PAD.encode(br#"{"alg":"none","kid":"k1"}"#),
        URL_SAFE_NO_PAD.encode(claims.as_bytes())
    );
    let err = validate_jwt_svid(&token, "aud", &forged_bundles(&forge_key(), "k1"))
        .expect_err("alg=none must fail");
    // The empty signature segment is caught first; either rejection is
    // fail-closed, and the alg check covers the padded-signature form below.
    assert!(!err.to_string().is_empty());

    let with_signature = format!(
        "{}.{}.{}",
        URL_SAFE_NO_PAD.encode(br#"{"alg":"none","kid":"k1"}"#),
        URL_SAFE_NO_PAD.encode(claims.as_bytes()),
        URL_SAFE_NO_PAD.encode(b"x")
    );
    let err = validate_jwt_svid(&with_signature, "aud", &forged_bundles(&forge_key(), "k1"))
        .expect_err("alg=none must fail");
    assert!(err.to_string().contains("none"));
}

#[test]
fn validate_rejects_a_symmetric_algorithm() {
    // Algorithm confusion: an attacker who can read the public JWT bundle
    // signs an HS256 token with the published public key as the HMAC secret.
    let claims = format!(
        r#"{{"sub":"spiffe://td.test/ns/test/sa/foo","aud":["aud"],"exp":{}}}"#,
        now() + 300
    );
    let token = format!(
        "{}.{}.{}",
        URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","kid":"k1"}"#),
        URL_SAFE_NO_PAD.encode(claims.as_bytes()),
        URL_SAFE_NO_PAD.encode(b"forged-mac")
    );
    let err = validate_jwt_svid(&token, "aud", &forged_bundles(&forge_key(), "k1"))
        .expect_err("HS256 must fail against a public-key bundle");
    assert!(err.to_string().contains("symmetric"));
}

#[test]
fn validate_rejects_unknown_critical_headers() {
    let key = forge_key();
    let token = sign_compact(
        &key,
        r#"{"alg":"ES256","kid":"k1","crit":["ferrum"],"ferrum":1}"#,
        &format!(
            r#"{{"sub":"spiffe://td.test/ns/test/sa/foo","aud":["aud"],"exp":{}}}"#,
            now() + 300
        ),
    );
    let err = validate_jwt_svid(&token, "aud", &forged_bundles(&key, "k1"))
        .expect_err("unknown critical headers must fail");
    assert!(err.to_string().contains("critical"));
}

#[test]
fn validate_rejects_a_kidless_token_when_the_bundle_is_ambiguous() {
    let key = forge_key();
    let token = sign_compact(
        &key,
        r#"{"alg":"ES256","typ":"JWT"}"#,
        &format!(
            r#"{{"sub":"spiffe://td.test/ns/test/sa/foo","aud":["aud"],"exp":{}}}"#,
            now() + 300
        ),
    );

    // One key: no `kid` is unambiguous and validates.
    validate_jwt_svid(&token, "aud", &forged_bundles(&key, "k1"))
        .expect("a single-key bundle resolves a kid-less token");

    // Two keys: the token no longer identifies which authority signed it.
    let mut ambiguous = forged_bundles(&key, "k1");
    ambiguous
        .get_mut(&td())
        .expect("local bundle")
        .push(PublishedJwtAuthority {
            trust_domain: td(),
            key_id: "k2".to_string(),
            public_key_pem: forge_key().public_key_pem,
        });
    let err = validate_jwt_svid(&token, "aud", &ambiguous)
        .expect_err("an ambiguous kid-less token must fail");
    assert!(err.to_string().contains("which JWT authority"));
}

// ── validate: time and claim hygiene ─────────────────────────────────────

#[test]
fn validate_rejects_an_expired_token() {
    let key = forge_key();
    let token = sign_compact(
        &key,
        r#"{"alg":"ES256","kid":"k1","typ":"JWT"}"#,
        &format!(
            r#"{{"sub":"spiffe://td.test/ns/test/sa/foo","aud":["aud"],"exp":{}}}"#,
            now() - 3600
        ),
    );
    let err = validate_jwt_svid(&token, "aud", &forged_bundles(&key, "k1"))
        .expect_err("an expired token must fail");
    assert!(err.to_string().contains("expired"));
}

#[test]
fn validate_requires_an_expiry_claim() {
    let key = forge_key();
    let token = sign_compact(
        &key,
        r#"{"alg":"ES256","kid":"k1","typ":"JWT"}"#,
        r#"{"sub":"spiffe://td.test/ns/test/sa/foo","aud":["aud"]}"#,
    );
    let err = validate_jwt_svid(&token, "aud", &forged_bundles(&key, "k1"))
        .expect_err("a token with no exp must fail");
    assert!(err.to_string().contains("expiry"));
}

#[test]
fn validate_rejects_a_not_yet_valid_token() {
    let key = forge_key();
    let token = sign_compact(
        &key,
        r#"{"alg":"ES256","kid":"k1","typ":"JWT"}"#,
        &format!(
            r#"{{"sub":"spiffe://td.test/ns/test/sa/foo","aud":["aud"],"nbf":{},"exp":{}}}"#,
            now() + 3600,
            now() + 7200
        ),
    );
    let err = validate_jwt_svid(&token, "aud", &forged_bundles(&key, "k1"))
        .expect_err("a not-yet-valid token must fail");
    assert!(err.to_string().contains("not yet valid"));
}

#[test]
fn validate_rejects_a_future_dated_issue_time() {
    let key = forge_key();
    let token = sign_compact(
        &key,
        r#"{"alg":"ES256","kid":"k1","typ":"JWT"}"#,
        &format!(
            r#"{{"sub":"spiffe://td.test/ns/test/sa/foo","aud":["aud"],"iat":{},"exp":{}}}"#,
            now() + 7200,
            now() + 7500
        ),
    );
    let err = validate_jwt_svid(&token, "aud", &forged_bundles(&key, "k1"))
        .expect_err("a future-dated iat must fail");
    assert!(err.to_string().contains("future"));
}

#[test]
fn validate_rejects_repeated_claim_keys() {
    // `{"aud":"attacker","aud":"victim"}` is ambiguous: a last-wins parser and
    // a first-wins parser disagree about what was signed.
    let key = forge_key();
    let token = sign_compact(
        &key,
        r#"{"alg":"ES256","kid":"k1","typ":"JWT"}"#,
        &format!(
            r#"{{"sub":"spiffe://td.test/ns/test/sa/foo","aud":["other"],"aud":["aud"],"exp":{}}}"#,
            now() + 300
        ),
    );
    let err = validate_jwt_svid(&token, "aud", &forged_bundles(&key, "k1"))
        .expect_err("repeated claim keys must fail");
    assert!(err.to_string().contains("repeats an object key"));
}

#[test]
fn validate_rejects_repeated_header_keys() {
    let key = forge_key();
    let token = sign_compact(
        &key,
        r#"{"alg":"HS256","alg":"ES256","kid":"k1"}"#,
        &format!(
            r#"{{"sub":"spiffe://td.test/ns/test/sa/foo","aud":["aud"],"exp":{}}}"#,
            now() + 300
        ),
    );
    let err = validate_jwt_svid(&token, "aud", &forged_bundles(&key, "k1"))
        .expect_err("repeated header keys must fail");
    assert!(err.to_string().contains("repeats an object key"));
}

#[test]
fn validate_rejects_a_non_numeric_expiry() {
    let key = forge_key();
    let token = sign_compact(
        &key,
        r#"{"alg":"ES256","kid":"k1","typ":"JWT"}"#,
        r#"{"sub":"spiffe://td.test/ns/test/sa/foo","aud":["aud"],"exp":"soon"}"#,
    );
    let err = validate_jwt_svid(&token, "aud", &forged_bundles(&key, "k1"))
        .expect_err("a string exp must fail");
    assert!(err.to_string().contains("non-numeric"));
}

#[test]
fn validate_rejects_a_bad_typ_header() {
    let key = forge_key();
    let token = sign_compact(
        &key,
        r#"{"alg":"ES256","kid":"k1","typ":"at+jwt"}"#,
        &format!(
            r#"{{"sub":"spiffe://td.test/ns/test/sa/foo","aud":["aud"],"exp":{}}}"#,
            now() + 300
        ),
    );
    let err = validate_jwt_svid(&token, "aud", &forged_bundles(&key, "k1"))
        .expect_err("a non-JWT typ must fail");
    assert!(err.to_string().contains("typ"));
}

// ── validate: malformed / oversized input ────────────────────────────────

#[test]
fn validate_rejects_structurally_malformed_tokens() {
    let bundles = forged_bundles(&forge_key(), "k1");
    for (name, token) in [
        ("empty", String::new()),
        ("one segment", "abc".to_string()),
        ("two segments", "abc.def".to_string()),
        ("four segments", "a.b.c.d".to_string()),
        ("empty middle segment", "abc..def".to_string()),
        ("padded base64", "ab=.cd.ef".to_string()),
        ("non-base64url", "ab+/.cd.ef".to_string()),
    ] {
        assert!(
            validate_jwt_svid(&token, "aud", &bundles).is_err(),
            "{name}: malformed token must be refused"
        );
    }
}

#[test]
fn validate_rejects_an_oversized_token() {
    let bundles = forged_bundles(&forge_key(), "k1");
    let huge = format!("{}.{}.{}", "a".repeat(9000), "b".repeat(16), "c".repeat(16));
    let err = validate_jwt_svid(&huge, "aud", &bundles).expect_err("oversized token must fail");
    assert!(err.to_string().contains("too large"));
}

#[test]
fn validate_reports_no_authority_when_the_bundle_set_is_empty() {
    let empty: BTreeMap<TrustDomain, Vec<PublishedJwtAuthority>> = BTreeMap::new();
    let err = validate_jwt_svid("a.b.c", "aud", &empty).expect_err("no authority must fail");
    assert!(
        err.to_string().contains("no JWT authority"),
        "an absent authority is 'unsupported', not 'bad token' (got: {err})"
    );
}

#[test]
fn validation_errors_never_echo_token_bytes() {
    let bundles = forged_bundles(&forge_key(), "k1");
    let marker = "SUPERSECRETMARKER";
    let token = format!(
        "{}.{}.{}",
        URL_SAFE_NO_PAD.encode(format!(r#"{{"alg":"ES256","kid":"{marker}"}}"#).as_bytes()),
        URL_SAFE_NO_PAD.encode(format!(r#"{{"sub":"{marker}","aud":["{marker}"]}}"#).as_bytes()),
        URL_SAFE_NO_PAD.encode(marker.as_bytes())
    );
    let err = validate_jwt_svid(&token, marker, &bundles).expect_err("must fail");
    assert!(
        !err.to_string().contains(marker),
        "rejection reasons must not reflect hostile token bytes (got: {err})"
    );
}

// ── JWKS bundles ─────────────────────────────────────────────────────────

#[test]
fn jwks_document_refuses_an_empty_authority_set() {
    let err = jwks_document(&[]).expect_err("an empty JWKS is not a conformant bundle");
    assert!(err.to_string().contains("no JWT authorities"));
}

#[test]
fn jwks_document_publishes_a_usable_jwks() {
    let signer = authority();
    let document = jwks_document(&signer.authorities()).expect("JWKS builds");
    let parsed: serde_json::Value = serde_json::from_slice(&document).expect("JWKS is JSON");
    let keys = parsed["keys"].as_array().expect("keys array");
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0]["kty"], "EC");
    assert_eq!(keys[0]["crv"], "P-256");
    assert_eq!(keys[0]["alg"], "ES256");
    assert_eq!(keys[0]["use"], "sig");
    assert_eq!(keys[0]["kid"], signer.authorities()[0].key_id.as_str());
    assert!(keys[0]["x"].as_str().is_some_and(|x| !x.is_empty()));
    assert!(keys[0]["y"].as_str().is_some_and(|y| !y.is_empty()));
    assert!(
        keys[0].get("d").is_none(),
        "a JWT bundle must never carry private key material"
    );
}

#[test]
fn jwks_document_rejects_duplicate_key_ids() {
    let one = forge_key();
    let two = forge_key();
    let err = jwks_document(&[
        PublishedJwtAuthority {
            trust_domain: td(),
            key_id: "same".to_string(),
            public_key_pem: one.public_key_pem,
        },
        PublishedJwtAuthority {
            trust_domain: td(),
            key_id: "same".to_string(),
            public_key_pem: two.public_key_pem,
        },
    ])
    .expect_err("ambiguous key ids must be refused");
    assert!(err.to_string().contains("share a key id"));
}

#[test]
fn jwks_document_rejects_malformed_authority_material() {
    for (name, key_id, pem) in [
        ("empty kid", "", "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----"),
        ("not a pem", "k1", "hello"),
        ("not base64", "k1", "-----BEGIN PUBLIC KEY-----\n!!!!\n-----END PUBLIC KEY-----"),
        (
            "not an spki",
            "k1",
            "-----BEGIN PUBLIC KEY-----\nAAECAwQFBgcICQoLDA0ODw==\n-----END PUBLIC KEY-----",
        ),
    ] {
        assert!(
            jwks_document(&[PublishedJwtAuthority {
                trust_domain: td(),
                key_id: key_id.to_string(),
                public_key_pem: pem.to_string(),
            }])
            .is_err(),
            "{name}: malformed authority material must not be published"
        );
    }
}

#[test]
fn jwks_document_rejects_a_multi_block_pem() {
    let one = forge_key();
    let two = forge_key();
    let concatenated = format!("{}{}", one.public_key_pem, two.public_key_pem);
    let err = jwks_document(&[PublishedJwtAuthority {
        trust_domain: td(),
        key_id: "k1".to_string(),
        public_key_pem: concatenated,
    }])
    .expect_err("a concatenated PEM hides the second key behind one kid");
    assert!(err.to_string().contains("more than one block"));
}

// ── rotation ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn rotation_keeps_pre_rotation_tokens_verifiable() {
    let signer = authority();
    let minted = signer
        .mint(&workload_id(), &["aud".to_string()], 0)
        .expect("mint before rotation");
    let before = signer.generation();

    let after = signer.rotate().await.expect("rotation succeeds");
    assert_eq!(after, before + 1, "rotation bumps the generation");

    let authorities = signer.authorities();
    assert_eq!(
        authorities.len(),
        2,
        "the retired key must stay published through the overlap"
    );

    validate_jwt_svid(&minted.token, "aud", &bundles_of(&signer))
        .expect("a token minted just before rotation stays verifiable");

    let after_rotation = signer
        .mint(&workload_id(), &["aud".to_string()], 0)
        .expect("mint after rotation");
    validate_jwt_svid(&after_rotation.token, "aud", &bundles_of(&signer))
        .expect("the fresh key validates too");
    assert_ne!(
        minted.key_id, after_rotation.key_id,
        "rotation must actually change the signing key"
    );
}

#[tokio::test]
async fn rotation_bounds_retained_key_cardinality() {
    let signer = Arc::new(
        LocalJwtAuthority::new(LocalJwtAuthorityConfig {
            trust_domain: td(),
            default_ttl_secs: 60,
            max_ttl_secs: 300,
            key_lifetime_secs: 0,
            max_retained_keys: 2,
        })
        .expect("authority builds"),
    );

    for _ in 0..10 {
        signer.rotate().await.expect("rotation succeeds");
    }

    let authorities = signer.authorities();
    assert!(
        authorities.len() <= 3,
        "active + at most 2 retained keys, got {}",
        authorities.len()
    );
    // The published set must still be a valid, unambiguous bundle.
    jwks_document(&authorities).expect("retained keys still form a valid JWKS");
}

#[tokio::test]
async fn rotate_if_due_is_a_no_op_while_the_key_is_young() {
    let signer = authority();
    let before = signer.generation();
    assert_eq!(
        signer.rotate_if_due().await.expect("no-op succeeds"),
        None,
        "a fresh key must not rotate"
    );
    assert_eq!(signer.generation(), before);
}

#[tokio::test]
async fn rotate_if_due_rotates_once_the_lifetime_has_elapsed() {
    let signer = Arc::new(
        LocalJwtAuthority::new(LocalJwtAuthorityConfig {
            trust_domain: td(),
            default_ttl_secs: 60,
            max_ttl_secs: 300,
            // Any key is immediately older than a zero-second lifetime... but
            // `0` disables rotation, so use the smallest enabled lifetime and
            // rely on `age >= lifetime` being true at age 0 only for `0`.
            key_lifetime_secs: 1,
            max_retained_keys: 2,
        })
        .expect("authority builds"),
    );
    let before = signer.generation();
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let rotated = signer.rotate_if_due().await.expect("rotation succeeds");
    assert_eq!(rotated, Some(before + 1));
}

// ── Workload API RPCs ────────────────────────────────────────────────────

#[tokio::test]
async fn fetch_jwtsvid_mints_for_the_attested_identity() {
    use ferrum_edge::identity::workload_api::proto::JwtsvidRequest;
    use ferrum_edge::identity::workload_api::proto::spiffe_workload_api_server::SpiffeWorkloadApi;

    let (svc, signer) = jwt_capable_service();
    let response = svc
        .fetch_jwtsvid(workload_request(JwtsvidRequest {
            audience: vec!["spiffe://td.test/api".to_string()],
            spiffe_id: String::new(),
        }))
        .await
        .expect("mint succeeds")
        .into_inner();

    assert_eq!(response.svids.len(), 1);
    assert_eq!(response.svids[0].spiffe_id, workload_id().as_str());
    let validated = validate_jwt_svid(
        &response.svids[0].svid,
        "spiffe://td.test/api",
        &bundles_of(&signer),
    )
    .expect("the minted token validates against the published bundle");
    assert_eq!(validated.spiffe_id, workload_id());
}

#[tokio::test]
async fn fetch_jwtsvid_accepts_an_explicit_matching_subject() {
    use ferrum_edge::identity::workload_api::proto::JwtsvidRequest;
    use ferrum_edge::identity::workload_api::proto::spiffe_workload_api_server::SpiffeWorkloadApi;

    let (svc, _) = jwt_capable_service();
    svc.fetch_jwtsvid(workload_request(JwtsvidRequest {
        audience: vec!["aud".to_string()],
        spiffe_id: workload_id().as_str().to_string(),
    }))
    .await
    .expect("the attested identity may be named explicitly");
}

#[tokio::test]
async fn fetch_jwtsvid_denies_a_caller_selected_subject() {
    use ferrum_edge::identity::workload_api::proto::JwtsvidRequest;
    use ferrum_edge::identity::workload_api::proto::spiffe_workload_api_server::SpiffeWorkloadApi;
    use tonic::Code;

    let (svc, _) = jwt_capable_service();
    let err = svc
        .fetch_jwtsvid(workload_request(JwtsvidRequest {
            audience: vec!["aud".to_string()],
            spiffe_id: "spiffe://td.test/ns/test/sa/victim".to_string(),
        }))
        .await
        .expect_err("an arbitrary subject must be refused");
    assert_eq!(err.code(), Code::PermissionDenied);
}

#[tokio::test]
async fn fetch_jwtsvid_rejects_an_empty_audience_list() {
    use ferrum_edge::identity::workload_api::proto::JwtsvidRequest;
    use ferrum_edge::identity::workload_api::proto::spiffe_workload_api_server::SpiffeWorkloadApi;
    use tonic::Code;

    let (svc, _) = jwt_capable_service();
    let err = svc
        .fetch_jwtsvid(workload_request(JwtsvidRequest {
            audience: Vec::new(),
            spiffe_id: String::new(),
        }))
        .await
        .expect_err("at least one audience is required");
    assert_eq!(err.code(), Code::InvalidArgument);
}

#[tokio::test]
async fn fetch_jwtsvid_requires_the_workload_metadata_header() {
    use ferrum_edge::identity::workload_api::proto::JwtsvidRequest;
    use ferrum_edge::identity::workload_api::proto::spiffe_workload_api_server::SpiffeWorkloadApi;
    use tonic::Code;

    let (svc, _) = jwt_capable_service();
    let err = svc
        .fetch_jwtsvid(Request::new(JwtsvidRequest {
            audience: vec!["aud".to_string()],
            spiffe_id: String::new(),
        }))
        .await
        .expect_err("the metadata gate runs first");
    assert_eq!(err.code(), Code::InvalidArgument);
}

#[tokio::test]
async fn fetch_jwt_bundles_streams_the_local_bundle_and_dedups_unchanged_generations() {
    use ferrum_edge::identity::workload_api::proto::JwtBundlesRequest;
    use ferrum_edge::identity::workload_api::proto::spiffe_workload_api_server::SpiffeWorkloadApi;
    use tokio::sync::watch;
    use tokio_stream::StreamExt;

    let jwt = authority();
    let ca: Arc<dyn CertificateAuthority> = Arc::new(JwtCapableCa {
        trust_domain: td(),
        jwt: Arc::clone(&jwt),
    });
    let attestor: Arc<dyn Attestor> = Arc::new(StubAttestor { id: workload_id() });
    let (tx, _) = watch::channel(0u64);
    let rotation = Arc::new(tx);
    let svc = WorkloadApiService::with_rotation_signal(
        vec![attestor],
        ca,
        td(),
        600,
        Arc::clone(&rotation),
    );

    let mut stream = svc
        .fetch_jwt_bundles(workload_request(JwtBundlesRequest {}))
        .await
        .expect("bundles stream opens")
        .into_inner();

    let first = tokio::time::timeout(std::time::Duration::from_secs(2), stream.next())
        .await
        .expect("timed out waiting for the initial bundle")
        .expect("stream ended unexpectedly")
        .expect("initial bundle was an error");
    assert!(
        !first.bundles.is_empty(),
        "an empty bundles map is never a success response"
    );
    let local = first
        .bundles
        .get(td().as_str())
        .expect("the local trust-domain bundle is mandatory");
    let parsed: serde_json::Value = serde_json::from_slice(local).expect("bundle is a JWKS");
    assert_eq!(parsed["keys"].as_array().expect("keys").len(), 1);

    // A rotation signal that does not change JWT authorities must not
    // republish an identical bundle.
    rotation.send_modify(|value| *value += 1);
    let deduped = tokio::time::timeout(std::time::Duration::from_millis(250), stream.next()).await;
    assert!(
        deduped.is_err(),
        "an unchanged authority set must not be republished"
    );

    // A real JWT key rotation must publish.
    jwt.rotate().await.expect("rotation succeeds");
    rotation.send_modify(|value| *value += 1);
    let updated = tokio::time::timeout(std::time::Duration::from_secs(2), stream.next())
        .await
        .expect("timed out waiting for the rotated bundle")
        .expect("stream ended unexpectedly")
        .expect("rotated bundle was an error");
    let local = updated
        .bundles
        .get(td().as_str())
        .expect("the local bundle is still mandatory");
    let parsed: serde_json::Value = serde_json::from_slice(local).expect("bundle is a JWKS");
    assert_eq!(
        parsed["keys"].as_array().expect("keys").len(),
        2,
        "the rotated bundle carries the new key plus the retained one"
    );
}

#[tokio::test]
async fn fetch_jwt_bundles_is_unimplemented_without_a_jwt_authority() {
    use ferrum_edge::identity::workload_api::proto::JwtBundlesRequest;
    use ferrum_edge::identity::workload_api::proto::spiffe_workload_api_server::SpiffeWorkloadApi;
    use tonic::Code;

    let ca: Arc<dyn CertificateAuthority> = Arc::new(JwtlessCa {
        trust_domain: td(),
    });
    let attestor: Arc<dyn Attestor> = Arc::new(StubAttestor { id: workload_id() });
    let svc = WorkloadApiService::new(vec![attestor], ca, td(), 600);

    let err = svc
        .fetch_jwt_bundles(workload_request(JwtBundlesRequest {}))
        .await
        .err()
        .expect("must not return Ok(stream) of empty maps");
    assert_eq!(err.code(), Code::Unimplemented);
}

#[tokio::test]
async fn validate_jwtsvid_round_trips_through_the_service() {
    use ferrum_edge::identity::workload_api::proto::spiffe_workload_api_server::SpiffeWorkloadApi;
    use ferrum_edge::identity::workload_api::proto::{JwtsvidRequest, ValidateJwtsvidRequest};

    let (svc, _) = jwt_capable_service();
    let minted = svc
        .fetch_jwtsvid(workload_request(JwtsvidRequest {
            audience: vec!["spiffe://td.test/api".to_string()],
            spiffe_id: String::new(),
        }))
        .await
        .expect("mint succeeds")
        .into_inner();

    let validated = svc
        .validate_jwtsvid(workload_request(ValidateJwtsvidRequest {
            audience: "spiffe://td.test/api".to_string(),
            svid: minted.svids[0].svid.clone(),
        }))
        .await
        .expect("validation succeeds")
        .into_inner();

    assert_eq!(validated.spiffe_id, workload_id().as_str());
    let claims = claims_of(&validated.claims_json);
    assert_eq!(claims["sub"], workload_id().as_str());
}

#[tokio::test]
async fn validate_jwtsvid_rejects_a_wrong_audience_through_the_service() {
    use ferrum_edge::identity::workload_api::proto::spiffe_workload_api_server::SpiffeWorkloadApi;
    use ferrum_edge::identity::workload_api::proto::{JwtsvidRequest, ValidateJwtsvidRequest};
    use tonic::Code;

    let (svc, _) = jwt_capable_service();
    let minted = svc
        .fetch_jwtsvid(workload_request(JwtsvidRequest {
            audience: vec!["intended".to_string()],
            spiffe_id: String::new(),
        }))
        .await
        .expect("mint succeeds")
        .into_inner();

    let err = svc
        .validate_jwtsvid(workload_request(ValidateJwtsvidRequest {
            audience: "attacker".to_string(),
            svid: minted.svids[0].svid.clone(),
        }))
        .await
        .expect_err("audience mismatch must fail");
    assert_eq!(err.code(), Code::InvalidArgument);
}

#[tokio::test]
async fn validate_jwtsvid_requires_the_workload_metadata_header() {
    use ferrum_edge::identity::workload_api::proto::ValidateJwtsvidRequest;
    use ferrum_edge::identity::workload_api::proto::spiffe_workload_api_server::SpiffeWorkloadApi;
    use tonic::Code;

    let (svc, _) = jwt_capable_service();
    let err = svc
        .validate_jwtsvid(Request::new(ValidateJwtsvidRequest {
            audience: "aud".to_string(),
            svid: "a.b.c".to_string(),
        }))
        .await
        .expect_err("the metadata gate runs first");
    assert_eq!(err.code(), Code::InvalidArgument);
}

#[tokio::test]
async fn x509_rpcs_are_unaffected_by_the_jwt_surface() {
    use ferrum_edge::identity::workload_api::proto::spiffe_workload_api_server::SpiffeWorkloadApi;
    use ferrum_edge::identity::workload_api::proto::{X509BundlesRequest, X509svidRequest};
    use tokio_stream::StreamExt;

    let (svc, _) = jwt_capable_service();

    let mut svids = svc
        .fetch_x509svid(workload_request(X509svidRequest {}))
        .await
        .expect("X.509 SVID stream opens")
        .into_inner();
    let svid = tokio::time::timeout(std::time::Duration::from_secs(2), svids.next())
        .await
        .expect("timed out")
        .expect("stream ended")
        .expect("first SVID was an error");
    assert_eq!(svid.svids[0].spiffe_id, workload_id().as_str());
    assert_eq!(svid.svids[0].x509_svid, b"stub-cert");

    let mut bundles = svc
        .fetch_x509_bundles(workload_request(X509BundlesRequest {}))
        .await
        .expect("X.509 bundle stream opens")
        .into_inner();
    let bundle = tokio::time::timeout(std::time::Duration::from_secs(2), bundles.next())
        .await
        .expect("timed out")
        .expect("stream ended")
        .expect("first bundle was an error");
    assert_eq!(
        bundle.bundles.get(td().as_str()).map(Vec::as_slice),
        Some(b"stub-root".as_slice())
    );
}
