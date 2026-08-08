//! Process-local JWT signing authority.
//!
//! [`LocalJwtAuthority`] is the JWT half of a CA backend that actually owns
//! signing material. It is used by
//! [`InternalCa`](crate::identity::ca::internal::InternalCa); backends that
//! delegate issuance to an external agent (SPIRE) deliberately do **not**
//! construct one — see [`JwtSvidSigner`].
//!
//! ## Rotation overlap
//!
//! Reads go through a lock-free [`ArcSwap`] snapshot; rotation is serialized
//! by an async gate and never runs on a request path. When a key rotates the
//! previous key is *retained for verification only* for
//! [`MAX_JWT_SVID_TTL_SECS`] + [`JWT_SVID_CLOCK_SKEW_LEEWAY_SECS`]. Because
//! every minted token's lifetime is clamped to `MAX_JWT_SVID_TTL_SECS`, a
//! token minted one instant before a rotation stays verifiable for its whole
//! bounded lifetime, and a retired key becomes unusable as soon as no token
//! it signed can still be live. Retention is additionally capped at
//! `max_retained_keys` entries, so both memory and key cardinality are
//! bounded regardless of how often rotation is driven.
//!
//! ## Key material
//!
//! The PKCS#8 private PEM exists only long enough for `jsonwebtoken` to copy
//! it into an [`EncodingKey`], and is held in a [`Zeroizing`] buffer until
//! then. Neither the private key nor a minted token appears in `Debug`,
//! `Display`, logs, or errors.

use std::fmt;
use std::sync::Arc;

use arc_swap::ArcSwap;
use chrono::{DateTime, Utc};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::Serialize;
use tracing::{debug, info};
use zeroize::Zeroizing;

use super::{
    DEFAULT_JWT_KEY_LIFETIME_SECS, DEFAULT_JWT_SVID_TTL_SECS, JWT_SVID_CLOCK_SKEW_LEEWAY_SECS,
    JwtSvidError, MAX_JWT_SVID_TTL_SECS, canonical_audiences, jwks,
};
use crate::identity::ca::PublishedJwtAuthority;
use crate::identity::spiffe::{SpiffeId, TrustDomain};

/// Algorithm Ferrum mints JWT-SVIDs with. ES256 keeps tokens small and is
/// supported by every SPIFFE consumer; it is asymmetric, so a JWT bundle
/// never carries anything a holder could sign with.
const JWT_SVID_SIGNING_ALG: Algorithm = Algorithm::ES256;

/// Default cap on retained verification-only keys (the active key plus this
/// many retired ones is the worst case published in a JWT bundle).
pub const DEFAULT_MAX_RETAINED_JWT_KEYS: usize = 3;

/// A JWT signing authority that can mint JWT-SVIDs for one trust domain.
///
/// Implemented by [`LocalJwtAuthority`]. A CA backend returns `Some` from
/// [`CertificateAuthority::jwt_signer`](crate::identity::ca::CertificateAuthority::jwt_signer)
/// only when it genuinely owns JWT signing material; the default is `None`,
/// which makes `FetchJWTSVID` fail closed with `UNIMPLEMENTED` rather than
/// inventing JWT trust for a backend that cannot supply it.
#[async_trait::async_trait]
pub trait JwtSvidSigner: Send + Sync + 'static {
    /// The trust domain this authority signs for. A mint request for any
    /// other trust domain must be refused.
    fn trust_domain(&self) -> &TrustDomain;

    /// Mint a JWT-SVID for `spiffe_id` targeting `audiences`.
    ///
    /// The caller is responsible for having *attested* `spiffe_id`; this
    /// method re-checks only that it belongs to this authority's trust
    /// domain. `ttl_secs == 0` selects the configured default; anything above
    /// the configured ceiling is clamped down, never up.
    fn mint(
        &self,
        spiffe_id: &SpiffeId,
        audiences: &[String],
        ttl_secs: u64,
    ) -> Result<MintedJwtSvid, JwtSvidError>;

    /// The authorities currently valid for verification: the active signing
    /// key plus every retired key still inside its rotation overlap.
    fn authorities(&self) -> Vec<PublishedJwtAuthority>;

    /// Monotonic generation counter, bumped on every rotation. Bundle streams
    /// use it to skip republishing an unchanged authority set.
    fn generation(&self) -> u64;

    /// Rotate the signing key if it has outlived its configured lifetime.
    ///
    /// Returns the new generation when a rotation happened. Driven from the
    /// background rotation task — key generation must never run on an RPC
    /// path.
    async fn rotate_if_due(&self) -> Result<Option<u64>, JwtSvidError>;
}

/// Shared handle to a JWT signing authority.
pub type SharedJwtSvidSigner = Arc<dyn JwtSvidSigner>;

/// A freshly minted JWT-SVID.
///
/// `token` is a bearer credential: the [`fmt::Debug`] impl redacts it, and it
/// must never be logged.
pub struct MintedJwtSvid {
    pub spiffe_id: SpiffeId,
    pub token: String,
    pub key_id: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl fmt::Debug for MintedJwtSvid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MintedJwtSvid")
            .field("spiffe_id", &self.spiffe_id)
            .field("token", &"<redacted>")
            .field("key_id", &self.key_id)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Construction-time configuration for [`LocalJwtAuthority`].
#[derive(Debug, Clone)]
pub struct LocalJwtAuthorityConfig {
    pub trust_domain: TrustDomain,
    /// Lifetime applied when a mint request asks for `0` seconds.
    pub default_ttl_secs: u64,
    /// Hard ceiling on minted JWT-SVID lifetime. Also the basis of the
    /// rotation overlap.
    pub max_ttl_secs: u64,
    /// How long a signing key stays active before [`LocalJwtAuthority::rotate_if_due`]
    /// replaces it. `0` disables time-based rotation (explicit
    /// [`LocalJwtAuthority::rotate`] still works).
    pub key_lifetime_secs: u64,
    /// Upper bound on retained verification-only keys.
    pub max_retained_keys: usize,
}

impl LocalJwtAuthorityConfig {
    /// Defaults for a trust domain: 5 min tokens, 1 h ceiling, 24 h key
    /// lifetime, 3 retained keys.
    pub fn new(trust_domain: TrustDomain) -> Self {
        Self {
            trust_domain,
            default_ttl_secs: DEFAULT_JWT_SVID_TTL_SECS,
            max_ttl_secs: MAX_JWT_SVID_TTL_SECS,
            key_lifetime_secs: DEFAULT_JWT_KEY_LIFETIME_SECS,
            max_retained_keys: DEFAULT_MAX_RETAINED_JWT_KEYS,
        }
    }
}

/// One signing key and its published public half.
struct JwtSigningKey {
    key_id: String,
    algorithm: Algorithm,
    /// Private signing key. Never exposed, never rendered.
    encoding: EncodingKey,
    /// SPKI PEM of the public half — this is what goes into JWT bundles.
    public_key_pem: String,
}

/// A key kept for verification only through the rotation overlap.
struct RetiredJwtKey {
    key: Arc<JwtSigningKey>,
    /// Instant after which the key is dropped from published authorities.
    verifiable_until: DateTime<Utc>,
}

/// Immutable snapshot swapped atomically on rotation.
struct AuthorityState {
    generation: u64,
    active: Arc<JwtSigningKey>,
    active_since: DateTime<Utc>,
    retired: Vec<RetiredJwtKey>,
}

/// Process-local JWT signing authority.
pub struct LocalJwtAuthority {
    trust_domain: TrustDomain,
    state: ArcSwap<AuthorityState>,
    /// Serializes rotation so two concurrent rotations cannot drop one
    /// another's retired set. Never taken on a mint / read path.
    rotate_gate: tokio::sync::Mutex<()>,
    default_ttl_secs: u64,
    max_ttl_secs: u64,
    key_lifetime_secs: u64,
    max_retained_keys: usize,
}

impl fmt::Debug for LocalJwtAuthority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.state.load();
        f.debug_struct("LocalJwtAuthority")
            .field("trust_domain", &self.trust_domain)
            .field("generation", &state.generation)
            .field("active_key_id", &state.active.key_id)
            .field("retained_keys", &state.retired.len())
            .finish()
    }
}

impl LocalJwtAuthority {
    /// Generate the first signing key and build the authority.
    pub fn new(config: LocalJwtAuthorityConfig) -> Result<Self, JwtSvidError> {
        let default_ttl_secs = if config.default_ttl_secs == 0 {
            DEFAULT_JWT_SVID_TTL_SECS
        } else {
            config.default_ttl_secs
        };
        let max_ttl_secs = if config.max_ttl_secs == 0 {
            MAX_JWT_SVID_TTL_SECS
        } else {
            config.max_ttl_secs.min(MAX_JWT_SVID_TTL_SECS)
        };
        let active = Arc::new(generate_signing_key()?);
        info!(
            trust_domain = %config.trust_domain,
            key_id = %active.key_id,
            "JWT-SVID authority initialised"
        );
        Ok(Self {
            trust_domain: config.trust_domain,
            state: ArcSwap::new(Arc::new(AuthorityState {
                generation: 1,
                active,
                active_since: Utc::now(),
                retired: Vec::new(),
            })),
            rotate_gate: tokio::sync::Mutex::new(()),
            default_ttl_secs: default_ttl_secs.min(max_ttl_secs),
            max_ttl_secs,
            key_lifetime_secs: config.key_lifetime_secs,
            max_retained_keys: config.max_retained_keys.max(1),
        })
    }

    /// Replace the active signing key, retaining the previous one for
    /// verification through the overlap window.
    ///
    /// Returns the new generation. Key generation is deliberately done here
    /// and never on a mint path.
    pub async fn rotate(&self) -> Result<u64, JwtSvidError> {
        let _gate = self.rotate_gate.lock().await;
        let fresh = Arc::new(generate_signing_key()?);
        let now = Utc::now();
        let overlap = self
            .max_ttl_secs
            .saturating_add(JWT_SVID_CLOCK_SKEW_LEEWAY_SECS);
        let overlap = chrono::Duration::try_seconds(overlap as i64).ok_or_else(|| {
            JwtSvidError::Internal("JWT-SVID rotation overlap is out of range".to_string())
        })?;

        let previous = self.state.load_full();
        let mut retired = Vec::with_capacity(self.max_retained_keys);
        retired.push(RetiredJwtKey {
            key: Arc::clone(&previous.active),
            verifiable_until: now + overlap,
        });
        for entry in &previous.retired {
            if retired.len() >= self.max_retained_keys {
                break;
            }
            if entry.verifiable_until > now {
                retired.push(RetiredJwtKey {
                    key: Arc::clone(&entry.key),
                    verifiable_until: entry.verifiable_until,
                });
            }
        }

        let generation = previous.generation.saturating_add(1);
        let key_id = fresh.key_id.clone();
        self.state.store(Arc::new(AuthorityState {
            generation,
            active: fresh,
            active_since: now,
            retired,
        }));
        info!(
            trust_domain = %self.trust_domain,
            generation,
            key_id = %key_id,
            "JWT-SVID signing key rotated"
        );
        Ok(generation)
    }

    /// Key id of the active signing key. Public information (it is the `kid`
    /// of every token this authority currently mints).
    pub fn active_key_id(&self) -> String {
        self.state.load().active.key_id.clone()
    }

    fn clamp_ttl(&self, requested: u64) -> u64 {
        let ttl = if requested == 0 {
            self.default_ttl_secs
        } else {
            requested
        };
        ttl.min(self.max_ttl_secs).max(1)
    }
}

#[async_trait::async_trait]
impl JwtSvidSigner for LocalJwtAuthority {
    fn trust_domain(&self) -> &TrustDomain {
        &self.trust_domain
    }

    fn mint(
        &self,
        spiffe_id: &SpiffeId,
        audiences: &[String],
        ttl_secs: u64,
    ) -> Result<MintedJwtSvid, JwtSvidError> {
        if spiffe_id.trust_domain() != &self.trust_domain {
            return Err(JwtSvidError::Denied(
                "SPIFFE ID is not in this authority's trust domain",
            ));
        }
        // Re-validate rather than trust the caller: this is the last gate
        // before an audience reaches a signed token.
        let audiences = canonical_audiences(audiences)?;
        let ttl = self.clamp_ttl(ttl_secs);

        let now = Utc::now();
        let lifetime = chrono::Duration::try_seconds(ttl as i64).ok_or_else(|| {
            JwtSvidError::Internal("JWT-SVID lifetime is out of range".to_string())
        })?;
        let expires_at = now + lifetime;

        let state = self.state.load();
        let key = Arc::clone(&state.active);
        drop(state);

        let mut header = Header::new(key.algorithm);
        header.typ = Some("JWT".to_string());
        header.kid = Some(key.key_id.clone());

        let claims = JwtSvidClaims {
            sub: spiffe_id.as_str(),
            aud: &audiences,
            exp: expires_at.timestamp(),
            iat: now.timestamp(),
            nbf: now.timestamp(),
            jti: random_token_id()?,
        };

        let token = jsonwebtoken::encode(&header, &claims, &key.encoding)
            // The error can carry serialization detail; keep it fixed so no
            // claim value can be reflected out of the mint path.
            .map_err(|_| JwtSvidError::Internal("JWT-SVID signing failed".to_string()))?;

        debug!(
            spiffe_id = %spiffe_id,
            key_id = %key.key_id,
            audiences = audiences.len(),
            ttl_secs = ttl,
            "minted JWT-SVID"
        );

        Ok(MintedJwtSvid {
            spiffe_id: spiffe_id.clone(),
            token,
            key_id: key.key_id.clone(),
            issued_at: now,
            expires_at,
        })
    }

    fn authorities(&self) -> Vec<PublishedJwtAuthority> {
        let state = self.state.load();
        let now = Utc::now();
        let mut published = Vec::with_capacity(1 + state.retired.len());
        published.push(PublishedJwtAuthority {
            trust_domain: self.trust_domain.clone(),
            key_id: state.active.key_id.clone(),
            public_key_pem: state.active.public_key_pem.clone(),
        });
        for entry in &state.retired {
            if entry.verifiable_until > now {
                published.push(PublishedJwtAuthority {
                    trust_domain: self.trust_domain.clone(),
                    key_id: entry.key.key_id.clone(),
                    public_key_pem: entry.key.public_key_pem.clone(),
                });
            }
        }
        published
    }

    fn generation(&self) -> u64 {
        self.state.load().generation
    }

    async fn rotate_if_due(&self) -> Result<Option<u64>, JwtSvidError> {
        if self.key_lifetime_secs == 0 {
            return Ok(None);
        }
        let due = {
            // Scoped so the `ArcSwap` guard is released before the await.
            let state = self.state.load();
            let age = Utc::now()
                .signed_duration_since(state.active_since)
                .num_seconds();
            age >= self.key_lifetime_secs as i64
        };
        if !due {
            return Ok(None);
        }
        self.rotate().await.map(Some)
    }
}

/// SPIFFE JWT-SVID claim set.
///
/// `sub` is the SPIFFE ID and `aud` / `exp` are required by the JWT-SVID
/// standard. `iat` / `nbf` bound the token at the front, and `jti` gives each
/// token a unique identity so a relying party can detect replay.
///
/// `iss` is deliberately **not** minted: the SPIFFE JWT-SVID standard does not
/// define one, and validators key trust off the `sub` trust domain plus the
/// bundle the key came from.
#[derive(Serialize)]
struct JwtSvidClaims<'a> {
    sub: &'a str,
    aud: &'a [String],
    exp: i64,
    iat: i64,
    nbf: i64,
    jti: String,
}

/// Generate an ES256 signing key and derive its RFC 7638 thumbprint key id.
fn generate_signing_key() -> Result<JwtSigningKey, JwtSvidError> {
    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(|e| {
        JwtSvidError::Internal(format!("JWT-SVID signing key generation failed: {e}"))
    })?;
    let public_key_pem = key_pair.public_key_pem();
    let key_id = jwks::published_authority_key_id(&public_key_pem)?;

    // Held zeroized and dropped as soon as `jsonwebtoken` has taken its own
    // copy — nothing else in the process ever sees the private PEM.
    let private_key_pem = Zeroizing::new(key_pair.serialize_pem());
    let encoding = EncodingKey::from_ec_pem(private_key_pem.as_bytes())
        .map_err(|_| JwtSvidError::Internal("JWT-SVID signing key is unusable".to_string()))?;
    drop(private_key_pem);

    Ok(JwtSigningKey {
        key_id,
        algorithm: JWT_SVID_SIGNING_ALG,
        encoding,
        public_key_pem,
    })
}

/// 128 bits of CSPRNG output, base64url-encoded, used as `jti`.
fn random_token_id() -> Result<String, JwtSvidError> {
    use crate::fips::backend::rand::SecureRandom;
    use base64::Engine as _;

    let rng = crate::fips::backend::rand::SystemRandom::new();
    let mut buf = [0u8; 16];
    rng.fill(&mut buf).map_err(|_| {
        JwtSvidError::Internal("JWT-SVID token id generation failed".to_string())
    })?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf))
}
