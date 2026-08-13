//! Finite authorization lifetime for the stock xDS bearer credential
//! (issue #3852).
//!
//! `FERRUM_MESH_STOCK_XDS_TOKEN_FILE` names an **externally issued** bearer —
//! typically a projected Kubernetes service-account token. Before this module
//! the client read it once per connection attempt, captured it in the tonic
//! interceptor, and then let the stream live for as long as the third-party
//! control plane was willing to hold it open. A stock ADS server that validates
//! only at RPC admission would therefore keep pushing discovery over a session
//! opened with a credential that had since expired or been revoked, and the
//! effective access lifetime became the lifetime of the TCP/H2 stream rather
//! than the token's TTL.
//!
//! The fix has three parts, all of them here:
//!
//! 1. **Change detection.** A watcher re-reads the configured source on a
//!    bounded cadence through the *same* hardened credential reader the connect
//!    path uses (`secrets::credential_file`): `O_NONBLOCK` open, regular-file
//!    check on the **opened** descriptor (so a projected-secret symlink swap
//!    resolves while a FIFO/socket/device is refused), a metadata fast-reject
//!    plus `take(limit + 1)` ceiling, UTF-8 validation, and an empty-after-trim
//!    rejection — all on a detached OS thread, never on a Tokio core worker.
//!    Both symlink swaps and in-place rewrites are detected because the
//!    comparison is over **content**, not inode identity.
//! 2. **A local authorization deadline.** A JWT-shaped token contributes its
//!    `exp` as a *reconnect scheduling hint only*, after a bounded, non-verifying
//!    local decode. It is never treated as proof of anything. An opaque token
//!    gets the operator-visible maximum stream lifetime, which also caps the
//!    JWT-derived deadline.
//! 3. **Fail-closed reconnection.** An invalid source does not merely fail the
//!    next read: it *prevents* reconnection. There is no freshness-only path and
//!    no fallback to the previously read token.
//!
//! Nothing here ever logs, metrics, or otherwise renders token bytes, decoded
//! claims, the configured path, or a digest of any of them. The content
//! fingerprint exists solely for in-process equality and is never exposed.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use tokio::sync::{Semaphore, watch};
use tonic::metadata::MetadataValue;
use tracing::{info, warn};

use super::stream_lifecycle::MeshConfigStreamCredential;
use crate::secrets::credential_file::{
    CredentialFileError, CredentialTrim, DEFAULT_CREDENTIAL_FILE_MAX_BYTES,
    read_credential_file_detached_guarded,
};

pub type BearerToken = MetadataValue<tonic::metadata::Ascii>;

/// Bound the complete stock bearer-token admission attempt, including waiting
/// for an earlier timed-out reader to leave the kernel.
pub const STOCK_XDS_TOKEN_FILE_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// A timed-out mount read may keep its detached OS thread blocked. The permit
/// moves into that thread, so repeated ADS reconnects and watcher polls cannot
/// accumulate more blocked readers while the same credential source remains
/// unavailable.
static STOCK_XDS_TOKEN_FILE_READ_LIMIT: std::sync::OnceLock<Arc<Semaphore>> =
    std::sync::OnceLock::new();

pub(crate) fn stock_xds_token_file_read_limit() -> Arc<Semaphore> {
    Arc::clone(STOCK_XDS_TOKEN_FILE_READ_LIMIT.get_or_init(|| Arc::new(Semaphore::new(1))))
}

/// Longest JWT segment this decoder will look at.
///
/// A bearer is already capped at 64 KiB by the credential reader; this bounds
/// the *parsing* work on a value that is untrusted input from an external
/// issuer. Anything larger simply has no `exp` hint.
const MAX_JWT_SEGMENT_BYTES: usize = 8 * 1024;

/// Longest decoded JWT payload this decoder will parse as JSON.
const MAX_JWT_PAYLOAD_BYTES: usize = 8 * 1024;

/// Never schedule a credential-driven reconnect sooner than this.
///
/// An already-expired or badly skewed `exp` would otherwise compute a deadline
/// in the past and turn the reconnect loop into a hot loop against the control
/// plane. The floor keeps the retry bounded; recovery still comes from the
/// operator replacing the token, which the watcher observes.
const MIN_CREDENTIAL_RECONNECT_FLOOR: Duration = Duration::from_secs(60);

/// In-process content identity of a bearer credential.
///
/// SHA-256 of the trimmed token bytes. Used ONLY to answer "is this the same
/// credential I connected with" without retaining a second copy of the secret
/// for comparison. It is never logged, exported, exposed on an admin surface,
/// or used as an authorization input — a digest of a secret is still an offline
/// oracle for it.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct StockCredentialFingerprint([u8; 32]);

impl StockCredentialFingerprint {
    fn of(raw_token: &str) -> Self {
        Self(crate::fips::approved::Sha256::digest(raw_token.as_bytes()))
    }
}

impl std::fmt::Debug for StockCredentialFingerprint {
    /// Deliberately opaque: a fingerprint that reaches a `Debug` log line is
    /// still credential-derived material.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StockCredentialFingerprint(<redacted>)")
    }
}

/// Closed set of reasons a configured credential source is unusable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StockCredentialInvalidReason {
    /// The configured pathname does not exist, or a projected symlink's target
    /// is missing.
    Missing,
    /// The opened target is not a regular file.
    NotRegularFile,
    /// Open/read failed for another reason.
    Unreadable,
    /// Empty after trimming.
    Empty,
    /// Exceeds the credential-file ceiling.
    Oversized,
    /// Not valid UTF-8.
    InvalidEncoding,
    /// Valid UTF-8 but not admissible as ASCII gRPC metadata.
    NotAsciiMetadata,
    /// The bounded read did not complete in time.
    ReadTimeout,
    /// The shared reader permit could not be acquired (shutdown).
    ReaderUnavailable,
}

impl StockCredentialInvalidReason {
    /// Fixed-cardinality label. Never carries the path or the credential.
    pub fn as_metric_label(self) -> &'static str {
        match self {
            Self::Missing => "token_source_missing",
            Self::NotRegularFile => "token_source_not_regular_file",
            Self::Unreadable => "token_source_unreadable",
            Self::Empty => "token_source_empty",
            Self::Oversized => "token_source_oversized",
            Self::InvalidEncoding => "token_source_invalid_encoding",
            Self::NotAsciiMetadata => "token_source_not_ascii_metadata",
            Self::ReadTimeout => "token_source_read_timeout",
            Self::ReaderUnavailable => "token_reader_unavailable",
        }
    }

    fn from_credential_file_error(error: &CredentialFileError) -> Self {
        match error {
            CredentialFileError::PathNotFound => Self::Missing,
            CredentialFileError::Io(io) if io.kind() == std::io::ErrorKind::NotFound => {
                Self::Missing
            }
            CredentialFileError::Io(_) => Self::Unreadable,
            CredentialFileError::NotRegularFile => Self::NotRegularFile,
            CredentialFileError::Oversized { .. } => Self::Oversized,
            CredentialFileError::InvalidUtf8 => Self::InvalidEncoding,
            CredentialFileError::Empty => Self::Empty,
            // A caller-side limit misconfiguration is impossible here (the
            // ceiling is a constant), but treat it as an unusable source rather
            // than silently succeeding.
            CredentialFileError::InvalidLimit { .. } => Self::Unreadable,
        }
    }
}

impl std::fmt::Display for StockCredentialInvalidReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_metric_label())
    }
}

impl std::error::Error for StockCredentialInvalidReason {}

/// What the last completed observation of the configured source found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StockCredentialState {
    /// No `FERRUM_MESH_STOCK_XDS_TOKEN_FILE` is configured; the stream carries
    /// no `authorization` metadata at all.
    NotConfigured,
    /// Configured but not yet observed. Reconnection proceeds — the connect
    /// path performs its own authoritative read and publishes the result.
    Unknown,
    Valid {
        fingerprint: StockCredentialFingerprint,
    },
    Invalid {
        reason: StockCredentialInvalidReason,
    },
}

impl StockCredentialState {
    pub fn is_invalid(self) -> bool {
        matches!(self, Self::Invalid { .. })
    }

    /// Health projection for the authenticated `/health` mesh detail.
    pub fn health(self) -> MeshConfigStreamCredential {
        match self {
            Self::NotConfigured => MeshConfigStreamCredential::NotConfigured,
            // An unobserved configured source is not yet a failure, but it is
            // not proof of validity either. Report the safe side.
            Self::Unknown => MeshConfigStreamCredential::NotConfigured,
            Self::Valid { .. } => MeshConfigStreamCredential::Valid,
            Self::Invalid { .. } => MeshConfigStreamCredential::SourceInvalid,
        }
    }
}

/// One published observation. `generation` advances only when `state` actually
/// changes, so an unchanged token never churns the ADS stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StockCredentialObservation {
    pub generation: u64,
    pub state: StockCredentialState,
}

/// Shared change-detection channel for the configured credential source.
///
/// Both the watcher task and the connect path publish into it, so the published
/// state always reflects the most recent *completed* read from either. That
/// closes the window where the connect path materializes a newer token than the
/// watcher last saw and the watcher's next (identical) publication would
/// otherwise look like a rotation.
#[derive(Clone)]
pub struct StockCredentialWatch {
    tx: Arc<watch::Sender<StockCredentialObservation>>,
    rx: watch::Receiver<StockCredentialObservation>,
}

impl StockCredentialWatch {
    pub fn new(initial: StockCredentialState) -> Self {
        let (tx, rx) = watch::channel(StockCredentialObservation {
            generation: 0,
            state: initial,
        });
        Self {
            tx: Arc::new(tx),
            rx,
        }
    }

    pub fn receiver(&self) -> watch::Receiver<StockCredentialObservation> {
        self.rx.clone()
    }

    pub fn latest(&self) -> StockCredentialObservation {
        *self.rx.borrow()
    }

    /// Publish an observation. Returns `true` when the state changed and a
    /// generation was consumed.
    pub fn publish(&self, state: StockCredentialState) -> bool {
        self.tx.send_if_modified(|current| {
            if current.state == state {
                return false;
            }
            current.generation = current.generation.saturating_add(1);
            current.state = state;
            true
        })
    }
}

/// Operator-visible lifetime policy for a stock bearer-authenticated stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StockCredentialLifetimePolicy {
    /// `FERRUM_MESH_STOCK_XDS_TOKEN_MAX_STREAM_LIFETIME_SECONDS`. The finite,
    /// documented maximum authenticated stream lifetime. Applies to opaque
    /// tokens and also caps any JWT-derived deadline.
    pub max_stream_lifetime: Duration,
    /// `FERRUM_MESH_STOCK_XDS_TOKEN_REFRESH_SKEW_SECONDS`. How far before a
    /// JWT-shaped token's `exp` the stream is retired.
    pub refresh_skew: Duration,
    /// `FERRUM_MESH_STOCK_XDS_TOKEN_WATCH_INTERVAL_SECONDS`. Credential-source
    /// re-read cadence.
    pub watch_interval: Duration,
}

impl Default for StockCredentialLifetimePolicy {
    fn default() -> Self {
        Self {
            max_stream_lifetime: Duration::from_secs(
                DEFAULT_STOCK_XDS_TOKEN_MAX_STREAM_LIFETIME_SECS,
            ),
            refresh_skew: Duration::from_secs(DEFAULT_STOCK_XDS_TOKEN_REFRESH_SKEW_SECS),
            watch_interval: Duration::from_secs(DEFAULT_STOCK_XDS_TOKEN_WATCH_INTERVAL_SECS),
        }
    }
}

pub const DEFAULT_STOCK_XDS_TOKEN_MAX_STREAM_LIFETIME_SECS: u64 = 3600;
pub const DEFAULT_STOCK_XDS_TOKEN_REFRESH_SKEW_SECS: u64 = 60;
pub const DEFAULT_STOCK_XDS_TOKEN_WATCH_INTERVAL_SECS: u64 = 10;
/// Lowest admissible maximum stream lifetime. Below this the reconnect cadence
/// is itself the availability problem.
pub const MIN_STOCK_XDS_TOKEN_MAX_STREAM_LIFETIME_SECS: u64 = 60;
/// Highest admissible maximum stream lifetime (24h).
pub const MAX_STOCK_XDS_TOKEN_MAX_STREAM_LIFETIME_SECS: u64 = 86_400;

/// The configured credential source plus its lifetime policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StockXdsCredentialSource {
    /// `None` sends no `authorization` metadata at all.
    path: Option<String>,
    policy: StockCredentialLifetimePolicy,
}

impl StockXdsCredentialSource {
    pub fn new(path: Option<String>, policy: StockCredentialLifetimePolicy) -> Self {
        Self { path, policy }
    }

    pub fn unauthenticated() -> Self {
        Self {
            path: None,
            policy: StockCredentialLifetimePolicy::default(),
        }
    }

    pub fn is_configured(&self) -> bool {
        self.path.is_some()
    }

    pub fn policy(&self) -> StockCredentialLifetimePolicy {
        self.policy
    }

    pub fn initial_state(&self) -> StockCredentialState {
        if self.path.is_some() {
            StockCredentialState::Unknown
        } else {
            StockCredentialState::NotConfigured
        }
    }

    /// Read and admit the configured credential.
    ///
    /// `Ok(None)` means no credential is configured. Everything else is either
    /// a usable credential or a closed-set invalidity reason — there is no
    /// "keep the previous token" path.
    pub async fn materialize(
        &self,
    ) -> Result<Option<StockBearerCredential>, StockCredentialInvalidReason> {
        let Some(path) = self.path.as_deref() else {
            return Ok(None);
        };
        let raw = read_stock_bearer_token_raw(path).await?;
        StockBearerCredential::admit(&raw, self.policy).map(Some)
    }
}

/// Why a credential-driven stream deadline was chosen. Fixed cardinality.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StockCredentialDeadlineBasis {
    /// Locally decoded JWT `exp`, minus the configured skew. A *scheduling
    /// hint*, never an authorization decision.
    JwtExpirationHint,
    /// The operator-visible maximum authenticated stream lifetime.
    MaxStreamLifetime,
}

impl StockCredentialDeadlineBasis {
    pub fn as_metric_label(self) -> &'static str {
        match self {
            Self::JwtExpirationHint => "jwt_exp_hint",
            Self::MaxStreamLifetime => "max_stream_lifetime",
        }
    }
}

/// A materialized, admitted bearer credential with a finite local
/// authorization lifetime.
pub struct StockBearerCredential {
    token: BearerToken,
    fingerprint: StockCredentialFingerprint,
    lifetime: Duration,
    basis: StockCredentialDeadlineBasis,
}

impl StockBearerCredential {
    /// Build the `authorization` metadata value, the content fingerprint, and
    /// the local authorization lifetime for one raw token.
    pub fn admit(
        raw_token: &str,
        policy: StockCredentialLifetimePolicy,
    ) -> Result<Self, StockCredentialInvalidReason> {
        let token: BearerToken = format!("Bearer {raw_token}")
            .parse()
            // The parse error would echo the token, so it is deliberately
            // dropped and replaced with a closed-set reason.
            .map_err(|_| StockCredentialInvalidReason::NotAsciiMetadata)?;
        let fingerprint = StockCredentialFingerprint::of(raw_token);
        let (lifetime, basis) = credential_lifetime(raw_token, policy, SystemTime::now());
        Ok(Self {
            token,
            fingerprint,
            lifetime,
            basis,
        })
    }

    pub fn token(&self) -> &BearerToken {
        &self.token
    }

    pub fn fingerprint(&self) -> StockCredentialFingerprint {
        self.fingerprint
    }

    /// How long this stream may stay authenticated, from now.
    pub fn lifetime(&self) -> Duration {
        self.lifetime
    }

    pub fn deadline_basis(&self) -> StockCredentialDeadlineBasis {
        self.basis
    }

    pub fn observed_state(&self) -> StockCredentialState {
        StockCredentialState::Valid {
            fingerprint: self.fingerprint,
        }
    }
}

impl std::fmt::Debug for StockBearerCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StockBearerCredential")
            .field("token", &"<redacted>")
            .field("lifetime_secs", &self.lifetime.as_secs())
            .field("basis", &self.basis.as_metric_label())
            .finish()
    }
}

/// Resolve the finite authorization lifetime for one raw token.
///
/// Exposed for external tests so the JWT-hint / opaque-bound split, the skew,
/// the maximum-lifetime cap, and the reconnect floor are all provable without a
/// control plane.
pub fn credential_lifetime(
    raw_token: &str,
    policy: StockCredentialLifetimePolicy,
    now: SystemTime,
) -> (Duration, StockCredentialDeadlineBasis) {
    let opaque = clamp_max_stream_lifetime(policy.max_stream_lifetime);
    let Some(exp) = jwt_expiration_hint(raw_token) else {
        return (opaque, StockCredentialDeadlineBasis::MaxStreamLifetime);
    };
    let Ok(remaining) = exp.duration_since(now) else {
        // Already past (or a skewed clock). Do not treat the claim as
        // authorization either way: reconnect at the floor so a replacement
        // token is picked up promptly without hot-looping.
        return (
            MIN_CREDENTIAL_RECONNECT_FLOOR.min(opaque),
            StockCredentialDeadlineBasis::JwtExpirationHint,
        );
    };
    let before_exp = remaining.saturating_sub(policy.refresh_skew);
    let bounded = before_exp.min(opaque).max(MIN_CREDENTIAL_RECONNECT_FLOOR.min(opaque));
    (bounded, StockCredentialDeadlineBasis::JwtExpirationHint)
}

fn clamp_max_stream_lifetime(configured: Duration) -> Duration {
    let secs = configured.as_secs().clamp(
        MIN_STOCK_XDS_TOKEN_MAX_STREAM_LIFETIME_SECS,
        MAX_STOCK_XDS_TOKEN_MAX_STREAM_LIFETIME_SECS,
    );
    Duration::from_secs(secs)
}

#[derive(serde::Deserialize)]
struct JwtExpClaim {
    /// Seconds since the Unix epoch. Any other shape is simply "no hint".
    exp: Option<i64>,
}

/// Bounded, **non-verifying** local decode of a JWT-shaped token's `exp`.
///
/// This is a reconnect *scheduling hint* only. The signature is not checked,
/// the issuer/audience are not checked, and no other claim is read or retained.
/// A malformed, oversized, non-JWT, or `exp`-less token yields `None` and falls
/// back to the operator-visible maximum stream lifetime.
pub fn jwt_expiration_hint(raw_token: &str) -> Option<SystemTime> {
    use base64::Engine as _;

    let mut segments = raw_token.split('.');
    let _header = segments.next()?;
    let payload = segments.next()?;
    let signature = segments.next()?;
    // Exactly three segments, all non-empty: anything else is not a JWS.
    if segments.next().is_some() || payload.is_empty() || signature.is_empty() {
        return None;
    }
    if payload.len() > MAX_JWT_SEGMENT_BYTES {
        return None;
    }
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()?;
    if decoded.len() > MAX_JWT_PAYLOAD_BYTES {
        return None;
    }
    let claim: JwtExpClaim = serde_json::from_slice(&decoded).ok()?;
    let exp = claim.exp?;
    if exp <= 0 {
        return None;
    }
    SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(exp as u64))
}

/// Read the raw bearer token through the shared hardened credential boundary.
///
/// The whole attempt — including waiting behind an earlier timed-out reader —
/// is bounded by [`STOCK_XDS_TOKEN_FILE_READ_TIMEOUT`]. The open/read itself
/// runs on a detached OS thread that owns the permit, so a stalled mount can
/// never pin a Tokio worker and repeated attempts cannot accumulate blocked
/// readers.
async fn read_stock_bearer_token_raw(path: &str) -> Result<String, StockCredentialInvalidReason> {
    let read = async {
        let permit = stock_xds_token_file_read_limit()
            .acquire_owned()
            .await
            .map_err(|_| StockCredentialInvalidReason::ReaderUnavailable)?;
        read_credential_file_detached_guarded(
            path,
            DEFAULT_CREDENTIAL_FILE_MAX_BYTES,
            CredentialTrim::Ends,
            "ferrum-stock-xds-token-file",
            permit,
        )
        .await
        .map_err(|error| StockCredentialInvalidReason::from_credential_file_error(&error))
    };
    match tokio::time::timeout(STOCK_XDS_TOKEN_FILE_READ_TIMEOUT, read).await {
        Ok(result) => result,
        Err(_) => Err(StockCredentialInvalidReason::ReadTimeout),
    }
}

/// Watch the configured credential source and publish content/validity changes.
///
/// Runs until shutdown and is joined with the other mesh background tasks, so
/// no detached reader survives retirement. It never publishes the credential
/// itself — only the closed-set state and a private content fingerprint — and
/// it never widens the client's authorization: a `Valid` observation is only
/// permission to *attempt* a connection, which then performs its own
/// authoritative read.
pub async fn start_stock_credential_watcher_with_shutdown(
    source: StockXdsCredentialSource,
    watch_handle: StockCredentialWatch,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    if !source.is_configured() {
        // Nothing to observe; park until shutdown so the join is uniform.
        super::common::wait_for_shutdown(&mut shutdown_rx).await;
        return;
    }
    let interval = source.policy().watch_interval.max(Duration::from_secs(1));
    info!(
        watch_interval_secs = interval.as_secs(),
        max_stream_lifetime_secs = clamp_max_stream_lifetime(source.policy().max_stream_lifetime)
            .as_secs(),
        refresh_skew_secs = source.policy().refresh_skew.as_secs(),
        "Stock xDS bearer-credential watcher starting; ADS streams are retired when the source \
         rotates, becomes invalid, or reaches its authorization deadline"
    );

    loop {
        let next_state = match source.materialize().await {
            Ok(Some(credential)) => credential.observed_state(),
            // `is_configured()` was checked above, so `Ok(None)` is
            // unreachable; treat it as unusable rather than silently valid.
            Ok(None) => StockCredentialState::Invalid {
                reason: StockCredentialInvalidReason::Missing,
            },
            Err(reason) => StockCredentialState::Invalid { reason },
        };
        if watch_handle.publish(next_state) {
            match next_state {
                StockCredentialState::Invalid { reason } => warn!(
                    reason = reason.as_metric_label(),
                    "Stock xDS bearer-credential source became invalid; retiring the ADS stream \
                     and refusing reconnection until valid material is available"
                ),
                _ => info!(
                    "Stock xDS bearer credential rotated; retiring the ADS stream and \
                     reconnecting with the replacement material"
                ),
            }
        }

        tokio::select! {
            biased;
            _ = super::common::wait_for_shutdown(&mut shutdown_rx) => {
                info!("Stock xDS bearer-credential watcher shutting down");
                return;
            }
            _ = tokio::time::sleep(interval) => {}
        }
    }
}
