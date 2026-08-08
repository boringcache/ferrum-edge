//! Gateway SVID source refresh.
//!
//! The gateway's X.509-SVID is configured as three independent material
//! sources (`FERRUM_GATEWAY_SVID_CERT_*`, `..._KEY_*`, `..._TRUST_BUNDLE_*`),
//! each of which may be a filesystem path, a `file://` URI, inline PEM, or a
//! typed provider URI (`vault://`, `aws://`, `azure://`, `gcp://`, `k8s://`,
//! `acme://`, `managed://`). Provider-issued SVIDs are short-lived by design,
//! so this watcher re-fetches every refreshable source and republishes the
//! bundle when its bytes change — the same contract the frontend/admin,
//! backend, and database TLS watchers already provide for external sources.
//!
//! Three properties are load-bearing and must survive any refactor:
//!
//! 1. **Generations never mix.** A change on any one source triggers one
//!    reload of *all three* through
//!    [`crate::identity::file_loader::load_svid_bundle_from_sources`], which
//!    re-reads cert, key, and trust bundle together and refuses a chain whose
//!    leaf does not match the key. A torn write (new cert, old key) is a
//!    refusal, not a published half-generation.
//! 2. **Last-good survives transient failure.** A source that cannot be read,
//!    or a bundle that fails validation, leaves the live SVID slot untouched
//!    and does not advance the backend SVID generation. The warning is emitted
//!    once and silenced until the source recovers.
//! 3. **The generation boundary advances only after a valid replacement.** The
//!    caller-supplied publish closure installs the bundle *then* bumps
//!    `backend_svid_rotation_tx`, so backend pool keys (`|svidg=<n>`), pool
//!    drains, and health-probe restarts all observe one coherent update — the
//!    identical pipeline file rotation and `POST /admin/tls/rotate/svid` use.
//!
//! Unlike the single-cadence [`crate::tls::source::subscription`] loops, each
//! source here keeps its own due time: a file source is re-read on the
//! gateway's 1s file cadence while a `vault://` source alongside it is fetched
//! only every `FERRUM_SECRET_REFRESH_INTERVAL_SECONDS` (or its own `?poll=`).
//! Collapsing the set onto the fastest member would poll a secret manager once
//! per second. Inline PEM is static until config reload, matching every other
//! TLS surface.

use std::time::{Duration, Instant};

use tokio::sync::watch;
use tracing::{info, warn};

use crate::identity::SvidBundle;
use crate::tls::events::{record_load_error, record_rebuild_error, record_rotation_success};
use crate::tls::source::subscription::{
    MaterialFingerprintEntry, WatchedMaterialSource, material_fingerprint,
    record_refresh_for_entries, source_poll_interval,
};
use crate::tls::source::{CertSource, MaterialKind, SourceScheme};
use crate::tls::spiffe::SpiffeTlsError;

/// Watch surface name used for TLS source metrics and the TLS event log.
pub const GATEWAY_SVID_SURFACE: &str = "gateway_svid";

/// Default re-read cadence for file-backed gateway SVID sources. This is the
/// historical gateway SVID file-watch interval and is deliberately faster than
/// the frontend/backend file watchers: a SPIFFE Helper rewrite should be picked
/// up promptly, and a local read is cheap.
pub const GATEWAY_SVID_FILE_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Upper bound on how long the watcher sleeps between wake-ups. A scheduling
/// bound only: a source is still fetched on its own configured cadence.
const MAX_WATCH_SLEEP: Duration = Duration::from_secs(60);

const CERT_LABEL: &str = "gateway_svid_cert";
const KEY_LABEL: &str = "gateway_svid_key";
const TRUST_BUNDLE_LABEL: &str = "gateway_svid_trust_bundle";

/// How often one configured gateway SVID source is re-read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewaySvidCadence {
    /// Inline PEM, or a scheme with no refreshable loader. Static until the
    /// configuration itself is reloaded.
    Static,
    /// File-backed source, re-read on the gateway SVID file cadence.
    File(Duration),
    /// Provider-backed source, re-fetched on
    /// `FERRUM_SECRET_REFRESH_INTERVAL_SECONDS` or the source's `?poll=`.
    Provider(Duration),
}

impl GatewaySvidCadence {
    /// The refresh interval, or `None` for a static source.
    pub fn interval(self) -> Option<Duration> {
        match self {
            Self::Static => None,
            Self::File(interval) | Self::Provider(interval) => Some(interval),
        }
    }

    /// `true` when the source can change underneath the running process.
    pub fn is_refreshable(self) -> bool {
        self.interval().is_some()
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Static => "static",
            Self::File(_) => "file",
            Self::Provider(_) => "provider",
        }
    }
}

/// Classify one configured source into its refresh cadence.
pub fn gateway_svid_cadence(
    source: &CertSource,
    file_default: Duration,
    provider_default: Duration,
) -> GatewaySvidCadence {
    let Some(interval) = source_poll_interval(source, file_default, provider_default) else {
        return GatewaySvidCadence::Static;
    };
    // Inline PEM never yields an interval, so anything left that is not a local
    // file is provider-backed: the secret managers plus `k8s://`, `acme://`,
    // and `managed://`.
    let file_backed = match source {
        CertSource::Path(_) => true,
        CertSource::Uri(uri) => uri.scheme == SourceScheme::File,
        CertSource::InlinePem(_) => false,
    };
    if file_backed {
        GatewaySvidCadence::File(interval)
    } else {
        GatewaySvidCadence::Provider(interval)
    }
}

/// The three configured gateway SVID material sources.
///
/// Holds both the parsed [`CertSource`]s (for fingerprinting) and the original
/// configured values (for the reload, which goes through the same loader that
/// startup and `POST /admin/tls/rotate/svid` use).
#[derive(Clone)]
pub struct GatewaySvidSourceSet {
    cert_value: String,
    key_value: String,
    trust_bundle_value: String,
    expected_spiffe_id: Option<String>,
    watched: Vec<WatchedMaterialSource>,
}

impl GatewaySvidSourceSet {
    pub fn new(
        cert_value: String,
        key_value: String,
        trust_bundle_value: String,
        expected_spiffe_id: Option<String>,
    ) -> Self {
        let cert = CertSource::parse(cert_value.as_str(), MaterialKind::Cert);
        let key = CertSource::parse(key_value.as_str(), MaterialKind::Key);
        let bundle = CertSource::parse(trust_bundle_value.as_str(), MaterialKind::CaBundle);
        let watched = vec![
            WatchedMaterialSource::new(CERT_LABEL, cert, MaterialKind::Cert),
            WatchedMaterialSource::new(KEY_LABEL, key, MaterialKind::Key),
            WatchedMaterialSource::new(TRUST_BUNDLE_LABEL, bundle, MaterialKind::CaBundle),
        ];
        Self {
            cert_value,
            key_value,
            trust_bundle_value,
            expected_spiffe_id,
            watched,
        }
    }

    pub fn watched_sources(&self) -> &[WatchedMaterialSource] {
        &self.watched
    }

    /// Re-read all three sources and validate them as one SVID bundle.
    pub fn load_bundle(&self) -> Result<SvidBundle, SpiffeTlsError> {
        crate::identity::file_loader::load_svid_bundle_from_sources(
            &self.cert_value,
            &self.key_value,
            &self.trust_bundle_value,
            self.expected_spiffe_id.as_deref(),
        )
    }
}

/// One source that could not be re-read on this pass.
#[derive(Debug, Clone)]
pub struct GatewaySvidSourceFailure {
    pub label: &'static str,
    pub kind: MaterialKind,
    pub scheme: SourceScheme,
    /// Already-redacted loader error: `MaterialError`'s producers withhold
    /// provider references before the error is constructed.
    pub error: String,
}

/// What one tracker pass concluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewaySvidPollOutcome {
    /// No source was due, or a source has not recovered yet.
    Idle,
    /// The first complete read established the comparison baseline.
    Baseline,
    /// Every source that was due fingerprinted to the same bytes.
    Unchanged,
    /// At least one source's bytes changed; the caller should reload.
    Changed,
    /// A due source could not be read; the caller keeps the last-good bundle.
    SourceUnavailable,
}

/// Result of one tracker pass.
#[derive(Debug, Clone)]
pub struct GatewaySvidPollReport {
    pub outcome: GatewaySvidPollOutcome,
    /// Entries successfully re-read on this pass — only the sources that were
    /// due, never the whole set.
    pub refreshed: Vec<MaterialFingerprintEntry>,
    pub failures: Vec<GatewaySvidSourceFailure>,
}

struct TrackedSource {
    watched: WatchedMaterialSource,
    cadence: GatewaySvidCadence,
    last: Option<MaterialFingerprintEntry>,
    due_at: Option<Instant>,
}

/// Per-source byte-fingerprint tracker for the gateway SVID material set.
///
/// Each source is re-read on its own cadence; the *set* of latest fingerprints
/// is what the rotation predicate compares, so a change to any one member
/// triggers one coherent reload of all three.
pub struct GatewaySvidSourceTracker {
    sources: Vec<TrackedSource>,
    published: Option<Vec<MaterialFingerprintEntry>>,
}

impl GatewaySvidSourceTracker {
    pub fn new(
        sources: &GatewaySvidSourceSet,
        file_default: Duration,
        provider_default: Duration,
    ) -> Self {
        let mut tracked = Vec::with_capacity(sources.watched_sources().len());
        for watched in sources.watched_sources() {
            let source = &watched.source;
            let cadence = gateway_svid_cadence(source, file_default, provider_default);
            tracked.push(TrackedSource {
                watched: watched.clone(),
                cadence,
                last: None,
                due_at: None,
            });
        }
        Self {
            sources: tracked,
            published: None,
        }
    }

    /// Configured cadence per source label, in cert / key / trust-bundle order.
    pub fn cadences(&self) -> Vec<(&'static str, GatewaySvidCadence)> {
        let mut cadences = Vec::with_capacity(self.sources.len());
        for source in &self.sources {
            cadences.push((source.watched.label, source.cadence));
        }
        cadences
    }

    /// `true` when at least one source can change underneath the process.
    pub fn is_watchable(&self) -> bool {
        self.sources.iter().any(|s| s.cadence.is_refreshable())
    }

    /// Re-read every source whose cadence is due and compare the resulting set
    /// against the last published one.
    pub fn poll(&mut self, now: Instant) -> GatewaySvidPollReport {
        let mut refreshed = Vec::new();
        let mut failures = Vec::new();

        for source in &mut self.sources {
            let due = match source.due_at {
                // A static source is fingerprinted once so it participates in
                // set equality, then never again.
                None => source.last.is_none(),
                Some(due_at) => due_at <= now,
            };
            if !due {
                continue;
            }
            if let Some(interval) = source.cadence.interval() {
                source.due_at = Some(now + interval);
            }
            match material_fingerprint(&source.watched) {
                Ok(entry) => {
                    refreshed.push(entry.clone());
                    source.last = Some(entry);
                }
                Err(error) => {
                    failures.push(GatewaySvidSourceFailure {
                        label: source.watched.label,
                        kind: source.watched.kind,
                        scheme: configured_scheme(&source.watched.source),
                        error: error.to_string(),
                    });
                }
            }
        }

        if !failures.is_empty() {
            return GatewaySvidPollReport {
                outcome: GatewaySvidPollOutcome::SourceUnavailable,
                refreshed,
                failures,
            };
        }

        let Some(current) = self.current_fingerprints() else {
            // A source failed on an earlier pass and is not due again yet.
            return GatewaySvidPollReport {
                outcome: GatewaySvidPollOutcome::Idle,
                refreshed,
                failures,
            };
        };

        let outcome = if self.published.is_none() {
            self.published = Some(current);
            GatewaySvidPollOutcome::Baseline
        } else if self.published.as_deref() == Some(current.as_slice()) {
            GatewaySvidPollOutcome::Unchanged
        } else {
            GatewaySvidPollOutcome::Changed
        };
        GatewaySvidPollReport {
            outcome,
            refreshed,
            failures,
        }
    }

    /// Adopt the current fingerprints as the comparison baseline.
    ///
    /// Called after a reload attempt whether or not it succeeded: recording a
    /// failing set stops the watcher from re-warning on every tick while a bad
    /// state is stable, and the next genuine change still compares unequal.
    pub fn commit(&mut self) {
        if let Some(current) = self.current_fingerprints() {
            self.published = Some(current);
        }
    }

    /// Latest fingerprints, or `None` while any source has never been read.
    pub fn current_fingerprints(&self) -> Option<Vec<MaterialFingerprintEntry>> {
        let mut entries = Vec::with_capacity(self.sources.len());
        for source in &self.sources {
            entries.push(source.last.clone()?);
        }
        Some(entries)
    }

    /// How long to sleep before the next source is due.
    pub fn next_delay(&self, now: Instant) -> Duration {
        let mut delay = MAX_WATCH_SLEEP;
        for source in &self.sources {
            let Some(due_at) = source.due_at else {
                continue;
            };
            delay = delay.min(due_at.saturating_duration_since(now));
        }
        delay
    }
}

fn configured_scheme(source: &CertSource) -> SourceScheme {
    match source {
        CertSource::Path(_) | CertSource::InlinePem(_) => SourceScheme::File,
        CertSource::Uri(uri) => uri.scheme,
    }
}

/// Install a validated bundle and return the new backend SVID generation.
///
/// Production wires this to `ProxyState::install_gateway_file_svid_bundle` plus
/// a `backend_svid_rotation_tx` bump, so the slot update strictly precedes the
/// generation bump that backend pools, health probes, and pool keys observe.
pub type GatewaySvidPublishFn = Box<dyn Fn(SvidBundle) -> u64 + Send + Sync + 'static>;

/// Configuration for [`run_gateway_svid_source_rotation_loop`].
pub struct GatewaySvidWatchConfig {
    pub sources: GatewaySvidSourceSet,
    /// Cadence for file-backed sources.
    pub file_interval: Duration,
    /// Cadence for provider-backed sources without an explicit `?poll=`
    /// (`FERRUM_SECRET_REFRESH_INTERVAL_SECONDS`).
    pub provider_interval: Duration,
    pub publish: GatewaySvidPublishFn,
}

/// Poll the configured gateway SVID sources and republish the bundle on change.
///
/// Exits immediately when every configured source is static, and cleanly when
/// the shutdown receiver fires.
pub async fn run_gateway_svid_source_rotation_loop(
    config: GatewaySvidWatchConfig,
    mut shutdown_rx: Option<watch::Receiver<bool>>,
) {
    let GatewaySvidWatchConfig {
        sources,
        file_interval,
        provider_interval,
        publish,
    } = config;

    let mut tracker = GatewaySvidSourceTracker::new(&sources, file_interval, provider_interval);
    if !tracker.is_watchable() {
        info!(
            "Gateway SVID sources are all static (inline PEM); automatic refresh is disabled — \
             rotate with POST /admin/tls/rotate/svid or a configuration reload"
        );
        return;
    }

    for (label, cadence) in tracker.cadences() {
        let interval_secs = cadence.interval().map(|i| i.as_secs()).unwrap_or(0);
        info!(
            source = label,
            cadence = cadence.as_str(),
            interval_secs,
            "Gateway SVID source refresh cadence"
        );
    }

    let mut failure_logged = false;

    loop {
        if shutdown_rx.as_ref().is_some_and(|rx| *rx.borrow()) {
            return;
        }

        let report = tracker.poll(Instant::now());
        match report.outcome {
            GatewaySvidPollOutcome::Idle | GatewaySvidPollOutcome::Baseline => {}
            GatewaySvidPollOutcome::SourceUnavailable => {
                record_source_failures(&sources, &report.failures, &mut failure_logged);
            }
            GatewaySvidPollOutcome::Unchanged => {
                note_recovery(&mut failure_logged);
                record_refresh_for_entries(GATEWAY_SVID_SURFACE, &report.refreshed, "unchanged");
            }
            GatewaySvidPollOutcome::Changed => {
                note_recovery(&mut failure_logged);
                reload_and_publish(&sources, &mut tracker, publish.as_ref());
            }
        }

        let delay = tracker.next_delay(Instant::now());
        if let Some(shutdown) = shutdown_rx.as_mut() {
            tokio::select! {
                _ = tokio::time::sleep(delay) => {}
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        return;
                    }
                }
            }
        } else {
            tokio::time::sleep(delay).await;
        }
    }
}

fn note_recovery(failure_logged: &mut bool) {
    if *failure_logged {
        info!("Gateway SVID source watcher recovered source access");
        *failure_logged = false;
    }
}

fn record_source_failures(
    sources: &GatewaySvidSourceSet,
    failures: &[GatewaySvidSourceFailure],
    failure_logged: &mut bool,
) {
    let registry = crate::plugins::prometheus_metrics::global_registry();
    for failure in failures {
        registry.record_tls_source_refresh(
            failure.scheme.as_str(),
            failure.kind.as_str(),
            GATEWAY_SVID_SURFACE,
            "load_error",
        );
    }

    // Only the sources that actually failed are attributed; a trust-bundle
    // fetch outage must not be recorded as a certificate failure.
    let mut failed = Vec::new();
    for watched in sources.watched_sources() {
        if failures.iter().any(|f| f.label == watched.label) {
            failed.push(watched.clone());
        }
    }
    let detail = describe_failures(failures);
    record_load_error(GATEWAY_SVID_SURFACE, &failed, &detail);

    if !*failure_logged {
        warn!(
            error = %detail,
            "Gateway SVID source could not be read; keeping the current SVID material \
             (silenced until the source recovers)"
        );
        *failure_logged = true;
    }
}

fn reload_and_publish(
    sources: &GatewaySvidSourceSet,
    tracker: &mut GatewaySvidSourceTracker,
    publish: &dyn Fn(SvidBundle) -> u64,
) {
    let entries = tracker.current_fingerprints().unwrap_or_default();
    // One coherent re-read of all three sources. If a source changes again
    // between the fingerprint pass and this load, the committed fingerprints
    // are older than the published material, so the next pass compares unequal
    // and reloads again — a redundant rotation, never a stale identity.
    match sources.load_bundle() {
        Ok(bundle) => {
            let spiffe_id = bundle.spiffe_id.to_string();
            let revision = publish(bundle);
            tracker.commit();
            record_refresh_for_entries(GATEWAY_SVID_SURFACE, &entries, "rotated");
            record_rotation_success(GATEWAY_SVID_SURFACE, &entries, revision);
            info!(
                spiffe_id = %spiffe_id,
                svid_revision = revision,
                "Gateway SVID sources reloaded; backend SVID rotation published"
            );
        }
        Err(error) => {
            // Record the failing set so a stable bad state does not re-warn on
            // every tick. The live SVID slot and the backend SVID generation
            // are both left untouched.
            tracker.commit();
            record_refresh_for_entries(GATEWAY_SVID_SURFACE, &entries, "rebuild_error");
            let error = anyhow::anyhow!("{error}");
            record_rebuild_error(GATEWAY_SVID_SURFACE, &entries, &error);
            warn!(
                error = %error,
                "Gateway SVID sources changed but the reload failed; keeping the current material"
            );
        }
    }
}

fn describe_failures(failures: &[GatewaySvidSourceFailure]) -> String {
    let mut rendered = Vec::with_capacity(failures.len());
    for failure in failures {
        rendered.push(format!("{}: {}", failure.label, failure.error));
    }
    rendered.join("; ")
}
