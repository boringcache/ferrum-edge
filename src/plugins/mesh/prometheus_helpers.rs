//! Prometheus helpers for Istio/GAMMA-style mesh metrics.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use dashmap::mapref::entry::Entry;

use crate::identity::ca::PublishedTrustBundle;
use crate::identity::spiffe::SpiffeId;
use crate::plugins::TransactionSummary;
use crate::plugins::prometheus_metrics::{HistogramBuckets, escape_label_value};

const MESH_CERT_EXPIRY_STALE_RETENTION_SECONDS: u64 = 6 * 60 * 60;
const MESH_CERT_EXPIRY_EVICTION_INTERVAL_SECONDS: u64 = 60;

static MESH_CERT_EXPIRY_UNIX_SECONDS: LazyLock<DashMap<MeshCertExpiryKey, MeshCertExpiryGauge>> =
    LazyLock::new(DashMap::new);
static MESH_CERT_EXPIRY_LAST_EVICTION_UNIX_SECONDS: AtomicU64 = AtomicU64::new(0);
static MESH_CERT_ROTATION_FAILURES: LazyLock<DashMap<MeshCertRotationFailureKey, AtomicU64>> =
    LazyLock::new(DashMap::new);
static MESH_CA_HEALTH: LazyLock<DashMap<MeshCaHealthKey, AtomicU64>> = LazyLock::new(DashMap::new);
static MESH_TRUST_BUNDLE_VERSIONS: LazyLock<
    DashMap<MeshTrustBundleVersionKey, TrustBundleVersionGauge>,
> = LazyLock::new(DashMap::new);
static MESH_CONFIG_LAST_RECEIVED: LazyLock<DashMap<Arc<str>, AtomicU64>> =
    LazyLock::new(DashMap::new);
static MESH_MTLS_HANDSHAKE_FAILURES: LazyLock<DashMap<MeshMtlsHandshakeFailureKey, AtomicU64>> =
    LazyLock::new(DashMap::new);
static MESH_FEDERATION_POLL_FAILURES: LazyLock<DashMap<MeshFederationPollFailureKey, AtomicU64>> =
    LazyLock::new(DashMap::new);
static MESH_FEDERATION_LAST_SUCCESS: LazyLock<DashMap<Arc<str>, AtomicU64>> =
    LazyLock::new(DashMap::new);
static XDS_STREAMS_REJECTED: AtomicU64 = AtomicU64::new(0);
static XDS_WARMING_PARTIAL_APPLIES: LazyLock<DashMap<Arc<str>, AtomicU64>> =
    LazyLock::new(DashMap::new);
static XDS_FIRST_SLICE_NACKS: LazyLock<DashMap<XdsFirstSliceNackKey, AtomicU64>> =
    LazyLock::new(DashMap::new);

/// Istio/GAMMA-style RED metric key for mesh HTTP-family requests.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MeshRequestKey {
    pub source_workload: Arc<str>,
    pub source_namespace: Arc<str>,
    pub source_principal: Arc<str>,
    pub source_app: Arc<str>,
    pub source_service: Arc<str>,
    pub destination_workload: Arc<str>,
    pub destination_namespace: Arc<str>,
    pub destination_principal: Arc<str>,
    pub destination_app: Arc<str>,
    pub destination_service: Arc<str>,
    pub request_protocol: Arc<str>,
    pub response_code: u16,
    pub response_flags: Arc<str>,
    pub connection_security_policy: Arc<str>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct MeshCertExpiryKey {
    spiffe_id: Arc<str>,
    source: Arc<str>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct MeshCertRotationFailureKey {
    spiffe_id: Arc<str>,
    source: Arc<str>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct MeshCaHealthKey {
    ca_type: Arc<str>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct MeshTrustBundleVersionKey {
    trust_domain: Arc<str>,
    source: Arc<str>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct MeshMtlsHandshakeFailureKey {
    reason: Arc<str>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct MeshFederationPollFailureKey {
    trust_domain: Arc<str>,
    endpoint: Arc<str>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct XdsFirstSliceNackKey {
    namespace: Arc<str>,
    type_url: Arc<str>,
}

struct MeshCertExpiryGauge {
    expires_at: AtomicU64,
    last_observed_at: AtomicU64,
}

impl MeshCertExpiryGauge {
    fn new(expires_at: u64, observed_at: u64) -> Self {
        Self {
            expires_at: AtomicU64::new(expires_at),
            last_observed_at: AtomicU64::new(observed_at),
        }
    }

    fn observe(&self, expires_at: u64, observed_at: u64) {
        self.expires_at.store(expires_at, Ordering::Relaxed);
        self.last_observed_at.store(observed_at, Ordering::Relaxed);
    }
}

struct TrustBundleVersionGauge {
    fingerprint: AtomicU64,
    version: AtomicU64,
}

impl TrustBundleVersionGauge {
    fn new(fingerprint: u64) -> Self {
        Self {
            fingerprint: AtomicU64::new(fingerprint),
            version: AtomicU64::new(1),
        }
    }

    fn observe(&self, fingerprint: u64) {
        let mut current = self.fingerprint.load(Ordering::Relaxed);
        while current != fingerprint {
            match self.fingerprint.compare_exchange_weak(
                current,
                fingerprint,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    self.version.fetch_add(1, Ordering::Relaxed);
                    break;
                }
                Err(actual) => current = actual,
            }
        }
    }
}

pub fn record_mesh_cert_expiry_seconds(
    spiffe_id: impl AsRef<str>,
    source: impl AsRef<str>,
    seconds_until_expiry: u64,
) {
    let now = unix_now_seconds();
    record_mesh_cert_expiry_unix_seconds(
        spiffe_id,
        source,
        now.saturating_add(seconds_until_expiry),
        now,
    );
}

pub fn record_mesh_cert_expiry_at(
    spiffe_id: &SpiffeId,
    source: impl AsRef<str>,
    not_after: &DateTime<Utc>,
) {
    record_mesh_cert_expiry_unix_seconds(
        spiffe_id.as_str(),
        source,
        not_after.timestamp().max(0) as u64,
        unix_now_seconds(),
    );
}

fn record_mesh_cert_expiry_unix_seconds(
    spiffe_id: impl AsRef<str>,
    source: impl AsRef<str>,
    expires_at: u64,
    observed_at: u64,
) {
    let key = MeshCertExpiryKey {
        spiffe_id: Arc::from(spiffe_id.as_ref()),
        source: Arc::from(source.as_ref()),
    };
    MESH_CERT_EXPIRY_UNIX_SECONDS
        .entry(key)
        .or_insert_with(|| MeshCertExpiryGauge::new(expires_at, observed_at))
        .observe(expires_at, observed_at);
}

pub fn increment_mesh_cert_rotation_failure(spiffe_id: impl AsRef<str>, source: impl AsRef<str>) {
    let key = MeshCertRotationFailureKey {
        spiffe_id: Arc::from(spiffe_id.as_ref()),
        source: Arc::from(source.as_ref()),
    };
    MESH_CERT_ROTATION_FAILURES
        .entry(key)
        .or_insert_with(|| AtomicU64::new(0))
        .fetch_add(1, Ordering::Relaxed);
}

pub fn set_mesh_ca_health(ca_type: impl AsRef<str>, healthy: bool) {
    let key = MeshCaHealthKey {
        ca_type: Arc::from(ca_type.as_ref()),
    };
    MESH_CA_HEALTH
        .entry(key)
        .or_insert_with(|| AtomicU64::new(0))
        .store(u64::from(healthy), Ordering::Relaxed);
}

pub fn record_mesh_trust_bundle(bundle: &PublishedTrustBundle, source: impl AsRef<str>) {
    record_mesh_trust_bundle_roots(
        bundle.trust_domain.as_str(),
        source,
        bundle.roots_der.as_slice(),
    );
}

pub fn record_mesh_trust_bundle_roots(
    trust_domain: impl AsRef<str>,
    source: impl AsRef<str>,
    roots_der: &[Vec<u8>],
) {
    let fingerprint = trust_bundle_fingerprint(roots_der);
    let key = MeshTrustBundleVersionKey {
        trust_domain: Arc::from(trust_domain.as_ref()),
        source: Arc::from(source.as_ref()),
    };
    MESH_TRUST_BUNDLE_VERSIONS
        .entry(key)
        .or_insert_with(|| TrustBundleVersionGauge::new(fingerprint))
        .observe(fingerprint);
}

/// Record the timestamp of the most recently installed mesh slice for `namespace`.
///
/// A mesh data-plane instance only ever installs slices for its own mesh
/// namespace, so the underlying map is effectively a single-element gauge —
/// the `retain` call deliberately evicts any stale namespace label that would
/// otherwise stick around forever in the `/metrics` output (for example after
/// `FERRUM_MESH_NAMESPACE` is reconfigured mid-process for testing). The map
/// shape is kept so the namespace label remains on the wire for alerting rules
/// that group by namespace; alerts must not rely on multiple namespace series
/// per gateway.
pub fn record_mesh_config_received(namespace: impl AsRef<str>) {
    let namespace = namespace.as_ref();
    MESH_CONFIG_LAST_RECEIVED.retain(|key, _| key.as_ref() == namespace);
    MESH_CONFIG_LAST_RECEIVED
        .entry(Arc::from(namespace))
        .or_insert_with(|| AtomicU64::new(0))
        .store(Utc::now().timestamp().max(0) as u64, Ordering::Relaxed);
}

pub fn increment_mesh_federation_poll_failure(
    trust_domain: impl AsRef<str>,
    endpoint: impl AsRef<str>,
) {
    let key = MeshFederationPollFailureKey {
        trust_domain: Arc::from(trust_domain.as_ref()),
        endpoint: Arc::from(endpoint.as_ref()),
    };
    MESH_FEDERATION_POLL_FAILURES
        .entry(key)
        .or_insert_with(|| AtomicU64::new(0))
        .fetch_add(1, Ordering::Relaxed);
}

pub fn record_mesh_federation_poll_success(
    trust_domain: impl AsRef<str>,
    fetched_at_unix_seconds: u64,
) {
    MESH_FEDERATION_LAST_SUCCESS
        .entry(Arc::from(trust_domain.as_ref()))
        .or_insert_with(|| AtomicU64::new(0))
        .store(fetched_at_unix_seconds, Ordering::Relaxed);
}

pub fn increment_mesh_mtls_handshake_failure(reason: impl AsRef<str>) {
    let key = MeshMtlsHandshakeFailureKey {
        reason: Arc::from(reason.as_ref()),
    };
    MESH_MTLS_HANDSHAKE_FAILURES
        .entry(key)
        .or_insert_with(|| AtomicU64::new(0))
        .fetch_add(1, Ordering::Relaxed);
}

/// Count an ADS stream the CP rejected because a node is already at its
/// per-node concurrent-stream ceiling (`FERRUM_XDS_MAX_STREAMS_PER_NODE`).
/// Aggregated (no per-node label) to avoid an unbounded, client-controlled
/// `node_id` metric dimension; the offending node id is still logged at `warn!`
/// at the reject site. Surfaces a DoS / misconfigured-client signal the plain
/// gRPC `RESOURCE_EXHAUSTED` status alone does not expose to scraping.
pub fn increment_xds_stream_rejected() {
    XDS_STREAMS_REJECTED.fetch_add(1, Ordering::Relaxed);
}

/// Count a NACK of a required mesh-slice type that occurred while the DP is
/// still waiting for its first slice. A persistently NACKing required type
/// wedges `wait_for_first_slice()` until the NACK circuit breaker trips, so a
/// non-zero, growing value here is the operator signal that startup
/// convergence is blocked by a malformed required resource.
pub fn increment_xds_first_slice_nack(namespace: impl AsRef<str>, type_url: impl AsRef<str>) {
    let key = XdsFirstSliceNackKey {
        namespace: Arc::from(namespace.as_ref()),
        type_url: Arc::from(type_url.as_ref()),
    };
    XDS_FIRST_SLICE_NACKS
        .entry(key)
        .or_insert_with(|| AtomicU64::new(0))
        .fetch_add(1, Ordering::Relaxed);
}

/// Count any defensive mesh-slice apply that is explicitly marked as version
/// skewed. Normal xDS apply now requires coherent required-type versions before
/// installing a slice, so this counter should remain zero unless a future caller
/// deliberately opts into applying a skewed warmed slice. Keyed by `namespace` only
/// (matching `ferrum_xds_first_slice_nacks_total`) — low, operator-bounded
/// cardinality; the per-type version strings live behind JWT on
/// `/mesh/config-drift` because they embed config timestamps + content digests.
pub fn increment_xds_warming_partial_apply(namespace: impl AsRef<str>) {
    XDS_WARMING_PARTIAL_APPLIES
        .entry(Arc::from(namespace.as_ref()))
        .or_insert_with(|| AtomicU64::new(0))
        .fetch_add(1, Ordering::Relaxed);
}

pub fn render_mesh_observability_metrics(output: &mut String) {
    let now = unix_now_seconds();
    maybe_evict_stale_mesh_cert_expiry_series(now);

    if !MESH_CERT_EXPIRY_UNIX_SECONDS.is_empty() {
        output.push_str(
            "# HELP ferrum_mesh_cert_expiry_seconds Seconds until mesh X.509-SVID expiry.\n",
        );
        output.push_str("# TYPE ferrum_mesh_cert_expiry_seconds gauge\n");
        for entry in MESH_CERT_EXPIRY_UNIX_SECONDS.iter() {
            let seconds_until_expiry = entry
                .value()
                .expires_at
                .load(Ordering::Relaxed)
                .saturating_sub(now);
            output.push_str(&format!(
                "ferrum_mesh_cert_expiry_seconds{{spiffe_id=\"{}\",source=\"{}\"}} {}\n",
                escape_label_value(&entry.key().spiffe_id),
                escape_label_value(&entry.key().source),
                seconds_until_expiry
            ));
        }
    }

    if !MESH_CERT_ROTATION_FAILURES.is_empty() {
        output.push_str(
            "# HELP ferrum_mesh_cert_rotation_failures_total Mesh certificate rotation failures.\n",
        );
        output.push_str("# TYPE ferrum_mesh_cert_rotation_failures_total counter\n");
        for entry in MESH_CERT_ROTATION_FAILURES.iter() {
            output.push_str(&format!(
                "ferrum_mesh_cert_rotation_failures_total{{spiffe_id=\"{}\",source=\"{}\"}} {}\n",
                escape_label_value(&entry.key().spiffe_id),
                escape_label_value(&entry.key().source),
                entry.value().load(Ordering::Relaxed)
            ));
        }
    }

    if !MESH_CA_HEALTH.is_empty() {
        output.push_str(
            "# HELP ferrum_mesh_ca_health Mesh CA backend health, 1 healthy and 0 unhealthy.\n",
        );
        output.push_str("# TYPE ferrum_mesh_ca_health gauge\n");
        for entry in MESH_CA_HEALTH.iter() {
            output.push_str(&format!(
                "ferrum_mesh_ca_health{{ca_type=\"{}\"}} {}\n",
                escape_label_value(&entry.key().ca_type),
                entry.value().load(Ordering::Relaxed)
            ));
        }
    }

    if !MESH_TRUST_BUNDLE_VERSIONS.is_empty() {
        output.push_str(
            "# HELP ferrum_mesh_trust_bundle_version Monotonic version of observed mesh trust bundles.\n",
        );
        output.push_str("# TYPE ferrum_mesh_trust_bundle_version gauge\n");
        for entry in MESH_TRUST_BUNDLE_VERSIONS.iter() {
            output.push_str(&format!(
                "ferrum_mesh_trust_bundle_version{{trust_domain=\"{}\",source=\"{}\"}} {}\n",
                escape_label_value(&entry.key().trust_domain),
                escape_label_value(&entry.key().source),
                entry.value().version.load(Ordering::Relaxed)
            ));
        }
    }

    if !MESH_CONFIG_LAST_RECEIVED.is_empty() {
        output.push_str("# HELP ferrum_mesh_config_last_received_timestamp_seconds Unix timestamp of the last installed mesh config slice.\n");
        output.push_str("# TYPE ferrum_mesh_config_last_received_timestamp_seconds gauge\n");
        for entry in MESH_CONFIG_LAST_RECEIVED.iter() {
            output.push_str(&format!(
                "ferrum_mesh_config_last_received_timestamp_seconds{{namespace=\"{}\"}} {}\n",
                escape_label_value(entry.key()),
                entry.value().load(Ordering::Relaxed)
            ));
        }
    }

    if !MESH_MTLS_HANDSHAKE_FAILURES.is_empty() {
        output.push_str(
            "# HELP ferrum_mesh_mtls_handshake_failures_total Frontend mesh TLS/mTLS handshake failures.\n",
        );
        output.push_str("# TYPE ferrum_mesh_mtls_handshake_failures_total counter\n");
        for entry in MESH_MTLS_HANDSHAKE_FAILURES.iter() {
            output.push_str(&format!(
                "ferrum_mesh_mtls_handshake_failures_total{{reason=\"{}\"}} {}\n",
                escape_label_value(&entry.key().reason),
                entry.value().load(Ordering::Relaxed)
            ));
        }
    }

    if !MESH_FEDERATION_POLL_FAILURES.is_empty() {
        output.push_str(
            "# HELP ferrum_mesh_federation_poll_failures_total SPIFFE federation trust-bundle poll failures.\n",
        );
        output.push_str("# TYPE ferrum_mesh_federation_poll_failures_total counter\n");
        for entry in MESH_FEDERATION_POLL_FAILURES.iter() {
            output.push_str(&format!(
                "ferrum_mesh_federation_poll_failures_total{{trust_domain=\"{}\",endpoint=\"{}\"}} {}\n",
                escape_label_value(&entry.key().trust_domain),
                escape_label_value(&entry.key().endpoint),
                entry.value().load(Ordering::Relaxed)
            ));
        }
    }

    if !MESH_FEDERATION_LAST_SUCCESS.is_empty() {
        output.push_str(
            "# HELP ferrum_mesh_federation_last_success_timestamp_seconds Unix timestamp of last successful SPIFFE federation poll.\n",
        );
        output.push_str("# TYPE ferrum_mesh_federation_last_success_timestamp_seconds gauge\n");
        output.push_str(
            "# HELP ferrum_mesh_federation_bundle_age_seconds Age of the cached federated trust bundle, in seconds.\n",
        );
        output.push_str("# TYPE ferrum_mesh_federation_bundle_age_seconds gauge\n");
        for entry in MESH_FEDERATION_LAST_SUCCESS.iter() {
            let last = entry.value().load(Ordering::Relaxed);
            let trust_domain = escape_label_value(entry.key());
            output.push_str(&format!(
                "ferrum_mesh_federation_last_success_timestamp_seconds{{trust_domain=\"{}\"}} {}\n",
                trust_domain, last
            ));
            // Age clamps to 0 when the cached "last" timestamp is somehow in the
            // future (clock skew on a restart). Saturating subtraction keeps the
            // gauge non-negative for a Prometheus `gauge` type.
            let age = now.saturating_sub(last);
            output.push_str(&format!(
                "ferrum_mesh_federation_bundle_age_seconds{{trust_domain=\"{}\"}} {}\n",
                trust_domain, age
            ));
        }
    }

    let xds_streams_rejected = XDS_STREAMS_REJECTED.load(Ordering::Relaxed);
    if xds_streams_rejected > 0 {
        output.push_str(
            "# HELP ferrum_xds_streams_rejected_total ADS streams rejected for exceeding the per-node concurrent-stream ceiling.\n",
        );
        output.push_str("# TYPE ferrum_xds_streams_rejected_total counter\n");
        output.push_str(&format!(
            "ferrum_xds_streams_rejected_total {xds_streams_rejected}\n"
        ));
    }

    if !XDS_WARMING_PARTIAL_APPLIES.is_empty() {
        output.push_str(
            "# HELP ferrum_xds_warming_partial_applies_total Mesh slices applied while marked as xDS required-version skewed. Normal coherent xDS apply should not increment this.\n",
        );
        output.push_str("# TYPE ferrum_xds_warming_partial_applies_total counter\n");
        for entry in XDS_WARMING_PARTIAL_APPLIES.iter() {
            output.push_str(&format!(
                "ferrum_xds_warming_partial_applies_total{{namespace=\"{}\"}} {}\n",
                escape_label_value(entry.key()),
                entry.value().load(Ordering::Relaxed)
            ));
        }
    }

    if !XDS_FIRST_SLICE_NACKS.is_empty() {
        output.push_str(
            "# HELP ferrum_xds_first_slice_nacks_total NACKs of a required mesh-slice type while the data plane is still waiting for its first slice.\n",
        );
        output.push_str("# TYPE ferrum_xds_first_slice_nacks_total counter\n");
        for entry in XDS_FIRST_SLICE_NACKS.iter() {
            output.push_str(&format!(
                "ferrum_xds_first_slice_nacks_total{{namespace=\"{}\",type_url=\"{}\"}} {}\n",
                escape_label_value(&entry.key().namespace),
                escape_label_value(&entry.key().type_url),
                entry.value().load(Ordering::Relaxed)
            ));
        }
    }
}

fn unix_now_seconds() -> u64 {
    Utc::now().timestamp().max(0) as u64
}

fn maybe_evict_stale_mesh_cert_expiry_series(now: u64) {
    let mut last = MESH_CERT_EXPIRY_LAST_EVICTION_UNIX_SECONDS.load(Ordering::Relaxed);
    loop {
        if last != 0 && now.saturating_sub(last) < MESH_CERT_EXPIRY_EVICTION_INTERVAL_SECONDS {
            return;
        }
        match MESH_CERT_EXPIRY_LAST_EVICTION_UNIX_SECONDS.compare_exchange_weak(
            last,
            now,
            Ordering::AcqRel,
            Ordering::Relaxed,
        ) {
            Ok(_) => {
                evict_stale_mesh_cert_expiry_series(now);
                return;
            }
            Err(actual) => last = actual,
        }
    }
}

fn evict_stale_mesh_cert_expiry_series(now: u64) {
    let stale_keys: Vec<_> = MESH_CERT_EXPIRY_UNIX_SECONDS
        .iter()
        .filter_map(|entry| {
            let expires_at = entry.value().expires_at.load(Ordering::Relaxed);
            let last_observed_at = entry.value().last_observed_at.load(Ordering::Relaxed);
            mesh_cert_expiry_series_is_stale(expires_at, last_observed_at, now)
                .then(|| entry.key().clone())
        })
        .collect();
    for key in stale_keys {
        MESH_CERT_EXPIRY_UNIX_SECONDS.remove(&key);
    }
}

fn mesh_cert_expiry_series_is_stale(expires_at: u64, last_observed_at: u64, now: u64) -> bool {
    let stale_after = expires_at
        .max(last_observed_at)
        .saturating_add(MESH_CERT_EXPIRY_STALE_RETENTION_SECONDS);
    now >= stale_after
}

/// Build a `MeshRequestKey` from a transaction summary.
///
/// Hard cap on the number of distinct interned mesh-label values.
///
/// The legitimate mesh label space (workload / namespace / principal / app /
/// service / protocol / response-flags / security-policy) is small and
/// bounded, so this comfortably covers steady-state cardinality. Some label
/// values (e.g. workload / namespace) are attacker-influenceable in certain
/// topologies, so the pool is capped to stay a bounded memory cost rather than
/// an unbounded growth vector: once full it simply stops interning new values
/// and falls back to a per-call allocation (no worse than the prior behavior).
const MESH_LABEL_INTERN_CAP: usize = 4096;

/// Process-wide intern pool that turns repeated mesh-label `&str` values into a
/// shared `Arc<str>` so [`mesh_request_key`] can clone (atomic increment)
/// instead of heap-allocating a fresh `Arc` per field on every call.
static MESH_LABEL_INTERN: LazyLock<DashMap<Box<str>, Arc<str>>> =
    LazyLock::new(|| DashMap::with_shard_amount(super::observability_shard_amount()));
static MESH_LABEL_INTERN_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Intern a mesh label value into a shared `Arc<str>`.
///
/// On the steady-state hot path (a previously-seen value) this is a single
/// hash lookup plus a cheap `Arc::clone`. A first-seen value allocates once and
/// is cached. Once the pool reaches [`MESH_LABEL_INTERN_CAP`] distinct values
/// it stops growing and falls back to a plain `Arc::from`, keeping memory
/// bounded under adversarial cardinality.
fn intern_label(value: &str) -> Arc<str> {
    if let Some(existing) = MESH_LABEL_INTERN.get(value) {
        return Arc::clone(existing.value());
    }
    if MESH_LABEL_INTERN_COUNT
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
            (count < MESH_LABEL_INTERN_CAP).then_some(count + 1)
        })
        .is_err()
    {
        return Arc::from(value);
    }

    match MESH_LABEL_INTERN.entry(Box::from(value)) {
        Entry::Occupied(entry) => {
            MESH_LABEL_INTERN_COUNT.fetch_sub(1, Ordering::Relaxed);
            Arc::clone(entry.get())
        }
        Entry::Vacant(entry) => {
            let interned = Arc::from(value);
            entry.insert(Arc::clone(&interned));
            interned
        }
    }
}

/// Build the RED/service-graph metric key for a mesh request.
///
/// Per-field label values are interned via [`intern_label`] so repeated label
/// values (the common case — a bounded set of workloads / namespaces /
/// protocols) become a hash lookup plus an `Arc` clone rather than ~11 fresh
/// heap allocations per call. This runs on the `log` phase (RED metrics,
/// service-graph aggregation, log shaping) and is gated off unless mesh
/// metrics / the service graph are enabled.
pub fn mesh_request_key(summary: &TransactionSummary) -> Option<MeshRequestKey> {
    if !summary.metadata.keys().any(|key| key.starts_with("mesh.")) {
        return None;
    }

    let source_workload = metadata_arc(&summary.metadata, "mesh.source.workload", "unknown");
    let source_namespace = metadata_arc(&summary.metadata, "mesh.source.namespace", "unknown");
    let source_principal = metadata_arc(&summary.metadata, "mesh.source.principal", "unknown");
    let source_app = metadata_arc_or_clone(&summary.metadata, "mesh.source.app", &source_workload);
    let source_service =
        metadata_arc_or_clone(&summary.metadata, "mesh.source.service", &source_workload);
    let destination_default = summary
        .proxy_name
        .as_deref()
        .or(summary.proxy_id.as_deref())
        .unwrap_or("unknown");
    let destination_workload = metadata_arc(
        &summary.metadata,
        "mesh.destination.workload",
        destination_default,
    );
    let destination_namespace =
        metadata_arc(&summary.metadata, "mesh.destination.namespace", "unknown");
    let destination_principal =
        metadata_arc(&summary.metadata, "mesh.destination.principal", "unknown");
    let destination_app = metadata_arc_or_clone(
        &summary.metadata,
        "mesh.destination.app",
        &destination_workload,
    );
    let destination_service = metadata_arc_or_clone(
        &summary.metadata,
        "mesh.destination.service",
        &destination_workload,
    );
    let request_protocol = metadata_arc_any(
        &summary.metadata,
        &["mesh.request_protocol", "request_protocol"],
        "http",
    );
    let response_flags = metadata_arc(
        &summary.metadata,
        "mesh.response_flags",
        inferred_response_flags(summary),
    );
    let connection_security_policy =
        metadata_arc(&summary.metadata, "mesh.connection_security_policy", "none");

    Some(MeshRequestKey {
        source_workload,
        source_namespace,
        source_principal,
        source_app,
        source_service,
        destination_workload,
        destination_namespace,
        destination_principal,
        destination_app,
        destination_service,
        request_protocol,
        response_code: summary.response_status_code,
        response_flags,
        connection_security_policy,
    })
}

fn metadata_arc(metadata: &HashMap<String, String>, key: &str, default: &str) -> Arc<str> {
    intern_label(metadata.get(key).map(String::as_str).unwrap_or(default))
}

fn trust_bundle_fingerprint(roots_der: &[Vec<u8>]) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for root in roots_der {
        hash ^= root.len() as u64;
        hash = hash.wrapping_mul(0x100000001b3);
        for byte in root {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x100000001b3);
        }
    }
    hash
}

fn metadata_arc_any(metadata: &HashMap<String, String>, keys: &[&str], default: &str) -> Arc<str> {
    intern_label(
        keys.iter()
            .find_map(|key| metadata.get(*key).map(String::as_str))
            .unwrap_or(default),
    )
}

fn metadata_arc_or_clone(
    metadata: &HashMap<String, String>,
    key: &str,
    default: &Arc<str>,
) -> Arc<str> {
    metadata
        .get(key)
        .map(|value| intern_label(value.as_str()))
        .unwrap_or_else(|| Arc::clone(default))
}

fn inferred_response_flags(summary: &TransactionSummary) -> &'static str {
    if summary.client_disconnected {
        "DC"
    } else if summary.error_class.is_some() || summary.body_error_class.is_some() {
        "UF"
    } else {
        "-"
    }
}

pub fn render_mesh_histogram(
    output: &mut String,
    key: &MeshRequestKey,
    histogram: &HistogramBuckets,
) {
    for (i, boundary) in histogram.boundaries.iter().enumerate() {
        let le = boundary.to_string();
        let labels = mesh_label_fragment(key, Some(&le));
        let count = histogram.counts[i].load(Ordering::Relaxed);
        output.push_str(&format!(
            "ferrum_mesh_request_duration_ms_bucket{{{}}} {}\n",
            labels, count
        ));
    }
    let total_count = histogram.count.load(Ordering::Relaxed);
    let labels = mesh_label_fragment(key, Some("+Inf"));
    output.push_str(&format!(
        "ferrum_mesh_request_duration_ms_bucket{{{}}} {}\n",
        labels, total_count
    ));
    let labels = mesh_label_fragment(key, None);
    let sum = f64::from_bits(histogram.sum.load(Ordering::Relaxed));
    output.push_str(&format!(
        "ferrum_mesh_request_duration_ms_sum{{{}}} {:.2}\n",
        labels, sum
    ));
    output.push_str(&format!(
        "ferrum_mesh_request_duration_ms_count{{{}}} {}\n",
        labels, total_count
    ));
}

pub fn mesh_label_fragment(key: &MeshRequestKey, le: Option<&str>) -> String {
    let mut labels = format!(
        "source_workload=\"{}\",source_namespace=\"{}\",source_principal=\"{}\",source_app=\"{}\",source_service=\"{}\",destination_workload=\"{}\",destination_namespace=\"{}\",destination_principal=\"{}\",destination_app=\"{}\",destination_service=\"{}\",request_protocol=\"{}\",response_code=\"{}\",response_flags=\"{}\",connection_security_policy=\"{}\"",
        escape_label_value(&key.source_workload),
        escape_label_value(&key.source_namespace),
        escape_label_value(&key.source_principal),
        escape_label_value(&key.source_app),
        escape_label_value(&key.source_service),
        escape_label_value(&key.destination_workload),
        escape_label_value(&key.destination_namespace),
        escape_label_value(&key.destination_principal),
        escape_label_value(&key.destination_app),
        escape_label_value(&key.destination_service),
        escape_label_value(&key.request_protocol),
        key.response_code,
        escape_label_value(&key.response_flags),
        escape_label_value(&key.connection_security_policy)
    );
    if let Some(le) = le {
        labels.push_str(&format!(",le=\"{}\"", le));
    }
    labels
}

/// Current value of the aggregate ADS stream rejection counter. Test-only
/// accessor so the cap can be asserted without scraping the full metrics text.
#[cfg(test)]
pub fn xds_streams_rejected_count() -> u64 {
    XDS_STREAMS_REJECTED.load(Ordering::Relaxed)
}

/// Current value of the warming partial-apply counter for a `namespace`.
/// Test-only accessor.
#[cfg(test)]
pub fn xds_warming_partial_apply_count(namespace: &str) -> u64 {
    XDS_WARMING_PARTIAL_APPLIES
        .get(namespace)
        .map(|entry| entry.load(Ordering::Relaxed))
        .unwrap_or(0)
}

/// Current value of the first-slice NACK counter for a `(namespace, type_url)`
/// pair. Test-only accessor.
#[cfg(test)]
pub fn xds_first_slice_nack_count(namespace: &str, type_url: &str) -> u64 {
    let key = XdsFirstSliceNackKey {
        namespace: Arc::from(namespace),
        type_url: Arc::from(type_url),
    };
    XDS_FIRST_SLICE_NACKS
        .get(&key)
        .map(|entry| entry.load(Ordering::Relaxed))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_mesh_observability_metrics_evicts_stale_expired_series() {
        let now = unix_now_seconds();
        let suffix = format!("{}-{}", std::process::id(), now);
        let stale_id = format!("spiffe://cluster.local/ns/default/sa/stale-{suffix}");
        let active_expired_id = format!("spiffe://cluster.local/ns/default/sa/active-{suffix}");

        record_mesh_cert_expiry_unix_seconds(
            &stale_id,
            "unit-test",
            now.saturating_sub(MESH_CERT_EXPIRY_STALE_RETENTION_SECONDS + 1),
            now.saturating_sub(MESH_CERT_EXPIRY_STALE_RETENTION_SECONDS + 1),
        );
        record_mesh_cert_expiry_unix_seconds(
            &active_expired_id,
            "unit-test",
            now.saturating_sub(1),
            now,
        );
        MESH_CERT_EXPIRY_LAST_EVICTION_UNIX_SECONDS.store(0, Ordering::Relaxed);

        let mut output = String::new();
        render_mesh_observability_metrics(&mut output);

        assert!(
            !output.contains(&stale_id),
            "stale expired certificate series should be evicted: {output}"
        );
        assert!(
            output.contains(&active_expired_id),
            "recently observed expired certificate should still be exported: {output}"
        );
    }

    #[test]
    fn render_emits_xds_stream_rejection_and_first_slice_nack_metrics() {
        let suffix = format!("{}-{}", std::process::id(), line!());
        let namespace = format!("ns-{suffix}");
        let type_url = "type.googleapis.com/envoy.config.cluster.v3.Cluster";

        let before = xds_streams_rejected_count();
        increment_xds_stream_rejected();
        increment_xds_stream_rejected();
        increment_xds_first_slice_nack(&namespace, type_url);
        increment_xds_warming_partial_apply(&namespace);

        assert_eq!(xds_streams_rejected_count() - before, 2);
        assert_eq!(xds_first_slice_nack_count(&namespace, type_url), 1);
        // Unique namespace → this test is the only writer for that series.
        assert_eq!(xds_warming_partial_apply_count(&namespace), 1);

        let total = xds_streams_rejected_count();
        let mut output = String::new();
        render_mesh_observability_metrics(&mut output);

        assert!(
            output.contains("# TYPE ferrum_xds_streams_rejected_total counter"),
            "rejection counter TYPE line missing: {output}"
        );
        assert!(
            output.contains(&format!("ferrum_xds_streams_rejected_total {total}\n")),
            "aggregate rejection counter value line missing: {output}"
        );
        assert!(
            output.contains("# TYPE ferrum_xds_first_slice_nacks_total counter"),
            "first-slice NACK counter TYPE line missing: {output}"
        );
        assert!(
            output.contains(&format!(
                "ferrum_xds_first_slice_nacks_total{{namespace=\"{namespace}\",type_url=\"{type_url}\"}} 1"
            )),
            "first-slice NACK counter series missing: {output}"
        );
        assert!(
            output.contains("# TYPE ferrum_xds_warming_partial_applies_total counter"),
            "warming partial-apply counter TYPE line missing: {output}"
        );
        assert!(
            output.contains(&format!(
                "ferrum_xds_warming_partial_applies_total{{namespace=\"{namespace}\"}} 1"
            )),
            "warming partial-apply counter series missing: {output}"
        );
    }
}
