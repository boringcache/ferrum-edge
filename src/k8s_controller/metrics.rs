use std::sync::atomic::{AtomicU64, Ordering};

use tracing::info;

pub struct ControllerMetrics {
    pub reconciliations: AtomicU64,
    pub full_syncs: AtomicU64,
    pub errors: AtomicU64,
    pub last_reconcile_duration_ms: AtomicU64,
    /// Rotating Gateway API status-plan cursor (#2397).
    ///
    /// Advanced after a successful budgeted planning pass when the update plan
    /// is empty (fairness must still progress), or after a successful
    /// status-patch batch on the serialized reconcile path. Patch errors and
    /// batch timeouts leave the cursor unchanged so the same bounded window is
    /// retried on the next reconcile.
    pub gateway_api_status_plan_cursor: AtomicU64,
    /// Reflector generations restarted because a watch scope produced no event
    /// for the configured idle window (`FERRUM_K8S_WATCH_IDLE_RELIST_SECS`), or
    /// because a replacement generation never finished its initial list.
    ///
    /// A quiet scope relists on every window even when it is perfectly healthy
    /// — bookmarks never reach us, so idleness is not evidence of a fault — so
    /// this counter measures relist *rate*, not error rate. What is diagnostic
    /// is a scope that relists while the cluster is known to be changing.
    pub watch_idle_relists: AtomicU64,
    /// Successful Gateway API route parent-status patches.
    pub route_status_publications: AtomicU64,
    /// Milliseconds from the patched route's Kubernetes `creationTimestamp` to
    /// the successful Ferrum parent-status write. Zero until the first
    /// successful publication that carried a parseable creation timestamp.
    ///
    /// This is the wait the Gateway API conformance suite observes (object
    /// exists → parent status appears). kube-rs does not expose a watch-event
    /// timestamp, so this is not a reflector-observation clock.
    pub last_route_status_publish_latency_ms: AtomicU64,
    /// Kubernetes status read/write operations abandoned because they exceeded
    /// their wall-clock budget (issue #4239).
    ///
    /// A status patch batch is awaited inline on the serialized reconcile loop,
    /// so an unbounded stalled request stops every other object's status from
    /// being published. Each expiry here is one object left for the next
    /// reconcile, not a lost write; a sustained rise means the API server's
    /// status path is degrading before it costs a whole reconcile round.
    pub status_request_timeouts: AtomicU64,
    /// Status patch batches abandoned by the reconciler's defensive outer
    /// timeout. The batch bounds itself, so this should stay at zero; any
    /// increase means a patch path escaped its own budget.
    pub status_batch_timeouts: AtomicU64,
    /// Istio status JSON Merge Patch 409s observed while applying Ferrum-owned
    /// conditions. Unlabeled: object identity and API error strings stay out.
    pub istio_status_conflicts: AtomicU64,
    /// Istio status writes that succeeded after at least one 409 retry.
    pub istio_status_retries: AtomicU64,
    /// Istio status writes that exhausted the bounded conflict retry budget
    /// without falling back to an unversioned patch.
    pub istio_status_retry_exhausted: AtomicU64,
    /// Istio status writes aborted because the live UID no longer matched the
    /// planned object (delete/recreate under the same name).
    pub istio_status_recreated: AtomicU64,
    /// Istio status writes aborted because the status read or write returned
    /// HTTP 404. Kubernetes answers a CRD that declares no `status` subresource
    /// with the same ordinary object-not-found response it uses for a deleted
    /// object, so that case lands here rather than under
    /// [`Self::istio_status_unsupported`].
    pub istio_status_not_found: AtomicU64,
    /// Istio status writes aborted because the API server does not serve the
    /// resource at all: HTTP 405, or a 404 whose body says the requested
    /// resource could not be found.
    pub istio_status_unsupported: AtomicU64,
    /// Istio status writes refused because the planned watch-snapshot UID was
    /// missing, so the write could not bind object identity.
    pub istio_status_missing_uid: AtomicU64,
}

impl Default for ControllerMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl ControllerMetrics {
    pub fn new() -> Self {
        Self {
            reconciliations: AtomicU64::new(0),
            full_syncs: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            last_reconcile_duration_ms: AtomicU64::new(0),
            gateway_api_status_plan_cursor: AtomicU64::new(0),
            watch_idle_relists: AtomicU64::new(0),
            route_status_publications: AtomicU64::new(0),
            last_route_status_publish_latency_ms: AtomicU64::new(0),
            status_request_timeouts: AtomicU64::new(0),
            status_batch_timeouts: AtomicU64::new(0),
            istio_status_conflicts: AtomicU64::new(0),
            istio_status_retries: AtomicU64::new(0),
            istio_status_retry_exhausted: AtomicU64::new(0),
            istio_status_recreated: AtomicU64::new(0),
            istio_status_not_found: AtomicU64::new(0),
            istio_status_unsupported: AtomicU64::new(0),
            istio_status_missing_uid: AtomicU64::new(0),
        }
    }

    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            reconciliations: self.reconciliations.load(Ordering::Relaxed),
            full_syncs: self.full_syncs.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
            last_reconcile_duration_ms: self.last_reconcile_duration_ms.load(Ordering::Relaxed),
            watch_idle_relists: self.watch_idle_relists.load(Ordering::Relaxed),
            route_status_publications: self.route_status_publications.load(Ordering::Relaxed),
            last_route_status_publish_latency_ms: self
                .last_route_status_publish_latency_ms
                .load(Ordering::Relaxed),
            status_request_timeouts: self.status_request_timeouts.load(Ordering::Relaxed),
            status_batch_timeouts: self.status_batch_timeouts.load(Ordering::Relaxed),
            istio_status_conflicts: self.istio_status_conflicts.load(Ordering::Relaxed),
            istio_status_retries: self.istio_status_retries.load(Ordering::Relaxed),
            istio_status_retry_exhausted: self.istio_status_retry_exhausted.load(Ordering::Relaxed),
            istio_status_recreated: self.istio_status_recreated.load(Ordering::Relaxed),
            istio_status_not_found: self.istio_status_not_found.load(Ordering::Relaxed),
            istio_status_unsupported: self.istio_status_unsupported.load(Ordering::Relaxed),
            istio_status_missing_uid: self.istio_status_missing_uid.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct MetricsSnapshot {
    pub reconciliations: u64,
    pub full_syncs: u64,
    pub errors: u64,
    pub last_reconcile_duration_ms: u64,
    pub watch_idle_relists: u64,
    pub route_status_publications: u64,
    pub last_route_status_publish_latency_ms: u64,
    pub status_request_timeouts: u64,
    pub status_batch_timeouts: u64,
    pub istio_status_conflicts: u64,
    pub istio_status_retries: u64,
    pub istio_status_retry_exhausted: u64,
    pub istio_status_recreated: u64,
    pub istio_status_not_found: u64,
    pub istio_status_unsupported: u64,
    pub istio_status_missing_uid: u64,
}

/// Milliseconds from `creation_rfc3339` to `published_unix_ms`.
///
/// `None` when the creation timestamp is missing or not RFC 3339. A publish
/// instant earlier than creation (clock skew) saturates at zero rather than
/// wrapping.
pub fn route_status_publish_latency_ms(
    creation_rfc3339: Option<&str>,
    published_unix_ms: u64,
) -> Option<u64> {
    let created = chrono::DateTime::parse_from_rfc3339(creation_rfc3339?).ok()?;
    let created_ms = u64::try_from(created.timestamp_millis()).ok()?;
    Some(published_unix_ms.saturating_sub(created_ms))
}

pub fn unix_now_ms() -> Option<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
}

/// Record a successful Gateway API route parent-status patch.
///
/// Non-route kinds (Gateway, GatewayClass, policies) are ignored so the
/// latency gauge stays a route-status signal.
pub fn record_route_status_publication(
    metrics: &ControllerMetrics,
    kind: &str,
    namespace: &str,
    name: &str,
    creation_rfc3339: Option<&str>,
    published_unix_ms: u64,
) {
    if !matches!(
        kind,
        "HTTPRoute" | "GRPCRoute" | "TCPRoute" | "TLSRoute" | "UDPRoute"
    ) {
        return;
    }
    metrics
        .route_status_publications
        .fetch_add(1, Ordering::Relaxed);
    let Some(latency_ms) = route_status_publish_latency_ms(creation_rfc3339, published_unix_ms)
    else {
        return;
    };
    metrics
        .last_route_status_publish_latency_ms
        .store(latency_ms, Ordering::Relaxed);
    info!(
        kind,
        namespace, name, latency_ms, "Gateway API route parent status published"
    );
}
