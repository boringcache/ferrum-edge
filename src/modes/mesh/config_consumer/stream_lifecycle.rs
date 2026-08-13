//! Shared mesh configuration-stream attempt and liveness policy (issue #3854).
//!
//! The three mesh configuration consumers — native `MeshSubscribe`
//! ([`super::native_client`]), the Ferrum-private ADS profile
//! ([`super::xds_client`]), and the third-party stock ADS profile
//! ([`super::stock_xds_client`]) — previously each classified a stream ending
//! and each built its own tonic endpoint. They drifted into the same two
//! defects:
//!
//! 1. A remote clean EOF (`Ok(None)` from `message()`) was treated as a
//!    *successful* attempt: backoff reset to the initial delay and the client
//!    stayed on (or returned to) the primary endpoint. A primary that accepts
//!    the RPC and immediately closes therefore pinned the client in a
//!    primary-only hot loop and a healthy fallback was never consulted.
//! 2. The endpoints configured only a **connect** timeout. Once established,
//!    a half-open or blackholed transport left `message().await` pending
//!    forever, so failover never happened and stale mesh state kept serving.
//!
//! This module is the one policy both halves now share. It is deliberately free
//! of gRPC/runtime I/O beyond building a tonic [`Endpoint`], so the
//! classification table is unit-testable without standing up a control plane.
//!
//! ## What is *not* shared
//!
//! Partial-state semantics stay per protocol. The native consumer publishes one
//! whole slice per frame; the two ADS consumers accumulate independent typed
//! responses and only publish once their own required-type gate is satisfied.
//! Nothing here decides when a slice may be built — it decides only what a
//! *stream attempt outcome* means for endpoint rotation and backoff.

use std::time::Duration;

use tonic::transport::Endpoint;

/// HTTP/2 PING interval on every mesh configuration stream.
///
/// Matches the hardened DP ConfigSync client
/// (`crate::grpc::configsync_lifecycle::CONFIGSYNC_HTTP2_KEEPALIVE_INTERVAL_SECS`);
/// the two are intentionally the same policy, not coincidentally equal values.
pub const MESH_CONFIG_STREAM_HTTP2_KEEPALIVE_INTERVAL_SECS: u64 = 30;
/// HTTP/2 PING ack deadline. A missed ack fails the stream, which is what turns
/// a blackholed established transport into an ordinary failover.
pub const MESH_CONFIG_STREAM_HTTP2_KEEPALIVE_TIMEOUT_SECS: u64 = 10;
/// TCP keepalive idle probe interval for mesh configuration sockets.
pub const MESH_CONFIG_STREAM_TCP_KEEPALIVE_SECS: u64 = 30;

/// Documented upper bound, in seconds, on detecting a half-open/blackholed
/// **established** mesh configuration stream.
///
/// One PING is emitted at most [`MESH_CONFIG_STREAM_HTTP2_KEEPALIVE_INTERVAL_SECS`]
/// after the last transport activity and its ack is awaited for at most
/// [`MESH_CONFIG_STREAM_HTTP2_KEEPALIVE_TIMEOUT_SECS`]. `keep_alive_while_idle`
/// is on, so this holds for a stream carrying **no application frames** — a
/// healthy but idle standard-xDS subscription does not have to be poked with
/// discovery traffic to stay observable.
pub const MESH_CONFIG_STREAM_LIVENESS_BOUND_SECS: u64 =
    MESH_CONFIG_STREAM_HTTP2_KEEPALIVE_INTERVAL_SECS
        + MESH_CONFIG_STREAM_HTTP2_KEEPALIVE_TIMEOUT_SECS;

/// A control plane that accepts the streaming RPC but never sends a first
/// message is indistinguishable from a blackhole at the application layer.
/// Bounded so a mute primary cannot hold startup.
pub const MESH_CONFIG_STREAM_FIRST_FRAME_TIMEOUT_SECS: u64 = 60;

/// A control plane may answer with frames yet never assemble a **complete**
/// generation (an ADS server that sends CDS and then nothing else). Armed only
/// while the runtime has no first slice at all, so a converged data plane is
/// never torn down for a quiet control plane.
pub const MESH_CONFIG_STREAM_FIRST_SLICE_TIMEOUT_SECS: u64 = 120;

/// Native `MeshSubscribe` application-silence bound.
///
/// Sized above the CP's 60s heartbeat cadence so a healthy idle subscription is
/// never mistaken for a dead one. Armed only once this stream has actually
/// observed a heartbeat, i.e. once the peer has demonstrated it emits them —
/// the same fail-safe shape ConfigSync gets from explicit negotiation.
pub const MESH_SUBSCRIBE_MAX_SILENCE_SECS: u64 = 150;

/// Per-invocation mesh configuration-stream timing policy.
///
/// Production always uses [`MeshStreamTimings::production`]. The value is
/// ordinary stack state — there is no global, environment, or `cfg` override —
/// so a compressed test value has no path into a production data plane. This
/// mirrors `ConfigSyncStreamTimings`, deliberately: hosted CI must be able to
/// prove first-frame and silence failover without sleeping for production
/// minutes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MeshStreamTimings {
    /// Bound from stream open to the first response frame of any subscribed
    /// type.
    pub first_frame: Duration,
    /// Bound from stream open to the first *installed* slice, armed only while
    /// the runtime has never had one.
    pub first_slice: Duration,
    /// Bound on application silence for consumers with an observed heartbeat.
    pub max_silence: Duration,
}

impl MeshStreamTimings {
    /// The shipped production policy.
    pub const fn production() -> Self {
        Self {
            first_frame: Duration::from_secs(MESH_CONFIG_STREAM_FIRST_FRAME_TIMEOUT_SECS),
            first_slice: Duration::from_secs(MESH_CONFIG_STREAM_FIRST_SLICE_TIMEOUT_SECS),
            max_silence: Duration::from_secs(MESH_SUBSCRIBE_MAX_SILENCE_SECS),
        }
    }
}

impl Default for MeshStreamTimings {
    fn default() -> Self {
        Self::production()
    }
}

/// Why *this* data plane chose to end an otherwise usable stream.
///
/// Every variant is a local decision. None of them says anything about the
/// remote endpoint's health, so none of them may rotate the endpoint or charge
/// the failure backoff — doing so would punish a healthy control plane for a
/// TLS rotation or a deliberate failback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeshStreamRetirement {
    /// Process shutdown.
    Shutdown,
    /// gRPC TLS material rotated; reconnect with the new material.
    TlsReload,
    /// The external bearer credential rotated, became invalid, or reached its
    /// authorization deadline (issue #3852).
    CredentialRotation,
    /// Proactive failback to the primary endpoint after a fallback delivered a
    /// first slice.
    PrimaryRetry,
}

impl MeshStreamRetirement {
    /// Fixed-cardinality label. Never carries an endpoint, node id, credential
    /// path, or any other unbounded value.
    pub fn as_metric_label(self) -> &'static str {
        match self {
            Self::Shutdown => "shutdown",
            Self::TlsReload => "tls_reload",
            Self::CredentialRotation => "credential_rotation",
            Self::PrimaryRetry => "primary_retry",
        }
    }
}

/// How one mesh configuration-stream attempt ended.
///
/// The critical distinction is between [`Self::LocalRetirement`] — an
/// intentional local decision — and everything else, which is evidence about
/// the endpoint. A remote clean EOF is **not** success: a configuration stream
/// is meant to stay open, so the peer hanging up before this data plane asked
/// it to is an endpoint failure that must rotate and back off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeshStreamAttempt {
    /// Intentional local retirement. Never penalizes the endpoint.
    LocalRetirement(MeshStreamRetirement),
    /// The peer closed the stream cleanly (gRPC OK / EOF) without this data
    /// plane asking it to.
    RemoteEof,
    /// Transport or gRPC status failure. `delivered_usable_state` records
    /// whether this attempt had already produced usable configuration, which is
    /// the same "healthy progress" split the DP ConfigSync client uses: a
    /// long-lived stream that eventually breaks is not a connect-storm.
    TransportFailure { delivered_usable_state: bool },
    /// The stream was accepted but no response frame arrived inside
    /// [`MeshStreamTimings::first_frame`].
    FirstFrameTimeout,
    /// Frames arrived but no complete generation was ever installed inside
    /// [`MeshStreamTimings::first_slice`], while the runtime had no slice at
    /// all.
    FirstSliceTimeout,
    /// An established stream went silent past [`MeshStreamTimings::max_silence`]
    /// despite a peer that had demonstrably been emitting heartbeats.
    LivenessTimeout,
    /// The peer's content was refused by a fail-closed local gate
    /// (subscription binding, config-revision ordering, NACK circuit breaker,
    /// unsolicited resource type). Staying attached would only let it keep
    /// serving refused state.
    PolicyRejected,
}

impl MeshStreamAttempt {
    /// Fixed-cardinality metric/log label.
    pub fn as_metric_label(self) -> &'static str {
        match self {
            Self::LocalRetirement(reason) => reason.as_metric_label(),
            Self::RemoteEof => "remote_clean_eof",
            Self::TransportFailure { .. } => "transport_failure",
            Self::FirstFrameTimeout => "first_frame_timeout",
            Self::FirstSliceTimeout => "first_slice_timeout",
            Self::LivenessTimeout => "keepalive_timeout",
            Self::PolicyRejected => "policy_rejected",
        }
    }

    /// True when this attempt is evidence *about the endpoint* rather than a
    /// local decision.
    pub fn is_endpoint_failure(self) -> bool {
        !matches!(self, Self::LocalRetirement(_))
    }

    /// What the outer reconnect loop must do next.
    pub fn disposition(self) -> MeshStreamDisposition {
        match self {
            // A local decision proves nothing about the peer.
            Self::LocalRetirement(_) => MeshStreamDisposition {
                advance_endpoint: false,
                increase_backoff: false,
            },
            // Always charge backoff for a clean close. A control plane that
            // accepts and immediately hangs up is the exact shape that produced
            // the primary-only hot loop; resetting to the initial delay here
            // would reintroduce it even though the endpoint now rotates.
            Self::RemoteEof => MeshStreamDisposition {
                advance_endpoint: true,
                increase_backoff: true,
            },
            // A break after real progress is not a connect-storm, so the delay
            // resets — but the endpoint still rotates, because the peer that
            // just failed is the one under suspicion.
            Self::TransportFailure {
                delivered_usable_state,
            } => MeshStreamDisposition {
                advance_endpoint: true,
                increase_backoff: !delivered_usable_state,
            },
            Self::FirstFrameTimeout
            | Self::FirstSliceTimeout
            | Self::LivenessTimeout
            | Self::PolicyRejected => MeshStreamDisposition {
                advance_endpoint: true,
                increase_backoff: true,
            },
        }
    }
}

/// The outer reconnect loop's next move for one attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MeshStreamDisposition {
    /// Rotate to the next configured endpoint in failover order.
    pub advance_endpoint: bool,
    /// Grow the bounded, jittered backoff instead of resetting it.
    pub increase_backoff: bool,
}

/// Apply the shared bounded transport-liveness policy to a mesh configuration
/// stream endpoint.
///
/// `connect_timeout_seconds` of `0` leaves tonic's explicit connect timeout
/// unset (the existing documented meaning of the mesh knob); the keepalive
/// policy is applied unconditionally because it is what bounds an **already
/// established** stream, which no connect timeout can.
pub fn configure_mesh_config_stream_endpoint(
    endpoint: Endpoint,
    connect_timeout_seconds: u64,
) -> Endpoint {
    let endpoint = if connect_timeout_seconds > 0 {
        endpoint.connect_timeout(Duration::from_secs(connect_timeout_seconds))
    } else {
        endpoint
    };
    endpoint
        .http2_keep_alive_interval(Duration::from_secs(
            MESH_CONFIG_STREAM_HTTP2_KEEPALIVE_INTERVAL_SECS,
        ))
        .keep_alive_timeout(Duration::from_secs(
            MESH_CONFIG_STREAM_HTTP2_KEEPALIVE_TIMEOUT_SECS,
        ))
        // Load-bearing: a standard xDS subscription is legitimately idle
        // between control-plane pushes, and without this tonic stops pinging
        // exactly when a blackhole would be invisible.
        .keep_alive_while_idle(true)
        .tcp_keepalive(Some(Duration::from_secs(
            MESH_CONFIG_STREAM_TCP_KEEPALIVE_SECS,
        )))
}

/// Fixed-cardinality readiness/health classification for the mesh
/// configuration stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeshConfigStreamState {
    /// A stream is established and this data plane has usable configuration.
    Connected,
    /// No slice has ever been installed; startup is still blocked.
    NeverReceivedSlice,
    /// The last attempt ended on a transport-liveness bound (keepalive, first
    /// frame, or first complete slice).
    StreamLivenessFailed,
    /// A slice was installed earlier and is still serving while the stream is
    /// down or reconnecting.
    ServingLastGood,
}

impl MeshConfigStreamState {
    pub fn as_label(self) -> &'static str {
        match self {
            Self::Connected => "connected",
            Self::NeverReceivedSlice => "never_received_slice",
            Self::StreamLivenessFailed => "stream_liveness_failed",
            Self::ServingLastGood => "serving_last_good",
        }
    }
}

/// Fixed-cardinality external-credential posture for the configuration stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeshConfigStreamCredential {
    /// No external bearer credential is configured for this protocol.
    NotConfigured,
    /// The configured credential source last read as valid.
    Valid,
    /// The configured credential source is missing, empty, non-regular,
    /// unreadable, oversized, or not valid ASCII metadata. Reconnection is
    /// refused while this holds (issue #3852).
    SourceInvalid,
}

impl MeshConfigStreamCredential {
    pub fn as_label(self) -> &'static str {
        match self {
            Self::NotConfigured => "not_configured",
            Self::Valid => "valid",
            Self::SourceInvalid => "source_invalid",
        }
    }
}

/// Operator-visible mesh configuration-stream status.
///
/// Every field is a closed set or a counter. No endpoint URL, node id, token,
/// claim, or credential path may be added here — this rides the authenticated
/// `/health` mesh detail and the reason labels are also used for metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct MeshConfigStreamStatus {
    /// Which consumer owns the stream: `native`, `xds`, or `stock_xds`.
    pub protocol: &'static str,
    /// Readiness classification ([`MeshConfigStreamState::as_label`]).
    pub state: &'static str,
    /// How the last completed attempt ended
    /// ([`MeshStreamAttempt::as_metric_label`]); `none` before the first one.
    pub last_attempt_outcome: &'static str,
    /// True while the client is attached to a non-primary configured endpoint.
    pub fallback_active: bool,
    /// Consecutive endpoint-failure attempts since the last usable state.
    pub consecutive_failures: u32,
    /// External-credential posture
    /// ([`MeshConfigStreamCredential::as_label`]).
    pub credential: &'static str,
    /// Documented bound (seconds) within which a half-open established stream
    /// is detected without any application frames.
    pub liveness_bound_seconds: u64,
}

impl MeshConfigStreamStatus {
    /// The pre-first-attempt status for `protocol`.
    pub fn initial(protocol: &'static str, credential: MeshConfigStreamCredential) -> Self {
        Self {
            protocol,
            state: MeshConfigStreamState::NeverReceivedSlice.as_label(),
            last_attempt_outcome: "none",
            fallback_active: false,
            consecutive_failures: 0,
            credential: credential.as_label(),
            liveness_bound_seconds: MESH_CONFIG_STREAM_LIVENESS_BOUND_SECS,
        }
    }
}

/// Rolling accounting for one consumer's reconnect loop.
///
/// Keeps the closed-set health projection and the shared backoff/rotation
/// decision in one place so the three consumers cannot drift again.
#[derive(Debug, Clone, Copy)]
pub struct MeshStreamTracker {
    protocol: &'static str,
    credential: MeshConfigStreamCredential,
    last_attempt_outcome: &'static str,
    consecutive_failures: u32,
    fallback_active: bool,
    liveness_failed: bool,
}

impl MeshStreamTracker {
    pub fn new(protocol: &'static str, credential: MeshConfigStreamCredential) -> Self {
        Self {
            protocol,
            credential,
            last_attempt_outcome: "none",
            consecutive_failures: 0,
            fallback_active: false,
            liveness_failed: false,
        }
    }

    /// Update the external-credential posture (issue #3852).
    pub fn set_credential(&mut self, credential: MeshConfigStreamCredential) {
        self.credential = credential;
    }

    /// Record which configured endpoint index the next/current attempt uses.
    pub fn set_endpoint_index(&mut self, index: usize) {
        self.fallback_active = index != 0;
    }

    /// Fold one completed attempt into the rolling view and return what the
    /// outer loop must do.
    pub fn record(&mut self, attempt: MeshStreamAttempt) -> MeshStreamDisposition {
        self.last_attempt_outcome = attempt.as_metric_label();
        self.liveness_failed = matches!(
            attempt,
            MeshStreamAttempt::LivenessTimeout
                | MeshStreamAttempt::FirstFrameTimeout
                | MeshStreamAttempt::FirstSliceTimeout
        );
        if attempt.is_endpoint_failure() {
            self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        } else {
            self.consecutive_failures = 0;
        }
        crate::plugins::mesh::prometheus_helpers::increment_mesh_config_stream_attempt(
            self.protocol,
            attempt.as_metric_label(),
        );
        attempt.disposition()
    }

    /// A stream is live and delivering; clear the failure run.
    pub fn record_usable_state(&mut self) {
        self.consecutive_failures = 0;
        self.liveness_failed = false;
    }

    /// Project the closed-set health view. `has_first_slice` comes from the
    /// mesh runtime, so "serving last good" cannot be claimed without one.
    pub fn status(&self, has_first_slice: bool, connected: bool) -> MeshConfigStreamStatus {
        let state = if connected && has_first_slice {
            MeshConfigStreamState::Connected
        } else if !has_first_slice {
            MeshConfigStreamState::NeverReceivedSlice
        } else if self.liveness_failed {
            MeshConfigStreamState::StreamLivenessFailed
        } else {
            MeshConfigStreamState::ServingLastGood
        };
        MeshConfigStreamStatus {
            protocol: self.protocol,
            state: state.as_label(),
            last_attempt_outcome: self.last_attempt_outcome,
            fallback_active: self.fallback_active,
            consecutive_failures: self.consecutive_failures,
            credential: self.credential.as_label(),
            liveness_bound_seconds: MESH_CONFIG_STREAM_LIVENESS_BOUND_SECS,
        }
    }
}
