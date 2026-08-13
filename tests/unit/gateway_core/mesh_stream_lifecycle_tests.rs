//! Mesh configuration-stream hardening: shared attempt/liveness policy
//! (issue #3854), stock xDS transport admission (issue #3853), and the stock
//! bearer credential's finite authorization lifetime (issue #3852).
//!
//! These are the pure-policy halves. The live stream behaviour (clean EOF
//! failover, partial-generation EOF, token rotation retiring a healthy stream)
//! is driven against a scripted third-party ADS server in
//! `tests/integration/mesh_stock_xds_tests.rs`.

use std::time::{Duration, SystemTime};

use base64::Engine as _;

use ferrum_edge::modes::mesh::config_consumer::stock_xds_credential::{
    DEFAULT_STOCK_XDS_TOKEN_MAX_STREAM_LIFETIME_SECS, MAX_STOCK_XDS_TOKEN_MAX_STREAM_LIFETIME_SECS,
    MIN_STOCK_XDS_TOKEN_MAX_STREAM_LIFETIME_SECS, StockBearerCredential,
    StockCredentialDeadlineBasis, StockCredentialInvalidReason, StockCredentialLifetimePolicy,
    StockCredentialState, StockCredentialWatch, StockXdsCredentialSource, credential_lifetime,
    jwt_expiration_hint,
};
use ferrum_edge::modes::mesh::config_consumer::stock_xds_transport::{
    StockXdsTransport, StockXdsTransportPolicy, StockXdsTransportRefusal,
    admit_stock_xds_endpoints, classify_stock_xds_endpoint, is_loopback_host,
};
use ferrum_edge::modes::mesh::config_consumer::stream_lifecycle::{
    MESH_CONFIG_STREAM_HTTP2_KEEPALIVE_INTERVAL_SECS,
    MESH_CONFIG_STREAM_HTTP2_KEEPALIVE_TIMEOUT_SECS, MESH_CONFIG_STREAM_LIVENESS_BOUND_SECS,
    MESH_CONFIG_STREAM_TCP_KEEPALIVE_SECS, MeshConfigStreamCredential, MeshStreamAttempt,
    MeshStreamRetirement, MeshStreamTimings, MeshStreamTracker,
};

// ── issue #3854: attempt classification ─────────────────────────────────

/// The whole point of the shared policy. Before it, all three consumers mapped
/// a remote `Ok(None)` onto "successful attempt": backoff reset to the initial
/// delay and the client stayed on (or snapped back to) the primary. A control
/// plane that accepted the RPC and immediately closed therefore produced a
/// primary-only reconnect loop that never consulted a healthy fallback.
#[test]
fn remote_clean_eof_rotates_the_endpoint_and_grows_backoff() {
    let disposition = MeshStreamAttempt::RemoteEof.disposition();
    assert!(
        disposition.advance_endpoint,
        "a clean close by the peer must advance to the configured fallback"
    );
    assert!(
        disposition.increase_backoff,
        "repeated clean closes must back off instead of resetting into a hot loop"
    );
    assert!(MeshStreamAttempt::RemoteEof.is_endpoint_failure());
    assert_eq!(
        MeshStreamAttempt::RemoteEof.as_metric_label(),
        "remote_clean_eof"
    );
}

#[test]
fn intentional_local_retirement_never_penalizes_the_endpoint() {
    for reason in [
        MeshStreamRetirement::Shutdown,
        MeshStreamRetirement::TlsReload,
        MeshStreamRetirement::CredentialRotation,
        MeshStreamRetirement::PrimaryRetry,
    ] {
        let attempt = MeshStreamAttempt::LocalRetirement(reason);
        let disposition = attempt.disposition();
        assert!(
            !attempt.is_endpoint_failure(),
            "{} is a local decision, not evidence about the peer",
            reason.as_metric_label()
        );
        assert!(!disposition.advance_endpoint, "{:?}", reason);
        assert!(!disposition.increase_backoff, "{:?}", reason);
    }
}

/// Mirrors the hardened DP ConfigSync split: a stream that already delivered
/// usable configuration and then broke is not a connect storm, so the delay
/// resets — but the endpoint still rotates, because the peer that just failed
/// is the one under suspicion.
#[test]
fn transport_failure_backoff_depends_on_whether_the_attempt_made_progress() {
    let fresh = MeshStreamAttempt::TransportFailure {
        delivered_usable_state: false,
    }
    .disposition();
    assert!(fresh.advance_endpoint);
    assert!(fresh.increase_backoff);

    let progressed = MeshStreamAttempt::TransportFailure {
        delivered_usable_state: true,
    }
    .disposition();
    assert!(progressed.advance_endpoint);
    assert!(!progressed.increase_backoff);
}

#[test]
fn liveness_and_policy_outcomes_rotate_and_back_off() {
    for attempt in [
        MeshStreamAttempt::FirstFrameTimeout,
        MeshStreamAttempt::FirstSliceTimeout,
        MeshStreamAttempt::LivenessTimeout,
        MeshStreamAttempt::PolicyRejected,
    ] {
        let disposition = attempt.disposition();
        assert!(disposition.advance_endpoint, "{:?}", attempt);
        assert!(disposition.increase_backoff, "{:?}", attempt);
        assert!(attempt.is_endpoint_failure(), "{:?}", attempt);
    }
}

/// Fixed cardinality is a security property here, not a tidiness one: these
/// labels go straight onto `/metrics` and the authenticated `/health` mesh
/// detail, and must never be able to carry an endpoint URL or a node id.
#[test]
fn attempt_labels_are_a_closed_set() {
    let labels = [
        MeshStreamAttempt::LocalRetirement(MeshStreamRetirement::Shutdown).as_metric_label(),
        MeshStreamAttempt::LocalRetirement(MeshStreamRetirement::TlsReload).as_metric_label(),
        MeshStreamAttempt::LocalRetirement(MeshStreamRetirement::CredentialRotation)
            .as_metric_label(),
        MeshStreamAttempt::LocalRetirement(MeshStreamRetirement::PrimaryRetry).as_metric_label(),
        MeshStreamAttempt::RemoteEof.as_metric_label(),
        MeshStreamAttempt::TransportFailure {
            delivered_usable_state: false,
        }
        .as_metric_label(),
        MeshStreamAttempt::FirstFrameTimeout.as_metric_label(),
        MeshStreamAttempt::FirstSliceTimeout.as_metric_label(),
        MeshStreamAttempt::LivenessTimeout.as_metric_label(),
        MeshStreamAttempt::PolicyRejected.as_metric_label(),
    ];
    let mut sorted = labels.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), labels.len(), "labels must be distinct");
    for label in labels {
        assert!(
            label
                .chars()
                .all(|c| c.is_ascii_lowercase() || c == '_' || c.is_ascii_digit()),
            "'{label}' must be a bare snake_case token"
        );
    }
    // `delivered_usable_state` is a backoff input, not a label dimension.
    assert_eq!(
        MeshStreamAttempt::TransportFailure {
            delivered_usable_state: true
        }
        .as_metric_label(),
        MeshStreamAttempt::TransportFailure {
            delivered_usable_state: false
        }
        .as_metric_label()
    );
}

/// The documented half-open detection bound must actually follow from the
/// keepalive constants rather than being an independently drifting number in
/// the docs.
#[test]
fn documented_liveness_bound_matches_the_keepalive_policy() {
    assert_eq!(
        MESH_CONFIG_STREAM_LIVENESS_BOUND_SECS,
        MESH_CONFIG_STREAM_HTTP2_KEEPALIVE_INTERVAL_SECS
            + MESH_CONFIG_STREAM_HTTP2_KEEPALIVE_TIMEOUT_SECS
    );
    assert_eq!(MESH_CONFIG_STREAM_LIVENESS_BOUND_SECS, 40);
    assert_eq!(MESH_CONFIG_STREAM_TCP_KEEPALIVE_SECS, 30);
}

#[test]
fn production_timings_are_finite_and_ordered() {
    let timings = MeshStreamTimings::production();
    assert!(timings.first_frame > Duration::ZERO);
    assert!(
        timings.first_slice > timings.first_frame,
        "a complete generation legitimately takes longer than a first frame"
    );
    assert!(
        timings.max_silence > Duration::from_secs(60),
        "the silence bound must sit above the 60s heartbeat cadence"
    );
}

// ── issue #3854: readiness projection ───────────────────────────────────

#[test]
fn tracker_reports_never_received_slice_until_one_is_installed() {
    let mut tracker =
        MeshStreamTracker::new("stock_xds", MeshConfigStreamCredential::NotConfigured);
    let status = tracker.status(false, false);
    assert_eq!(status.state, "never_received_slice");
    assert_eq!(status.last_attempt_outcome, "none");
    assert_eq!(status.credential, "not_configured");
    assert_eq!(
        status.liveness_bound_seconds,
        MESH_CONFIG_STREAM_LIVENESS_BOUND_SECS
    );

    // Even after a liveness failure, "never received a slice" is the more
    // accurate readiness answer: there is nothing last-good to serve.
    tracker.record(MeshStreamAttempt::LivenessTimeout);
    assert_eq!(tracker.status(false, false).state, "never_received_slice");
}

#[test]
fn tracker_distinguishes_liveness_failure_from_serving_last_good() {
    let mut tracker = MeshStreamTracker::new("native", MeshConfigStreamCredential::NotConfigured);

    tracker.record(MeshStreamAttempt::LivenessTimeout);
    let status = tracker.status(true, false);
    assert_eq!(status.state, "stream_liveness_failed");
    assert_eq!(status.last_attempt_outcome, "keepalive_timeout");
    assert_eq!(status.consecutive_failures, 1);

    tracker.record(MeshStreamAttempt::RemoteEof);
    let status = tracker.status(true, false);
    assert_eq!(status.state, "serving_last_good");
    assert_eq!(status.last_attempt_outcome, "remote_clean_eof");
    assert_eq!(status.consecutive_failures, 2);

    assert_eq!(tracker.status(true, true).state, "connected");
}

#[test]
fn tracker_clears_the_failure_run_on_intentional_retirement_and_on_usable_state() {
    let mut tracker = MeshStreamTracker::new("xds", MeshConfigStreamCredential::NotConfigured);
    tracker.record(MeshStreamAttempt::RemoteEof);
    tracker.record(MeshStreamAttempt::RemoteEof);
    assert_eq!(tracker.status(true, false).consecutive_failures, 2);

    tracker.record(MeshStreamAttempt::LocalRetirement(
        MeshStreamRetirement::TlsReload,
    ));
    assert_eq!(tracker.status(true, false).consecutive_failures, 0);

    tracker.record(MeshStreamAttempt::RemoteEof);
    tracker.record_usable_state();
    let status = tracker.status(true, true);
    assert_eq!(status.consecutive_failures, 0);
    assert_eq!(status.state, "connected");
}

#[test]
fn tracker_reports_fallback_activation_without_naming_the_endpoint() {
    let mut tracker =
        MeshStreamTracker::new("stock_xds", MeshConfigStreamCredential::NotConfigured);
    tracker.set_endpoint_index(0);
    assert!(!tracker.status(true, true).fallback_active);
    tracker.set_endpoint_index(1);
    assert!(tracker.status(true, true).fallback_active);

    let rendered =
        serde_json::to_string(&tracker.status(true, true)).expect("status serializes for /health");
    for forbidden in ["http://", "https://", "://", "token", "/var/run"] {
        assert!(
            !rendered.contains(forbidden),
            "the health projection must stay label-free: {rendered}"
        );
    }
}

// ── issue #3853: stock xDS transport admission ──────────────────────────

fn policy(token: bool, production: bool, allow_plaintext: bool) -> StockXdsTransportPolicy {
    StockXdsTransportPolicy {
        token_configured: token,
        production_mode: production,
        allow_loopback_plaintext: allow_plaintext,
    }
}

#[test]
fn https_endpoints_are_admitted_as_authenticated_tls() {
    let admitted = admit_stock_xds_endpoints(
        &[
            "https://istiod.istio-system.svc:15012".to_string(),
            "https://istiod-backup.istio-system.svc:15012".to_string(),
        ],
        policy(true, true, false),
    )
    .expect("an all-https set with a bearer is the production posture");
    assert_eq!(
        admitted,
        vec![
            StockXdsTransport::AuthenticatedTls,
            StockXdsTransport::AuthenticatedTls
        ]
    );
    assert!(StockXdsTransport::AuthenticatedTls.allows_authorization_metadata());
    assert!(!StockXdsTransport::LoopbackPlaintextDev.allows_authorization_metadata());
}

/// A bearer credential over h2c is the disclosure this gate exists to stop.
/// Loopback is not an exception: the credential still leaves the process.
#[test]
fn a_bearer_token_refuses_plaintext_even_on_loopback_with_the_dev_switch_on() {
    let refusal =
        classify_stock_xds_endpoint(0, "http://127.0.0.1:15012", policy(true, false, true))
            .expect_err("a bearer must never ride h2c");
    assert_eq!(
        refusal.refusal,
        StockXdsTransportRefusal::PlaintextWithBearerToken
    );
}

#[test]
fn production_mode_refuses_plaintext_without_a_bearer_too() {
    let refusal =
        classify_stock_xds_endpoint(0, "http://127.0.0.1:15012", policy(false, true, true))
            .expect_err("production mode requires TLS with or without a credential");
    assert_eq!(
        refusal.refusal,
        StockXdsTransportRefusal::PlaintextInProduction
    );
}

#[test]
fn plaintext_is_off_by_default_and_loopback_only_when_enabled() {
    let disabled =
        classify_stock_xds_endpoint(0, "http://127.0.0.1:15012", policy(false, false, false))
            .expect_err("plaintext must be opt-in");
    assert_eq!(
        disabled.refusal,
        StockXdsTransportRefusal::PlaintextNotEnabled
    );

    let remote_url = "http://istiod.istio-system.svc:15012";
    let remote = classify_stock_xds_endpoint(0, remote_url, policy(false, false, true))
        .expect_err("the development switch is loopback-only");
    assert_eq!(
        remote.refusal,
        StockXdsTransportRefusal::PlaintextNotLoopback
    );

    for loopback in [
        "http://127.0.0.1:15012",
        "http://127.0.0.5:15012",
        "http://localhost:15012",
        "http://[::1]:15012",
    ] {
        assert_eq!(
            classify_stock_xds_endpoint(0, loopback, policy(false, false, true))
                .expect("loopback development plaintext is admissible"),
            StockXdsTransport::LoopbackPlaintextDev,
            "{loopback}"
        );
    }
}

/// Per-endpoint admission alone cannot guarantee failover does not downgrade,
/// so the WHOLE set is refused when it mixes postures.
#[test]
fn a_mixed_secure_and_plaintext_set_is_refused_as_a_whole() {
    let refusal = admit_stock_xds_endpoints(
        &[
            "https://istiod.istio-system.svc:15012".to_string(),
            "http://127.0.0.1:15012".to_string(),
        ],
        policy(false, false, true),
    )
    .expect_err("a secure primary must not be able to fail over to plaintext");
    assert_eq!(
        refusal.refusal,
        StockXdsTransportRefusal::MixedTransportPosture
    );
    assert_eq!(refusal.index, 1);

    // Order must not matter: a plaintext PRIMARY with a TLS fallback is the
    // same refusal.
    let reversed = admit_stock_xds_endpoints(
        &[
            "http://127.0.0.1:15012".to_string(),
            "https://istiod.istio-system.svc:15012".to_string(),
        ],
        policy(false, false, true),
    )
    .expect_err("a mixed set is refused whichever way round it is written");
    assert_eq!(
        reversed.refusal,
        StockXdsTransportRefusal::MixedTransportPosture
    );
}

#[test]
fn malformed_ambiguous_and_credential_bearing_urls_are_refused() {
    let cases = [
        (
            "istiod.istio-system.svc:15012",
            StockXdsTransportRefusal::MissingScheme,
        ),
        (
            "grpc://istiod:15012",
            StockXdsTransportRefusal::UnsupportedScheme,
        ),
        ("https://", StockXdsTransportRefusal::MissingHost),
        (
            "https://user:secret@istiod:15012",
            StockXdsTransportRefusal::EmbeddedCredentials,
        ),
    ];
    for (url, expected) in cases {
        let refusal =
            classify_stock_xds_endpoint(0, url, policy(false, false, true)).expect_err(url);
        assert_eq!(refusal.refusal, expected, "{url}");
    }
}

/// A configured ADS URL is operator-authored but unbounded, and may carry a
/// query or userinfo. Refusals must therefore identify it by index and closed-set
/// classification only.
#[test]
fn refusal_diagnostics_never_echo_the_configured_url() {
    let url = "http://secret-host.internal.example:15012/?token=super-secret";
    let refusal = classify_stock_xds_endpoint(3, url, policy(true, true, false))
        .expect_err("plaintext with a bearer is refused");
    let rendered = refusal.to_string();
    assert!(rendered.contains("endpoint #3"), "{rendered}");
    assert!(rendered.contains("scheme='http'"), "{rendered}");
    assert!(!rendered.contains("secret-host"), "{rendered}");
    assert!(!rendered.contains("super-secret"), "{rendered}");
    assert!(!rendered.contains(url), "{rendered}");
    assert_eq!(refusal.scheme(), "http");
    assert_eq!(refusal.host_class(), "remote");
}

#[test]
fn loopback_classification_does_not_resolve_hostnames() {
    assert!(is_loopback_host("127.0.0.1"));
    assert!(is_loopback_host("127.9.9.9"));
    assert!(is_loopback_host("::1"));
    assert!(is_loopback_host("[::1]"));
    assert!(is_loopback_host("LOCALHOST"));
    // A name that merely resolves to loopback is not a configuration property.
    assert!(!is_loopback_host("localhost.localdomain"));
    assert!(!is_loopback_host("istiod.istio-system.svc"));
    assert!(!is_loopback_host("0.0.0.0"));
}

// ── issue #3852: credential lifetime ────────────────────────────────────

fn jwt_with_exp(exp_epoch_secs: i64) -> String {
    let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256"}"#);
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(format!(r#"{{"exp":{exp_epoch_secs},"sub":"system:serviceaccount:x:y"}}"#));
    format!("{header}.{payload}.c2ln")
}

fn lifetime_policy(max: u64, skew: u64) -> StockCredentialLifetimePolicy {
    StockCredentialLifetimePolicy {
        max_stream_lifetime: Duration::from_secs(max),
        refresh_skew: Duration::from_secs(skew),
        watch_interval: Duration::from_secs(10),
    }
}

#[test]
fn an_opaque_token_gets_the_operator_visible_maximum_stream_lifetime() {
    let (lifetime, basis) = credential_lifetime(
        "an-opaque-projected-token",
        lifetime_policy(900, 60),
        SystemTime::now(),
    );
    assert_eq!(lifetime, Duration::from_secs(900));
    assert_eq!(basis, StockCredentialDeadlineBasis::MaxStreamLifetime);
    assert_eq!(basis.as_metric_label(), "max_stream_lifetime");
}

#[test]
fn a_jwt_shaped_token_reconnects_before_exp_with_the_configured_skew() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
    let token = jwt_with_exp(1_000_600);
    let (lifetime, basis) = credential_lifetime(&token, lifetime_policy(3600, 60), now);
    assert_eq!(
        lifetime,
        Duration::from_secs(540),
        "600s until exp, minus the 60s skew"
    );
    assert_eq!(basis, StockCredentialDeadlineBasis::JwtExpirationHint);
}

/// The `exp` is only ever a scheduling hint. A long-lived JWT must still be
/// reauthenticated at the operator-visible maximum, which is what stops a
/// peer-issued claim from silently extending Ferrum's own bound.
#[test]
fn the_maximum_stream_lifetime_caps_a_far_future_jwt_exp() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
    let token = jwt_with_exp(1_000_000 + 86_400);
    let (lifetime, basis) = credential_lifetime(&token, lifetime_policy(600, 60), now);
    assert_eq!(lifetime, Duration::from_secs(600));
    assert_eq!(basis, StockCredentialDeadlineBasis::JwtExpirationHint);
}

#[test]
fn an_already_expired_or_skewed_jwt_falls_back_to_a_reconnect_floor() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
    let token = jwt_with_exp(999_000);
    let (lifetime, basis) = credential_lifetime(&token, lifetime_policy(3600, 60), now);
    assert_eq!(
        lifetime,
        Duration::from_secs(60),
        "an expired claim must not compute a past deadline and hot-loop"
    );
    assert_eq!(basis, StockCredentialDeadlineBasis::JwtExpirationHint);
}

#[test]
fn jwt_expiration_hint_is_bounded_and_refuses_non_jws_shapes() {
    assert!(jwt_expiration_hint(&jwt_with_exp(2_000_000_000)).is_some());
    // Not three segments.
    assert!(jwt_expiration_hint("opaque").is_none());
    assert!(jwt_expiration_hint("a.b").is_none());
    assert!(jwt_expiration_hint("a.b.c.d").is_none());
    // Empty payload/signature.
    assert!(jwt_expiration_hint("a..c").is_none());
    assert!(jwt_expiration_hint("a.b.").is_none());
    // Not base64url.
    assert!(jwt_expiration_hint("a.!!!!.c").is_none());
    // Valid base64url that is not JSON.
    let not_json = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"plain text");
    assert!(jwt_expiration_hint(&format!("a.{not_json}.c")).is_none());
    // JSON without `exp`, and with a non-positive `exp`.
    let no_exp = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"sub":"x"}"#);
    assert!(jwt_expiration_hint(&format!("a.{no_exp}.c")).is_none());
    let zero_exp = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"exp":0}"#);
    assert!(jwt_expiration_hint(&format!("a.{zero_exp}.c")).is_none());
    // An oversized payload segment is not parsed at all.
    let oversized = "A".repeat(9 * 1024);
    assert!(jwt_expiration_hint(&format!("a.{oversized}.c")).is_none());
}

#[test]
fn credential_fingerprints_distinguish_rotation_from_an_unchanged_token() {
    let policy = lifetime_policy(3600, 60);
    let first = StockBearerCredential::admit("projected-token-a", policy).expect("valid ascii");
    let same = StockBearerCredential::admit("projected-token-a", policy).expect("valid ascii");
    let rotated = StockBearerCredential::admit("projected-token-b", policy).expect("valid ascii");

    assert_eq!(
        first.fingerprint(),
        same.fingerprint(),
        "an unchanged token must not churn the ADS stream"
    );
    assert_ne!(first.fingerprint(), rotated.fingerprint());
    assert_eq!(
        first.token().to_str().expect("ascii metadata"),
        "Bearer projected-token-a"
    );
}

/// A digest of a secret is still an offline oracle for it, so the fingerprint
/// must not be renderable — not even through `Debug`.
#[test]
fn credential_debug_output_never_carries_token_material() {
    let credential =
        StockBearerCredential::admit("super-secret-projected-token", lifetime_policy(3600, 60))
            .expect("valid ascii");
    let rendered = format!("{credential:?}");
    assert!(!rendered.contains("super-secret-projected-token"), "{rendered}");
    assert!(rendered.contains("<redacted>"), "{rendered}");

    let fingerprint = format!("{:?}", credential.fingerprint());
    assert_eq!(fingerprint, "StockCredentialFingerprint(<redacted>)");
}

#[test]
fn a_non_ascii_token_is_refused_without_echoing_it() {
    let reason = StockBearerCredential::admit("tökén-with-non-ascii", lifetime_policy(3600, 60))
        .expect_err("gRPC metadata is ASCII");
    assert_eq!(reason, StockCredentialInvalidReason::NotAsciiMetadata);
    let rendered = reason.to_string();
    assert_eq!(rendered, "token_source_not_ascii_metadata");
    assert!(!rendered.contains("tökén"));
}

#[test]
fn invalid_reason_labels_are_a_closed_snake_case_set() {
    let reasons = [
        StockCredentialInvalidReason::Missing,
        StockCredentialInvalidReason::NotRegularFile,
        StockCredentialInvalidReason::Unreadable,
        StockCredentialInvalidReason::Empty,
        StockCredentialInvalidReason::Oversized,
        StockCredentialInvalidReason::InvalidEncoding,
        StockCredentialInvalidReason::NotAsciiMetadata,
        StockCredentialInvalidReason::ReadTimeout,
        StockCredentialInvalidReason::ReaderUnavailable,
    ];
    let mut labels: Vec<&str> = reasons.iter().map(|r| r.as_metric_label()).collect();
    labels.sort_unstable();
    labels.dedup();
    assert_eq!(labels.len(), reasons.len());
    for label in labels {
        assert!(
            label
                .chars()
                .all(|c| c.is_ascii_lowercase() || c == '_'),
            "'{label}'"
        );
    }
}

#[test]
fn the_credential_watch_only_advances_its_generation_on_a_real_change() {
    let credential = StockBearerCredential::admit("token-a", lifetime_policy(3600, 60)).unwrap();
    let rotated = StockBearerCredential::admit("token-b", lifetime_policy(3600, 60)).unwrap();

    let watch = StockCredentialWatch::new(StockCredentialState::Unknown);
    assert_eq!(watch.latest().generation, 0);

    assert!(watch.publish(credential.observed_state()));
    assert_eq!(watch.latest().generation, 1);

    // Re-reading the SAME token must not retire a healthy stream.
    assert!(!watch.publish(credential.observed_state()));
    assert_eq!(watch.latest().generation, 1);

    assert!(watch.publish(rotated.observed_state()));
    assert_eq!(watch.latest().generation, 2);

    assert!(watch.publish(StockCredentialState::Invalid {
        reason: StockCredentialInvalidReason::Missing
    }));
    assert_eq!(watch.latest().generation, 3);
    assert!(watch.latest().state.is_invalid());
    assert_eq!(
        watch.latest().state.health(),
        MeshConfigStreamCredential::SourceInvalid
    );
}

#[test]
fn an_unconfigured_credential_source_reports_not_configured() {
    let source = StockXdsCredentialSource::unauthenticated();
    assert!(!source.is_configured());
    assert_eq!(source.initial_state(), StockCredentialState::NotConfigured);
    assert_eq!(
        StockCredentialState::NotConfigured.health(),
        MeshConfigStreamCredential::NotConfigured
    );
}

#[test]
fn a_configured_source_starts_unobserved_rather_than_assumed_valid() {
    let source = StockXdsCredentialSource::new(
        Some("/var/run/secrets/tokens/istio-token".to_string()),
        StockCredentialLifetimePolicy::default(),
    );
    assert!(source.is_configured());
    assert_eq!(source.initial_state(), StockCredentialState::Unknown);
    // An unobserved source must not be advertised as valid on `/health`.
    assert_eq!(
        StockCredentialState::Unknown.health(),
        MeshConfigStreamCredential::NotConfigured
    );
}

#[test]
fn the_default_lifetime_policy_stays_inside_the_documented_bounds() {
    let policy = StockCredentialLifetimePolicy::default();
    assert_eq!(
        policy.max_stream_lifetime.as_secs(),
        DEFAULT_STOCK_XDS_TOKEN_MAX_STREAM_LIFETIME_SECS
    );
    assert!(
        policy.max_stream_lifetime.as_secs() >= MIN_STOCK_XDS_TOKEN_MAX_STREAM_LIFETIME_SECS
            && policy.max_stream_lifetime.as_secs() <= MAX_STOCK_XDS_TOKEN_MAX_STREAM_LIFETIME_SECS
    );
    assert!(policy.refresh_skew < policy.max_stream_lifetime);
    assert!(policy.watch_interval > Duration::ZERO);
}

// ── invalid-source reads through the real hardened boundary ─────────────

#[tokio::test]
async fn every_invalid_credential_source_shape_fails_closed_with_a_bounded_reason() {
    let temp = tempfile::tempdir().expect("temp dir");

    let missing = temp.path().join("absent-token");
    let source = StockXdsCredentialSource::new(
        Some(missing.to_string_lossy().into_owned()),
        StockCredentialLifetimePolicy::default(),
    );
    assert_eq!(
        source.materialize().await.expect_err("absent source"),
        StockCredentialInvalidReason::Missing
    );

    let empty = temp.path().join("empty-token");
    std::fs::write(&empty, b"   \n\t ").expect("write");
    let source = StockXdsCredentialSource::new(
        Some(empty.to_string_lossy().into_owned()),
        StockCredentialLifetimePolicy::default(),
    );
    assert_eq!(
        source.materialize().await.expect_err("empty source"),
        StockCredentialInvalidReason::Empty
    );

    let directory = temp.path().join("token-dir");
    std::fs::create_dir(&directory).expect("mkdir");
    let source = StockXdsCredentialSource::new(
        Some(directory.to_string_lossy().into_owned()),
        StockCredentialLifetimePolicy::default(),
    );
    assert_eq!(
        source.materialize().await.expect_err("non-regular source"),
        StockCredentialInvalidReason::NotRegularFile
    );

    let oversized = temp.path().join("oversized-token");
    std::fs::write(
        &oversized,
        vec![b'x'; ferrum_edge::secrets::credential_file::DEFAULT_CREDENTIAL_FILE_MAX_BYTES + 1],
    )
    .expect("write");
    let source = StockXdsCredentialSource::new(
        Some(oversized.to_string_lossy().into_owned()),
        StockCredentialLifetimePolicy::default(),
    );
    assert_eq!(
        source.materialize().await.expect_err("oversized source"),
        StockCredentialInvalidReason::Oversized
    );

    let non_ascii = temp.path().join("non-ascii-token");
    std::fs::write(&non_ascii, "tökén".as_bytes()).expect("write");
    let source = StockXdsCredentialSource::new(
        Some(non_ascii.to_string_lossy().into_owned()),
        StockCredentialLifetimePolicy::default(),
    );
    assert_eq!(
        source.materialize().await.expect_err("non-ascii source"),
        StockCredentialInvalidReason::NotAsciiMetadata
    );
}

/// A projected Kubernetes secret rotates by swapping a symlink, not by
/// rewriting the file in place. Detection must therefore be content-based.
#[tokio::test]
async fn a_projected_symlink_swap_is_observed_as_a_content_rotation() {
    let temp = tempfile::tempdir().expect("temp dir");
    let first = temp.path().join("..data-1");
    let second = temp.path().join("..data-2");
    std::fs::write(&first, b"projected-token-one\n").expect("write");
    std::fs::write(&second, b"projected-token-two\n").expect("write");
    let link = temp.path().join("token");

    #[cfg(unix)]
    std::os::unix::fs::symlink(&first, &link).expect("symlink");
    #[cfg(not(unix))]
    std::fs::copy(&first, &link).expect("copy");

    let source = StockXdsCredentialSource::new(
        Some(link.to_string_lossy().into_owned()),
        StockCredentialLifetimePolicy::default(),
    );
    let before = source
        .materialize()
        .await
        .expect("readable")
        .expect("configured");

    #[cfg(unix)]
    {
        std::fs::remove_file(&link).expect("unlink");
        std::os::unix::fs::symlink(&second, &link).expect("relink");
    }
    #[cfg(not(unix))]
    std::fs::copy(&second, &link).expect("copy");

    let after = source
        .materialize()
        .await
        .expect("readable")
        .expect("configured");
    assert_ne!(
        before.fingerprint(),
        after.fingerprint(),
        "a symlink swap must be observed as a rotation"
    );

    let watch = StockCredentialWatch::new(StockCredentialState::Unknown);
    assert!(watch.publish(before.observed_state()));
    assert!(watch.publish(after.observed_state()));
    assert_eq!(watch.latest().generation, 2);
}
