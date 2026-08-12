//! Protocol-neutral authorization lifetime for admitted streams (issue #3815).
//!
//! These cover the arbiter itself — earliest-deadline-wins, the finite fallback
//! maximum for credentials with no authoritative expiry, the unauthenticated
//! carve-out, non-extension by activity — plus the bounded termination classes
//! and the fixed-cardinality counter surface.

use std::sync::Arc;
use std::time::Duration;

use ferrum_edge::_test_support::{
    request_received_at_for_test, set_request_credential_deadline_for_test,
};
use ferrum_edge::config::types::Consumer;
use ferrum_edge::plugins::{Plugin, RequestContext};
use ferrum_edge::proxy::auth_lifetime::{
    StreamAuthDeadline, StreamAuthProtocolFamily, StreamAuthTermination, compose_absolute_bound,
    counters, effective_request_auth_deadline, effective_stream_auth_deadline,
    expired_authorization, record_termination, request_is_authenticated,
};

const DEFAULT_MAX: u64 = 3_600;

fn consumer(username: &str) -> Arc<Consumer> {
    Arc::new(Consumer {
        id: username.to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        username: username.to_string(),
        custom_id: None,
        credentials: std::collections::HashMap::new(),
        acl_groups: Vec::new(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    })
}

fn anonymous_ctx() -> RequestContext {
    RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/sse".to_string(),
    )
}

fn authenticated_ctx() -> RequestContext {
    let mut ctx = anonymous_ctx();
    ctx.identified_consumer = Some(consumer("alice"));
    ctx
}

// --- The arbiter -----------------------------------------------------------

#[tokio::test]
async fn unauthenticated_streams_are_not_bounded_by_this_contract() {
    let ctx = anonymous_ctx();
    assert!(!request_is_authenticated(&ctx));
    assert!(effective_request_auth_deadline(&ctx, DEFAULT_MAX).is_none());
}

#[tokio::test]
async fn an_external_identity_alone_is_an_authenticated_principal() {
    let mut ctx = anonymous_ctx();
    ctx.authenticated_identity = Some("spiffe://example/sa/api".to_string());
    assert!(request_is_authenticated(&ctx));
    assert!(effective_request_auth_deadline(&ctx, DEFAULT_MAX).is_some());
}

#[tokio::test]
async fn credential_deadline_wins_when_earlier_than_the_fallback_maximum() {
    let mut ctx = authenticated_ctx();
    let received_at = request_received_at_for_test(&ctx);
    set_request_credential_deadline_for_test(&mut ctx, Some(received_at + Duration::from_secs(30)));

    let plan = effective_request_auth_deadline(&ctx, DEFAULT_MAX).expect("authenticated");
    assert_eq!(plan.termination, StreamAuthTermination::CredentialExpired);
    assert_eq!(plan.at, received_at + Duration::from_secs(30));
}

#[tokio::test]
async fn fallback_maximum_bounds_a_credential_without_authoritative_expiry() {
    // `key_auth` / `basic_auth` / `hmac_auth` / LDAP shape: authenticated, but
    // no provider-supplied expiry. There must still be a finite bound.
    let ctx = authenticated_ctx();
    let received_at = request_received_at_for_test(&ctx);

    let plan = effective_request_auth_deadline(&ctx, 900).expect("authenticated");
    assert_eq!(
        plan.termination,
        StreamAuthTermination::AuthenticatedStreamMaxLifetime
    );
    assert_eq!(plan.at, received_at + Duration::from_secs(900));
}

#[tokio::test]
async fn fallback_maximum_wins_when_the_credential_outlives_it() {
    let mut ctx = authenticated_ctx();
    let received_at = request_received_at_for_test(&ctx);
    set_request_credential_deadline_for_test(
        &mut ctx,
        Some(received_at + Duration::from_secs(7_200)),
    );

    let plan = effective_request_auth_deadline(&ctx, 900).expect("authenticated");
    assert_eq!(
        plan.termination,
        StreamAuthTermination::AuthenticatedStreamMaxLifetime
    );
    assert_eq!(plan.at, received_at + Duration::from_secs(900));
}

#[tokio::test]
async fn an_exactly_equal_credential_deadline_is_attributed_to_the_credential() {
    let mut ctx = authenticated_ctx();
    let received_at = request_received_at_for_test(&ctx);
    set_request_credential_deadline_for_test(
        &mut ctx,
        Some(received_at + Duration::from_secs(900)),
    );

    let plan = effective_request_auth_deadline(&ctx, 900).expect("authenticated");
    assert_eq!(plan.termination, StreamAuthTermination::CredentialExpired);
}

#[tokio::test]
async fn an_already_elapsed_credential_deadline_stays_in_the_past() {
    let mut ctx = authenticated_ctx();
    let received_at = request_received_at_for_test(&ctx);
    let elapsed = received_at
        .checked_sub(Duration::from_secs(1))
        .expect("representable");
    set_request_credential_deadline_for_test(&mut ctx, Some(elapsed));

    let plan = effective_request_auth_deadline(&ctx, DEFAULT_MAX).expect("authenticated");
    assert_eq!(plan.termination, StreamAuthTermination::CredentialExpired);
    assert_eq!(plan.at, elapsed);
}

#[tokio::test(start_paused = true)]
async fn activity_never_extends_the_deadline() {
    let mut ctx = authenticated_ctx();
    let received_at = request_received_at_for_test(&ctx);
    set_request_credential_deadline_for_test(&mut ctx, Some(received_at + Duration::from_secs(30)));

    let first = effective_request_auth_deadline(&ctx, DEFAULT_MAX).expect("authenticated");
    // Simulate a continuously active stream: time advances, the request context
    // is re-consulted, and the answer must be the same absolute instant.
    tokio::time::advance(Duration::from_secs(20)).await;
    let later = effective_request_auth_deadline(&ctx, DEFAULT_MAX).expect("authenticated");

    assert_eq!(first.at, later.at);
    assert_eq!(first.termination, later.termination);
}

#[tokio::test(start_paused = true)]
async fn the_fallback_maximum_is_anchored_at_request_receipt_not_at_evaluation() {
    let ctx = authenticated_ctx();
    let received_at = request_received_at_for_test(&ctx);

    // A slow request must not buy extra authorized lifetime.
    tokio::time::advance(Duration::from_secs(120)).await;
    let plan = effective_request_auth_deadline(&ctx, 900).expect("authenticated");
    assert_eq!(plan.at, received_at + Duration::from_secs(900));
}

// --- Stream (TCP/TLS, UDP/DTLS) sessions -----------------------------------

#[tokio::test]
async fn unauthenticated_stream_sessions_are_not_bounded() {
    let anchor = tokio::time::Instant::now();
    assert!(effective_stream_auth_deadline(false, None, anchor, DEFAULT_MAX).is_none());
    // Even with a deadline present, an unauthenticated session is out of scope.
    assert!(
        effective_stream_auth_deadline(
            false,
            Some(anchor + Duration::from_secs(5)),
            anchor,
            DEFAULT_MAX
        )
        .is_none()
    );
}

#[tokio::test]
async fn stream_sessions_take_the_earlier_of_certificate_expiry_and_the_maximum() {
    let anchor = tokio::time::Instant::now();

    let cert = effective_stream_auth_deadline(
        true,
        Some(anchor + Duration::from_secs(45)),
        anchor,
        DEFAULT_MAX,
    )
    .expect("authenticated");
    assert_eq!(cert.termination, StreamAuthTermination::CredentialExpired);
    assert_eq!(cert.at, anchor + Duration::from_secs(45));

    let capped = effective_stream_auth_deadline(true, None, anchor, 60).expect("authenticated");
    assert_eq!(
        capped.termination,
        StreamAuthTermination::AuthenticatedStreamMaxLifetime
    );
    assert_eq!(capped.at, anchor + Duration::from_secs(60));
}

// --- Bounded, redacted vocabulary ------------------------------------------

#[test]
fn termination_classes_are_a_closed_set_of_compiled_in_literals() {
    assert_eq!(
        StreamAuthTermination::CredentialExpired.as_str(),
        "credential_expired"
    );
    assert_eq!(
        StreamAuthTermination::AuthenticatedStreamMaxLifetime.as_str(),
        "authenticated_stream_max_lifetime"
    );
}

#[test]
fn client_visible_messages_never_carry_credential_or_expiry_detail() {
    let forbidden = [
        "exp",
        "notAfter",
        "not_after",
        "notBefore",
        "sub",
        "jwt",
        "token",
        "issuer",
        "cert",
        "serial",
        "@",
        "spiffe",
    ];
    for termination in [
        StreamAuthTermination::CredentialExpired,
        StreamAuthTermination::AuthenticatedStreamMaxLifetime,
    ] {
        for message in [
            termination.grpc_message(),
            termination.post_commit_message(),
            termination.as_str(),
        ] {
            let lowered = message.to_ascii_lowercase();
            for needle in forbidden {
                assert!(
                    !lowered.contains(&needle.to_ascii_lowercase()),
                    "{message:?} must not leak {needle:?}"
                );
            }
            // No digits: an expiry value or a timestamp could only appear as one.
            assert!(
                !message.chars().any(|c| c.is_ascii_digit()),
                "{message:?} must not carry a numeric value"
            );
        }
    }
}

#[test]
fn protocol_families_are_a_fixed_closed_inventory() {
    let families = [
        StreamAuthProtocolFamily::Http,
        StreamAuthProtocolFamily::Grpc,
        StreamAuthProtocolFamily::GrpcWeb,
        StreamAuthProtocolFamily::WebSocket,
        StreamAuthProtocolFamily::StreamTcp,
        StreamAuthProtocolFamily::StreamUdp,
    ];
    let names: Vec<&str> = families.iter().map(|f| f.as_str()).collect();
    assert_eq!(
        names,
        vec![
            "http",
            "grpc",
            "grpc_web",
            "websocket",
            "stream_tcp",
            "stream_udp"
        ]
    );
}

#[test]
fn counters_expose_every_family_and_only_those_families() {
    let snapshot = counters();
    let expected = [
        "http",
        "grpc",
        "grpc_web",
        "websocket",
        "stream_tcp",
        "stream_udp",
    ];
    assert_eq!(snapshot.credential_expired.len(), expected.len());
    assert_eq!(
        snapshot.authenticated_stream_max_lifetime.len(),
        expected.len()
    );
    for family in expected {
        assert!(snapshot.credential_expired.contains_key(family));
        assert!(
            snapshot
                .authenticated_stream_max_lifetime
                .contains_key(family)
        );
    }
}

#[test]
fn recording_a_termination_increments_only_its_own_class_and_family() {
    // Process-global monotonic counters: compare deltas, never absolutes, so
    // this stays correct alongside other tests in the same binary.
    let before = counters();
    record_termination(
        StreamAuthTermination::CredentialExpired,
        StreamAuthProtocolFamily::StreamUdp,
    );
    let after = counters();

    assert_eq!(
        after.credential_expired["stream_udp"] - before.credential_expired["stream_udp"],
        1
    );
    assert_eq!(
        after.authenticated_stream_max_lifetime["stream_udp"],
        before.authenticated_stream_max_lifetime["stream_udp"]
    );
    // The counter carries no dimension other than the family, so recording one
    // family cannot move another.
    assert_eq!(
        after.credential_expired["http"],
        before.credential_expired["http"]
    );
}

#[test]
fn the_runtime_metrics_snapshot_serializes_without_any_unbounded_label() {
    let snapshot = counters();
    let json = serde_json::to_value(&snapshot).expect("serializable");
    let object = json.as_object().expect("object");
    let mut keys: Vec<&String> = object.keys().collect();
    keys.sort();
    assert_eq!(
        keys,
        vec![
            &"authenticated_stream_max_lifetime".to_string(),
            &"credential_expired".to_string()
        ]
    );
}

// --- kTLS fallback for deadline-bearing stream sessions (issue #3816) -------
//
// A kernel-TLS frontend leg is relayed by `splice(2)`: the kernel owns both
// sockets, so the relay cannot be wrapped by `AuthorizationDeadlineStream`, and
// after `dangerous_into_kernel_connection` there is no safe conversion back to a
// userspace rustls session. The handoff is therefore refused BEFORE the
// handshake for any listener whose plugin chain can admit an authenticated
// principal, and such a connection is relayed normally on the buffered
// userspace path where the deadline IS enforceable.

fn mtls_auth_plugin() -> Arc<dyn ferrum_edge::plugins::Plugin> {
    Arc::new(
        ferrum_edge::plugins::mtls_auth::MtlsAuth::new(&serde_json::json!({
            "cert_field": "subject_cn"
        }))
        .expect("valid mtls_auth config"),
    )
}

fn observability_plugin() -> Arc<dyn ferrum_edge::plugins::Plugin> {
    Arc::new(
        ferrum_edge::plugins::correlation_id::CorrelationId::new(&serde_json::json!({}))
            .expect("valid correlation_id config"),
    )
}

#[test]
fn mtls_auth_declares_that_it_admits_an_authenticated_stream_principal() {
    assert!(
        mtls_auth_plugin().admits_authenticated_stream_principal(),
        "mtls_auth maps a client certificate to a consumer and contributes the leaf notAfter \
         as the session authorization deadline, so it must keep a listener off the kTLS path"
    );
}

#[test]
fn an_ordinary_stream_plugin_does_not_declare_a_stream_principal() {
    assert!(!observability_plugin().admits_authenticated_stream_principal());
}

#[test]
fn a_listener_with_mtls_auth_is_kept_off_the_ktls_handoff() {
    let plugins = vec![observability_plugin(), mtls_auth_plugin()];
    assert!(
        !ferrum_edge::_test_support::ktls_handoff_eligible_for_test(true, false, false, &plugins),
        "an mTLS-authenticated TCP+TLS listener must stay on the buffered userspace path so its \
         admitted session can be bounded by the certificate deadline"
    );
}

#[test]
fn the_ktls_fast_path_survives_for_listeners_that_cannot_admit_a_principal() {
    let plugins = vec![observability_plugin()];
    assert!(ferrum_edge::_test_support::ktls_handoff_eligible_for_test(
        true, false, false, &plugins
    ));
    assert!(ferrum_edge::_test_support::ktls_handoff_eligible_for_test(
        true,
        false,
        false,
        &[] as &[Arc<dyn ferrum_edge::plugins::Plugin>]
    ));
}

#[test]
fn the_pre_existing_ktls_refusals_are_unchanged() {
    let plugins: Vec<Arc<dyn ferrum_edge::plugins::Plugin>> = Vec::new();
    // opt-in off
    assert!(!ferrum_edge::_test_support::ktls_handoff_eligible_for_test(
        false, false, false, &plugins
    ));
    // TLS backend: splice needs both ends raw
    assert!(!ferrum_edge::_test_support::ktls_handoff_eligible_for_test(
        true, true, false, &plugins
    ));
    // decrypted first-bytes inspection already took plaintext out of the session
    assert!(!ferrum_edge::_test_support::ktls_handoff_eligible_for_test(
        true, false, true, &plugins
    ));
}

// --- The deadline-aware userspace frontend leg -----------------------------

/// The relay wrapper terminates BOTH directions of a continuously active
/// session at the absolute deadline, and relayed bytes never push it out.
#[tokio::test(start_paused = true)]
async fn the_userspace_frontend_leg_terminates_both_directions_at_the_deadline() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (client, mut peer) = tokio::io::duplex(64 * 1024);
    let expired = Arc::new(AtomicBool::new(false));
    let deadline_at = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut leg = ferrum_edge::_test_support::authorization_deadline_stream_for_test(
        client,
        deadline_at,
        Arc::clone(&expired),
    );

    // Continuous traffic BEFORE the deadline keeps working in both directions.
    for _ in 0..8 {
        leg.write_all(b"ping").await.expect("write before deadline");
        let mut buf = [0u8; 4];
        peer.read_exact(&mut buf).await.expect("peer read");
        peer.write_all(b"pong").await.expect("peer write");
        let mut back = [0u8; 4];
        leg.read_exact(&mut back)
            .await
            .expect("read before deadline");
        assert_eq!(&back, b"pong");
        tokio::time::sleep(Duration::from_millis(400)).await;
    }
    assert!(
        !expired.load(Ordering::Acquire),
        "relayed bytes must never refresh an absolute authorization deadline, but they also \
         must not trip it early"
    );

    // Cross the deadline. Both halves now fail, deterministically and with a
    // fixed, credential-free `TimedOut` classification.
    tokio::time::sleep(Duration::from_secs(3)).await;

    let read_err = leg
        .read(&mut [0u8; 4])
        .await
        .expect_err("read after deadline");
    assert_eq!(read_err.kind(), std::io::ErrorKind::TimedOut);
    let write_err = leg.write(b"ping").await.expect_err("write after deadline");
    assert_eq!(write_err.kind(), std::io::ErrorKind::TimedOut);
    assert!(expired.load(Ordering::Acquire));

    // Nothing credential-bearing reaches the classifier or the debug log.
    let message = read_err.to_string();
    assert!(!message.contains("alice"));
    assert!(!message.contains("notAfter"));
    assert!(!message.to_ascii_lowercase().contains("cert"));

    // Shutdown is always allowed through: it is the teardown the deadline is
    // trying to reach, so refusing it would leave the socket half-open.
    leg.shutdown().await.expect("shutdown after deadline");
}

/// A session with no authorization deadline is untouched: the wrapper is only
/// installed when the arbiter produced a plan.
#[tokio::test(start_paused = true)]
async fn an_unauthenticated_stream_session_gets_no_deadline_plan() {
    let anchor = tokio::time::Instant::now();
    assert!(effective_stream_auth_deadline(false, None, anchor, DEFAULT_MAX).is_none());
}

// ── Composed absolute bounds for the H3 write / upload seams (issue #3815) ──
//
// Every H3 downstream write and request-upload drain races the EARLIEST of the
// authorization plan and whatever absolute bound the protocol already had. The
// composer and its attribution helper are the one place that decision is made,
// so ~fifteen call sites cannot drift apart.

fn plan_at(at: tokio::time::Instant, termination: StreamAuthTermination) -> StreamAuthDeadline {
    StreamAuthDeadline { at, termination }
}

#[tokio::test(start_paused = true)]
async fn the_composed_bound_is_the_earliest_of_the_two_absolute_plans() {
    let now = tokio::time::Instant::now();
    let earlier = now + Duration::from_secs(5);
    let later = now + Duration::from_secs(50);

    // Authorization earlier than the client's RPC deadline.
    assert_eq!(
        compose_absolute_bound(
            Some(later),
            Some(plan_at(earlier, StreamAuthTermination::CredentialExpired))
        ),
        Some(earlier)
    );
    // Client's RPC deadline earlier than authorization.
    assert_eq!(
        compose_absolute_bound(
            Some(earlier),
            Some(plan_at(later, StreamAuthTermination::CredentialExpired))
        ),
        Some(earlier)
    );
}

#[tokio::test(start_paused = true)]
async fn a_missing_bound_never_widens_the_other() {
    let now = tokio::time::Instant::now();
    let at = now + Duration::from_secs(5);

    // The client `grpc-timeout` is OPTIONAL, which is exactly why the plain
    // HTTP relays were unbounded before: with no protocol deadline the
    // authorization plan must still be the bound.
    assert_eq!(
        compose_absolute_bound(
            None,
            Some(plan_at(at, StreamAuthTermination::AuthenticatedStreamMaxLifetime))
        ),
        Some(at)
    );
    // An unauthenticated request carries no authorization lifetime, so the
    // protocol's own bound is unchanged.
    assert_eq!(compose_absolute_bound(Some(at), None), Some(at));
    assert_eq!(compose_absolute_bound(None, None), None);
}

#[tokio::test(start_paused = true)]
async fn attribution_reports_authorization_only_once_its_own_instant_has_passed() {
    let now = tokio::time::Instant::now();
    let plan = plan_at(
        now + Duration::from_secs(5),
        StreamAuthTermination::CredentialExpired,
    );

    // Before the authorization instant: a fired composed bound belongs to the
    // protocol deadline, so the client-deadline terminal stays selected.
    assert_eq!(expired_authorization(Some(plan)), None);
    assert_eq!(expired_authorization(None), None);

    // At/after it, authorization is attributed — a tie goes to the security
    // decision, matching the biased `select!` ordering in every relay.
    tokio::time::advance(Duration::from_secs(5)).await;
    assert_eq!(
        expired_authorization(Some(plan)),
        Some(StreamAuthTermination::CredentialExpired)
    );
    // Still nothing to attribute for an unauthenticated stream.
    assert_eq!(expired_authorization(None), None);
}
