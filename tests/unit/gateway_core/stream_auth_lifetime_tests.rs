//! Protocol-neutral authorization lifetime for admitted streams (issue #3815).
//!
//! These cover the arbiter itself — earliest-deadline-wins, the finite fallback
//! maximum for credentials with no authoritative expiry, the unauthenticated
//! carve-out, non-extension by activity — plus the bounded termination classes
//! and the fixed-cardinality counter surface.

use std::sync::Arc;
use std::time::Duration;

use ferrum_edge::_test_support::{
    BufferedUploadWaitOutcomeForTest, authorization_bounded_header_deadline_for_test,
    authorization_expired_dispatch_placeholder_for_test,
    authorization_expired_pre_commitment_response_for_test,
    collect_buffered_upload_under_authorization_for_test, direct_h2_upload_join_bound_for_test,
    dispatch_phase_authorization_expiry_for_test, request_received_at_for_test,
    request_upload_auth_deadline_for_test, set_request_credential_deadline_for_test,
    within_stream_auth_deadline_for_test,
};
use ferrum_edge::config::types::Consumer;
use ferrum_edge::plugins::RequestContext;
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
    // Match the `exp` claim as a field/token rather than as a raw substring:
    // the fixed, non-sensitive word "expired" is intentionally client-visible.
    let forbidden = [
        "\"exp\"",
        "exp=",
        "exp:",
        "exp ",
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
            Some(plan_at(
                at,
                StreamAuthTermination::AuthenticatedStreamMaxLifetime
            ))
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

// --- The H1/H2 request-upload seam (#3815) ---------------------------------

#[tokio::test]
async fn an_unauthenticated_upload_installs_no_authorization_bound() {
    // No principal was admitted, so there is no authorization lifetime to
    // enforce and no timer is registered on the upload at all.
    assert!(request_upload_auth_deadline_for_test(&anonymous_ctx(), DEFAULT_MAX).is_none());
}

#[tokio::test]
async fn an_authenticated_upload_is_bounded_by_the_same_plan_as_its_response() {
    let mut ctx = authenticated_ctx();
    let credential_at = tokio::time::Instant::now() + Duration::from_secs(30);
    set_request_credential_deadline_for_test(&mut ctx, Some(credential_at));

    let (upload_plan, family, _latch) =
        request_upload_auth_deadline_for_test(&ctx, DEFAULT_MAX).expect("authenticated upload");
    let response_plan =
        effective_request_auth_deadline(&ctx, DEFAULT_MAX).expect("authenticated response");

    // ONE plan for both directions: the upload cannot outlive the response
    // bound, and neither can outlive the credential.
    assert_eq!(upload_plan.at, credential_at);
    assert_eq!(upload_plan, response_plan);
    assert_eq!(
        upload_plan.termination,
        StreamAuthTermination::CredentialExpired
    );
    // A plain request is bounded, and reported, as HTTP.
    assert_eq!(family, StreamAuthProtocolFamily::Http);
}

#[tokio::test]
async fn an_upload_family_follows_the_request_flavor() {
    let mut ctx = authenticated_ctx();
    ctx.headers
        .insert("content-type".to_string(), "application/grpc".to_string());
    let (_, family, _) = request_upload_auth_deadline_for_test(&ctx, DEFAULT_MAX).unwrap();
    assert_eq!(family, StreamAuthProtocolFamily::Grpc);

    let mut ctx = authenticated_ctx();
    ctx.headers.insert(
        "content-type".to_string(),
        "application/grpc-web+proto".to_string(),
    );
    let (_, family, _) = request_upload_auth_deadline_for_test(&ctx, DEFAULT_MAX).unwrap();
    assert_eq!(family, StreamAuthProtocolFamily::GrpcWeb);

    let mut ctx = authenticated_ctx();
    ctx.headers
        .insert("content-type".to_string(), "text/event-stream".to_string());
    let (_, family, _) = request_upload_auth_deadline_for_test(&ctx, DEFAULT_MAX).unwrap();
    assert_eq!(family, StreamAuthProtocolFamily::Http);
}

#[tokio::test]
async fn an_upload_shares_one_latch_with_the_response_direction() {
    let ctx = authenticated_ctx();
    let (_, _, upload_latch) = request_upload_auth_deadline_for_test(&ctx, DEFAULT_MAX).unwrap();
    let (_, _, second_handle) = request_upload_auth_deadline_for_test(&ctx, DEFAULT_MAX).unwrap();

    // `WebSocket` keeps this test's increments clear of the `http` /
    // `stream_udp` delta assertions elsewhere in this binary.
    assert!(upload_latch.record_once(
        StreamAuthTermination::CredentialExpired,
        StreamAuthProtocolFamily::WebSocket
    ));
    assert!(
        !second_handle.record_once(
            StreamAuthTermination::CredentialExpired,
            StreamAuthProtocolFamily::WebSocket
        ),
        "both directions of one request share a single termination"
    );
    assert_eq!(
        second_handle.observed(),
        Some(StreamAuthTermination::CredentialExpired)
    );
}

// --- The fixed pre-commitment terminal (#3815) -----------------------------

#[tokio::test]
async fn a_pre_commitment_expiry_is_a_fixed_redacted_401_for_plain_http() {
    let ctx = authenticated_ctx();
    let (status, headers, body) = authorization_expired_pre_commitment_response_for_test(
        &ctx,
        StreamAuthTermination::CredentialExpired,
        false,
    );
    assert_eq!(status, 401);
    assert_eq!(
        headers.get("content-type").map(String::as_str),
        Some("application/json")
    );
    assert_eq!(body, br#"{"error":"Unauthorized"}"#.to_vec());
    // Redaction: no expiry instant, claim, subject, or provider detail.
    let rendered = String::from_utf8(body).unwrap();
    assert!(!rendered.chars().any(|c| c.is_ascii_digit()));
    assert!(!headers.contains_key("grpc-status"));
}

#[tokio::test]
async fn a_pre_commitment_expiry_is_unauthenticated_trailers_for_native_grpc() {
    let ctx = authenticated_ctx();
    let (status, headers, body) = authorization_expired_pre_commitment_response_for_test(
        &ctx,
        StreamAuthTermination::CredentialExpired,
        true,
    );
    // gRPC errors ride HTTP 200 with the status in trailing metadata.
    assert_eq!(status, 200);
    assert_eq!(headers.get("grpc-status").map(String::as_str), Some("16"));
    assert_eq!(
        headers.get("grpc-message").map(String::as_str),
        Some("credential expired")
    );
    assert!(body.is_empty(), "no gRPC message may be fabricated");
}

#[tokio::test]
async fn the_pre_commitment_terminal_class_is_a_closed_bounded_vocabulary() {
    let ctx = authenticated_ctx();
    let (_, headers, _) = authorization_expired_pre_commitment_response_for_test(
        &ctx,
        StreamAuthTermination::AuthenticatedStreamMaxLifetime,
        true,
    );
    assert_eq!(
        headers.get("grpc-message").map(String::as_str),
        Some("authenticated stream lifetime reached")
    );
}

// --- Post-admission TCP setup enforcement (#3816) --------------------------

#[tokio::test(start_paused = true)]
async fn an_unauthenticated_stream_setup_stage_runs_unbounded() {
    let ran = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = Arc::clone(&ran);
    let result = within_stream_auth_deadline_for_test(None, async move {
        tokio::time::sleep(Duration::from_secs(600)).await;
        flag.store(true, std::sync::atomic::Ordering::SeqCst);
        7u8
    })
    .await;
    assert_eq!(result, Ok(7));
    assert!(ran.load(std::sync::atomic::Ordering::SeqCst));
}

#[tokio::test(start_paused = true)]
async fn a_setup_stage_inside_the_authorization_lifetime_completes() {
    let plan = plan_at(
        tokio::time::Instant::now() + Duration::from_secs(60),
        StreamAuthTermination::CredentialExpired,
    );
    let result = within_stream_auth_deadline_for_test(Some(plan), async {
        tokio::time::sleep(Duration::from_secs(5)).await;
        "connected"
    })
    .await;
    assert_eq!(result, Ok("connected"));
}

#[tokio::test(start_paused = true)]
async fn a_setup_stage_is_cancelled_at_the_authorization_deadline() {
    // The stage models a backend dial (or an outbound PROXY/prefix write) that
    // would otherwise complete AFTER the credential expired. Cancelling it is
    // what guarantees no backend byte is written on an expired credential.
    let completed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = Arc::clone(&completed);
    let plan = plan_at(
        tokio::time::Instant::now() + Duration::from_secs(10),
        StreamAuthTermination::AuthenticatedStreamMaxLifetime,
    );
    let result = within_stream_auth_deadline_for_test(Some(plan), async move {
        tokio::time::sleep(Duration::from_secs(30)).await;
        flag.store(true, std::sync::atomic::Ordering::SeqCst);
    })
    .await;
    assert_eq!(
        result,
        Err(StreamAuthTermination::AuthenticatedStreamMaxLifetime)
    );
    assert!(
        !completed.load(std::sync::atomic::Ordering::SeqCst),
        "the setup stage must be dropped at the deadline, not allowed to finish"
    );
}

#[tokio::test(start_paused = true)]
async fn an_already_elapsed_lifetime_refuses_a_setup_stage_outright() {
    let started = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = Arc::clone(&started);
    let plan = plan_at(
        tokio::time::Instant::now(),
        StreamAuthTermination::CredentialExpired,
    );
    tokio::time::advance(Duration::from_secs(1)).await;
    let result = within_stream_auth_deadline_for_test(Some(plan), async move {
        flag.store(true, std::sync::atomic::Ordering::SeqCst);
        tokio::time::sleep(Duration::from_secs(1)).await;
    })
    .await;
    assert_eq!(result, Err(StreamAuthTermination::CredentialExpired));
    assert!(
        !started.load(std::sync::atomic::Ordering::SeqCst),
        "a stage entered after the deadline must never run"
    );
}

#[tokio::test]
async fn the_setup_expiry_kind_is_client_side_and_health_neutral() {
    use ferrum_edge::proxy::stream_error::{StreamSetupError, StreamSetupKind};

    let kind = StreamSetupKind::AuthorizationExpired;
    // Client-side: the gateway applied a policy to the client's own credential,
    // so the disconnect cause and direction are client-attributed and no
    // backend health signal is derived from it.
    assert!(kind.is_client_side());
    assert_eq!(kind.tls_side(), None);
    assert_eq!(
        kind.direction(),
        ferrum_edge::plugins::Direction::ClientToBackend
    );
    let rendered = StreamSetupError::new(kind, "before any backend byte was written".to_string())
        .to_string();
    // Redacted: the contract, never the credential, its subject, or its expiry.
    assert!(rendered.contains("authorization lifetime"), "{rendered}");
    assert!(!rendered.chars().any(|c| c.is_ascii_digit()), "{rendered}");
}

// --- Buffered H1/H2 uploads (#3815) ----------------------------------------
//
// A request body that a request-body plugin, a gRPC-Web translation, or retry
// replay forces into memory never reaches the streaming upload adapters, so the
// collect itself must carry the absolute plan. A continuously active upload
// makes progress on every poll, so neither the (often absent) client RPC
// deadline nor the progress-refreshed operator stall timeout bounds it.

fn upload_plan(
    after: Duration,
    termination: StreamAuthTermination,
) -> (
    StreamAuthDeadline,
    StreamAuthProtocolFamily,
    ferrum_edge::proxy::auth_lifetime::StreamAuthTerminationLatch,
) {
    (
        plan_at(tokio::time::Instant::now() + after, termination),
        StreamAuthProtocolFamily::WebSocket,
        ferrum_edge::proxy::auth_lifetime::StreamAuthTerminationLatch::default(),
    )
}

#[tokio::test(start_paused = true)]
async fn a_continuously_active_buffered_upload_stops_at_the_authorization_deadline() {
    // No client RPC deadline and `backend_read_timeout_ms = 0`: without the
    // authorization arm this collect is completely unbounded.
    let plan = upload_plan(
        Duration::from_secs(30),
        StreamAuthTermination::CredentialExpired,
    );
    let latch = plan.2.clone();
    let outcome = collect_buffered_upload_under_authorization_for_test(
        async {
            // A client that keeps sending: the collect makes progress on every
            // poll, so it never stalls and never resolves either.
            for _ in 0..600 {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            Ok(())
        },
        None,
        0,
        Some(plan),
    )
    .await;
    assert_eq!(
        outcome,
        BufferedUploadWaitOutcomeForTest::AuthorizationExpired(
            StreamAuthTermination::CredentialExpired
        )
    );
    assert_eq!(
        latch.observed(),
        Some(StreamAuthTermination::CredentialExpired),
        "the collect must latch the bounded class for the request"
    );
}

#[tokio::test(start_paused = true)]
async fn a_buffered_upload_reports_the_fallback_maximum_class_when_that_bound_wins() {
    let plan = upload_plan(
        Duration::from_secs(5),
        StreamAuthTermination::AuthenticatedStreamMaxLifetime,
    );
    let outcome = collect_buffered_upload_under_authorization_for_test(
        std::future::pending::<Result<(), ()>>(),
        None,
        0,
        Some(plan),
    )
    .await;
    assert_eq!(
        outcome,
        BufferedUploadWaitOutcomeForTest::AuthorizationExpired(
            StreamAuthTermination::AuthenticatedStreamMaxLifetime
        )
    );
}

#[tokio::test(start_paused = true)]
async fn an_already_elapsed_plan_fails_a_buffered_collect_closed_without_polling_it() {
    let polled = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = Arc::clone(&polled);
    let plan = upload_plan(
        Duration::from_secs(0),
        StreamAuthTermination::CredentialExpired,
    );
    tokio::time::advance(Duration::from_secs(1)).await;
    let outcome = collect_buffered_upload_under_authorization_for_test(
        async move {
            flag.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        },
        None,
        0,
        Some(plan),
    )
    .await;
    assert_eq!(
        outcome,
        BufferedUploadWaitOutcomeForTest::AuthorizationExpired(
            StreamAuthTermination::CredentialExpired
        )
    );
    assert!(
        !polled.load(std::sync::atomic::Ordering::SeqCst),
        "the authorization arm is biased first, so an elapsed plan never reads client bytes"
    );
}

#[tokio::test(start_paused = true)]
async fn an_earlier_client_rpc_deadline_still_wins_a_buffered_collect() {
    let plan = upload_plan(
        Duration::from_secs(30),
        StreamAuthTermination::CredentialExpired,
    );
    let latch = plan.2.clone();
    let rpc_deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    let outcome = collect_buffered_upload_under_authorization_for_test(
        std::future::pending::<Result<(), ()>>(),
        Some(rpc_deadline),
        0,
        Some(plan),
    )
    .await;
    assert_eq!(outcome, BufferedUploadWaitOutcomeForTest::DeadlineExceeded);
    assert_eq!(
        latch.observed(),
        None,
        "a client-chosen RPC expiry is not an authorization termination"
    );
}

#[tokio::test(start_paused = true)]
async fn an_earlier_operator_stall_timeout_still_wins_a_buffered_collect() {
    let plan = upload_plan(
        Duration::from_secs(30),
        StreamAuthTermination::CredentialExpired,
    );
    let outcome = collect_buffered_upload_under_authorization_for_test(
        std::future::pending::<Result<(), ()>>(),
        None,
        1_000,
        Some(plan),
    )
    .await;
    assert_eq!(outcome, BufferedUploadWaitOutcomeForTest::TimedOut);
}

#[tokio::test(start_paused = true)]
async fn an_unauthenticated_buffered_collect_is_completely_unaffected() {
    let outcome = collect_buffered_upload_under_authorization_for_test(
        async { Ok(()) },
        None,
        0,
        None,
    )
    .await;
    assert_eq!(outcome, BufferedUploadWaitOutcomeForTest::Collected);
}

#[tokio::test(start_paused = true)]
async fn a_buffered_collect_that_completes_before_expiry_is_forwarded() {
    let plan = upload_plan(
        Duration::from_secs(30),
        StreamAuthTermination::CredentialExpired,
    );
    let latch = plan.2.clone();
    let outcome = collect_buffered_upload_under_authorization_for_test(
        async {
            tokio::time::sleep(Duration::from_secs(1)).await;
            Ok(())
        },
        None,
        0,
        Some(plan),
    )
    .await;
    assert_eq!(outcome, BufferedUploadWaitOutcomeForTest::Collected);
    assert_eq!(latch.observed(), None);
}

#[tokio::test(start_paused = true)]
async fn a_client_disconnect_during_a_buffered_collect_keeps_its_own_outcome() {
    let plan = upload_plan(
        Duration::from_secs(30),
        StreamAuthTermination::CredentialExpired,
    );
    let outcome = collect_buffered_upload_under_authorization_for_test(
        async { Err(()) },
        None,
        0,
        Some(plan),
    )
    .await;
    assert_eq!(outcome, BufferedUploadWaitOutcomeForTest::ClientError);
}

#[tokio::test(start_paused = true)]
async fn a_buffered_collect_and_a_second_direction_record_one_termination() {
    let plan = upload_plan(
        Duration::from_secs(2),
        StreamAuthTermination::CredentialExpired,
    );
    let latch = plan.2.clone();
    let outcome = collect_buffered_upload_under_authorization_for_test(
        std::future::pending::<Result<(), ()>>(),
        None,
        0,
        Some(plan),
    )
    .await;
    assert!(matches!(
        outcome,
        BufferedUploadWaitOutcomeForTest::AuthorizationExpired(_)
    ));
    assert!(
        !latch.record_once(
            StreamAuthTermination::CredentialExpired,
            StreamAuthProtocolFamily::WebSocket
        ),
        "the opposite direction must not count a second termination"
    );
}

// --- Dispatch-phase attribution (#3815) ------------------------------------

#[tokio::test(start_paused = true)]
async fn a_dispatch_phase_attributes_an_elapsed_authorization_bound_once() {
    let plan = upload_plan(
        Duration::from_secs(1),
        StreamAuthTermination::CredentialExpired,
    );
    assert_eq!(
        dispatch_phase_authorization_expiry_for_test(Some(&plan)),
        None,
        "a bound that has not elapsed is the protocol's own, not authorization's"
    );
    tokio::time::advance(Duration::from_secs(2)).await;
    assert_eq!(
        dispatch_phase_authorization_expiry_for_test(Some(&plan)),
        Some(StreamAuthTermination::CredentialExpired)
    );
    assert_eq!(
        plan.2.observed(),
        Some(StreamAuthTermination::CredentialExpired)
    );
    // Idempotent: a second phase observing the same elapsed plan cannot count
    // a second termination.
    assert_eq!(
        dispatch_phase_authorization_expiry_for_test(Some(&plan)),
        Some(StreamAuthTermination::CredentialExpired)
    );
    assert!(!plan.2.record_once(
        StreamAuthTermination::CredentialExpired,
        StreamAuthProtocolFamily::WebSocket
    ));
}

#[tokio::test]
async fn an_unauthenticated_dispatch_phase_never_attributes_authorization() {
    assert_eq!(dispatch_phase_authorization_expiry_for_test(None), None);
}

#[tokio::test]
async fn the_dispatch_placeholder_is_health_neutral_and_redacted() {
    let (status, body, connection_error, error_class) =
        authorization_expired_dispatch_placeholder_for_test();
    assert_eq!(status, 401);
    assert_eq!(body, br#"{"error":"Unauthorized"}"#.to_vec());
    assert!(
        !connection_error,
        "the gateway cancelled the dispatch; no connect failure occurred"
    );
    // `client_disconnect` is never retried and is backend-health neutral, so the
    // gateway's own security decision cannot be charged to the upstream.
    assert_eq!(error_class, Some("client_disconnect"));
    let rendered = String::from_utf8(body).unwrap();
    assert!(!rendered.chars().any(|c| c.is_ascii_digit()), "{rendered}");
}

// --- The response-header wait (#3815) --------------------------------------

#[tokio::test(start_paused = true)]
async fn the_authorization_lifetime_bounds_an_otherwise_unbounded_header_wait() {
    // No client `grpc-timeout` and `backend_read_timeout_ms = 0`: the wait had
    // no bound at all, and a bodyless request gives the upload adapter nothing
    // to fire on.
    assert_eq!(
        authorization_bounded_header_deadline_for_test(None, 0, None),
        None
    );
    assert_eq!(
        authorization_bounded_header_deadline_for_test(None, 0, Some(5_000)),
        Some((5_000, "authorization"))
    );
}

#[tokio::test(start_paused = true)]
async fn an_earlier_protocol_header_bound_still_wins() {
    assert_eq!(
        authorization_bounded_header_deadline_for_test(None, 1_000, Some(5_000)),
        Some((1_000, "operator"))
    );
    assert_eq!(
        authorization_bounded_header_deadline_for_test(Some(800), 0, Some(5_000)),
        Some((800, "client"))
    );
}

#[tokio::test(start_paused = true)]
async fn a_later_protocol_header_bound_loses_to_the_authorization_lifetime() {
    assert_eq!(
        authorization_bounded_header_deadline_for_test(Some(60_000), 30_000, Some(5_000)),
        Some((5_000, "authorization"))
    );
    // A tie is attributed to the security decision.
    assert_eq!(
        authorization_bounded_header_deadline_for_test(None, 5_000, Some(5_000)),
        Some((5_000, "authorization"))
    );
}

// --- The direct-H2 early-response upload join (#3815) ----------------------

#[tokio::test(start_paused = true)]
async fn the_authorization_lifetime_bounds_an_otherwise_unbounded_upload_join() {
    // `backend_read_timeout_ms = 0` with no RPC deadline is the documented
    // "0 = no timeout" contract: an early backend response would otherwise wait
    // on the detached upload indefinitely.
    assert_eq!(direct_h2_upload_join_bound_for_test(None, 0, None), None);
    assert_eq!(
        direct_h2_upload_join_bound_for_test(None, 0, Some(4_000)),
        Some((4_000, "authorization"))
    );
}

#[tokio::test(start_paused = true)]
async fn an_earlier_protocol_upload_join_bound_still_wins() {
    assert_eq!(
        direct_h2_upload_join_bound_for_test(None, 1_000, Some(9_000)),
        Some((1_000, "operator_timeout"))
    );
    assert_eq!(
        direct_h2_upload_join_bound_for_test(Some(700), 0, Some(9_000)),
        Some((700, "rpc_deadline"))
    );
}

#[tokio::test(start_paused = true)]
async fn a_later_protocol_upload_join_bound_loses_to_the_authorization_lifetime() {
    assert_eq!(
        direct_h2_upload_join_bound_for_test(Some(60_000), 30_000, Some(2_500)),
        Some((2_500, "authorization"))
    );
    assert_eq!(
        direct_h2_upload_join_bound_for_test(None, 2_500, Some(2_500)),
        Some((2_500, "authorization")),
        "a tie is attributed to the security decision"
    );
}

// --- Source contracts for the dispatch seams (#3815) -----------------------
//
// These seams live inside `handle_proxy_request_inner` / `proxy_to_backend*`,
// which need a live listener, a pooled backend, and a real hyper transport to
// drive. The behavior each one composes is unit-tested above; these assertions
// keep the WIRING from silently regressing — a buffered arm reverting to the
// unbounded collect, or the direct-H2 upload join losing its gate.

const PROXY_SOURCE: &str = include_str!("../../../src/proxy/mod.rs");
const GRPC_PROXY_SOURCE: &str = include_str!("../../../src/proxy/grpc_proxy.rs");

#[test]
fn every_post_admission_buffered_upload_collect_carries_the_authorization_plan() {
    // reqwest buffered (limited + unlimited) and the H3-backend bridge's
    // buffered arms (limited + unlimited).
    assert_eq!(
        PROXY_SOURCE
            .matches("collect_request_body_under_authorization(")
            .count(),
        4,
        "a post-admission buffered upload arm reverted to the unbounded collect"
    );
    // Both buffered native-gRPC collects.
    assert_eq!(
        GRPC_PROXY_SOURCE
            .matches("collect_request_body_under_authorization(")
            .count(),
        2,
        "a buffered gRPC upload arm reverted to the unbounded collect"
    );
    // Every authorization arm returns the health-neutral placeholder, so the
    // single pre-commitment terminal decides the client-visible shape.
    assert_eq!(
        PROXY_SOURCE
            .matches("Err(AuthorizedUploadWaitError::AuthorizationExpired(_)) => {")
            .count(),
        4
    );
}

#[test]
fn the_pre_authentication_prebuffer_stays_on_the_unbounded_collect() {
    // `buffer_request_body_for_before_proxy` runs BEFORE any principal is
    // admitted, so there is no authorization lifetime to enforce there and no
    // credential deadline to read. Widening it would be a false bound.
    let prebuffer = PROXY_SOURCE
        .split("async fn buffer_request_body_for_before_proxy(")
        .nth(1)
        .expect("pre-authentication prebuffer")
        .split("pub(crate) fn request_may_have_body")
        .next()
        .expect("bounded prebuffer body");
    assert!(!prebuffer.contains("collect_request_body_under_authorization"));
}

#[test]
fn the_direct_h2_upload_completion_gate_is_installed_for_authenticated_requests() {
    let gate = PROXY_SOURCE
        .split("let needs_upload_completion_gate =")
        .nth(1)
        .expect("direct-H2 upload-completion gate decision")
        .split(';')
        .next()
        .expect("bounded gate decision");
    assert!(
        gate.contains("effective_max_request_body_size_bytes > 0"),
        "the size-limit reason must stay: {gate}"
    );
    assert!(
        gate.contains("upload_auth_deadline.is_some()"),
        "an authenticated direct-H2 request needs the upload join even with limits off: {gate}"
    );
    assert!(
        PROXY_SOURCE.contains("if needs_upload_completion_gate {"),
        "the gate decision must drive the completion-channel installation"
    );
}

#[test]
fn the_direct_h2_upload_join_reports_authorization_rather_than_an_indeterminate_size() {
    // An authorization-terminated upload also reports `Abandoned`, which the
    // size gate classifies as FailClosed. That must not surface as a 502
    // backend fault.
    let fail_closed = PROXY_SOURCE
        .split("DirectH2UploadGate::FailClosed => {")
        .nth(1)
        .expect("direct-H2 fail-closed arm")
        .split("\"HTTP/2 request upload did not establish an authoritative size decision")
        .next()
        .expect("bounded fail-closed arm");
    assert!(fail_closed.contains("upload_auth_deadline"));
    assert!(fail_closed.contains("latch.observed()"));
    assert!(fail_closed.contains("authorization_expired_dispatch_placeholder("));
}

#[test]
fn every_h1h2_response_header_wait_composes_the_authorization_lifetime() {
    // The definition plus five composed waits: the reqwest initial attempt, the
    // reqwest retry attempt, mesh mTLS, HBONE, and the Unix-socket pool.
    // Direct-H2 composes through `authorization_bounded_header_deadline` instead,
    // because it carries a typed bound source.
    assert_eq!(
        PROXY_SOURCE
            .matches("compose_dispatch_phase_auth_bound(")
            .count(),
        6,
        "an H1/H2 response-header wait lost its authorization bound"
    );
    assert!(PROXY_SOURCE.contains("authorization_bounded_header_deadline("));
    assert!(PROXY_SOURCE.contains("ResponseHeaderDeadlineSource::Authorization => {"));
    // The definition plus seven attributions: those five waits, the direct-H2
    // header wait, and the direct-H2 early-response upload join. Each attributes
    // the fired bound, so an authorization expiry is never reported as a backend
    // timeout or a client RPC deadline.
    assert_eq!(
        PROXY_SOURCE
            .matches("dispatch_phase_authorization_expiry(")
            .count(),
        8,
        "an H1/H2 dispatch phase lost its authorization attribution"
    );
    // Every one of those exits returns the health-neutral placeholder: the
    // definition plus twelve call sites (four buffered collects, five header
    // waits, the direct-H2 header wait, the direct-H2 upload join, and the
    // direct-H2 fail-closed guard).
    assert_eq!(
        PROXY_SOURCE
            .matches("authorization_expired_dispatch_placeholder(")
            .count(),
        13,
        "an H1/H2 authorization exit stopped being health-neutral"
    );
}

#[test]
fn both_buffered_grpc_authorization_exits_release_their_admission_state() {
    let branches: Vec<&str> = PROXY_SOURCE
        .split("Err(grpc_proxy::GrpcRequestBodyCollectError::AuthorizationExpired(")
        .skip(1)
        .map(|branch| {
            branch
                .split("Err(grpc_proxy::GrpcRequestBodyCollectError::Proxy")
                .next()
                .expect("bounded buffered gRPC authorization branch")
        })
        .collect();
    assert_eq!(branches.len(), 2, "split and mixed buffered gRPC arms");
    for branch in branches {
        assert!(branch.contains("grpc_probe_guard.disarm()"));
        assert!(branch.contains("release_circuit_breaker_probe_on_admission_reject("));
        assert!(branch.contains("preacquired_backend_admission.take_if_acquired()"));
        assert!(branch.contains("finalize_authorization_expired_rejection("));
        assert!(branch.contains("authorization_expired_buffered_grpc_upload"));
    }
}

#[test]
fn the_buffered_grpc_authorization_terminal_is_unauthenticated_and_latched() {
    // `grpc-status: 16` (`UNAUTHENTICATED`), never a fabricated DEADLINE_EXCEEDED.
    let normalized = PROXY_SOURCE
        .split("fn normalized_authorization_expired(")
        .nth(1)
        .expect("buffered gRPC authorization terminal")
        .split("\n}\n")
        .next()
        .expect("bounded terminal builder");
    assert!(normalized.contains("AUTHORIZATION_EXPIRED_GRPC_STATUS_HEADER"));
    assert!(normalized.contains("termination.grpc_message()"));
    assert!(
        !normalized.contains("GATEWAY_DEADLINE_EXCEEDED"),
        "an expired credential is never reported as a client-chosen RPC deadline"
    );
    // The bounded class reaches the transaction summary through the ordinary latch.
    let finalize = PROXY_SOURCE
        .split("async fn finalize_authorization_expired_rejection(")
        .nth(1)
        .expect("buffered gRPC authorization finalizer")
        .split("\n}\n")
        .next()
        .expect("bounded finalizer");
    assert!(finalize.contains("ctx.latch_authorization_termination(termination);"));
}
