//! Authorization lifetime of an admitted PLAIN-UDP session (issue #3816).
//!
//! `admit_plain_udp_stream` runs the full `on_stream_connect` chain, so a
//! plain-UDP session can carry an identified consumer, an authenticated
//! identity, and a `credential_deadline_at` exactly like the DTLS-terminating
//! frontend does — but `on_stream_connect` runs ONCE, at admission, and is
//! never repeated. Without this contract a plain-UDP session outlived the
//! credential that admitted it indefinitely, and any custom or future
//! stream-auth plugin could create an indefinitely authorized session.
//!
//! These drive the production seams — the anchored plan, the bounded
//! post-admission setup stages, the pre-commit re-check, the client→backend
//! datagram gate, the hook-ingress gate, the backend reply direction's
//! deadline arm, and the exactly-once teardown — through
//! `UdpAuthorizationSessionProbe`, which builds a REAL `UdpSession` with a real
//! connected backend socket, a real overload connection guard, and a real
//! bounded hook-ingress channel.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use ferrum_edge::_test_support::{
    UdpAuthorizationSessionProbe, UdpReplyRecvOutcomeForTest,
    udp_authorization_disconnect_classification_for_test,
    udp_authorization_expired_before_commit_for_test,
    udp_setup_stage_under_authorization_for_test,
};
use ferrum_edge::plugins::{Direction, DisconnectCause};
use ferrum_edge::proxy::auth_lifetime::{
    STREAM_AUTH_TERMINATION_METADATA_KEY, StreamAuthDeadline, StreamAuthProtocolFamily,
    StreamAuthTermination, StreamAuthTerminationLatch, counters, effective_stream_auth_deadline,
};
use ferrum_edge::proxy::stream_error::StreamSetupKind;
use ferrum_edge::retry::ErrorClass;

/// A plan that has ALREADY elapsed, so no scheduling can change the verdict.
///
/// `checked_sub` rather than `-`: `tokio::time::Instant` is monotonic-clock
/// based, so a process started very close to boot could underflow. Falling back
/// to "now" is still an elapsed plan, because every check reads the clock again
/// and settles on `>=`.
fn elapsed_plan(termination: StreamAuthTermination) -> StreamAuthDeadline {
    StreamAuthDeadline {
        at: tokio::time::Instant::now()
            .checked_sub(Duration::from_secs(1))
            .unwrap_or_else(tokio::time::Instant::now),
        termination,
    }
}

fn future_plan(after: Duration, termination: StreamAuthTermination) -> StreamAuthDeadline {
    StreamAuthDeadline {
        at: tokio::time::Instant::now() + after,
        termination,
    }
}

/// The process-wide `stream_udp` counter pair.
///
/// The unit-test binary runs in parallel and other suites (the DTLS
/// authorization coverage) share this family, so these tests assert the counter
/// MOVED rather than pinning an exact global delta. "Exactly once" is asserted
/// deterministically against the session's own shared
/// [`StreamAuthTerminationLatch`], which is the mechanism that gates the counter
/// increment in the first place.
fn stream_udp_terminations() -> (u64, u64) {
    let snapshot = counters();
    (
        snapshot.credential_expired["stream_udp"],
        snapshot.authenticated_stream_max_lifetime["stream_udp"],
    )
}

async fn probe(
    plan: Option<StreamAuthDeadline>,
    latch: StreamAuthTerminationLatch,
    with_hooks: bool,
) -> UdpAuthorizationSessionProbe {
    UdpAuthorizationSessionProbe::new(plan, latch, with_hooks)
        .await
        .expect("probe session binds loopback UDP sockets")
}

// ── The plan itself ─────────────────────────────────────────────────────

#[tokio::test(start_paused = true)]
async fn an_unauthenticated_plain_udp_session_carries_no_authorization_bound() {
    // No principal was admitted, so there is nothing to bound. This is the
    // overwhelmingly common plain-UDP posture (DNS, syslog, QUIC passthrough),
    // and it must keep its exact previous behavior.
    assert_eq!(
        effective_stream_auth_deadline(
            false,
            Some(tokio::time::Instant::now() + Duration::from_secs(5)),
            tokio::time::Instant::now(),
            3_600,
        ),
        None,
        "an unauthenticated UDP session must not be given an authorization plan"
    );

    let latch = StreamAuthTerminationLatch::default();
    let session = probe(None, latch.clone(), false).await;

    session.forward(b"unauthenticated").await.expect(
        "an unauthenticated session forwards exactly as it did before the contract existed",
    );
    assert_eq!(
        session.backend_recv().await.expect("backend datagram"),
        b"unauthenticated".to_vec()
    );
    // Time far past any plausible maximum: still unbounded, because there is
    // no plan at all.
    tokio::time::advance(Duration::from_secs(86_400 * 2)).await;
    session
        .forward(b"still-unauthenticated")
        .await
        .expect("an unauthenticated session is never terminated by this contract");
    assert_eq!(
        session.backend_recv().await.expect("backend datagram"),
        b"still-unauthenticated".to_vec()
    );

    assert_eq!(session.observed_termination(), None);
    assert!(!session.reply_task_stop_requested());
    assert!(
        !session
            .metadata()
            .contains_key(STREAM_AUTH_TERMINATION_METADATA_KEY)
    );
    assert!(
        latch.observed().is_none(),
        "an unauthenticated session settles no termination, so it moves no stream_udp counter"
    );
}

#[tokio::test(start_paused = true)]
async fn the_effective_bound_is_the_earliest_of_credential_and_finite_maximum() {
    let anchor = tokio::time::Instant::now();

    // A short-TTL credential wins over the maximum.
    let credential = effective_stream_auth_deadline(
        true,
        Some(anchor + Duration::from_secs(30)),
        anchor,
        3_600,
    )
    .expect("an authenticated session is bounded");
    assert_eq!(
        credential.termination,
        StreamAuthTermination::CredentialExpired
    );
    assert_eq!(credential.at, anchor + Duration::from_secs(30));

    // A credential with no authoritative expiry still gets a finite bound.
    let fallback = effective_stream_auth_deadline(true, None, anchor, 120)
        .expect("a credential with no expiry is bounded by the finite maximum");
    assert_eq!(
        fallback.termination,
        StreamAuthTermination::AuthenticatedStreamMaxLifetime
    );
    assert_eq!(fallback.at, anchor + Duration::from_secs(120));

    // A credential that outlives the maximum is capped by the maximum.
    let capped = effective_stream_auth_deadline(
        true,
        Some(anchor + Duration::from_secs(9_000)),
        anchor,
        120,
    )
    .expect("an authenticated session is bounded");
    assert_eq!(
        capped.termination,
        StreamAuthTermination::AuthenticatedStreamMaxLifetime
    );
    assert_eq!(capped.at, anchor + Duration::from_secs(120));
}

#[tokio::test(start_paused = true)]
async fn the_maximum_is_anchored_at_admission_not_after_the_plugin_chain() {
    // `process_new_session_datagram` captures the anchor BEFORE the epoch
    // resolve, the mesh egress decision, and `on_stream_connect`. A
    // deliberately slow admission plugin must therefore not buy the session
    // extra authorized lifetime.
    let anchor = tokio::time::Instant::now();
    tokio::time::advance(Duration::from_secs(90)).await;

    let plan = effective_stream_auth_deadline(true, None, anchor, 120)
        .expect("an authenticated session is bounded");
    assert_eq!(
        plan.at,
        anchor + Duration::from_secs(120),
        "the maximum must be measured from admission, not from when the chain finished"
    );
    assert!(
        plan.at < tokio::time::Instant::now() + Duration::from_secs(120),
        "a 90s admission chain must consume the session's own lifetime, not extend it"
    );
}

// ── Post-admission setup stages ─────────────────────────────────────────

#[tokio::test(start_paused = true)]
async fn an_already_expired_admission_never_polls_a_setup_stage() {
    // First-datagram policy hooks, DNS resolution, and the backend connect are
    // all `stream_udp_setup_stage_under_authorization` stages. An
    // already-elapsed plan must run NONE of them: no hook side effect, no name
    // resolved, no backend dialled.
    let entered = Arc::new(AtomicBool::new(false));
    let stage_entered = Arc::clone(&entered);
    let failure = udp_setup_stage_under_authorization_for_test(
        Some(elapsed_plan(StreamAuthTermination::CredentialExpired)),
        || async move {
            stage_entered.store(true, Ordering::SeqCst);
        },
    )
    .await
    .expect_err("an elapsed plan refuses the stage");

    assert!(
        !entered.load(Ordering::SeqCst),
        "the stage future must be dropped unpolled"
    );
    assert_eq!(
        failure.setup_kind,
        Some(StreamSetupKind::AuthorizationExpired)
    );
    assert_eq!(failure.error_class, ErrorClass::RequestError);
    assert_eq!(failure.disconnect_cause, DisconnectCause::RecvError);
    assert_eq!(failure.disconnect_direction, Direction::ClientToBackend);
    assert_eq!(
        failure.probe_releases, 1,
        "a claimed HALF_OPEN probe slot is released NEUTRALLY exactly once"
    );
    assert_eq!(
        failure
            .metadata
            .get(STREAM_AUTH_TERMINATION_METADATA_KEY)
            .map(String::as_str),
        Some("credential_expired")
    );
}

#[tokio::test(start_paused = true)]
async fn an_expiry_during_setup_drops_the_running_stage() {
    // A stage that started before the deadline is CANCELLED at it, so a
    // half-finished DNS lookup or backend connect is abandoned rather than
    // completed for a credential that is no longer authorizing.
    let completed = Arc::new(AtomicBool::new(false));
    let stage_completed = Arc::clone(&completed);
    let failure = udp_setup_stage_under_authorization_for_test(
        Some(future_plan(
            Duration::from_millis(50),
            StreamAuthTermination::AuthenticatedStreamMaxLifetime,
        )),
        || async move {
            tokio::time::sleep(Duration::from_secs(30)).await;
            stage_completed.store(true, Ordering::SeqCst);
        },
    )
    .await
    .expect_err("a stage that outruns the deadline is cancelled");

    assert!(
        !completed.load(Ordering::SeqCst),
        "the cancelled stage must not run its completion side effect"
    );
    assert_eq!(
        failure
            .metadata
            .get(STREAM_AUTH_TERMINATION_METADATA_KEY)
            .map(String::as_str),
        Some("authenticated_stream_max_lifetime")
    );
    assert_eq!(failure.probe_releases, 1);
}

#[tokio::test(start_paused = true)]
async fn an_unauthenticated_setup_stage_runs_unbounded() {
    let completed = udp_setup_stage_under_authorization_for_test(None, || async {
        tokio::time::sleep(Duration::from_secs(3_600)).await;
        "done"
    })
    .await
    .expect("an unauthenticated session registers no timer at all");
    assert_eq!(completed, "done");
}

#[tokio::test(start_paused = true)]
async fn the_pre_commit_recheck_refuses_a_session_that_expired_during_synchronous_setup() {
    // The synchronous work between two await points is invisible to the
    // deadline arms, so the plan is re-read immediately before the session is
    // inserted, counted as a backend success, or handed its first send.
    let plan = future_plan(
        Duration::from_secs(10),
        StreamAuthTermination::CredentialExpired,
    );
    assert_eq!(
        udp_authorization_expired_before_commit_for_test(Some(plan), tokio::time::Instant::now()),
        None,
        "a live plan commits"
    );
    assert_eq!(
        udp_authorization_expired_before_commit_for_test(Some(plan), plan.at),
        Some(StreamAuthTermination::CredentialExpired),
        "exact-deadline equality settles as expiry"
    );
    assert_eq!(
        udp_authorization_expired_before_commit_for_test(None, tokio::time::Instant::now()),
        None,
        "an unauthenticated session is always committable"
    );
}

// ── Client → backend direction ──────────────────────────────────────────

#[tokio::test(start_paused = true)]
async fn an_elapsed_deadline_refuses_the_next_client_datagram_immediately() {
    let latch = StreamAuthTerminationLatch::default();
    let before = stream_udp_terminations();
    let session = probe(
        Some(elapsed_plan(StreamAuthTermination::CredentialExpired)),
        latch.clone(),
        false,
    )
    .await;

    let error = session
        .forward(b"post-expiry")
        .await
        .expect_err("an expired credential forwards no datagram");

    // Refused inline, not by a timer task that has yet to be scheduled.
    assert!(
        session.backend_received().is_none(),
        "no datagram may reach the backend after expiry"
    );
    assert_eq!(session.bytes_sent(), 0);
    assert_eq!(
        session.observed_termination(),
        Some(StreamAuthTermination::CredentialExpired)
    );
    assert!(
        session.reply_task_stop_requested(),
        "the first observer wakes the reply task so teardown does not wait for a backend datagram"
    );
    assert_eq!(
        session
            .metadata()
            .get(STREAM_AUTH_TERMINATION_METADATA_KEY)
            .map(String::as_str),
        Some("credential_expired")
    );
    let after = stream_udp_terminations();
    assert!(
        after.0 >= before.0 + 1,
        "the fixed-cardinality stream_udp credential_expired counter records the termination"
    );
    assert!(
        !latch.record_once(
            StreamAuthTermination::AuthenticatedStreamMaxLifetime,
            StreamAuthProtocolFamily::StreamUdp,
        ),
        "the session is already settled, so no second class can ever be counted for it"
    );

    // Redaction: the client-visible/logged error names the contract only.
    let message = error.to_lowercase();
    for forbidden in [
        "probe-consumer",
        "key_auth",
        "127.0.0.1",
        "expires",
        "certificate",
        "token",
    ] {
        assert!(
            !message.contains(forbidden),
            "the authorization setup error must not disclose {forbidden}: {error}"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn continuous_traffic_does_not_refresh_the_authorization_deadline() {
    let latch = StreamAuthTerminationLatch::default();
    let session = probe(
        Some(future_plan(
            Duration::from_millis(300),
            StreamAuthTermination::AuthenticatedStreamMaxLifetime,
        )),
        latch.clone(),
        false,
    )
    .await;

    for round in 0..3u8 {
        session
            .forward(&[round])
            .await
            .expect("traffic inside the lifetime is forwarded");
        let received = session.backend_recv().await.expect("backend datagram");
        assert_eq!(received, vec![round]);
        tokio::time::advance(Duration::from_millis(90)).await;
    }
    assert_eq!(session.observed_termination(), None, "still authorized");

    // 270ms of continuous activity did not move the absolute deadline.
    tokio::time::advance(Duration::from_millis(60)).await;
    session
        .forward(b"past-deadline")
        .await
        .expect_err("relayed datagrams never extend an anchored authorization deadline");
    assert!(session.backend_received().is_none());
    assert_eq!(
        session.observed_termination(),
        Some(StreamAuthTermination::AuthenticatedStreamMaxLifetime)
    );
}

#[tokio::test(start_paused = true)]
async fn settlement_is_exactly_once_across_a_burst_of_refused_datagrams() {
    let latch = StreamAuthTerminationLatch::default();
    let before = stream_udp_terminations();
    let session = probe(
        Some(elapsed_plan(StreamAuthTermination::CredentialExpired)),
        latch.clone(),
        false,
    )
    .await;

    for _ in 0..16 {
        assert!(session.forward(b"burst").await.is_err());
    }

    assert!(
        stream_udp_terminations().0 >= before.0 + 1,
        "the burst recorded the termination"
    );
    assert_eq!(session.metadata().len(), 1, "one bounded metadata stamp");
    assert!(
        !latch.record_once(
            StreamAuthTermination::AuthenticatedStreamMaxLifetime,
            StreamAuthProtocolFamily::StreamUdp,
        ),
        "the shared latch refuses a second settlement, so no later phase can double count"
    );
}

// ── Hook-ingress direction ──────────────────────────────────────────────

#[tokio::test(start_paused = true)]
async fn the_hook_ingress_path_refuses_after_expiry_without_a_backpressure_drop() {
    let latch = StreamAuthTerminationLatch::default();
    let session = probe(
        Some(future_plan(
            Duration::from_millis(100),
            StreamAuthTermination::CredentialExpired,
        )),
        latch.clone(),
        true,
    )
    .await;

    assert!(
        session.enqueue_hook_datagram(b"authorized"),
        "an authorized datagram is admitted to the bounded hook queue"
    );
    let drops_before = session.hook_ingress_drops();

    tokio::time::advance(Duration::from_millis(150)).await;
    assert!(
        !session.enqueue_hook_datagram(b"post-expiry"),
        "an expired session queues no payload and runs no datagram hook"
    );
    assert_eq!(
        session.hook_ingress_drops(),
        drops_before,
        "a policy refusal is not gateway backpressure and must not move hook_ingress_drops"
    );
    assert_eq!(
        session.observed_termination(),
        Some(StreamAuthTermination::CredentialExpired)
    );
    assert!(session.reply_task_stop_requested());
}

#[tokio::test(start_paused = true)]
async fn expiry_teardown_cancels_the_hook_ingress_worker() {
    let latch = StreamAuthTerminationLatch::default();
    let session = probe(
        Some(elapsed_plan(StreamAuthTermination::CredentialExpired)),
        latch.clone(),
        true,
    )
    .await;
    assert!(session.spawn_hook_ingress_worker());
    assert!(session.hook_ingress_sender_present());

    // Settle through the production client-side gate, then run the teardown the
    // reply task performs at exit.
    assert!(session.forward(b"post-expiry").await.is_err());
    let summary = session
        .run_reply_task_exit_teardown()
        .expect("this generation owns the removal");
    assert!(summary.connection_error.is_some());

    // The worker's cancellation IS the dropped ingress sender: `recv` resolves
    // to `None` and the worker exits instead of waiting for another client
    // datagram, and an in-flight hook await is cancelled by the dedicated
    // hook-ingress notify.
    assert!(
        !session.hook_ingress_sender_present(),
        "teardown must take the hook-ingress sender so the worker wakes and exits"
    );
    assert!(
        !session.enqueue_hook_datagram(b"after-teardown"),
        "nothing can be enqueued for a torn-down session"
    );
    // Give the worker a scheduling turn; it must not forward anything.
    tokio::task::yield_now().await;
    assert!(session.backend_received().is_none());
}

// ── Backend → client direction ──────────────────────────────────────────

#[tokio::test(start_paused = true)]
async fn the_backend_reply_direction_settles_an_already_elapsed_plan_before_a_ready_datagram() {
    // Biased and pre-checked: a backend datagram that is ALREADY readable must
    // not be delivered to a client whose credential stopped authorizing the
    // session, and the verdict must not depend on `select!` scheduling.
    let stop = AtomicBool::new(false);
    let notify = tokio::sync::Notify::new();
    let plan = elapsed_plan(StreamAuthTermination::AuthenticatedStreamMaxLifetime);
    let outcome: UdpReplyRecvOutcomeForTest<u8> =
        ferrum_edge::_test_support::udp_reply_recv_until_stop_or_expiry_for_test(
            &stop,
            &notify,
            Some(plan),
            std::future::ready(7u8),
            std::future::pending(),
        )
        .await;
    assert_eq!(
        outcome,
        UdpReplyRecvOutcomeForTest::AuthorizationExpired(
            StreamAuthTermination::AuthenticatedStreamMaxLifetime
        )
    );
}

#[tokio::test(start_paused = true)]
async fn the_backend_reply_direction_stops_when_the_deadline_fires_mid_wait() {
    let stop = AtomicBool::new(false);
    let notify = tokio::sync::Notify::new();
    let outcome: UdpReplyRecvOutcomeForTest<u8> =
        ferrum_edge::_test_support::udp_reply_recv_until_stop_or_expiry_for_test(
            &stop,
            &notify,
            Some(future_plan(
                Duration::from_millis(40),
                StreamAuthTermination::CredentialExpired,
            )),
            std::future::pending::<u8>(),
            std::future::pending(),
        )
        .await;
    assert_eq!(
        outcome,
        UdpReplyRecvOutcomeForTest::AuthorizationExpired(StreamAuthTermination::CredentialExpired)
    );
}

#[tokio::test(start_paused = true)]
async fn an_unauthenticated_reply_receive_is_unchanged() {
    let stop = AtomicBool::new(false);
    let notify = tokio::sync::Notify::new();
    assert_eq!(
        ferrum_edge::_test_support::udp_reply_recv_until_stop_or_expiry_for_test(
            &stop,
            &notify,
            None,
            std::future::ready(9u8),
            std::future::pending(),
        )
        .await,
        UdpReplyRecvOutcomeForTest::Received(9u8)
    );

    // Idle/drain stop still wins for an unauthenticated session.
    stop.store(true, Ordering::Release);
    assert_eq!(
        ferrum_edge::_test_support::udp_reply_recv_until_stop_or_expiry_for_test(
            &stop,
            &notify,
            None,
            std::future::pending::<u8>(),
            std::future::pending(),
        )
        .await,
        UdpReplyRecvOutcomeForTest::Stopped
    );
}

#[tokio::test(start_paused = true)]
async fn an_authorized_session_still_observes_idle_and_drain_stops() {
    // The authorization arm must not shadow the pre-existing idle/drain/global
    // shutdown races.
    let stop = AtomicBool::new(true);
    let notify = tokio::sync::Notify::new();
    assert_eq!(
        ferrum_edge::_test_support::udp_reply_recv_until_stop_or_expiry_for_test(
            &stop,
            &notify,
            Some(future_plan(
                Duration::from_secs(3_600),
                StreamAuthTermination::CredentialExpired
            )),
            std::future::pending::<u8>(),
            std::future::pending(),
        )
        .await,
        UdpReplyRecvOutcomeForTest::Stopped
    );

    let live = AtomicBool::new(false);
    assert_eq!(
        ferrum_edge::_test_support::udp_reply_recv_until_stop_or_expiry_for_test(
            &live,
            &notify,
            Some(future_plan(
                Duration::from_secs(3_600),
                StreamAuthTermination::CredentialExpired
            )),
            std::future::pending::<u8>(),
            std::future::ready(()),
        )
        .await,
        UdpReplyRecvOutcomeForTest::Stopped,
        "listener/global shutdown still cancels an authorized session"
    );
}

// ── Teardown, generation identity, and accounting ───────────────────────

#[tokio::test(start_paused = true)]
async fn expiry_teardown_invalidates_the_cached_generation_and_removes_only_it() {
    let latch = StreamAuthTerminationLatch::default();
    let session = probe(
        Some(elapsed_plan(StreamAuthTermination::CredentialExpired)),
        latch.clone(),
        false,
    )
    .await;

    assert_eq!(
        session.cached_generation_is_live(),
        (true, true),
        "before teardown the recv-loop fast-path cache resolves this generation"
    );
    assert!(session.session_map_contains());

    assert!(session.forward(b"post-expiry").await.is_err());
    assert!(session.run_reply_task_exit_teardown().is_some());

    assert_eq!(
        session.cached_generation_is_live(),
        (false, false),
        "the generation is marked expired BEFORE reuse, and the stale cache entry is cleared"
    );
    assert!(
        !session.session_map_contains(),
        "the exact expired generation is removed, so the next datagram creates a new session"
    );
}

#[tokio::test(start_paused = true)]
async fn teardown_releases_the_overload_guard_and_session_slot_exactly_once() {
    let latch = StreamAuthTerminationLatch::default();
    let session = probe(
        Some(elapsed_plan(
            StreamAuthTermination::AuthenticatedStreamMaxLifetime,
        )),
        latch.clone(),
        false,
    )
    .await;
    assert_eq!(session.overload_active_connections(), 1);
    assert_eq!(session.active_sessions(), 1);

    assert!(session.forward(b"post-expiry").await.is_err());
    assert!(session.run_reply_task_exit_teardown().is_some());
    assert_eq!(session.overload_active_connections(), 0);
    assert_eq!(session.active_sessions(), 0);

    // Identity-aware removal: a second teardown owns nothing and must not
    // decrement anything a second time.
    assert!(
        session.run_reply_task_exit_teardown().is_none(),
        "only the generation that won the removal emits a summary"
    );
    assert_eq!(session.overload_active_connections(), 0);
    assert_eq!(session.active_sessions(), 0);
}

#[tokio::test(start_paused = true)]
async fn a_simultaneous_idle_removal_and_authorization_expiry_release_exactly_once() {
    let latch = StreamAuthTerminationLatch::default();
    let before = stream_udp_terminations();
    let session = probe(
        Some(elapsed_plan(StreamAuthTermination::CredentialExpired)),
        latch.clone(),
        true,
    )
    .await;

    // The authorization expiry is observed on the client side …
    assert!(session.forward(b"post-expiry").await.is_err());
    // … while the idle-cleanup task wins the identity-aware removal.
    assert!(session.run_idle_cleanup_removal());
    assert_eq!(session.overload_active_connections(), 0);
    assert_eq!(session.active_sessions(), 0);

    // The reply task's own exit then owns nothing.
    assert!(session.run_reply_task_exit_teardown().is_none());
    assert_eq!(session.overload_active_connections(), 0);
    assert_eq!(session.active_sessions(), 0);
    assert!(
        stream_udp_terminations().0 >= before.0 + 1,
        "the race recorded the termination"
    );
    assert!(
        !latch.record_once(
            StreamAuthTermination::CredentialExpired,
            StreamAuthProtocolFamily::StreamUdp,
        ),
        "exactly one settlement: the idle path cannot count a second one"
    );
    // The bounded class still reaches whichever summary is delivered, because
    // it was stamped into the session metadata before the removal race.
    assert_eq!(
        session
            .metadata()
            .get(STREAM_AUTH_TERMINATION_METADATA_KEY)
            .map(String::as_str),
        Some("credential_expired")
    );
}

#[tokio::test(start_paused = true)]
async fn the_disconnect_summary_names_a_client_side_health_neutral_authorization_decision() {
    let latch = StreamAuthTerminationLatch::default();
    let session = probe(
        Some(elapsed_plan(
            StreamAuthTermination::AuthenticatedStreamMaxLifetime,
        )),
        latch.clone(),
        false,
    )
    .await;
    assert!(session.forward(b"post-expiry").await.is_err());

    let summary = session
        .run_reply_task_exit_teardown()
        .expect("this generation owns the removal");

    let (message, class, cause, direction) = udp_authorization_disconnect_classification_for_test();
    assert_eq!(summary.connection_error.as_deref(), Some(message.as_str()));
    assert_eq!(summary.error_class, Some(class));
    assert_eq!(summary.disconnect_cause, Some(cause));
    assert_eq!(summary.disconnect_direction, Some(direction));

    // Client-side and backend-health-neutral: the same attribution the DTLS
    // relay-phase expiry uses, so `stream_disconnects` never reads a gateway
    // policy decision as a backend outage.
    assert_eq!(cause, DisconnectCause::RecvError);
    assert_eq!(direction, Direction::ClientToBackend);
    assert_eq!(class, ErrorClass::RequestError);

    assert_eq!(
        summary
            .metadata
            .get(STREAM_AUTH_TERMINATION_METADATA_KEY)
            .map(String::as_str),
        Some("authenticated_stream_max_lifetime"),
        "the bounded class reaches the transaction summary and on_stream_disconnect"
    );

    // Redaction: nothing about the credential, the identity, the deadline, the
    // certificate, the token, or the source address is in the cause text.
    let lower = message.to_lowercase();
    for forbidden in [
        "probe-consumer",
        "127.0.0.1",
        "certificate",
        "token",
        "jwt",
        "notafter",
        "exp=",
    ] {
        assert!(
            !lower.contains(forbidden),
            "the disconnect cause must not disclose {forbidden}: {message}"
        );
    }
    assert!(
        !message.chars().any(|c| c.is_ascii_digit()),
        "the disconnect cause must carry no expiry or address digits: {message}"
    );
}

#[tokio::test(start_paused = true)]
async fn an_unauthenticated_session_teardown_reports_no_authorization_decision() {
    let latch = StreamAuthTerminationLatch::default();
    let session = probe(None, latch, false).await;
    session.forward(b"data").await.expect("forward succeeds");
    let _ = session.backend_recv().await;

    let summary = session
        .run_reply_task_exit_teardown()
        .expect("this generation owns the removal");
    assert_eq!(summary.connection_error, None);
    assert_eq!(summary.error_class, None);
    assert!(
        !summary
            .metadata
            .contains_key(STREAM_AUTH_TERMINATION_METADATA_KEY),
        "an unauthenticated session carries no authorization termination metadata"
    );
}

// ── Concurrency ─────────────────────────────────────────────────────────

#[tokio::test(start_paused = true)]
async fn concurrent_directions_settle_one_termination_between_them() {
    // Both directions are armed from the same absolute plan, so both can become
    // ready at the same instant. The shared latch makes the pair record one
    // termination for the session.
    let latch = StreamAuthTerminationLatch::default();
    let before = stream_udp_terminations();
    let session = Arc::new(
        probe(
            Some(elapsed_plan(StreamAuthTermination::CredentialExpired)),
            latch.clone(),
            true,
        )
        .await,
    );

    let settles = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::new();
    for _ in 0..4 {
        let session = Arc::clone(&session);
        let settles = Arc::clone(&settles);
        handles.push(tokio::spawn(async move {
            if session.forward(b"race").await.is_err() {
                settles.fetch_add(1, Ordering::Relaxed);
            }
            let _ = session.enqueue_hook_datagram(b"race");
        }));
    }
    for handle in handles {
        let _ = handle.await;
    }

    assert_eq!(
        settles.load(Ordering::Relaxed),
        4,
        "every datagram is refused"
    );
    assert!(
        stream_udp_terminations().0 >= before.0 + 1,
        "the concurrent observers recorded the termination"
    );
    assert!(
        !latch.record_once(
            StreamAuthTermination::CredentialExpired,
            StreamAuthProtocolFamily::StreamUdp,
        ),
        "concurrent observers still settle exactly once between them"
    );
    assert_eq!(session.metadata().len(), 1);
}

// ── Hot-path and wiring contracts ───────────────────────────────────────

const UDP_PROXY_SOURCE: &str = include_str!("../../../src/proxy/udp_proxy.rs");

fn body_of(marker: &str) -> &'static str {
    UDP_PROXY_SOURCE
        .split(marker)
        .nth(1)
        .unwrap_or_else(|| panic!("{marker} not found in udp_proxy.rs"))
}

/// The datagram gate must stay lock-free and allocation-free.
///
/// A UDP proxy's per-datagram budget is why the module already keeps a coarse
/// cached clock and a `last_client` fast path. The authorization gate is one
/// `Option` discriminant test plus, for an AUTHENTICATED session only, one
/// monotonic instant comparison — no per-datagram mutex, map walk, allocation,
/// timer task, or formatted string.
#[test]
fn the_client_to_backend_authorization_gate_stays_on_the_hot_path_budget() {
    let gate = body_of("fn refuse_if_authorization_expired(")
        .split("\n    }\n")
        .next()
        .expect("the gate body");
    for forbidden in ["format!(", "to_string()", "tokio::spawn", "sleep", "iter()"] {
        assert!(
            !gate.contains(forbidden),
            "the per-datagram authorization gate must not use `{forbidden}`: {gate}"
        );
    }

    let expired_now = body_of("fn authorization_expired_now(")
        .split("\n    }\n")
        .next()
        .expect("the expiry predicate body");
    assert!(
        expired_now.contains("self.authorization.as_ref()?"),
        "an unauthenticated session must short-circuit before any clock read"
    );
    assert!(
        expired_now.contains("tokio::time::Instant::now() >= authorization.plan.at"),
        "the gate is a monotonic instant comparison"
    );
    for forbidden in ["lock()", "format!(", "Vec::", "String::"] {
        assert!(
            !expired_now.contains(forbidden),
            "the per-datagram expiry predicate must not use `{forbidden}`"
        );
    }
}

/// The backend reply direction arms ONE timer, outside its receive loop.
#[test]
fn the_reply_task_arms_its_authorization_timer_once() {
    let create_session = body_of("async fn create_session(");
    let arm_at = create_session
        .find("let mut reply_authorization_deadline")
        .expect("the reply task's authorization arm");
    let loop_at = create_session[arm_at..]
        .find("\n        loop {")
        .expect("the reply receive loop");
    assert!(
        loop_at > 0,
        "the deadline must be armed BEFORE the receive loop, so no per-datagram timer is \
         registered"
    );
    let receive_loop = &create_session[arm_at + loop_at..];
    assert!(
        !receive_loop.contains("tokio::time::sleep_until("),
        "the receive loop must not re-arm a timer per datagram"
    );
    assert_eq!(
        receive_loop
            .matches("udp_reply_recv_until_stop_or_expiry(")
            .count(),
        2,
        "both the DTLS-backend and plain-UDP-backend receive arms are bounded"
    );
}

/// The authorization arm is biased first, and an already-elapsed plan settles
/// without polling the receive at all.
#[test]
fn the_reply_receive_prefers_the_authorization_arm() {
    let body = body_of("pub(crate) async fn udp_reply_recv_until_stop_or_expiry");
    let precheck_at = body
        .find("if tokio::time::Instant::now() >= plan.at {")
        .expect("the already-elapsed pre-check");
    let select_at = body.find("tokio::select! {").expect("the bounded select");
    assert!(
        precheck_at < select_at,
        "an already-elapsed plan must settle before `select!` can pick a ready receive"
    );
    let select = &body[select_at..];
    let biased_at = select.find("biased;").expect("biased select");
    let deadline_at = select
        .find("authorization_deadline.as_mut()")
        .expect("the authorization arm");
    let recv_at = select
        .find("udp_reply_recv_until_stop(")
        .expect("the receive arm");
    assert!(
        biased_at < deadline_at && deadline_at < recv_at,
        "the authorization arm must be the FIRST select arm"
    );
}

/// Every post-admission setup stage that can await is bounded, and the session
/// is re-checked before it is committed.
#[test]
fn every_plain_udp_setup_stage_runs_under_the_authorization_deadline() {
    let new_session = body_of("async fn process_new_session_datagram(");
    // Anchored before the epoch resolve and the admission chain.
    let anchor_at = new_session
        .find("let auth_anchor = tokio::time::Instant::now();")
        .expect("the admission anchor");
    let epoch_at = new_session
        .find("let epoch = request_epoch.load();")
        .expect("the epoch resolve");
    let admit_at = new_session
        .find("admit_plain_udp_stream(")
        .expect("the on_stream_connect chain");
    assert!(
        anchor_at < epoch_at && epoch_at < admit_at,
        "the fallback maximum must be anchored before any slow admission work"
    );
    assert!(
        new_session.contains("effective_stream_auth_deadline("),
        "the plain-UDP path must compute an effective authorization plan"
    );
    // The first-datagram policy hooks are bounded.
    let first_datagram = new_session
        .find("let first_datagram_allowed =")
        .expect("the bounded first-datagram policy stage");
    assert!(first_datagram > admit_at);
    // The pending drain stops at expiry.
    let drain_gate = new_session
        .find("'drain: while let Some(batch) = take_pending_datagrams(")
        .expect("the labeled pending-datagram drain");
    let drain_break = new_session[drain_gate..]
        .find("break 'drain;")
        .expect("the drain's expiry break");
    let drain_hook = new_session[drain_gate..]
        .find("udp_datagram_allowed(")
        .expect("the drain's per-datagram hook");
    assert!(
        drain_break < drain_hook,
        "the pending-datagram drain must stop at expiry BEFORE running another hook"
    );

    let create_session = body_of("async fn create_session(");
    assert_eq!(
        create_session
            .matches("stream_udp_setup_stage_under_authorization(")
            .count(),
        2,
        "DNS resolution and the backend connect/handshake are both bounded"
    );
    let commit_check = create_session
        .find("udp_authorization_expired_before_commit(")
        .expect("the pre-commit re-check");
    let cb_success = create_session
        .find("// Record circuit breaker success")
        .expect("the backend success accounting");
    let insert = create_session
        .find("sessions.insert(client_addr, session.clone());")
        .expect("the session map insert");
    assert!(
        commit_check < cb_success && cb_success < insert,
        "the synchronous gap must be re-checked before ANY backend success is recorded and \
         before the session is committed"
    );
}

/// The gate is installed on every client→backend production path.
#[test]
fn every_client_to_backend_path_is_gated() {
    let forward = body_of("async fn forward_client_datagram_to_backend(")
        .split("\n}\n")
        .next()
        .expect("the forward body");
    let gate_at = forward
        .find("session.refuse_if_authorization_expired().is_some()")
        .expect("the forward gate");
    let publish_at = forward
        .find("last_request_size")
        .expect("the amplification budget publish");
    assert!(
        gate_at < publish_at,
        "the gate must precede the amplification-budget publish and the backend send, so an \
         expired credential moves no gateway state"
    );

    let enqueue = body_of("fn enqueue_session_hook_datagram(")
        .split("\n}\n")
        .next()
        .expect("the enqueue body");
    let enqueue_gate = enqueue
        .find("session.refuse_if_authorization_expired().is_some()")
        .expect("the hook-ingress gate");
    let queue_at = enqueue.find("hook_ingress_tx").expect("the queue lookup");
    assert!(
        enqueue_gate < queue_at,
        "an expired session must be refused before any payload is queued or charged"
    );
    assert!(
        !enqueue[..enqueue_gate].contains("record_hook_ingress_drop"),
        "a policy refusal must not be recorded as gateway backpressure"
    );
}
