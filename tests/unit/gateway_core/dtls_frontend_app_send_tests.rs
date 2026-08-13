//! Terminating frontend DTLS application-send wire-commit (issue #3820).
//!
//! Enqueue into `app_in_rx` is not a client-facing commit. These drive the
//! production driver/helper seam: queued plaintext is cancelled on deadline
//! or send-future drop; a `send_to` wait crossing the deadline emits nothing;
//! exact ties fail closed; shutdown does not flush expired/cancelled queued
//! replies; success completes only after the send future itself completes;
//! unauthenticated behavior keeps the no-timer path.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use ferrum_edge::_test_support::{
    FrontendAppSendAdmitForTest, FrontendAppSendRejectForTest, admit_frontend_app_send_for_test,
    earliest_frontend_app_send_deadline_for_test, frontend_app_ciphertext_send_until_expiry_for_test,
    frontend_app_send_cancel_fired_for_test, frontend_app_send_reject_as_str_for_test,
    shutdown_queued_frontend_app_send_for_test,
};

const DTLS_SOURCE: &str = include_str!("../../../src/dtls/mod.rs");
const UDP_PROXY_SOURCE: &str = include_str!("../../../src/proxy/udp_proxy.rs");

fn elapsed_deadline() -> tokio::time::Instant {
    tokio::time::Instant::now()
        .checked_sub(Duration::from_secs(1))
        .expect("elapsed deadline")
}

fn future_deadline(delta: Duration) -> tokio::time::Instant {
    tokio::time::Instant::now() + delta
}

#[test]
fn earliest_frontend_app_send_deadline_composition() {
    assert_eq!(
        earliest_frontend_app_send_deadline_for_test(None, None),
        None,
        "no deadline only when both inputs are absent"
    );

    let session = future_deadline(Duration::from_secs(10));
    assert_eq!(
        earliest_frontend_app_send_deadline_for_test(None, Some(session)),
        Some(session)
    );
    assert_eq!(
        earliest_frontend_app_send_deadline_for_test(Some(session), None),
        Some(session)
    );

    let earlier = future_deadline(Duration::from_secs(5));
    let later = future_deadline(Duration::from_secs(30));
    assert_eq!(
        earliest_frontend_app_send_deadline_for_test(Some(earlier), Some(later)),
        Some(earlier)
    );
    assert_eq!(
        earliest_frontend_app_send_deadline_for_test(Some(later), Some(earlier)),
        Some(earlier),
        "a later per-call deadline must not override an earlier session bound"
    );
    assert_eq!(
        earliest_frontend_app_send_deadline_for_test(Some(session), Some(session)),
        Some(session),
        "equal deadlines stay unchanged"
    );
}

#[test]
fn later_per_call_deadline_cannot_extend_session_authorization() {
    let now = tokio::time::Instant::now();
    let session = now + Duration::from_secs(5);
    let later_per_call = now + Duration::from_secs(60);
    let effective =
        earliest_frontend_app_send_deadline_for_test(Some(later_per_call), Some(session));
    assert_eq!(effective, Some(session));

    let after_session = now + Duration::from_secs(10);
    assert_eq!(
        admit_frontend_app_send_for_test(false, effective, after_session),
        FrontendAppSendAdmitForTest::Expired,
        "effective deadline must honor the earlier session bound"
    );
    assert_eq!(
        admit_frontend_app_send_for_test(false, Some(later_per_call), after_session),
        FrontendAppSendAdmitForTest::Proceed,
        "sanity: per-call alone would incorrectly proceed"
    );
    assert_eq!(
        shutdown_queued_frontend_app_send_for_test(false, effective, after_session),
        FrontendAppSendRejectForTest::Expired,
        "shutdown classification must use the same earliest bound"
    );
}

#[test]
fn queued_application_data_is_cancelled_on_deadline() {
    let now = tokio::time::Instant::now();
    assert_eq!(
        admit_frontend_app_send_for_test(false, Some(elapsed_deadline()), now),
        FrontendAppSendAdmitForTest::Expired,
        "an already-elapsed deadline must not encrypt queued plaintext"
    );
    assert_eq!(
        admit_frontend_app_send_for_test(false, Some(now), now),
        FrontendAppSendAdmitForTest::Expired,
        "exact-deadline ties fail closed"
    );
}

#[test]
fn dropping_the_send_future_marks_the_queued_request_cancelled() {
    let (_cancel_tx, mut cancel_rx) = tokio::sync::oneshot::channel::<()>();
    assert!(
        !frontend_app_send_cancel_fired_for_test(&mut cancel_rx),
        "a live send future must not look cancelled"
    );
    drop(_cancel_tx);
    assert!(
        frontend_app_send_cancel_fired_for_test(&mut cancel_rx),
        "dropping the proxy send future must mark the queued request cancelled"
    );
    let now = tokio::time::Instant::now();
    assert_eq!(
        admit_frontend_app_send_for_test(true, Some(future_deadline(Duration::from_secs(30))), now),
        FrontendAppSendAdmitForTest::Cancelled,
        "a cancelled queued request must not be encrypted even if the deadline has not elapsed"
    );
}

#[test]
fn shutdown_does_not_flush_expired_or_cancelled_queued_replies() {
    let now = tokio::time::Instant::now();
    assert_eq!(
        shutdown_queued_frontend_app_send_for_test(false, Some(elapsed_deadline()), now),
        FrontendAppSendRejectForTest::Expired
    );
    assert_eq!(
        shutdown_queued_frontend_app_send_for_test(
            true,
            Some(future_deadline(Duration::from_secs(30))),
            now
        ),
        FrontendAppSendRejectForTest::Cancelled
    );
    assert_eq!(
        shutdown_queued_frontend_app_send_for_test(
            false,
            Some(future_deadline(Duration::from_secs(30))),
            now
        ),
        FrontendAppSendRejectForTest::Closed,
        "a leftover authorized queued reply is closed on shutdown, not flushed as a wire commit"
    );
}

#[test]
fn unauthenticated_admission_stays_unbounded() {
    let now = tokio::time::Instant::now();
    assert_eq!(
        admit_frontend_app_send_for_test(false, None, now),
        FrontendAppSendAdmitForTest::Proceed
    );
    assert_eq!(
        shutdown_queued_frontend_app_send_for_test(false, None, now),
        FrontendAppSendRejectForTest::Closed
    );
}

#[test]
fn reject_strings_are_bounded_and_redacted() {
    for reject in [
        FrontendAppSendRejectForTest::Expired,
        FrontendAppSendRejectForTest::Cancelled,
        FrontendAppSendRejectForTest::Closed,
    ] {
        let text = frontend_app_send_reject_as_str_for_test(reject);
        assert!(!text.is_empty());
        let lower = text.to_ascii_lowercase();
        for forbidden in [
            "notafter",
            "spiffe",
            "certificate",
            "identity",
            "bearer",
            "1970-",
            "not_before",
        ] {
            assert!(
                !lower.contains(forbidden),
                "reject string {text:?} must not carry {forbidden}"
            );
        }
    }
}

#[tokio::test(start_paused = true)]
async fn an_elapsed_deadline_never_polls_the_application_send() {
    let polled = Arc::new(AtomicBool::new(false));
    let polled_send = Arc::clone(&polled);
    let outcome = frontend_app_ciphertext_send_until_expiry_for_test(
        Some(elapsed_deadline()),
        None,
        std::future::poll_fn(move |_| {
            polled_send.store(true, Ordering::SeqCst);
            std::task::Poll::Ready(7usize)
        }),
    )
    .await;
    assert_eq!(outcome, Err(FrontendAppSendRejectForTest::Expired));
    assert!(
        !polled.load(Ordering::SeqCst),
        "an already-elapsed deadline must never poll socket.send_to"
    );
}

#[tokio::test(start_paused = true)]
async fn a_socket_send_wait_crossing_the_deadline_emits_nothing() {
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let emitted = Arc::new(AtomicBool::new(false));
    let emitted_send = Arc::clone(&emitted);
    let deadline = future_deadline(Duration::from_millis(20));
    let raced = tokio::spawn(async move {
        frontend_app_ciphertext_send_until_expiry_for_test(Some(deadline), None, async move {
            let _ = release_rx.await;
            emitted_send.store(true, Ordering::SeqCst);
            1usize
        })
        .await
    });
    tokio::task::yield_now().await;
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_millis(20)).await;
    let _ = release_tx.send(());
    assert_eq!(
        raced.await.expect("join"),
        Err(FrontendAppSendRejectForTest::Expired)
    );
    assert!(
        !emitted.load(Ordering::SeqCst),
        "a send_to that became ready after the deadline must not emit ciphertext"
    );
}

#[tokio::test(start_paused = true)]
async fn exact_deadline_ties_fail_closed() {
    let now = tokio::time::Instant::now();
    let polled = Arc::new(AtomicBool::new(false));
    let polled_send = Arc::clone(&polled);
    let outcome = frontend_app_ciphertext_send_until_expiry_for_test(
        Some(now),
        None,
        std::future::poll_fn(move |_| {
            polled_send.store(true, Ordering::SeqCst);
            std::task::Poll::Ready(3usize)
        }),
    )
    .await;
    assert_eq!(outcome, Err(FrontendAppSendRejectForTest::Expired));
    assert!(
        !polled.load(Ordering::SeqCst),
        "an exact-deadline tie must not poll the application send"
    );
}

#[tokio::test(start_paused = true)]
async fn dropping_cancel_during_a_socket_wait_emits_nothing() {
    let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel::<()>();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let emitted = Arc::new(AtomicBool::new(false));
    let emitted_send = Arc::clone(&emitted);
    let deadline = future_deadline(Duration::from_secs(30));
    let raced = tokio::spawn(async move {
        let mut cancel_rx = cancel_rx;
        frontend_app_ciphertext_send_until_expiry_for_test(
            Some(deadline),
            Some(&mut cancel_rx),
            async move {
                let _ = release_rx.await;
                emitted_send.store(true, Ordering::SeqCst);
                1usize
            },
        )
        .await
    });
    tokio::task::yield_now().await;
    tokio::task::yield_now().await;
    drop(cancel_tx);
    let _ = release_tx.send(());
    assert_eq!(
        raced.await.expect("join"),
        Err(FrontendAppSendRejectForTest::Cancelled)
    );
    assert!(
        !emitted.load(Ordering::SeqCst),
        "cancelling an in-flight send_to must drop it rather than emit ciphertext"
    );
}

#[tokio::test(start_paused = true)]
async fn success_completes_only_after_the_socket_accepts() {
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let accepted = Arc::new(AtomicBool::new(false));
    let accepted_send = Arc::clone(&accepted);
    let deadline = future_deadline(Duration::from_secs(30));
    let raced = tokio::spawn(async move {
        frontend_app_ciphertext_send_until_expiry_for_test(Some(deadline), None, async move {
            let _ = release_rx.await;
            accepted_send.store(true, Ordering::SeqCst);
        })
        .await
    });
    tokio::task::yield_now().await;
    tokio::task::yield_now().await;
    assert!(
        !accepted.load(Ordering::SeqCst),
        "success must not complete at enqueue; the socket wait is still pending"
    );
    let _ = release_tx.send(());
    assert_eq!(raced.await.expect("join"), Ok(()));
    assert!(accepted.load(Ordering::SeqCst));
}

#[tokio::test(start_paused = true)]
async fn unauthenticated_sends_have_no_timer() {
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let emitted = Arc::new(AtomicBool::new(false));
    let emitted_send = Arc::clone(&emitted);
    let raced = tokio::spawn(async move {
        frontend_app_ciphertext_send_until_expiry_for_test(None, None, async move {
            let _ = release_rx.await;
            emitted_send.store(true, Ordering::SeqCst);
            4usize
        })
        .await
    });
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(86_400)).await;
    let _ = release_tx.send(());
    assert_eq!(raced.await.expect("join"), Ok(4));
    assert!(
        emitted.load(Ordering::SeqCst),
        "unauthenticated DTLS keeps the no-timer send path"
    );
}

#[test]
fn driver_and_proxy_use_the_deadline_aware_actual_commit_api() {
    assert!(
        DTLS_SOURCE.contains("pub async fn send_committed("),
        "the terminating frontend sender must expose the actual-commit API"
    );
    assert!(
        DTLS_SOURCE.contains("earliest_frontend_app_send_deadline("),
        "per-call and session deadlines must compose with earliest-deadline-wins"
    );
    assert!(
        !DTLS_SOURCE.contains("deadline.or(session_deadline)"),
        "Option::or prefers the per-call deadline and must not be used"
    );
    assert!(
        DTLS_SOURCE.contains("fail_queued_frontend_app_sends("),
        "shutdown must fail queued application sends rather than encrypt them"
    );
    assert!(
        !DTLS_SOURCE.contains("Drain any queued replies before"),
        "shutdown must not drain queued application replies onto the wire"
    );
    let shutdown = DTLS_SOURCE
        .split("_ = shutdown_rx.recv() => {")
        .nth(1)
        .expect("server shutdown arm");
    let shutdown_body = shutdown.split("incoming_rx.recv()").next().expect("arm");
    assert!(
        shutdown_body.contains("fail_queued_frontend_app_sends("),
        "shutdown must complete queued sends as expired/cancelled/closed"
    );
    assert!(
        !shutdown_body.contains("send_application_data"),
        "shutdown must not encrypt queued application replies"
    );
    assert!(
        DTLS_SOURCE.contains("frontend_app_ciphertext_send_until_expiry("),
        "application ciphertext send_to must go through the deadline-aware helper"
    );
    assert!(
        DTLS_SOURCE.contains("struct PendingAppSend"),
        "client-side DtlsConnection completion semantics stay on PendingAppSend"
    );

    let helper = DTLS_SOURCE
        .split("pub(crate) async fn frontend_app_ciphertext_send_until_expiry")
        .nth(1)
        .expect("ciphertext helper")
        .split("\nfn fail_queued_frontend_app_sends")
        .next()
        .expect("helper body");
    let precheck = helper
        .find("admit_frontend_app_send(")
        .expect("already-elapsed admit");
    let authenticated = helper
        .split("(Some(at), None) =>")
        .nth(1)
        .expect("authenticated no-cancel arm");
    let biased = authenticated.find("biased;").expect("biased");
    let expiry = authenticated
        .find("tokio::time::sleep_until(at)")
        .expect("expiry arm");
    let send_arm = authenticated
        .find("result = send =>")
        .expect("send arm");
    assert!(
        precheck < helper.find("(Some(at), None) =>").expect("arm"),
        "an elapsed deadline is refused before polling send"
    );
    assert!(
        biased < expiry && expiry < send_arm,
        "expiry is biased first so exact-deadline ties fail closed"
    );
    assert!(
        !helper.contains("timeout_at("),
        "timeout_at would poll the inner send first"
    );
    assert!(
        helper.contains("(None, None) => Ok(send.await)"),
        "unauthenticated sends await with no timer"
    );

    let dtls_inner = UDP_PROXY_SOURCE
        .split("async fn handle_dtls_client_inner(")
        .nth(1)
        .expect("dtls inner");
    assert!(dtls_inner.contains("client_sender.send_committed("));
    assert!(dtls_inner.contains("bind_authorization_deadline(plan.at)"));
    assert!(!dtls_inner.contains("client_sender.send(&data)"));
    let send_call = dtls_inner
        .split("client_sender.send_committed(")
        .nth(1)
        .expect("commit call");
    assert!(
        send_call.contains("reply_auth_plan.map(|plan| plan.at)"),
        "the proxy must pass the admitted deadline into the actual-commit API"
    );
}
