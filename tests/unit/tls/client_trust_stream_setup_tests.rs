//! Post-admission TCP+TLS setup under frontend client-trust retirement
//! (issue #3857).
//!
//! Registration happens right after the frontend handshake, but the client leg
//! is not polled again until the relay starts. Everything in between — the
//! decrypted first-bytes read, DNS resolution, retry backoff, the backend dial
//! and its TLS/PROXY setup, and the forward of the decrypted prefix that
//! first-bytes inspection had already consumed — is an await the relay's
//! `TrustFencedStream` cannot reach. A withdrawal landing there used to retire
//! the session while setup carried on, and the buffered prefix was then written
//! straight to the backend under nothing but the credential's own lifetime.
//!
//! These cases drive the production seams directly:
//!
//! - a blocked setup stage is interrupted promptly, and its future is dropped
//!   rather than resumed;
//! - a connect-retry backoff is interrupted the same way;
//! - the buffered prefix is never written after retirement, whether the
//!   withdrawal lands before the forward or races a write parked on a full
//!   backend buffer;
//! - trust retirement and credential expiry stay independent, earliest-wins
//!   causes, with the operator's decision reported on a tie;
//! - settlement is client-side, health-neutral, redacted, and counted once.
//!
//! No sleeps: every case is driven by an explicit publication.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use ferrum_edge::_test_support::{
    PrefixForwardRejectForTest, StreamSetupInterruptForTest,
    tcp_forward_prefix_under_trust_fence_for_test, tcp_retry_backoff_within_bounds_for_test,
    tcp_settle_stream_trust_withdrawal_for_test, tcp_setup_stage_within_bounds_for_test,
};
use ferrum_edge::proxy::auth_lifetime::{StreamAuthDeadline, StreamAuthTermination};
use ferrum_edge::proxy::stream_error::{StreamSetupKind, find_stream_setup_error};
use ferrum_edge::tls::ClientTrustSessionGuard;
use ferrum_edge::tls::client_trust::{self, ClientTrustMaterial, ClientTrustScope};
use tokio::io::AsyncReadExt;

use super::client_trust_tests::isolated_registry;

const SCOPE: ClientTrustScope = ClientTrustScope::ProxyFrontend;

/// Long enough that the backend duplex buffer fills part way through.
const PREFIX: &[u8] = b"0123456789abcdef";

/// Arm the proxy-frontend domain and register one client-certificate
/// transport, exactly as the TCP+TLS path does after its handshake.
fn armed_transport() -> ClientTrustSessionGuard {
    client_trust::publish_accepted_material(
        SCOPE,
        ClientTrustMaterial::from_test_digest([1u8; 32]),
    );
    client_trust::capture(SCOPE)
        .expect("scope is armed")
        .register(true)
        .expect("a client-certificate transport registers")
}

/// Publish a candidate that drops the accepted anchor: authority narrows, so
/// every transport registered below the new generation is retired.
fn withdraw_client_ca() {
    client_trust::publish_accepted_material(
        SCOPE,
        ClientTrustMaterial::from_test_digest([2u8; 32]),
    );
}

fn fenced_total() -> u64 {
    client_trust::snapshot()
        .into_iter()
        .find(|row| row.scope == SCOPE)
        .map(|row| row.fenced)
        .expect("every scope is snapshotted")
}

fn elapsed_plan(termination: StreamAuthTermination) -> Option<StreamAuthDeadline> {
    Some(StreamAuthDeadline {
        at: tokio::time::Instant::now() - Duration::from_secs(1),
        termination,
    })
}

/// A setup stage that never completes and records whether it was dropped.
struct BlockedStage(Arc<AtomicBool>);

impl Future for BlockedStage {
    type Output = ();

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
        Poll::Pending
    }
}

impl Drop for BlockedStage {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

/// A setup stage that records whether it was ever polled.
struct ObservedStage(Arc<AtomicBool>);

impl Future for ObservedStage {
    type Output = ();

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
        self.0.store(true, Ordering::SeqCst);
        Poll::Ready(())
    }
}

// ---------------------------------------------------------------------------
// Setup stages
// ---------------------------------------------------------------------------

#[tokio::test]
#[allow(clippy::await_holding_lock)] // the process-global registry is serialized for the whole case
async fn an_already_withdrawn_transport_never_polls_a_setup_stage() {
    let _guard = isolated_registry();
    let transport = armed_transport();
    withdraw_client_ca();
    assert!(transport.session().is_retired());

    let polled = Arc::new(AtomicBool::new(false));
    let stage = ObservedStage(Arc::clone(&polled));
    let session = transport.session();
    let outcome = tcp_setup_stage_within_bounds_for_test(None, Some(session), stage).await;

    assert_eq!(
        outcome.unwrap_err(),
        StreamSetupInterruptForTest::TrustWithdrawn
    );
    assert!(
        !polled.load(Ordering::SeqCst),
        "a withdrawn transport must not run another setup stage at all"
    );
}

#[tokio::test]
#[allow(clippy::await_holding_lock)] // the process-global registry is serialized for the whole case
async fn a_withdrawal_interrupts_a_blocked_post_admission_setup_stage() {
    let _guard = isolated_registry();
    let transport = armed_transport();
    let dropped = Arc::new(AtomicBool::new(false));
    let stage = BlockedStage(Arc::clone(&dropped));
    let session = transport.session();

    // The stage stands in for DNS resolution, the backend dial, or the backend
    // TLS handshake: it is parked, and only the withdrawal can end it.
    let (outcome, ()) = tokio::join!(
        tcp_setup_stage_within_bounds_for_test(None, Some(session), stage),
        async {
            tokio::task::yield_now().await;
            withdraw_client_ca();
        }
    );

    assert_eq!(
        outcome.unwrap_err(),
        StreamSetupInterruptForTest::TrustWithdrawn
    );
    assert!(
        dropped.load(Ordering::SeqCst),
        "the interrupted stage must be dropped, not left to finish"
    );
}

#[tokio::test]
#[allow(clippy::await_holding_lock)] // the process-global registry is serialized for the whole case
async fn a_withdrawal_interrupts_a_connect_retry_backoff() {
    let _guard = isolated_registry();
    let transport = armed_transport();
    let session = transport.session();
    let backoff = Duration::from_secs(3600);

    // A retry backoff is the longest unattended setup wait there is. The clock
    // is left alone: the case only completes if the withdrawal — not the delay
    // — is what returns.
    let (outcome, ()) = tokio::join!(
        tcp_retry_backoff_within_bounds_for_test(None, Some(session), backoff),
        async {
            tokio::task::yield_now().await;
            withdraw_client_ca();
        }
    );

    assert_eq!(
        outcome.unwrap_err(),
        StreamSetupInterruptForTest::TrustWithdrawn
    );
}

#[tokio::test]
async fn an_unregistered_transport_runs_setup_stages_unbounded() {
    // Plaintext, kTLS, and anonymous-TLS connections register nothing, so they
    // keep the previous behaviour and poll no retirement future at all.
    let polled = Arc::new(AtomicBool::new(false));
    let stage = ObservedStage(Arc::clone(&polled));
    let outcome = tcp_setup_stage_within_bounds_for_test(None, None, stage).await;

    assert!(outcome.is_ok());
    assert!(polled.load(Ordering::SeqCst));
}

#[tokio::test]
#[allow(clippy::await_holding_lock)] // the process-global registry is serialized for the whole case
async fn an_elapsed_credential_still_settles_as_an_authorization_expiry() {
    let _guard = isolated_registry();
    let transport = armed_transport();
    let session = transport.session();
    let plan = elapsed_plan(StreamAuthTermination::CredentialExpired);

    // Trust still stands, so the credential's own lifetime keeps its own
    // termination class: the two bounds are independent.
    let stage = std::future::pending::<()>();
    let outcome = tcp_setup_stage_within_bounds_for_test(plan, Some(session), stage).await;

    let expected = StreamAuthTermination::CredentialExpired;
    assert_eq!(
        outcome.unwrap_err(),
        StreamSetupInterruptForTest::AuthorizationExpired(expected)
    );
}

#[tokio::test]
#[allow(clippy::await_holding_lock)] // the process-global registry is serialized for the whole case
async fn a_withdrawal_outranks_a_credential_that_also_elapsed() {
    let _guard = isolated_registry();
    let transport = armed_transport();
    withdraw_client_ca();
    let session = transport.session();
    let plan = elapsed_plan(StreamAuthTermination::AuthenticatedStreamMaxLifetime);

    // Both bounds are eligible at this observation. An authority decision the
    // operator has already taken outranks a timer that merely also elapsed —
    // the ordering the WebSocket stop arbiter and the DTLS delivery fence use.
    let stage = std::future::pending::<()>();
    let outcome = tcp_setup_stage_within_bounds_for_test(plan, Some(session), stage).await;

    assert_eq!(
        outcome.unwrap_err(),
        StreamSetupInterruptForTest::TrustWithdrawn
    );
}

// ---------------------------------------------------------------------------
// The buffered decrypted prefix
// ---------------------------------------------------------------------------

#[tokio::test]
#[allow(clippy::await_holding_lock)] // the process-global registry is serialized for the whole case
async fn a_withdrawn_transport_forwards_no_inspected_prefix_byte() {
    let _guard = isolated_registry();
    let transport = armed_transport();
    withdraw_client_ca();
    let session = transport.session();

    let (mut backend, mut peer) = tokio::io::duplex(64);
    let writer = &mut backend;
    let outcome =
        tcp_forward_prefix_under_trust_fence_for_test(writer, PREFIX, Some(session)).await;

    assert!(matches!(
        outcome,
        Err(PrefixForwardRejectForTest::TrustWithdrawn)
    ));
    let mut seen = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_millis(50), peer.read(&mut seen)).await;
    assert!(
        read.is_err(),
        "not one already-decrypted client byte may reach the backend after retirement"
    );
}

#[tokio::test]
#[allow(clippy::await_holding_lock)] // the process-global registry is serialized for the whole case
async fn a_withdrawal_racing_the_prefix_write_abandons_the_remainder() {
    let _guard = isolated_registry();
    let transport = armed_transport();
    let session = transport.session();

    // The backend never reads, so the write parks with the prefix half
    // delivered — the exact window in which a withdrawal used to stay invisible
    // until the relay started.
    let (mut backend, mut peer) = tokio::io::duplex(4);
    let writer = &mut backend;
    let (outcome, ()) = tokio::join!(
        tcp_forward_prefix_under_trust_fence_for_test(writer, PREFIX, Some(session)),
        async {
            tokio::task::yield_now().await;
            withdraw_client_ca();
        }
    );

    assert!(matches!(
        outcome,
        Err(PrefixForwardRejectForTest::TrustWithdrawn)
    ));
    let mut buffered = [0u8; 4];
    peer.read_exact(&mut buffered)
        .await
        .expect("bytes written before the withdrawal stay written");
    assert_eq!(&buffered, b"0123");
    let mut extra = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_millis(50), peer.read(&mut extra)).await;
    assert!(
        read.is_err(),
        "the rest of the prefix must be abandoned, not completed after retirement"
    );
}

#[tokio::test]
#[allow(clippy::await_holding_lock)] // the process-global registry is serialized for the whole case
async fn a_live_transport_forwards_the_whole_inspected_prefix() {
    let _guard = isolated_registry();
    let transport = armed_transport();
    let session = transport.session();

    let (mut backend, mut peer) = tokio::io::duplex(64);
    let writer = &mut backend;
    tcp_forward_prefix_under_trust_fence_for_test(writer, PREFIX, Some(session))
        .await
        .expect("a live transport forwards its prefix unchanged");

    let mut seen = [0u8; 16];
    peer.read_exact(&mut seen).await.expect("peer read");
    assert_eq!(&seen, PREFIX);
}

#[tokio::test]
#[allow(clippy::await_holding_lock)] // the process-global registry is serialized for the whole case
async fn a_backend_write_failure_stays_backend_evidence() {
    let _guard = isolated_registry();
    let transport = armed_transport();
    let session = transport.session();

    // Trust still stands, so a failing backend leg reports as backend evidence
    // rather than borrowing the health-neutral trust refusal.
    let (mut backend, peer) = tokio::io::duplex(64);
    drop(peer);
    let writer = &mut backend;
    let outcome =
        tcp_forward_prefix_under_trust_fence_for_test(writer, PREFIX, Some(session)).await;

    assert!(matches!(outcome, Err(PrefixForwardRejectForTest::Io(_))));
}

// ---------------------------------------------------------------------------
// Settlement
// ---------------------------------------------------------------------------

#[test]
fn a_setup_withdrawal_settles_once_and_stays_client_side() {
    let _guard = isolated_registry();
    let transport = armed_transport();
    withdraw_client_ca();
    let session = transport.session();
    let before = fenced_total();

    let latch = AtomicBool::new(false);
    let error = tcp_settle_stream_trust_withdrawal_for_test(Some(session), &latch);
    let repeat = tcp_settle_stream_trust_withdrawal_for_test(Some(session), &latch);

    assert_eq!(
        fenced_total(),
        before + 1,
        "a connection settles its withdrawal once however many fences observe it"
    );

    for settled in [&error, &repeat] {
        let kind = find_stream_setup_error(settled)
            .expect("the refusal carries a typed stream-setup kind")
            .kind;
        assert_eq!(kind, StreamSetupKind::ClientTrustWithdrawn);
        assert!(
            kind.is_client_side(),
            "a withdrawn client-trust decision is a local authorization event, \
             never evidence about the upstream"
        );
        assert_eq!(
            settled.to_string(),
            "Frontend client trust withdrawn during setup before any backend byte was written"
        );
    }
}
