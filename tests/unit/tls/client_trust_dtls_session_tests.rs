//! Post-admission ACCEPTED-DTLS work under frontend client-trust retirement
//! (issue #3857).
//!
//! The DTLS session driver fences its own plaintext delivery, accept handoff,
//! and ciphertext sends, then exits and closes its channels. That is not a
//! retirement fence for the DETACHED proxy handler the connection was already
//! delivered to: it runs arbitrary awaited `on_stream_connect` hooks, then
//! resolves a backend, takes a circuit-breaker slot, awaits DNS, dials plain
//! UDP or performs a backend DTLS handshake, and starts two relay tasks. Each
//! of those can be parked when the withdrawal lands and then resume and commit
//! backend work under a decision the operator has revoked.
//!
//! These cases drive the production seams directly:
//!
//! - a blocked accepted-DTLS `on_stream_connect` hook is dropped mid-poll, no
//!   later hook runs, and the chain hands back its admission permits;
//! - an already-retired accepted connection starts no hook and never even
//!   BUILDS a backend setup stage;
//! - a withdrawal during DNS / backend setup drops the stage and releases a
//!   claimed HALF_OPEN probe slot NEUTRALLY;
//! - a datagram parked in a client-to-backend hook cannot commit to the backend
//!   afterwards, and a backend reply parked in its hook is not delivered;
//! - trust retirement and credential expiry stay independent, earliest-wins
//!   causes with the operator's decision reported on a tie;
//! - anonymous / static DTLS is unchanged and polls no retirement future;
//! - the fence counter is recorded exactly once for the connection however many
//!   boundaries observe the same withdrawal, and every diagnostic is a fixed,
//!   redacted literal.
//!
//! No sleeps: every case is driven by an explicit publication.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use ferrum_edge::_test_support as support;
use ferrum_edge::plugins::{
    Direction, DisconnectCause, Plugin, PluginResult, StreamConnectionContext, UdpDatagramContext,
    UdpDatagramVerdict,
};
use ferrum_edge::proxy::auth_lifetime::{
    StreamAuthDeadline, StreamAuthTermination, StreamAuthTerminationLatch,
};
use ferrum_edge::proxy::stream_error::StreamSetupKind;
use ferrum_edge::retry::ErrorClass;
use ferrum_edge::tls::ClientTrustSessionGuard;
use ferrum_edge::tls::client_trust::{self, ClientTrustMaterial, ClientTrustScope};
use ferrum_edge::{BackendScheme, ConsumerIndex};

use super::client_trust_tests::isolated_registry;

/// The accepted session's frontend client-trust fence, as the `udp_proxy`
/// handler and both relay directions carry it.
type Fence = support::DtlsTrustFenceForTest;
/// How the accepted-DTLS `on_stream_connect` chain ended.
type ConnectOutcome = support::DtlsStreamConnectOutcomeForTest;
/// Why one relayed DTLS datagram stage was interrupted.
type RelayInterrupt = support::DtlsRelayInterruptForTest;
/// Outcome of one backend-to-client datagram after its raced hook chain.
type ReplyCommit = support::DtlsReplyDatagramCommitForTest;
/// The classified settlement a post-admission bound returns.
type Settlement = support::DtlsAuthorizationExpiryForTest;

const SCOPE: ClientTrustScope = ClientTrustScope::FrontendDtls;

/// The one client-visible / log-visible refusal for a fenced accepted DTLS
/// session. Fixed, compiled-in, and free of any certificate field.
const FENCED_MESSAGE: &str = "Frontend client trust withdrawn during setup (DTLS session) with no \
                              further backend datagram forwarded";

// ---------------------------------------------------------------------------
// Production seams, wrapped so every case reads the same way
// ---------------------------------------------------------------------------

/// The production accepted-DTLS `on_stream_connect` chain, under this session's
/// fence.
async fn run_connect_chain(
    plugins: &[Arc<dyn Plugin>],
    ctx: &mut StreamConnectionContext,
    fence: &Fence,
) -> ConnectOutcome {
    support::dtls_stream_connect_chain_under_trust_fence_for_test(plugins, ctx, fence).await
}

/// One post-admission backend-setup stage (DNS, the backend UDP connect, the
/// backend DTLS handshake) under BOTH post-admission bounds.
async fn run_setup_stage<S, F>(
    plan: Option<StreamAuthDeadline>,
    fence: &Fence,
    stage: S,
) -> Result<F::Output, Settlement>
where
    S: FnOnce() -> F,
    F: Future,
{
    support::dtls_setup_stage_under_bounds_for_test(plan, fence, stage).await
}

/// One client-to-backend relay stage — receive, an awaited per-datagram hook,
/// or the backend commit — under both post-admission bounds.
async fn run_c2b<F>(
    plan: Option<StreamAuthDeadline>,
    latch: &StreamAuthTerminationLatch,
    fence: &Fence,
    stage: F,
) -> Result<F::Output, RelayInterrupt>
where
    F: Future,
{
    support::dtls_c2b_under_bounds_for_test(plan, latch, fence, stage).await
}

/// The backend-to-client `on_udp_datagram` chain under both bounds.
async fn run_reply_hooks(
    plugins: &[Arc<dyn Plugin>],
    payload: &[u8],
    plan: Option<StreamAuthDeadline>,
    fence: &Fence,
) -> ReplyCommit {
    support::dtls_reply_commit_after_backend_hooks_for_test(plugins, payload, plan, fence).await
}

/// Install one stream admission permit whose release increments `released`.
fn hold_permit(ctx: &mut StreamConnectionContext, released: Arc<AtomicUsize>) {
    support::stream_ctx_hold_admission_permit_for_test(ctx, released);
}

// ---------------------------------------------------------------------------
// Trust-domain helpers
// ---------------------------------------------------------------------------

/// Arm the frontend-DTLS domain and register one client-certificate session,
/// exactly as the DTLS driver does after validating the presented chain.
fn armed_session() -> ClientTrustSessionGuard {
    let material = ClientTrustMaterial::from_test_digest([1u8; 32]);
    client_trust::publish_accepted_material(SCOPE, material);
    client_trust::capture(SCOPE)
        .expect("scope is armed")
        .register(true)
        .expect("a client-certificate session registers")
}

/// Publish a candidate that drops the accepted anchor: authority narrows, so
/// every session registered below the new generation is retired.
fn withdraw_client_ca() {
    let material = ClientTrustMaterial::from_test_digest([2u8; 32]);
    client_trust::publish_accepted_material(SCOPE, material);
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

// ---------------------------------------------------------------------------
// Stage and plugin doubles
// ---------------------------------------------------------------------------

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

/// A stage that records whether it was ever polled.
struct ObservedStage(Arc<AtomicBool>);

impl Future for ObservedStage {
    type Output = ();

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
        self.0.store(true, Ordering::SeqCst);
        Poll::Ready(())
    }
}

/// Records its own drop, so a case can prove a future was dropped rather than
/// left to finish.
struct DropWitness(Arc<AtomicBool>);

impl Drop for DropWitness {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

/// A stream-connect hook that parks forever, standing in for any plugin whose
/// hook awaits arbitrary I/O (a remote authorization call, a throttle wait).
struct BlockedStreamConnect {
    entered: Arc<AtomicBool>,
    dropped: Arc<AtomicBool>,
}

#[async_trait]
impl Plugin for BlockedStreamConnect {
    fn name(&self) -> &str {
        "test_blocked_dtls_stream_connect"
    }

    async fn on_stream_connect(&self, _ctx: &mut StreamConnectionContext) -> PluginResult {
        let _witness = DropWitness(Arc::clone(&self.dropped));
        self.entered.store(true, Ordering::SeqCst);
        std::future::pending::<()>().await;
        PluginResult::Continue
    }
}

/// A stream-connect hook that records whether it ran at all.
struct RecordingStreamConnect(Arc<AtomicBool>);

#[async_trait]
impl Plugin for RecordingStreamConnect {
    fn name(&self) -> &str {
        "test_recording_dtls_stream_connect"
    }

    async fn on_stream_connect(&self, _ctx: &mut StreamConnectionContext) -> PluginResult {
        self.0.store(true, Ordering::SeqCst);
        PluginResult::Continue
    }
}

/// A stream-connect hook that withdraws the client CA while it runs, so the
/// withdrawal lands as the hook returns rather than while it is pending.
struct WithdrawingStreamConnect(Arc<AtomicBool>);

#[async_trait]
impl Plugin for WithdrawingStreamConnect {
    fn name(&self) -> &str {
        "test_withdrawing_dtls_stream_connect"
    }

    async fn on_stream_connect(&self, _ctx: &mut StreamConnectionContext) -> PluginResult {
        self.0.store(true, Ordering::SeqCst);
        withdraw_client_ca();
        PluginResult::Continue
    }
}

/// A per-datagram hook that parks forever and records its own drop.
struct BlockedDatagramHook {
    entered: Arc<AtomicBool>,
    dropped: Arc<AtomicBool>,
}

#[async_trait]
impl Plugin for BlockedDatagramHook {
    fn name(&self) -> &str {
        "test_blocked_dtls_datagram"
    }

    fn requires_udp_datagram_hooks(&self) -> bool {
        true
    }

    async fn on_udp_datagram(&self, _ctx: &UdpDatagramContext<'_>) -> UdpDatagramVerdict {
        let _witness = DropWitness(Arc::clone(&self.dropped));
        self.entered.store(true, Ordering::SeqCst);
        std::future::pending::<()>().await;
        UdpDatagramVerdict::Forward
    }
}

fn dtls_stream_ctx() -> StreamConnectionContext {
    StreamConnectionContext::new(
        "203.0.113.9".to_string(),
        "203.0.113.9".to_string(),
        "dtls-proxy".to_string(),
        Some("DTLS Proxy".to_string()),
        5684,
        BackendScheme::Dtls,
        Arc::new(ConsumerIndex::new(&[])),
    )
}

// ---------------------------------------------------------------------------
// The accepted-session `on_stream_connect` chain
// ---------------------------------------------------------------------------

#[tokio::test]
#[allow(clippy::await_holding_lock)] // the process-global registry is serialized for the case
async fn a_withdrawal_interrupts_a_blocked_accepted_dtls_hook() {
    let _guard = isolated_registry();
    let session = armed_session();
    let fence = Fence::new(Some(session.session()));

    let entered = Arc::new(AtomicBool::new(false));
    let dropped = Arc::new(AtomicBool::new(false));
    let later_ran = Arc::new(AtomicBool::new(false));
    let plugins: Vec<Arc<dyn Plugin>> = vec![
        Arc::new(BlockedStreamConnect {
            entered: Arc::clone(&entered),
            dropped: Arc::clone(&dropped),
        }),
        Arc::new(RecordingStreamConnect(Arc::clone(&later_ran))),
    ];

    let mut ctx = dtls_stream_ctx();
    // Model a hook that already took an admission permit before the blocked one
    // parked: the fence must hand it back, exactly once.
    let released = Arc::new(AtomicUsize::new(0));
    hold_permit(&mut ctx, Arc::clone(&released));
    let before = fenced_total();

    let (outcome, ()) = tokio::join!(run_connect_chain(&plugins, &mut ctx, &fence), async {
        // No sleep: the blocked hook is parked, so the very next scheduling
        // point is the explicit publication that retires the session.
        tokio::task::yield_now().await;
        withdraw_client_ca();
    });

    assert_eq!(outcome, ConnectOutcome::TrustWithdrawn);
    assert!(
        entered.load(Ordering::SeqCst),
        "the case is only meaningful if the blocked hook really started"
    );
    assert!(
        dropped.load(Ordering::SeqCst),
        "the in-flight hook future must be dropped, not left to finish"
    );
    assert!(
        !later_ran.load(Ordering::SeqCst),
        "no later hook may run once the trust decision is withdrawn"
    );
    assert_eq!(
        released.load(Ordering::SeqCst),
        1,
        "every admission permit the chain took is released exactly once"
    );
    assert_eq!(fenced_total(), before + 1);

    // Draining the permits was the release; dropping the context is not a
    // second one.
    drop(ctx);
    assert_eq!(released.load(Ordering::SeqCst), 1);
}

#[tokio::test]
#[allow(clippy::await_holding_lock)] // the process-global registry is serialized for the case
async fn an_already_retired_connection_starts_no_stream_connect_hook() {
    let _guard = isolated_registry();
    let session = armed_session();
    withdraw_client_ca();
    let fence = Fence::new(Some(session.session()));
    assert!(fence.is_retired());

    let ran = Arc::new(AtomicBool::new(false));
    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(RecordingStreamConnect(Arc::clone(&ran)))];
    let mut ctx = dtls_stream_ctx();
    let released = Arc::new(AtomicUsize::new(0));
    hold_permit(&mut ctx, Arc::clone(&released));

    let outcome = run_connect_chain(&plugins, &mut ctx, &fence).await;

    assert_eq!(outcome, ConnectOutcome::TrustWithdrawn);
    assert!(
        !ran.load(Ordering::SeqCst),
        "a retired accepted connection must not start a hook at all"
    );
    assert_eq!(released.load(Ordering::SeqCst), 1);
}

#[tokio::test]
#[allow(clippy::await_holding_lock)] // the process-global registry is serialized for the case
async fn a_withdrawal_landing_as_the_last_hook_returns_is_not_admitted() {
    let _guard = isolated_registry();
    let session = armed_session();
    let fence = Fence::new(Some(session.session()));

    // The only hook withdraws the CA while it runs, so the chain completes and
    // the withdrawal is observed by the trailing re-check the chain still owns
    // rather than by a mid-poll race.
    let ran = Arc::new(AtomicBool::new(false));
    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(WithdrawingStreamConnect(Arc::clone(&ran)))];
    let mut ctx = dtls_stream_ctx();
    let released = Arc::new(AtomicUsize::new(0));
    hold_permit(&mut ctx, Arc::clone(&released));
    let before = fenced_total();

    let outcome = run_connect_chain(&plugins, &mut ctx, &fence).await;

    assert!(
        ran.load(Ordering::SeqCst),
        "the case is only meaningful if the hook really ran to completion"
    );
    assert_eq!(outcome, ConnectOutcome::TrustWithdrawn);
    assert_eq!(released.load(Ordering::SeqCst), 1);
    assert_eq!(fenced_total(), before + 1);
}

#[tokio::test]
#[allow(clippy::await_holding_lock)] // the process-global registry is serialized for the case
async fn a_live_accepted_session_runs_the_whole_connect_chain() {
    let _guard = isolated_registry();
    let session = armed_session();
    let fence = Fence::new(Some(session.session()));

    let first = Arc::new(AtomicBool::new(false));
    let second = Arc::new(AtomicBool::new(false));
    let plugins: Vec<Arc<dyn Plugin>> = vec![
        Arc::new(RecordingStreamConnect(Arc::clone(&first))),
        Arc::new(RecordingStreamConnect(Arc::clone(&second))),
    ];
    let mut ctx = dtls_stream_ctx();
    let released = Arc::new(AtomicUsize::new(0));
    hold_permit(&mut ctx, Arc::clone(&released));
    let before = fenced_total();

    let outcome = run_connect_chain(&plugins, &mut ctx, &fence).await;

    assert_eq!(outcome, ConnectOutcome::Admitted);
    assert!(first.load(Ordering::SeqCst) && second.load(Ordering::SeqCst));
    assert_eq!(
        released.load(Ordering::SeqCst),
        0,
        "an admitted session keeps its permits for the relay"
    );
    assert_eq!(fenced_total(), before);
}

// ---------------------------------------------------------------------------
// Post-admission backend setup
// ---------------------------------------------------------------------------

#[tokio::test]
#[allow(clippy::await_holding_lock)] // the process-global registry is serialized for the case
async fn a_withdrawal_during_backend_setup_drops_it_and_frees_the_probe() {
    let _guard = isolated_registry();
    let session = armed_session();
    let fence = Fence::new(Some(session.session()));

    let dropped = Arc::new(AtomicBool::new(false));
    let dropped_stage = Arc::clone(&dropped);
    let before = fenced_total();

    // The stage stands in for DNS resolution, the backend UDP connect, or the
    // backend DTLS handshake: it is parked, and only the withdrawal ends it.
    let stage = || BlockedStage(dropped_stage);
    let (outcome, ()) = tokio::join!(run_setup_stage(None, &fence, stage), async {
        tokio::task::yield_now().await;
        withdraw_client_ca();
    });

    let settled = outcome.expect_err("a retired session establishes no backend");
    assert!(
        dropped.load(Ordering::SeqCst),
        "the interrupted setup stage must be dropped, not left to finish"
    );
    assert_eq!(settled.probe_releases, 1, "the HALF_OPEN probe slot is freed once");
    let kind = settled.setup_kind.expect("a typed stream-setup kind");
    assert_eq!(kind, StreamSetupKind::ClientTrustWithdrawn);
    assert!(
        kind.is_client_side(),
        "an operator-side authorization decision is never backend evidence"
    );
    assert_eq!(settled.disconnect_cause, DisconnectCause::RecvError);
    assert_eq!(settled.disconnect_direction, Direction::ClientToBackend);
    assert_eq!(settled.error_class, ErrorClass::RequestError);
    assert_eq!(settled.error, FENCED_MESSAGE);
    assert!(
        settled.metadata.is_empty(),
        "a trust withdrawal is not a credential expiry and stamps no class"
    );
    assert_eq!(fenced_total(), before + 1);
}

#[tokio::test]
#[allow(clippy::await_holding_lock)] // the process-global registry is serialized for the case
async fn an_already_retired_session_never_builds_a_setup_stage() {
    let _guard = isolated_registry();
    let session = armed_session();
    withdraw_client_ca();
    let fence = Fence::new(Some(session.session()));

    let built = Arc::new(AtomicBool::new(false));
    let polled = Arc::new(AtomicBool::new(false));
    let built_stage = Arc::clone(&built);
    let polled_stage = Arc::clone(&polled);
    let stage = || {
        built_stage.store(true, Ordering::SeqCst);
        ObservedStage(polled_stage)
    };

    let outcome = run_setup_stage(None, &fence, stage).await;
    let settled = outcome.expect_err("a retired session resolves and dials nothing");

    assert!(!built.load(Ordering::SeqCst), "a retired session must not even construct the stage");
    assert!(!polled.load(Ordering::SeqCst));
    assert_eq!(settled.setup_kind, Some(StreamSetupKind::ClientTrustWithdrawn));
    assert_eq!(settled.probe_releases, 1);
}

#[tokio::test]
#[allow(clippy::await_holding_lock)] // the process-global registry is serialized for the case
async fn a_withdrawal_outranks_a_credential_that_also_elapsed() {
    let _guard = isolated_registry();
    let session = armed_session();
    withdraw_client_ca();
    let fence = Fence::new(Some(session.session()));
    let plan = elapsed_plan(StreamAuthTermination::AuthenticatedStreamMaxLifetime);

    // Both post-admission bounds are eligible at this one observation. An
    // authority decision the operator has already taken outranks a timer that
    // merely also elapsed.
    let stage = std::future::pending::<()>;
    let outcome = run_setup_stage(plan, &fence, stage).await;
    let settled = outcome.expect_err("a retired session establishes no backend");

    assert_eq!(settled.setup_kind, Some(StreamSetupKind::ClientTrustWithdrawn));
}

#[tokio::test]
#[allow(clippy::await_holding_lock)] // the process-global registry is serialized for the case
async fn an_elapsed_credential_alone_still_settles_as_an_expiry() {
    let _guard = isolated_registry();
    let session = armed_session();
    let fence = Fence::new(Some(session.session()));
    let plan = elapsed_plan(StreamAuthTermination::CredentialExpired);

    // Trust still stands, so adding the trust bound did not absorb the
    // credential's own lifetime: the two stay independent causes.
    let stage = std::future::pending::<()>;
    let outcome = run_setup_stage(plan, &fence, stage).await;
    let settled = outcome.expect_err("an elapsed credential establishes no backend");

    assert_eq!(settled.setup_kind, Some(StreamSetupKind::AuthorizationExpired));
}

// ---------------------------------------------------------------------------
// The relay directions
// ---------------------------------------------------------------------------

#[tokio::test]
#[allow(clippy::await_holding_lock)] // the process-global registry is serialized for the case
async fn a_datagram_parked_in_a_hook_cannot_commit_after_withdrawal() {
    let _guard = isolated_registry();
    let session = armed_session();
    let fence = Fence::new(Some(session.session()));
    let latch = StreamAuthTerminationLatch::default();

    // The hook is parked, holding the datagram that was received while the
    // decision still stood. Only the withdrawal can end it.
    let committed = Arc::new(AtomicBool::new(false));
    let dropped = Arc::new(AtomicBool::new(false));
    let committed_stage = Arc::clone(&committed);
    let dropped_stage = Arc::clone(&dropped);
    let stage = async move {
        let _witness = DropWitness(dropped_stage);
        std::future::pending::<()>().await;
        committed_stage.store(true, Ordering::SeqCst);
    };

    let (outcome, ()) = tokio::join!(run_c2b(None, &latch, &fence, stage), async {
        tokio::task::yield_now().await;
        withdraw_client_ca();
    });

    assert_eq!(
        outcome.expect_err("a retired session commits nothing"),
        RelayInterrupt::TrustWithdrawn
    );
    assert!(
        dropped.load(Ordering::SeqCst),
        "the pending hook/commit future must be dropped, not resumed"
    );
    assert!(
        !committed.load(Ordering::SeqCst),
        "a datagram received before the withdrawal must not reach the backend"
    );
}

#[tokio::test]
#[allow(clippy::await_holding_lock)] // the process-global registry is serialized for the case
async fn an_already_retired_relay_never_polls_a_client_stage() {
    let _guard = isolated_registry();
    let session = armed_session();
    withdraw_client_ca();
    let fence = Fence::new(Some(session.session()));
    let latch = StreamAuthTerminationLatch::default();

    let polled = Arc::new(AtomicBool::new(false));
    let stage = ObservedStage(Arc::clone(&polled));
    let outcome = run_c2b(None, &latch, &fence, stage).await;

    assert_eq!(
        outcome.expect_err("a retired session commits nothing"),
        RelayInterrupt::TrustWithdrawn
    );
    assert!(!polled.load(Ordering::SeqCst));
}

#[tokio::test]
#[allow(clippy::await_holding_lock)] // the process-global registry is serialized for the case
async fn a_backend_reply_parked_in_a_hook_is_not_delivered() {
    let _guard = isolated_registry();
    let session = armed_session();
    let fence = Fence::new(Some(session.session()));

    let entered = Arc::new(AtomicBool::new(false));
    let dropped = Arc::new(AtomicBool::new(false));
    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(BlockedDatagramHook {
        entered: Arc::clone(&entered),
        dropped: Arc::clone(&dropped),
    })];

    let (commit, ()) = tokio::join!(run_reply_hooks(&plugins, b"reply", None, &fence), async {
        tokio::task::yield_now().await;
        withdraw_client_ca();
    });

    assert_eq!(commit, ReplyCommit::TrustWithdrawn);
    assert!(entered.load(Ordering::SeqCst));
    assert!(
        dropped.load(Ordering::SeqCst),
        "the pending reply hook must be dropped, not allowed to deliver"
    );
}

#[tokio::test]
#[allow(clippy::await_holding_lock)] // the process-global registry is serialized for the case
async fn a_live_relay_still_commits_in_both_directions() {
    let _guard = isolated_registry();
    let session = armed_session();
    let fence = Fence::new(Some(session.session()));
    let latch = StreamAuthTerminationLatch::default();

    let polled = Arc::new(AtomicBool::new(false));
    let stage = ObservedStage(Arc::clone(&polled));
    run_c2b(None, &latch, &fence, stage)
        .await
        .expect("a live session forwards normally");
    assert!(polled.load(Ordering::SeqCst));

    let none: Vec<Arc<dyn Plugin>> = Vec::new();
    let commit = run_reply_hooks(&none, b"reply", None, &fence).await;
    assert_eq!(commit, ReplyCommit::Commit);
}

// ---------------------------------------------------------------------------
// Anonymous / static DTLS, and once-only fixed-cardinality settlement
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_anonymous_dtls_session_arms_no_fence_and_is_unchanged() {
    // No registry guard: an unarmed fence must not touch the trust domain at
    // all — no retirement future, no waker, no atomic.
    let fence = Fence::new(None);
    assert!(!fence.is_armed());
    assert!(!fence.is_retired());

    let ran = Arc::new(AtomicBool::new(false));
    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(RecordingStreamConnect(Arc::clone(&ran)))];
    let mut ctx = dtls_stream_ctx();
    let outcome = run_connect_chain(&plugins, &mut ctx, &fence).await;
    assert_eq!(outcome, ConnectOutcome::Admitted);
    assert!(ran.load(Ordering::SeqCst));

    let polled = Arc::new(AtomicBool::new(false));
    let stage = || ObservedStage(Arc::clone(&polled));
    run_setup_stage(None, &fence, stage)
        .await
        .expect("an anonymous session runs setup unbounded");
    assert!(polled.load(Ordering::SeqCst));

    let latch = StreamAuthTerminationLatch::default();
    let relayed = Arc::new(AtomicBool::new(false));
    let stage = ObservedStage(Arc::clone(&relayed));
    run_c2b(None, &latch, &fence, stage)
        .await
        .expect("an anonymous session relays unbounded");
    assert!(relayed.load(Ordering::SeqCst));

    // An unarmed fence records nothing at all, however often it is settled.
    fence.record_fenced_once();
    fence.record_fenced_once();
}

#[tokio::test]
#[allow(clippy::await_holding_lock)] // the process-global registry is serialized for the case
async fn the_connection_fence_counter_is_recorded_exactly_once() {
    let _guard = isolated_registry();
    let session = armed_session();
    withdraw_client_ca();
    let fence = Fence::new(Some(session.session()));
    let latch = StreamAuthTerminationLatch::default();
    let before = fenced_total();

    // Every boundary on this connection observes the SAME withdrawal: the
    // admission chain, a setup stage, the pre-relay gate, and both relay
    // directions. They share one latch, so the fixed-cardinality counter moves
    // once.
    let plugins: Vec<Arc<dyn Plugin>> = Vec::new();
    let mut ctx = dtls_stream_ctx();
    let chain = run_connect_chain(&plugins, &mut ctx, &fence).await;
    assert_eq!(chain, ConnectOutcome::TrustWithdrawn);

    let stage = std::future::pending::<()>;
    let outcome = run_setup_stage(None, &fence, stage).await;
    let settled = outcome.expect_err("a retired session establishes no backend");

    let parked = std::future::pending::<()>();
    let relayed = run_c2b(None, &latch, &fence, parked).await;
    assert_eq!(
        relayed.expect_err("a retired session commits nothing"),
        RelayInterrupt::TrustWithdrawn
    );

    let repeat = fence.settle_withdrawal();
    fence.record_fenced_once();

    assert_eq!(fenced_total(), before + 1, "one fence observation per connection");

    // Diagnostics are fixed-cardinality and redacted: one compiled-in literal,
    // identical at every boundary, naming no certificate field, no trust
    // material, no path, and no generation.
    for message in [settled.error.as_str(), repeat.error.as_str()] {
        assert_eq!(message, FENCED_MESSAGE);
        for leak in ["CN=", "SAN", "serial", "issuer", "sha256", "generation", "/"] {
            assert!(!message.contains(leak), "the refusal must not carry `{leak}`: {message}");
        }
    }
    assert_eq!(repeat.setup_kind, Some(StreamSetupKind::ClientTrustWithdrawn));
    assert!(settled.metadata.is_empty());
}
