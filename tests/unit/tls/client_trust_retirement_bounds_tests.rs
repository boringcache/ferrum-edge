//! Bounds and owner scoping around frontend client-trust retirement
//! (issues #3857, #3858).
//!
//! Three properties that the retirement fence itself does not give you:
//!
//! - **The retired transport is closed within a bound.** `graceful_shutdown()`
//!   stops new streams and ends keep-alive, but an already-open in-flight body
//!   (SSE, gRPC server streaming, a chunked download) has no natural end, so an
//!   unbounded drain keeps feeding a peer whose trust the operator just
//!   withdrew. Every other transport bounds or aborts; the H1/H2 proxy arm and
//!   the untimed admin arm must too.
//! - **Retirement is owner scoped.** A generated mesh `NodeWaypoint` DTLS
//!   listener must not join the operator `FrontendDtls` trust domain: its
//!   material is published by the mesh slice, so an unrelated operator CRL edit
//!   would otherwise retire mesh datapath sessions and count them under
//!   `scope="frontend_dtls"`.
//! - **`retire()` cancels before it latches.** `is_retired()` reads the
//!   cancellation token, so latching first leaves a window where an observer
//!   that loses the `swap` race reads `false` on an already-retired session.
//!
//! The two drain bounds and the cancel-before-latch ordering are *orderings
//! inside one function*, not observable end states, so they are pinned as
//! source-shape contracts over the production files. Everything else is driven
//! through the production seams.

use ferrum_edge::dtls::{DtlsServerLimits, dtls_client_trust_scope_for_owner};
use ferrum_edge::tls::ClientTrustScope;
use ferrum_edge::tls::client_trust;

use super::client_trust_tests::{isolated_registry, test_material};

fn read_source(relative: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(relative);
    match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) => panic!("read {}: {e}", path.display()),
    }
}

/// Byte offset of `needle` inside `haystack`, failing with context.
fn index_of(haystack: &str, needle: &str, context: &str) -> usize {
    match haystack.find(needle) {
        Some(index) => index,
        None => panic!("{context}: expected to find {needle:?}"),
    }
}

/// The slice of `source` from `start_marker` up to the next `end_marker`.
///
/// Anchoring on both ends keeps a `contains()` assertion from being satisfied by
/// an unrelated neighbouring arm.
fn region_between(source: &str, start_marker: &str, end_marker: &str, context: &str) -> String {
    let start = index_of(source, start_marker, context);
    let rest = &source[start..];
    let end = index_of(rest, end_marker, context) + end_marker.len();
    rest[..end].to_string()
}

// ---------------------------------------------------------------------------
// Finding 1 — the retirement drain is bounded on H1/H2 and on admin HTTPS
// ---------------------------------------------------------------------------

/// The proxy HTTPS/H2 retirement arm must not poll the hyper connection to
/// completion without a bound.
///
/// `AUTHORIZATION_TRANSPORT_CLOSE_SETTLE` is the same window the
/// authorization-lifetime arm in the very same `select!` uses; dropping the
/// pinned connection when the `select!` returns is the hard close. Without it,
/// an SSE / gRPC server-streaming / chunked response opened before the
/// withdrawal keeps streaming to the revoked peer for the life of the stream.
#[test]
fn the_proxy_tls_retirement_arm_bounds_its_drain() {
    let source = read_source("src/proxy/mod.rs");
    let arm = region_between(
        &source,
        "\"Retiring established TLS connection: frontend client-certificate trust was withdrawn\"",
        "_ = shutdown_rx.changed() =>",
        "proxy retirement arm",
    );
    assert!(
        arm.contains("graceful_shutdown()"),
        "the retirement arm must still start with hyper's own graceful shutdown:\n{arm}"
    );
    assert!(
        arm.contains("AUTHORIZATION_TRANSPORT_CLOSE_SETTLE"),
        "the retirement drain must be bounded by AUTHORIZATION_TRANSPORT_CLOSE_SETTLE, so an \
         in-flight streaming body cannot keep feeding a peer whose trust was withdrawn:\n{arm}"
    );
    let shutdown = index_of(&arm, "graceful_shutdown()", "proxy retirement arm");
    let bound = index_of(
        &arm,
        "AUTHORIZATION_TRANSPORT_CLOSE_SETTLE",
        "proxy retirement arm",
    );
    assert!(
        shutdown < bound,
        "GOAWAY / end-of-keepalive must precede the bounded settle:\n{arm}"
    );
}

/// The admin HTTPS listener has two retirement arms. The timed one already
/// drains inside the configured slowloris deadline; the untimed one
/// (`FERRUM_ADMIN_HTTP_HEADER_READ_TIMEOUT_SECONDS=0`) has no listener window
/// to borrow, so it must use the shared settle instead of polling forever.
#[test]
fn the_untimed_admin_retirement_arm_bounds_its_drain() {
    let source = read_source("src/admin/mod.rs");
    let untimed = region_between(
        &source,
        "if header_read_timeout_seconds == 0 {",
        "let deadline = Duration::from_secs(header_read_timeout_seconds);",
        "untimed admin branch",
    );
    assert!(
        untimed.contains("wait_for_admin_trust_withdrawal"),
        "the untimed branch must still carry the trust-withdrawal arm:\n{untimed}"
    );
    assert!(
        untimed.contains("graceful_shutdown()"),
        "the untimed retirement arm must still start with graceful shutdown:\n{untimed}"
    );
    assert!(
        untimed.contains("AUTHORIZATION_TRANSPORT_CLOSE_SETTLE"),
        "with no header-read deadline configured there is no listener window to drain inside, so \
         the untimed admin retirement drain must be bounded by the shared settle:\n{untimed}"
    );
}

/// The bound both arms use is a real, finite, non-zero `Duration`, and it is
/// reachable from the admin module.
#[test]
fn the_shared_transport_close_settle_is_finite_and_non_zero() {
    let source = read_source("src/proxy/mod.rs");
    let declaration = "pub(crate) const AUTHORIZATION_TRANSPORT_CLOSE_SETTLE: Duration =";
    assert!(
        source.contains(declaration),
        "the settle window must stay a crate-visible constant so the admin listener shares it"
    );
    let value = "AUTHORIZATION_TRANSPORT_CLOSE_SETTLE: Duration = Duration::from_secs(2)";
    assert!(
        source.contains(value),
        "the settle window must stay a finite, non-zero duration"
    );
}

// ---------------------------------------------------------------------------
// Finding 2 — DTLS retirement is owner scoped
// ---------------------------------------------------------------------------

/// An ordinary operator `FERRUM_DTLS_*` listener joins the `FrontendDtls`
/// domain: that is the domain whose material `publish_frontend_dtls_generation`
/// actually swaps onto its `DtlsServer`.
#[test]
fn an_operator_dtls_listener_joins_the_frontend_dtls_trust_domain() {
    assert_eq!(
        dtls_client_trust_scope_for_owner(false),
        Some(ClientTrustScope::FrontendDtls)
    );
    assert_eq!(
        DtlsServerLimits::default().client_trust_scope,
        Some(ClientTrustScope::FrontendDtls),
        "the default must keep every existing DTLS listener in the operator domain"
    );
}

/// A generated mesh `NodeWaypoint` listener joins no domain.
///
/// `StreamListenerManager::swap_active_dtls_frontend_config` deliberately skips
/// those handles and `publish_mesh_node_waypoint_dtls_generation` publishes no
/// trust material, so registering their sessions in the operator domain would
/// have let an operator CRL edit retire mesh datapath sessions — and attribute
/// them to `scope="frontend_dtls"` — while a mesh-side narrowing retired
/// nothing.
#[test]
fn a_node_waypoint_dtls_listener_joins_no_operator_trust_domain() {
    assert_eq!(
        dtls_client_trust_scope_for_owner(true),
        None,
        "a NodeWaypoint listener's trust anchors are mesh-owned; it must not be retirable by an \
         operator FERRUM_DTLS_* publication"
    );
}

/// The end-to-end consequence: an operator `FrontendDtls` withdrawal retires
/// only the sessions that captured that scope. A listener whose owner scope is
/// `None` captures nothing at all, so it has no session to retire and does not
/// inflate the operator scope's retirement counter.
#[test]
fn an_operator_dtls_withdrawal_does_not_reach_an_unscoped_listener() {
    let _guard = isolated_registry();

    let wide = test_material(&["ca-a", "ca-b"]);
    let narrowed = test_material(&["ca-b"]);
    client_trust::publish_accepted_material(ClientTrustScope::FrontendDtls, wide);

    // The operator listener's session: scope `Some(FrontendDtls)`.
    let operator_scope = dtls_client_trust_scope_for_owner(false);
    let operator_session = operator_scope
        .and_then(client_trust::capture)
        .expect("the operator DTLS scope is armed")
        .register(true)
        .expect("a verified client-certificate DTLS session registers");

    // The NodeWaypoint listener's session: scope `None`, so there is nothing to
    // capture and the listener never touches the armed operator domain at all.
    let node_waypoint_admission = match dtls_client_trust_scope_for_owner(true) {
        Some(scope) => client_trust::capture(scope),
        None => None,
    };
    assert!(
        node_waypoint_admission.is_none(),
        "an unscoped listener must capture no generation even while FrontendDtls is armed"
    );

    let publication =
        client_trust::publish_accepted_material(ClientTrustScope::FrontendDtls, narrowed);

    assert!(publication.withdrew(), "removing a CA is a withdrawal");
    assert_eq!(
        publication.retired_sessions, 1,
        "exactly the operator listener's session is retired"
    );
    assert!(operator_session.session().is_retired());
}

// ---------------------------------------------------------------------------
// Finding 4 — retire() cancels before it latches
// ---------------------------------------------------------------------------

/// `is_retired()` reads the cancellation token, and every admission gate in the
/// codebase reads `is_retired()`. Latching first would leave a window in which
/// a second observer — `register`'s post-insert re-check, or the TCP+TLS relay
/// gate — loses the `swap` race, sees a token that has not been cancelled yet,
/// and admits one more step on an already-retired session.
///
/// The ordering is internal to `retire`, so it is pinned on the source. The
/// exactly-once behaviour the `swap` provides is pinned below.
#[test]
fn retire_cancels_the_token_before_it_latches() {
    let source = read_source("src/tls/client_trust.rs");
    let body = region_between(
        &source,
        "fn retire(&self, _reason: ClientTrustRetirementReason) -> bool {",
        "/// Record that this transport refused a request",
        "ClientTrustSession::retire",
    );
    let cancel = index_of(&body, "self.inner.token.cancel();", "retire body");
    let latch = index_of(&body, "self.inner.retired.swap(true,", "retire body");
    assert!(
        cancel < latch,
        "retire() must cancel the token before latching, so the observable `is_retired()` edge \
         strictly precedes the exactly-once accounting edge:\n{body}"
    );
}

/// Cancelling first must not cost the exactly-once accounting: the `swap` is
/// still what decides which caller reports the retirement.
#[test]
fn cancel_before_latch_keeps_retirement_accounting_exactly_once() {
    let _guard = isolated_registry();

    client_trust::publish_accepted_material(
        ClientTrustScope::ProxyFrontend,
        test_material(&["ca-a", "ca-b", "ca-c"]),
    );
    let session = client_trust::capture(ClientTrustScope::ProxyFrontend)
        .expect("armed")
        .register(true)
        .expect("registered");

    let first = client_trust::publish_accepted_material(
        ClientTrustScope::ProxyFrontend,
        test_material(&["ca-b", "ca-c"]),
    );
    let second = client_trust::publish_accepted_material(
        ClientTrustScope::ProxyFrontend,
        test_material(&["ca-c"]),
    );

    assert!(session.session().is_retired());
    assert_eq!(first.retired_sessions, 1);
    assert_eq!(
        second.retired_sessions, 0,
        "a session retired by an earlier publication must not be counted again"
    );
}
