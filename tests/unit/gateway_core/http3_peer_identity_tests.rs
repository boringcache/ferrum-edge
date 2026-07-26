//! Unit coverage for the HTTP/3 per-connection peer-identity snapshot
//! (`ferrum_edge::http3::peer_identity`) — issue #2938.
//!
//! Regression context: with `FERRUM_TLS_EARLY_DATA_METHODS` non-empty, every H3
//! connection was materialized at 0.5-RTT via quinn's `into_0rtt()` and its
//! `peer_identity()` was captured once, immediately — before the client's
//! `Certificate` flight had arrived. That pre-handshake `None` was then pinned
//! for the life of the connection, so `mtls_auth` and the mesh SPIFFE identity
//! plugin saw no certificate on *every* request, including fully handshaken
//! 1-RTT ones.
//!
//! The invariants pinned here:
//!   1. 0-RTT is refused outright when the listener does client authentication.
//!   2. The pre-handshake snapshot exposes no identity at all (fail closed).
//!   3. Only `established()` carries an identity, and it is never early data.
//!   4. A snapshot already handed to an in-flight request never mutates.
//!   5. Slots are per connection — one connection's identity cannot leak into
//!      another's, and a connection whose handshake never completed keeps an
//!      empty slot.
//!   6. The 0.5-RTT accept loop snapshots ready streams before publishing
//!      successful handshake completion.

use std::sync::Arc;

use ferrum_edge::http3::peer_identity::{
    H3ConnectionIdentity, H3PeerIdentity, quic_max_early_data_size, zero_rtt_admitted,
};

fn leaf() -> Vec<u8> {
    vec![0x30, 0x82, 0x01, 0xAA]
}

fn intermediate() -> Vec<u8> {
    vec![0x30, 0x82, 0x02, 0xBB]
}

fn root() -> Vec<u8> {
    vec![0x30, 0x82, 0x03, 0xCC]
}

fn compact_whitespace(input: &str) -> String {
    input.chars().filter(|ch| !ch.is_whitespace()).collect()
}

// ---------------------------------------------------------------------------
// 1. 0-RTT admission
// ---------------------------------------------------------------------------

#[test]
fn zero_rtt_is_refused_when_client_auth_is_configured() {
    // The core availability fix: an H3 listener with a frontend client-cert
    // verifier must never take the 0.5-RTT accept path, so peer identity is
    // only ever read after handshake completion. The matching TLS configuration
    // also disables client early data for the same listener posture.
    assert!(
        !zero_rtt_admitted(true, true),
        "FERRUM_TLS_EARLY_DATA_METHODS must not enable the 0.5-RTT accept path \
         on a client-authenticated H3 listener"
    );
}

#[test]
fn zero_rtt_stays_enabled_for_non_mtls_listeners() {
    // Non-mTLS H3 early data is unchanged by the fix.
    assert!(zero_rtt_admitted(true, false));
}

#[test]
fn zero_rtt_stays_disabled_without_early_data_methods() {
    // 0-RTT remains opt-in. Neither posture turns it on by itself.
    assert!(!zero_rtt_admitted(false, false));
    assert!(!zero_rtt_admitted(false, true));
}

#[test]
fn quic_early_data_advertisement_matches_application_admission() {
    assert_eq!(quic_max_early_data_size(false, false), 0);
    assert_eq!(quic_max_early_data_size(false, true), 0);
    assert_eq!(
        quic_max_early_data_size(true, false),
        u32::MAX,
        "enabled non-mTLS QUIC early data must use quinn's only valid enabled size"
    );
    assert_eq!(
        quic_max_early_data_size(true, true),
        0,
        "an mTLS listener must disable early data at TLS as well as refusing into_0rtt"
    );
}

#[test]
fn h3_early_data_uses_the_bounded_stateful_resumption_cache() {
    let source = compact_whitespace(include_str!("../../../src/http3/server.rs"));
    let conditional = source
        .find("ifserver_tls_config.max_early_data_size==0{")
        .expect("stateless QUIC ticketer must be conditional on early data being disabled");
    let cache = source[conditional..]
        .find("server_tls_config.session_storage=")
        .map(|offset| conditional + offset)
        .expect("H3 TLS builder must install the bounded stateful session cache");
    let ticketer_block = &source[conditional..cache];

    assert!(
        ticketer_block.contains("rustls::crypto::ring::Ticketer::new()"),
        "stateless tickets must be used only when server early data is disabled"
    );
    assert!(
        source[cache..].contains(
            "rustls::server::ServerSessionMemoryCache::new(tls_policy.session_cache_size)"
        ),
        "HTTP/3 server 0-RTT state must be bounded by FERRUM_TLS_SESSION_CACHE_SIZE"
    );
}

#[test]
fn h3_accepts_ready_early_streams_before_publishing_handshake_completion() {
    let source = compact_whitespace(include_str!("../../../src/http3/server.rs"));
    let selection = source
        .find("tokio::select!{biased;accepted=h3_conn.accept()")
        .expect("the H3 accept loop must poll request acceptance first");
    let completion = source[selection..]
        .find("completed=completion_rx")
        .map(|offset| selection + offset)
        .expect("the H3 accept loop must observe handshake completion");
    let publication = source[completion..]
        .find("peer_identity.publish_handshake_result(handshake_succeeded,peer_certs)")
        .map(|offset| completion + offset)
        .expect("successful handshake completion must publish through the identity slot");

    assert!(selection < completion);
    assert!(completion < publication);
}

// ---------------------------------------------------------------------------
// 2 + 3. Snapshot contents
// ---------------------------------------------------------------------------

#[test]
fn pre_handshake_snapshot_exposes_no_identity() {
    // A request that lands inside the 0.5-RTT window must not be able to gain
    // an mTLS identity. It is early data and it carries nothing: no leaf, no
    // chain, and no connection caches that could later be populated.
    let identity = H3PeerIdentity::pre_handshake();
    assert!(identity.is_early_data);
    assert!(identity.client_cert_der.is_none());
    assert!(identity.client_cert_chain_der.is_none());
    assert!(identity.mtls_auth_connection_cache.is_none());
    assert!(
        identity.peer_spiffe_extraction_cache.is_none(),
        "SPIFFE metadata must not be derivable before the handshake completes"
    );
}

#[test]
fn established_snapshot_exposes_leaf_chain_and_caches_and_is_not_early_data() {
    // Post-handshake: the leaf goes to `mtls_auth` / `spiffe_identity`, the
    // intermediates go to per-proxy CA filtering, and both connection caches
    // exist so multiplexed streams reuse one evaluation. `is_early_data` is
    // hard-coded false — an identity-bearing snapshot is by construction not
    // early data, which is what stops early data being accepted as
    // authenticated.
    let identity = H3PeerIdentity::established(Some(vec![leaf(), intermediate(), root()]));
    assert!(!identity.is_early_data);
    assert_eq!(identity.client_cert_der.as_deref(), Some(&leaf()));
    assert_eq!(
        identity.client_cert_chain_der.as_deref(),
        Some(&vec![intermediate(), root()])
    );
    assert!(identity.mtls_auth_connection_cache.is_some());
    assert!(
        identity.peer_spiffe_extraction_cache.is_some(),
        "SPIFFE metadata becomes available once the authenticated handshake completed"
    );
}

#[test]
fn established_snapshot_without_intermediates_has_no_chain() {
    // A single-cert peer keeps the same shape the pre-fix code produced: a leaf
    // and no chain slice.
    let identity = H3PeerIdentity::established(Some(vec![leaf()]));
    assert_eq!(identity.client_cert_der.as_deref(), Some(&leaf()));
    assert!(identity.client_cert_chain_der.is_none());
    assert!(identity.mtls_auth_connection_cache.is_some());
}

#[test]
fn established_snapshot_without_peer_certs_exposes_no_identity_but_is_not_early_data() {
    // A handshake that completed with no client certificate (no verifier
    // configured, or an optional verifier the peer declined) still leaves the
    // connection out of the early-data window, and still exposes nothing — so
    // `mtls_auth` fails closed exactly as before.
    for peer_certs in [None, Some(Vec::new())] {
        let identity = H3PeerIdentity::established(peer_certs);
        assert!(!identity.is_early_data);
        assert!(identity.client_cert_der.is_none());
        assert!(identity.client_cert_chain_der.is_none());
        assert!(identity.mtls_auth_connection_cache.is_none());
        assert!(identity.peer_spiffe_extraction_cache.is_none());
    }
}

// ---------------------------------------------------------------------------
// 4 + 5. Slot lifecycle
// ---------------------------------------------------------------------------

#[test]
fn slot_starts_pre_handshake_and_publishes_identity_exactly_once() {
    let slot = H3ConnectionIdentity::pre_handshake();

    let before = slot.snapshot();
    assert!(before.is_early_data);
    assert!(before.client_cert_der.is_none());

    slot.publish_handshake_result(true, Some(vec![leaf(), intermediate()]));

    let after = slot.snapshot();
    assert!(!after.is_early_data);
    assert_eq!(after.client_cert_der.as_deref(), Some(&leaf()));
    assert_eq!(
        after.client_cert_chain_der.as_deref(),
        Some(&vec![intermediate()])
    );
}

#[test]
fn snapshot_handed_to_an_inflight_request_is_not_mutated_by_a_later_publish() {
    // The accept loop takes ONE snapshot per request stream. A request that was
    // admitted inside the 0.5-RTT window must keep the early-data, no-identity
    // view it was dispatched with — it must not retroactively become an
    // authenticated request when the handshake later completes.
    let slot = H3ConnectionIdentity::pre_handshake();
    let inflight = slot.snapshot();

    slot.publish_handshake_result(true, Some(vec![leaf()]));

    assert!(inflight.is_early_data);
    assert!(inflight.client_cert_der.is_none());
    assert!(inflight.peer_spiffe_extraction_cache.is_none());
    // ...while a stream accepted after publication sees the identity.
    assert!(slot.snapshot().client_cert_der.is_some());
}

#[test]
fn a_connection_whose_handshake_never_completed_keeps_an_empty_slot() {
    // Handshake timeout / cancellation path: the completion task closes the
    // connection and never publishes. The slot must stay pre-handshake rather
    // than acquiring an identity from anywhere.
    let cancelled = H3ConnectionIdentity::pre_handshake();
    let authenticated = H3ConnectionIdentity::pre_handshake();

    authenticated.publish_handshake_result(true, Some(vec![leaf(), intermediate()]));

    let cancelled_snapshot = cancelled.snapshot();
    assert!(cancelled_snapshot.is_early_data);
    assert!(
        cancelled_snapshot.client_cert_der.is_none(),
        "a failed/cancelled handshake must not expose an identity"
    );
    assert!(cancelled_snapshot.peer_spiffe_extraction_cache.is_none());
}

#[test]
fn a_failed_handshake_cannot_clear_early_data_or_publish_identity() {
    // Quinn's ZeroRttAccepted receiver resolves to false when the connection is
    // lost before Connected. That signal must not transition the slot: buffered
    // 0-RTT streams remain replay-gated and cannot acquire a peer identity from
    // a handshake that never authenticated.
    let slot = H3ConnectionIdentity::pre_handshake();

    slot.publish_handshake_result(false, Some(vec![leaf(), intermediate()]));

    let snapshot = slot.snapshot();
    assert!(snapshot.is_early_data);
    assert!(snapshot.client_cert_der.is_none());
    assert!(snapshot.client_cert_chain_der.is_none());
    assert!(snapshot.mtls_auth_connection_cache.is_none());
    assert!(snapshot.peer_spiffe_extraction_cache.is_none());
}

#[test]
fn slots_are_per_connection_and_do_not_share_identity() {
    // Two concurrent connections presenting different certificates must keep
    // their own identities and their own connection caches; nothing is global.
    let conn_a = H3ConnectionIdentity::pre_handshake();
    let conn_b = H3ConnectionIdentity::pre_handshake();

    conn_a.publish_handshake_result(true, Some(vec![leaf()]));
    conn_b.publish_handshake_result(true, Some(vec![intermediate()]));

    let a = conn_a.snapshot();
    let b = conn_b.snapshot();
    assert_eq!(a.client_cert_der.as_deref(), Some(&leaf()));
    assert_eq!(b.client_cert_der.as_deref(), Some(&intermediate()));

    let a_cache = a
        .peer_spiffe_extraction_cache
        .as_ref()
        .expect("connection A has a SPIFFE cache");
    let b_cache = b
        .peer_spiffe_extraction_cache
        .as_ref()
        .expect("connection B has a SPIFFE cache");
    assert!(
        !Arc::ptr_eq(a_cache, b_cache),
        "SPIFFE extraction caches must not be shared across QUIC connections"
    );

    let a_mtls = a
        .mtls_auth_connection_cache
        .as_ref()
        .expect("connection A has an mtls_auth cache");
    let b_mtls = b
        .mtls_auth_connection_cache
        .as_ref()
        .expect("connection B has an mtls_auth cache");
    assert!(!Arc::ptr_eq(a_mtls, b_mtls));
}

#[test]
fn a_second_publish_cannot_replace_the_established_identity_or_caches() {
    // Defence in depth: production has one publisher per connection, and the
    // holder enforces that lifecycle too. If a future refactor accidentally
    // invokes a second publisher, it must not replace the certificate beneath
    // request contexts already sharing the first identity's auth caches.
    let slot = H3ConnectionIdentity::pre_handshake();
    slot.publish_handshake_result(true, Some(vec![leaf()]));
    let first = slot.snapshot();

    slot.publish_handshake_result(true, Some(vec![intermediate()]));
    let second = slot.snapshot();

    assert_eq!(second.client_cert_der.as_deref(), Some(&leaf()));
    let first_cache = first.mtls_auth_connection_cache.as_ref().expect("first");
    let second_cache = second.mtls_auth_connection_cache.as_ref().expect("second");
    assert!(Arc::ptr_eq(first_cache, second_cache));
}
