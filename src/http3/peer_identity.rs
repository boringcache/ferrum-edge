//! Per-connection HTTP/3 peer-identity snapshot.
//!
//! A QUIC connection's peer certificate is only knowable once the TLS 1.3
//! handshake has completed. When 0-RTT is enabled the gateway materializes the
//! `quinn::Connection` at 0.5-RTT — *before* the client's `Certificate` /
//! `Finished` flight has arrived — so reading `Connection::peer_identity()`
//! at that moment always yields `None`. Pinning that pre-handshake `None` for
//! the lifetime of the connection silently disabled frontend H3 mTLS for every
//! request on every H3 connection (issue #2938).
//!
//! This module owns the two halves of the fix:
//!
//! 1. [`zero_rtt_admitted`] — the admission decision. A listener configured
//!    with a frontend client-certificate verifier never takes quinn's
//!    `into_0rtt()` path at all and sets the QUIC TLS early-data size to zero.
//!    Incoming 0.5-RTT precedes client authentication, so materializing the
//!    connection there would create a pre-handshake identity window.
//! 2. [`H3ConnectionIdentity`] — a lock-free, per-connection `ArcSwap` slot
//!    holding one coherent [`H3PeerIdentity`] snapshot. Requests read the whole
//!    snapshot with a single `load_full()`, so `is_early_data` and the peer
//!    certificate can never be observed out of step with each other. The slot
//!    starts at [`H3PeerIdentity::pre_handshake`] (early data, **no** identity)
//!    and is republished exactly once, when the handshake completion future
//!    resolves, with the identity quinn then reports.
//!
//! The two rules that make this fail-closed:
//!
//! - An identity-bearing snapshot is only ever produced by
//!   [`H3PeerIdentity::established`], which hard-codes `is_early_data = false`.
//!   A request can therefore never be treated as authenticated early data.
//! - A slot is created per connection and is never shared between connections,
//!   so a handshake that fails, times out, or is cancelled simply leaves its
//!   own slot at the pre-handshake snapshot. No other connection's identity can
//!   leak into it.

use std::sync::Arc;

use arc_swap::ArcSwap;

use crate::plugins::mesh::spiffe_identity::SpiffeIdentityConnectionCache;
use crate::plugins::mtls_auth::MtlsAuthConnectionCache;

/// Whether the HTTP/3 listener may use quinn's `into_0rtt()` 0.5-RTT accept
/// path for a connection.
///
/// 0-RTT requires the operator to have opted in via
/// `FERRUM_TLS_EARLY_DATA_METHODS`, **and** requires the listener not to be
/// doing frontend client-certificate authentication. Taking the 0.5-RTT path
/// under client auth would materialize the connection before the peer's
/// certificate is known.
#[inline]
pub fn zero_rtt_admitted(
    early_data_methods_configured: bool,
    client_auth_configured: bool,
) -> bool {
    early_data_methods_configured && !client_auth_configured
}

/// QUIC rustls `max_early_data_size` for the listener posture.
///
/// Quinn accepts only `0` or `u32::MAX`. Keep the TLS advertisement coupled to
/// [`zero_rtt_admitted`]: an mTLS listener must disable early data in the TLS
/// configuration as well as refusing the 0.5-RTT application accept path.
/// Otherwise a stateful-resumption fallback could accept replayable client
/// early data and deliver it only after the full handshake, where the request
/// loop would no longer be able to distinguish it from ordinary 1-RTT data.
#[inline]
pub fn quic_max_early_data_size(
    early_data_methods_configured: bool,
    client_auth_configured: bool,
) -> u32 {
    if zero_rtt_admitted(early_data_methods_configured, client_auth_configured) {
        u32::MAX
    } else {
        0
    }
}

/// One coherent view of an HTTP/3 connection's peer identity, published as a
/// unit so a request stream cannot mix an early-data flag from one point in the
/// connection lifecycle with a certificate from another.
#[derive(Debug, Default)]
pub struct H3PeerIdentity {
    /// True only while the connection is still inside the 0.5-RTT window (the
    /// TLS handshake has not completed). Requests snapshotting this value are
    /// early data: method-gated by `FERRUM_TLS_EARLY_DATA_METHODS` and marked
    /// `Early-Data: 1` toward the backend (RFC 8470).
    pub is_early_data: bool,
    /// Peer leaf certificate DER, when the peer authenticated.
    pub client_cert_der: Option<Arc<Vec<u8>>>,
    /// Intermediate/CA certificates (index 1+) for per-proxy CA filtering in
    /// `mtls_auth`.
    pub client_cert_chain_der: Option<Arc<Vec<Vec<u8>>>>,
    /// Connection-scoped `mtls_auth` evaluation cache. Present only when a peer
    /// certificate is present, so it can never be reused across an identity
    /// change.
    pub mtls_auth_connection_cache: Option<Arc<MtlsAuthConnectionCache>>,
    /// Connection-scoped SPIFFE extraction cache, present under the same
    /// condition as `mtls_auth_connection_cache`.
    pub peer_spiffe_extraction_cache: Option<Arc<SpiffeIdentityConnectionCache>>,
}

impl H3PeerIdentity {
    /// The pre-handshake snapshot: requests are early data and **no** peer
    /// identity is exposed. This is the only snapshot with
    /// `is_early_data == true`, and it deliberately carries no certificate,
    /// chain, or cache.
    pub fn pre_handshake() -> Self {
        Self {
            is_early_data: true,
            ..Self::default()
        }
    }

    /// The post-handshake snapshot built from the certificate chain quinn
    /// reports once the TLS handshake has completed. `is_early_data` is always
    /// `false` here — an identity-bearing snapshot is by construction not early
    /// data.
    pub fn established(peer_certs: Option<Vec<Vec<u8>>>) -> Self {
        let client_cert_der: Option<Arc<Vec<u8>>> = peer_certs
            .as_ref()
            .and_then(|certs| certs.first())
            .map(|cert| Arc::new(cert.clone()));
        let client_cert_chain_der: Option<Arc<Vec<Vec<u8>>>> = peer_certs
            .as_ref()
            .filter(|certs| certs.len() > 1)
            .map(|certs| Arc::new(certs[1..].to_vec()));
        // The peer cert is fixed for the connection once the handshake
        // completes, so both caches derive their outcome once and every
        // multiplexed request stream reuses it. Allocated only alongside a
        // real certificate.
        let mtls_auth_connection_cache = client_cert_der
            .as_ref()
            .map(|_| Arc::new(MtlsAuthConnectionCache::new()));
        let peer_spiffe_extraction_cache = client_cert_der
            .as_ref()
            .map(|_| Arc::new(SpiffeIdentityConnectionCache::new()));
        Self {
            is_early_data: false,
            client_cert_der,
            client_cert_chain_der,
            mtls_auth_connection_cache,
            peer_spiffe_extraction_cache,
        }
    }
}

/// Per-connection, lock-free holder for the current [`H3PeerIdentity`].
///
/// The accept loop performs one `ArcSwap::load_full()` per accepted request
/// stream — no lock, no allocation beyond the `Arc` refcount bump it already
/// paid when cloning the per-request certificate handles.
#[derive(Debug)]
pub struct H3ConnectionIdentity {
    slot: ArcSwap<H3PeerIdentity>,
}

impl H3ConnectionIdentity {
    /// Create a slot in the pre-handshake state (0.5-RTT window, no identity).
    pub fn pre_handshake() -> Self {
        Self {
            slot: ArcSwap::from_pointee(H3PeerIdentity::pre_handshake()),
        }
    }

    /// Publish the post-handshake identity, atomically clearing the early-data
    /// flag in the same swap.
    ///
    /// Called exactly once per connection: from the accept path itself on the
    /// ordinary full-handshake branches (where the connection future only
    /// resolves after the peer's `Finished` has been processed, and before any
    /// request stream can be accepted), or from the task awaiting quinn's
    /// `ZeroRttAccepted` future on the 0.5-RTT branch. Never before the
    /// handshake has actually completed.
    pub fn publish_established(&self, peer_certs: Option<Vec<Vec<u8>>>) {
        let established = Arc::new(H3PeerIdentity::established(peer_certs));
        let current = self.slot.load_full();
        if !current.is_early_data {
            return;
        }
        // Enforce the documented one-publication lifecycle in the holder
        // itself. If a future refactor accidentally creates two publishers,
        // only the first transition from the unique pre-handshake snapshot can
        // win; a later certificate can never replace the identity and caches
        // already shared with multiplexed request contexts.
        let _previous = self.slot.compare_and_swap(&current, established);
    }

    /// Read the current snapshot. One lock-free load; every field a request
    /// uses comes from this single consistent view.
    #[inline]
    pub fn snapshot(&self) -> Arc<H3PeerIdentity> {
        self.slot.load_full()
    }
}
