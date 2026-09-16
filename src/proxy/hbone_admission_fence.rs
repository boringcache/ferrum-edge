//! Receiver-side admission fence for live HBONE tunnels (issues #5042, #5568
//! and #5574).
//!
//! An HBONE CONNECT is admitted exactly once: the peer identity gate, the
//! effective PeerAuthentication transport mode, the relay-destination
//! ownership guard, and the authorize-phase plugin chain (`mesh_authz`) all
//! judge the CONNECT request, and the relay then byte-copies for as long as the
//! tunnel lives. Without this fence a tunnel admitted under one policy
//! generation kept flowing after the operator published a tighter one, and
//! NOTHING bounded it: an established inbound HBONE mTLS session is never
//! re-handshaked, so neither the peer SVID's expiry nor a later trust decision
//! ends it. That is also what blocks source-side inner-connection reuse
//! (#5042 step 2): a reused tunnel would carry later requests under a stale
//! decision.
//!
//! The fence keeps a registry of live admitted tunnels, each holding the
//! admission snapshot those gates evaluated. Every request-epoch publication
//! and every inbound PeerAuthentication swap schedules ONE sweep (concurrent
//! requests coalesce) that re-applies the gates to every live tunnel against
//! the CURRENT epoch and policy. A tunnel that would no longer be admitted is
//! revoked: its relay observes the cancellation as a terminal transport error,
//! which resets the CONNECT stream toward the peer and closes the backend leg
//! through the relay's ordinary teardown path.
//!
//! Sweeps run off the request path on one background task at a time, and only
//! authorize plugins that declare themselves re-evaluation-safe
//! ([`crate::plugins::Plugin::reevaluates_live_admission`]) are re-run. That
//! keeps a publication's cost to local policy evaluation over the live
//! tunnels — microseconds per tunnel, no external call and no consumed budget —
//! so a routine config apply can never drain a real client's rate-limit budget
//! or mass-revoke healthy tunnels because an external authorizer is briefly
//! unreachable. Within `mesh_authz`, `CUSTOM` (`ext_authz`) delegations are
//! additionally NOT re-consulted (see
//! [`crate::plugins::mesh::authz::MESH_AUTHZ_REEVALUATION_METADATA_KEY`]): the
//! provider's admission-time verdict stands for the tunnel's life, exactly as
//! before, while the local DENY/ALLOW tiers are re-applied.
//!
//! The fence bounds TWO dimensions, POLICY and CREDENTIALS (issues #5568 and
//! #5574). Beside the policy gates, a sweep re-checks the credential the
//! CONNECT was admitted on: the admitted leaf's `notAfter`, and — when the
//! gateway trust generation or the enforced mesh inbound CRL generation has
//! moved since admission — whether the retained peer chain still anchors in
//! the trust bundles the published generation carries AND is unrevoked under
//! the CRLs the inbound SPIFFE verifier enforces right now. Every gateway
//! trust publication (`ProxyState::publish_live_gateway_trust`, the ONE writer
//! of the request-facing trust generation) and every CRL publication
//! (`ProxyState::publish_mesh_inbound_crls`, the ONE writer of the enforced
//! set) therefore requests a sweep, and a bounded expiry watcher requests one
//! when the earliest live tunnel's leaf ages out so an expired SVID is revoked
//! on a mesh where nothing is being republished at all.
//!
//! What remains outside the fence is narrow and deliberate: an `action: CUSTOM`
//! ext_authz delegation is not re-consulted (below). See `docs/mesh.md` →
//! "HBONE Admission Fence".

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, Weak};

use dashmap::DashMap;
use futures_util::FutureExt;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use super::hbone_proxy::{
    inbound_hbone_relay_effective_destination_decision,
    inbound_ingress_relay_effective_destination_allowed,
};
use super::{
    MeshInboundTlsPolicy, SharedMeshInboundTlsPolicy, inbound_hbone_relay_destination_decision,
    mesh_egress_udp_destination_allowed, mesh_inbound_peer_auth_transport_mismatch_for_policy,
};
use crate::config::types::{Proxy, UpstreamTarget};
use crate::plugins::mesh::authz::MESH_AUTHZ_REEVALUATION_METADATA_KEY;
use crate::plugins::{Plugin, PluginResult, ProxyProtocol, RequestContext};
use crate::request_epoch::{RequestEpoch, RequestEpochStore};

/// Client-visible / log-visible message for a tunnel the fence revoked. A
/// compiled-in literal: no policy name, principal, or destination.
pub const HBONE_ADMISSION_REVOKED_MESSAGE: &str =
    "HBONE tunnel terminated: mesh admission revoked by a later policy generation";

/// Why a sweep revoked a live tunnel. Fixed cardinality; used as a metric label.
///
/// The variants are declared, indexed, and rendered in GATE ORDER — the order
/// [`HboneAdmissionFence::reevaluate`] applies them, which is the order the
/// CONNECT path applies them — with the fail-closed arm last. The `reason`
/// label is an operator's only attribution, so a tunnel failing two gates must
/// carry the one its peer's next CONNECT would actually be refused with.
///
/// The three credential arms sit in the order the inbound handshake verifier
/// itself would report them, derived from webpki's own path-building sequence
/// (`rustls-webpki::verify_cert::build_chain_inner`) rather than chosen here:
///
/// 1. [`Self::PeerExpired`] — `check_issuer_independent_properties` validates
///    the certificate's `notAfter` BEFORE the trust-anchor loop is entered, and
///    propagates with `?`. An aged-out leaf is therefore refused with
///    `CertExpired` whatever the anchors or the CRLs would have said.
/// 2. [`Self::PeerTrust`] — the anchor loop seeds its error with
///    `Error::UnknownIssuer` and only calls `check_signed_chain` — the one
///    place revocation is consulted — after a candidate anchor's subject
///    matches the certificate's issuer. A chain that anchors nowhere never
///    reaches the CRL at all, so it reads as a trust withdrawal even when the
///    enforced list also names it.
/// 3. [`Self::PeerRevoked`] — reported only once a complete path to an anchor
///    exists and the enforced CRL lists a certificate on it. Where several
///    anchors are tried and only some match, `Error::most_specific` decides,
///    and it ranks `CertRevoked` (270) far above `UnknownIssuer` (0) — so a
///    chain that anchors somewhere and is revoked there is `peer_revoked`, not
///    `peer_trust`, which is the same answer the peer's next handshake gets.
///
/// `peer_expired` outranks both on the same scale (`CertExpired` is 290), which
/// is the second reason the fence decides expiry first; the first is that the
/// chain re-verification validates at the current instant and would otherwise
/// report an aged-out leaf as an anchoring failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HboneRevocationReason {
    /// The admitting configured proxy is gone from the published generation
    /// (or was deleted and recreated, which is a new incarnation).
    ProxyWithdrawn,
    /// The admitted peer SVID has passed its `notAfter` (issue #5568). An
    /// established inbound mTLS session is never re-handshaked, so this is the
    /// only thing that ends a tunnel whose credential simply aged out.
    PeerExpired,
    /// The peer's chain no longer anchors in the trust bundles the published
    /// gateway trust generation carries — the issuing CA was removed, the
    /// federated trust domain was retired, or the trust material was withdrawn
    /// outright (issue #5568).
    PeerTrust,
    /// The peer's chain still anchors, but the CRL set the mesh inbound SPIFFE
    /// verifier enforces now revokes a certificate on it — the leaf itself or
    /// an issuing intermediate, since the shared CRL policy is full-chain
    /// (issue #5574). An established inbound mTLS session is never
    /// re-handshaked, so before this a revoked workload credential kept its
    /// already-admitted tunnels flowing until they ended on their own.
    PeerRevoked,
    /// The authorize-phase chain now denies the admitted CONNECT.
    AuthorizationDenied,
    /// The tunnel's transport no longer satisfies the effective
    /// PeerAuthentication mode for its application port.
    PeerAuthTransport,
    /// The relay destination is no longer one this terminator owns.
    RelayDestination,
    /// Re-evaluation itself could not produce a verdict (an authorize plugin
    /// unwound, the published trust bundle for the peer's trust domain is not
    /// compilable into a verifier, or the enforced CRL set cannot be applied to
    /// one — unparseable, or itself past `nextUpdate`). Fail closed: an
    /// un-judgeable tunnel is cut rather than left serving under a generation
    /// nothing checked it against.
    ReevaluationFailed,
}

impl HboneRevocationReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProxyWithdrawn => "proxy_withdrawn",
            Self::PeerExpired => "peer_expired",
            Self::PeerTrust => "peer_trust",
            Self::PeerRevoked => "peer_revoked",
            Self::AuthorizationDenied => "authorization_denied",
            Self::PeerAuthTransport => "peer_auth_transport",
            Self::RelayDestination => "relay_destination",
            Self::ReevaluationFailed => "reevaluation_failed",
        }
    }

    const ALL: [Self; 8] = [
        Self::ProxyWithdrawn,
        Self::PeerExpired,
        Self::PeerTrust,
        Self::PeerRevoked,
        Self::AuthorizationDenied,
        Self::PeerAuthTransport,
        Self::RelayDestination,
        Self::ReevaluationFailed,
    ];

    const fn index(self) -> usize {
        match self {
            Self::ProxyWithdrawn => 0,
            Self::PeerExpired => 1,
            Self::PeerTrust => 2,
            Self::PeerRevoked => 3,
            Self::AuthorizationDenied => 4,
            Self::PeerAuthTransport => 5,
            Self::RelayDestination => 6,
            Self::ReevaluationFailed => 7,
        }
    }

    fn from_index(index: u8) -> Option<Self> {
        Self::ALL.get(usize::from(index)).copied()
    }
}

/// Which relay-destination ownership guard admitted the tunnel, so the sweep
/// re-applies exactly that guard (`handle_hbone_request` /
/// `handle_hbone_udp_request` parity).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HboneRelayDestinationGate {
    /// Synthesized Ambient/NodeWaypoint/ServiceWaypoint inbound relay: the
    /// destination must remain one this proxy terminates for.
    InboundRelay,
    /// Synthesized Sidecar `ingress[]` remap: the declared listener →
    /// `defaultEndpoint` mapping must remain intact.
    IngressRelay,
    /// Datagram-over-HBONE relay: a terminator-owned local destination, or an
    /// admitted EgressGateway external UDP endpoint.
    Datagram,
    /// Explicitly configured proxy: no ownership guard applies; presence in the
    /// published generation is the gate.
    Configured,
}

/// The peer credential an HBONE CONNECT was admitted on, retained so a sweep
/// can re-decide the credential question a later generation asks (issue #5568).
///
/// Built once, at admission, from material the connection already holds: both
/// DER fields are `Arc` clones of exactly what the accept path took out of the
/// rustls session (the snapshot's `RequestContext` holds the same two `Arc`s),
/// so the retention costs two refcount bumps rather than a copy of the chain,
/// and `leaf_not_after` is the single X.509 parse this type performs. Nothing
/// certificate-shaped is re-derived per sweep.
///
/// Carries no private key and no rendered subject/SAN: `spiffe_id` is the
/// identity the request path already published, and the DER is the peer's own
/// public chain.
pub struct HbonePeerCredential {
    /// The peer SPIFFE identity the CONNECT was authorized under. Its trust
    /// domain is what the re-check looks the published bundles up by.
    pub spiffe_id: crate::identity::SpiffeId,
    /// The admitted leaf, DER-encoded — the certificate `spiffe_id` was read
    /// from. Retaining it is what lets a sweep re-verify the chain against a
    /// later generation's anchors instead of trusting a remembered verdict.
    pub leaf_der: Arc<Vec<u8>>,
    /// The intermediates the peer offered, in chain order. `None` when it
    /// presented a leaf only, which is the ordinary SPIFFE SVID shape.
    pub intermediates_der: Option<Arc<Vec<Vec<u8>>>>,
    /// The admitted leaf's `notAfter`, converted ONCE to the monotonic clock at
    /// admission (the same conversion `spiffe_identity` caches per connection,
    /// `plugins::utils::auth_flow::try_credential_deadline_from_unix_seconds`).
    /// Monotonic on purpose: a wall-clock rollback must not be able to extend a
    /// live tunnel's credential.
    ///
    /// `None` only when the leaf's `notAfter` outruns the representable
    /// monotonic range (issue #5396) — a certificate with no practical
    /// expiration rather than an unbounded admission.
    pub leaf_not_after: Option<tokio::time::Instant>,
    /// Whether the gateway trust generation that admitted this CONNECT
    /// positively carried a usable X.509 bundle for `spiffe_id`'s trust domain.
    ///
    /// `false` leaves the TRUST half of the gate inapplicable for this tunnel's
    /// whole life, and is the guard against a false mass revocation: the fence
    /// only ever revokes for a trust change it can observe as a REGRESSION from
    /// a state it saw. A mesh inbound listener with no gateway SVID material
    /// verifies peers chain-only against the operator client-CA bundle — which
    /// the request epoch's gateway trust does not describe at all, and which
    /// `tls::client_trust` already bounds separately (issue #3857) — so such a
    /// tunnel must not be judged against bundles that never admitted it. The
    /// expiry half still applies.
    pub anchored_at_admission: bool,
}

impl HbonePeerCredential {
    /// Capture the credential an admitted CONNECT was authorized on, or `None`
    /// when there is nothing to re-check.
    ///
    /// `None` covers every shape with no certificate-derived peer identity to
    /// bound: a PERMISSIVE plaintext-admitted tunnel, a peer that presented no
    /// certificate, and a kernel-attested (node-waypoint eBPF) or
    /// HBONE-asserted `peer_spiffe_id`, which carries no leaf and therefore no
    /// validity window — bounding one by a certificate deadline would be a
    /// fiction, exactly as `RequestContext::has_certificate_spiffe_principal`
    /// records.
    pub(crate) fn from_admitted_connect(
        ctx: &RequestContext,
        gateway_trust: &crate::request_epoch::GatewayTrustEpoch,
    ) -> Option<Self> {
        if !ctx.has_certificate_spiffe_principal() {
            return None;
        }
        let spiffe_id = ctx.peer_spiffe_id.clone()?;
        let leaf_der = Arc::clone(ctx.tls_client_cert_der.as_ref()?);
        let anchored_at_admission = gateway_trust
            .svid()
            .as_ref()
            .as_ref()
            .and_then(|bundle| bundle.trust_bundles.get(spiffe_id.trust_domain()))
            .is_some_and(|bundle| !bundle.x509_authorities.is_empty());
        let leaf_not_after = monotonic_leaf_expiry(leaf_der.as_slice());
        Some(Self {
            spiffe_id,
            leaf_der,
            intermediates_der: ctx.tls_client_cert_chain_der.clone(),
            leaf_not_after,
            anchored_at_admission,
        })
    }
}

/// The monotonic conversion of a leaf's `notAfter`.
///
/// Parsed here rather than read off `RequestContext::credential_deadline_at`
/// because that field is the MINIMUM across every accepted credential on the
/// request — a JWT `exp` from mesh `RequestAuthentication` lands on it too —
/// and a `peer_expired` revocation must describe the peer's SVID, not whichever
/// credential happened to expire first. Parsing the retained leaf keeps the
/// expiry and the chain describing the same certificate, the same invariant
/// `spiffe_identity::derive_peer_spiffe_extraction` holds for its own pair.
///
/// A leaf that cannot be parsed, or whose ASN.1 interval is not coherent,
/// yields an ALREADY-ELAPSED deadline: the CONNECT that carried it was admitted
/// against a verifier that did parse it, so a parse failure here means the
/// fence cannot bound the credential and must fail closed rather than leave the
/// tunnel unbounded.
fn monotonic_leaf_expiry(leaf_der: &[u8]) -> Option<tokio::time::Instant> {
    use crate::plugins::utils::auth_flow::{
        CredentialDeadline, try_credential_deadline_from_unix_seconds,
    };
    use crate::plugins::utils::cert_validity::CertValidityWindow;
    use x509_parser::prelude::*;

    let elapsed = || Some(tokio::time::Instant::now());
    let Ok((_, parsed)) = X509Certificate::from_der(leaf_der) else {
        return elapsed();
    };
    let Some(validity) = CertValidityWindow::from_certificate(&parsed) else {
        return elapsed();
    };
    match try_credential_deadline_from_unix_seconds(validity.not_after_unix, 0) {
        CredentialDeadline::Bounded(deadline) => Some(deadline),
        CredentialDeadline::Unbounded => None,
        CredentialDeadline::Invalid => elapsed(),
    }
}

/// Everything the CONNECT admission gates evaluated, captured after admission
/// so a sweep can re-run the same decision against a later generation.
pub struct HboneAdmissionSnapshot {
    /// Request context after the authorize and `before_proxy` phases. Cloned
    /// per sweep because `authorize` takes `&mut`.
    pub ctx: RequestContext,
    /// The effective (post-route-override) proxy the relay dialed through.
    pub proxy: Arc<Proxy>,
    pub upstream_target: Option<Arc<UpstreamTarget>>,
    pub is_tls: bool,
    pub has_verified_peer_certificate: bool,
    pub mesh_inbound_pre_handshake_app_port: Option<u16>,
    pub destination_gate: HboneRelayDestinationGate,
    /// The address the relay actually dialled, when one was resolved. The
    /// ordinary inbound relay screens post-DNS loopback answers before the
    /// dial, and the sweep re-applies that screen to this address — authority
    /// matching admits a declared hostname without resolving it, so the
    /// authority decision alone cannot see a tunnel pinned to `127.0.0.0/8`.
    pub resolved_ip: Option<IpAddr>,
    /// `Some` only for a proxy present in the published configuration;
    /// synthesized relay proxies are absent from every generation by design.
    pub proxy_lifecycle_generation: Option<u64>,
    /// The protocol the request path resolved the admitting plugin view with.
    /// The authorize chain is protocol-scoped and an HBONE CONNECT carrying
    /// `content-type: application/grpc` classifies as gRPC, so the sweep must
    /// re-resolve the SAME view rather than assume plain HTTP.
    pub request_protocol: ProxyProtocol,
    /// Whether the admitting view came from `grpc_web_request_view` rather than
    /// `request_view`; see [`Self::request_protocol`].
    pub grpc_web_request: bool,
    /// [`HboneAdmissionFence::sweep_epoch`] as captured BEFORE the request path
    /// read the epoch and PeerAuthentication policy these gates judged. See
    /// [`HboneAdmissionFence::admit`] for the publish-then-recheck contract.
    pub admission_sweep_epoch: u64,
    /// [`crate::request_epoch::GatewayTrustEpoch::generation`] of the epoch this
    /// CONNECT was admitted under (issue #5568).
    ///
    /// Read from the SAME `RequestEpoch` load the gates judged, so it is
    /// covered by the existing publish-then-recheck contract without a second
    /// capture. A sweep whose epoch still publishes this generation skips the
    /// chain re-verification entirely: the trust material cannot have changed,
    /// so an ordinary policy publication never pays for certificate path
    /// building.
    pub gateway_trust_generation: u64,
    /// [`crate::tls::crl_policy::EnforcedCrlSet::generation`] of the CRL set the
    /// mesh inbound SPIFFE verifier enforced when this CONNECT handshook
    /// (issue #5574).
    ///
    /// Read at the admit site from the same slot the verifier reads, and after
    /// the request path captured [`Self::admission_sweep_epoch`], so the
    /// publish-then-recheck contract that covers the epoch and the
    /// PeerAuthentication policy covers this too: `publish_mesh_inbound_crls`
    /// stores and only then requests a sweep, so a CONNECT admitted under the
    /// superseded set necessarily captured a stale sweep counter and
    /// [`HboneAdmissionFence::admit`] schedules a fresh pass for it.
    ///
    /// A sweep whose enforced set still publishes this generation skips the
    /// chain re-verification for the same reason an unchanged trust generation
    /// does: the records cannot have changed.
    pub mesh_inbound_crl_generation: u64,
    /// The peer credential this tunnel was admitted on, when the CONNECT
    /// carried a certificate-derived SPIFFE principal. `None` leaves the
    /// credential gate inapplicable — see
    /// [`HbonePeerCredential::from_admitted_connect`].
    pub peer_credential: Option<HbonePeerCredential>,
}

struct AdmittedHboneTunnelInner {
    id: u64,
    token: CancellationToken,
    /// ONE terminal-state word: `TUNNEL_LIVE`, `TUNNEL_RETIRED`, or
    /// `TUNNEL_REVOKED_BASE + HboneRevocationReason::index()`. See those
    /// constants for why retirement and revocation share it.
    state: AtomicU8,
    snapshot: HboneAdmissionSnapshot,
    fence: Weak<HboneAdmissionFence>,
}

/// The relay is still carrying bytes and no sweep has claimed the tunnel.
///
/// `AdmittedHboneTunnel::retire` and `AdmittedHboneTunnel::claim_revocation`
/// are the ONLY writers and each is a single compare-exchange out of this
/// value, so exactly one of them wins. Two separate atomics could not give
/// that: a sweep that read "not retired" microseconds before the relay ended
/// still counted, logged and metered a revocation for a tunnel carrying no
/// bytes, and the datagram relay — which reads `revoked_reason()` after
/// `retire()` and has no `first_failure` to cross-check against — then reported
/// an ordinary idle/EOF close as an admission revocation.
const TUNNEL_LIVE: u8 = 0;
/// The relay ended first. The tunnel is neither swept, counted, nor classified
/// as revoked.
const TUNNEL_RETIRED: u8 = 1;
/// A sweep claimed the tunnel; the value is this base plus
/// `HboneRevocationReason::index()`. The reason stays readable after the relay
/// calls `retire()`, which is how the datagram relay classifies its own close.
const TUNNEL_REVOKED_BASE: u8 = 2;

impl Drop for AdmittedHboneTunnelInner {
    fn drop(&mut self) {
        if let Some(fence) = self.fence.upgrade() {
            let ptr = std::ptr::from_mut(self).cast_const();
            fence
                .tunnels
                .remove_if(&self.id, |_, weak| std::ptr::eq(weak.as_ptr(), ptr));
        }
    }
}

/// One live admitted tunnel. Held by the relay task; dropping the last handle
/// deregisters the tunnel. Cheap to clone (one `Arc` bump).
#[derive(Clone)]
pub struct AdmittedHboneTunnel {
    inner: Arc<AdmittedHboneTunnelInner>,
}

impl AdmittedHboneTunnel {
    /// The admission snapshot; the relay reads its `ctx` for the transaction
    /// summary so the tunnel is cloned once, not twice.
    pub fn snapshot(&self) -> &HboneAdmissionSnapshot {
        &self.inner.snapshot
    }

    /// Owned cancellation handle for the relay's termination bound.
    pub fn revocation_token(&self) -> CancellationToken {
        self.inner.token.clone()
    }

    /// The admitted credential's monotonic expiry, when this tunnel carries
    /// one. `None` for a tunnel with no certificate-derived peer credential and
    /// for a leaf whose `notAfter` is beyond the representable monotonic range.
    fn credential_deadline(&self) -> Option<tokio::time::Instant> {
        self.inner.snapshot.peer_credential.as_ref()?.leaf_not_after
    }

    /// Whether a sweep revoked this tunnel, and why. `None` for a tunnel that
    /// is still live and for one whose relay retired it first.
    pub fn revoked_reason(&self) -> Option<HboneRevocationReason> {
        self.inner
            .state
            .load(Ordering::Acquire)
            .checked_sub(TUNNEL_REVOKED_BASE)
            .and_then(HboneRevocationReason::from_index)
    }

    /// Deregister the tunnel the instant its relay ends, before the transaction
    /// summary and the operator logging chain run. `true` means this call won
    /// the terminal transition — the relay ended before any sweep claimed the
    /// tunnel; `false` means a sweep had already claimed it and its reason
    /// stays readable through [`Self::revoked_reason`].
    ///
    /// The transition is ONE compare-exchange against the same word
    /// [`Self::claim_revocation`] uses, so a sweep judging this tunnel and the
    /// relay ending cannot both win: `ferrum_mesh_hbone_tunnel_revocations_total`
    /// and [`HboneAdmissionFence::live_tunnels`] count only tunnels that were
    /// still carrying bytes. `Drop` stays the safety net for every path that
    /// cannot reach this call.
    pub fn retire(&self) -> bool {
        let won = self.transition_from_live(TUNNEL_RETIRED);
        if let Some(fence) = self.inner.fence.upgrade() {
            let ptr = Arc::as_ptr(&self.inner);
            fence
                .tunnels
                .remove_if(&self.inner.id, |_, weak| std::ptr::eq(weak.as_ptr(), ptr));
        }
        won
    }

    /// Claim this tunnel for revocation and record the reason, WITHOUT
    /// cancelling yet. `true` means this caller won the claim and owns the
    /// accounting; the cancellation edge is published afterwards by
    /// [`Self::publish_revocation`]. A tunnel the relay already retired, or one
    /// a previous sweep already claimed, refuses the claim.
    ///
    /// The reason is recorded before the cancellation because the relay reads
    /// `revoked_reason()` as soon as it observes the cancellation, and the
    /// datagram relay has no first-failure record to classify instead, so a
    /// cancellation the reason has not caught up with would be reported as a
    /// transport failure. Nothing depends on seeing the cancellation edge
    /// first: the only `is_cancelled()` reader is the sweep loop, and sweeps
    /// are serialized by `sweep_serial`.
    fn claim_revocation(&self, reason: HboneRevocationReason) -> bool {
        self.transition_from_live(TUNNEL_REVOKED_BASE + reason.index() as u8)
    }

    /// The ONE write that ends a tunnel: a single compare-exchange out of
    /// [`TUNNEL_LIVE`]. `true` means this caller won.
    fn transition_from_live(&self, terminal: u8) -> bool {
        self.inner
            .state
            .compare_exchange(TUNNEL_LIVE, terminal, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    /// Publish the cancellation edge for a tunnel already claimed by
    /// [`Self::claim_revocation`].
    ///
    /// This is the LAST step of a revocation, after the counter, the metric,
    /// and the log. Cancellation is the only edge anything outside the sweep
    /// waits on — the relay's revocation bound, and an operator or test reading
    /// [`HboneAdmissionFence::revocations`] the moment a tunnel ends — so
    /// anything that observes it must already be able to observe the
    /// accounting. Cancelling first left a real window in which a revoked
    /// tunnel was reported by nothing at all.
    fn publish_revocation(&self) {
        self.inner.token.cancel();
    }
}

/// Process-wide registry of live admitted HBONE tunnels plus the sweep that
/// re-applies their admission gates. One per `ProxyState`.
pub struct HboneAdmissionFence {
    tunnels: DashMap<u64, Weak<AdmittedHboneTunnelInner>>,
    next_id: AtomicU64,
    sweeps_requested: AtomicU64,
    sweeps_completed: AtomicU64,
    /// Serializes sweeps; a request that arrives mid-sweep is folded into the
    /// next pass by the requested/completed counters.
    sweep_serial: tokio::sync::Mutex<()>,
    revocations: [AtomicU64; HboneRevocationReason::ALL.len()],
    reevaluations: AtomicU64,
    /// `true` while the bounded expiry watcher task is running. At most one
    /// exists; it exits once no live tunnel carries a finite credential
    /// deadline, so a mesh with no SVID-bearing tunnels runs no timer at all.
    expiry_watcher: AtomicBool,
    /// Re-arm signal for the expiry watcher. A tunnel admitted with an EARLIER
    /// deadline than the one the watcher is parked on must not wait for that
    /// later deadline to fire.
    expiry_wakeup: tokio::sync::Notify,
    request_epoch: Arc<RequestEpochStore>,
    mesh_inbound_tls_policy: SharedMeshInboundTlsPolicy,
    /// The CRL set the mesh inbound SPIFFE peer verifier enforces, read live so
    /// a sweep re-checks retained chains against exactly the records the next
    /// handshake would police (issue #5574). The same slot the verifier holds.
    mesh_inbound_crls: crate::tls::crl_policy::SharedEnforcedCrlSet,
}

impl HboneAdmissionFence {
    pub fn new(
        request_epoch: Arc<RequestEpochStore>,
        mesh_inbound_tls_policy: SharedMeshInboundTlsPolicy,
        mesh_inbound_crls: crate::tls::crl_policy::SharedEnforcedCrlSet,
    ) -> Self {
        Self {
            tunnels: DashMap::new(),
            next_id: AtomicU64::new(1),
            sweeps_requested: AtomicU64::new(0),
            sweeps_completed: AtomicU64::new(0),
            sweep_serial: tokio::sync::Mutex::new(()),
            revocations: Default::default(),
            reevaluations: AtomicU64::new(0),
            expiry_watcher: AtomicBool::new(false),
            expiry_wakeup: tokio::sync::Notify::new(),
            request_epoch,
            mesh_inbound_tls_policy,
            mesh_inbound_crls,
        }
    }

    /// Register an admitted tunnel. The returned handle keeps it sweepable
    /// until the relay retires or drops it.
    ///
    /// Publish-then-recheck closes the admission race. The request path spends
    /// the whole authenticate/authorize/`before_proxy` chain, the
    /// circuit-breaker check, the upgrade-handle extraction, and a full backend
    /// dial between reading the epoch and reaching this insert, and a
    /// publication landing inside that window schedules a sweep whose registry
    /// read — including the `tunnels.is_empty()` fast path — can complete
    /// BEFORE the insert. Such a tunnel would then be judged only by the
    /// superseded generation, and, because sweeps are exclusively
    /// publication-driven, would never be re-judged on a quiet mesh.
    ///
    /// The request path therefore captures [`Self::sweep_epoch`] BEFORE it
    /// reads the epoch and the PeerAuthentication policy the gates evaluate
    /// (both publishers bump the counter AFTER their store, so a gate that read
    /// stale state necessarily captured a stale counter too). If the counter
    /// has moved by the time the tunnel is registered, this schedules a fresh
    /// sweep that is guaranteed to see it. The insert and the
    /// sequentially-consistent load below are ordered against
    /// [`Self::request_sweep`]'s increment and its registry read, so at least
    /// one of the two sides observes the other.
    pub fn admit(self: &Arc<Self>, snapshot: HboneAdmissionSnapshot) -> AdmittedHboneTunnel {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let admission_sweep_epoch = snapshot.admission_sweep_epoch;
        let inner = Arc::new(AdmittedHboneTunnelInner {
            id,
            token: CancellationToken::new(),
            state: AtomicU8::new(TUNNEL_LIVE),
            snapshot,
            fence: Arc::downgrade(self),
        });
        self.tunnels.insert(id, Arc::downgrade(&inner));
        let tunnel = AdmittedHboneTunnel { inner };
        if self.sweeps_requested.load(Ordering::SeqCst) != admission_sweep_epoch {
            self.request_sweep();
        }
        if tunnel.credential_deadline().is_some() {
            self.arm_expiry_watcher();
        }
        tunnel
    }

    /// Make sure the bounded expiry watcher is running and parked on the
    /// earliest live credential deadline (issue #5568).
    ///
    /// Sweeps are otherwise exclusively publication-driven, so on a quiet mesh
    /// nothing would ever notice that an admitted SVID aged out. The watcher is
    /// the one timer this fence owns: at most one task, parked on an exact
    /// `sleep_until`, re-armed from the registry after every pass, and gone as
    /// soon as no live tunnel carries a finite deadline.
    fn arm_expiry_watcher(self: &Arc<Self>) {
        // A watcher already parked on a LATER deadline has to be re-armed, not
        // skipped: this tunnel may expire first. `Notify::notify_one` stores a
        // permit when there is no waiter, so a nudge that races the watcher's
        // own re-arm is not lost.
        self.expiry_wakeup.notify_one();
        if self.expiry_watcher.swap(true, Ordering::AcqRel) {
            return;
        }
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            self.expiry_watcher.store(false, Ordering::Release);
            warn!(
                live_tunnels = self.tunnels.len(),
                "HBONE admission fence expiry watcher could not start outside a tokio runtime; \
                 an admitted peer SVID that expires will not be revoked until the next publication"
            );
            return;
        };
        let fence = Arc::clone(self);
        handle.spawn(async move {
            fence.run_expiry_watcher().await;
        });
    }

    async fn run_expiry_watcher(self: Arc<Self>) {
        loop {
            let Some(deadline) = self.earliest_live_credential_deadline() else {
                // Clear the flag, then re-read the registry: a tunnel admitted
                // between the scan above and this store would otherwise find
                // the flag still set, skip arming, and never be watched.
                self.expiry_watcher.store(false, Ordering::Release);
                if self.earliest_live_credential_deadline().is_some()
                    && !self.expiry_watcher.swap(true, Ordering::AcqRel)
                {
                    continue;
                }
                return;
            };
            tokio::select! {
                _ = tokio::time::sleep_until(deadline) => {
                    // Await the sweep rather than firing and forgetting: the
                    // re-arm below reads the registry, and a tunnel this pass
                    // has not yet claimed would still publish the deadline that
                    // just fired, spinning the watcher until the relay caught
                    // up.
                    self.sweep_and_settle().await;
                }
                _ = self.expiry_wakeup.notified() => {}
            }
        }
    }

    /// The earliest credential deadline across tunnels that are still LIVE.
    ///
    /// A revoked or retired tunnel is excluded so an elapsed deadline stops
    /// being re-armed the moment a sweep claims it, without waiting for the
    /// relay to deregister.
    fn earliest_live_credential_deadline(&self) -> Option<tokio::time::Instant> {
        // Collected BEFORE any handle is released, exactly as `sweep_once`
        // does: `AdmittedHboneTunnelInner::drop` deregisters through
        // `tunnels.remove_if`, so letting the last strong reference fall while
        // a `DashMap` iterator still holds a shard would deadlock the fence.
        let live: Vec<Arc<AdmittedHboneTunnelInner>> = self
            .tunnels
            .iter()
            .filter_map(|entry| entry.value().upgrade())
            .collect();
        live.into_iter()
            .filter(|inner| inner.state.load(Ordering::Acquire) == TUNNEL_LIVE)
            .filter_map(|inner| inner.snapshot.peer_credential.as_ref()?.leaf_not_after)
            .min()
    }

    /// Run ONE fresh pass and await it. Only the expiry watcher uses it; every
    /// publication path stays fire-and-forget through [`Self::request_sweep`].
    ///
    /// Deliberately not `request_sweep` + await. Coalescing would let this fold
    /// into a pass that had already read the clock BEFORE the deadline fired,
    /// which leaves the expired tunnel live and the watcher re-arming on the
    /// same elapsed deadline — a spin, not a revocation. Taking the serial lock
    /// and sweeping directly guarantees a pass whose `Instant::now()` is after
    /// the wake.
    ///
    /// The completed counter still advances only to the request count read
    /// BEFORE the pass, exactly as [`Self::run_pending_sweeps`] does, so a
    /// publication that lands mid-pass is not falsely reported as swept.
    async fn sweep_and_settle(&self) {
        let _serial = self.sweep_serial.lock().await;
        let requested = self.sweeps_requested.load(Ordering::Acquire);
        self.sweep_once().await;
        self.sweeps_completed.fetch_max(requested, Ordering::AcqRel);
    }

    /// The sweep-request counter as of this call.
    ///
    /// The HBONE request path captures it before loading the request epoch it
    /// admits against and carries it in
    /// [`HboneAdmissionSnapshot::admission_sweep_epoch`]; [`Self::admit`]
    /// compares it against the live counter to detect a publication that raced
    /// the admission. Two relaxed-cost atomic loads per CONNECT, nothing on the
    /// byte-relay path.
    pub fn sweep_epoch(&self) -> u64 {
        self.sweeps_requested.load(Ordering::SeqCst)
    }

    /// Number of tunnels currently registered.
    pub fn live_tunnels(&self) -> usize {
        self.tunnels.len()
    }

    /// Revocations recorded for `reason` since process start.
    ///
    /// A revoked tunnel is counted here BEFORE its cancellation token fires, so
    /// anything woken by that cancellation — the relay, an operator poll, a
    /// test — already observes the increment.
    pub fn revocations(&self, reason: HboneRevocationReason) -> u64 {
        self.revocations[reason.index()].load(Ordering::Acquire)
    }

    /// Live-tunnel authorize-chain re-evaluations performed by sweeps.
    pub fn reevaluations(&self) -> u64 {
        self.reevaluations.load(Ordering::Relaxed)
    }

    /// Sweeps that have run to completion.
    pub fn sweeps_completed(&self) -> u64 {
        self.sweeps_completed.load(Ordering::Acquire)
    }

    /// Schedule a sweep against the current request epoch and inbound
    /// PeerAuthentication policy. Returns immediately; the sweep runs on the
    /// ambient tokio runtime.
    ///
    /// Outside a runtime the request cannot be scheduled at all, so it is
    /// dropped with a `warn!` naming the live-tunnel count it could not
    /// re-judge — the one place this fence can silently stop being a fence.
    /// Every production publication path (`ProxyState::update_config` /
    /// `update_mesh_config` / the incremental applies,
    /// `apply_mesh_inbound_tls_reload`, and the TLS material reload tasks that
    /// call `publish_mesh_inbound_crls`) runs inside the runtime,
    /// `spawn_blocking` workers carry a runtime context, and startup
    /// publication precedes every live tunnel.
    pub fn request_sweep(self: &Arc<Self>) {
        // Sequentially consistent: `admit` inserts into the registry and then
        // loads this counter, while this increments the counter and then reads
        // the registry. One of the two must observe the other, or an admission
        // racing this publication would escape the fence entirely.
        self.sweeps_requested.fetch_add(1, Ordering::SeqCst);
        if self.tunnels.is_empty() {
            // Nothing to fence; account the sweep as complete so waiters see a
            // settled state without spawning.
            let requested = self.sweeps_requested.load(Ordering::Acquire);
            self.sweeps_completed.fetch_max(requested, Ordering::AcqRel);
            return;
        }
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            warn!(
                requested = self.sweeps_requested.load(Ordering::Acquire),
                completed = self.sweeps_completed.load(Ordering::Acquire),
                live_tunnels = self.tunnels.len(),
                "HBONE admission fence sweep requested outside a tokio runtime; live tunnels \
                 will not be re-judged until the next in-runtime publication"
            );
            return;
        };
        let fence = Arc::clone(self);
        handle.spawn(async move {
            fence.run_pending_sweeps().await;
        });
    }

    async fn run_pending_sweeps(self: Arc<Self>) {
        let _serial = self.sweep_serial.lock().await;
        loop {
            let requested = self.sweeps_requested.load(Ordering::Acquire);
            if self.sweeps_completed.load(Ordering::Acquire) >= requested {
                return;
            }
            self.sweep_once().await;
            self.sweeps_completed.fetch_max(requested, Ordering::AcqRel);
        }
    }

    async fn sweep_once(&self) {
        let epoch = self.request_epoch.load();
        let policy = self.mesh_inbound_tls_policy.load_full();
        // Compiled at most ONCE per sweep, and only if some tunnel actually
        // reaches the chain re-verification. An ordinary policy publication
        // therefore does no certificate path building at all.
        let trust = SweepTrustView::for_epoch(&epoch, &self.mesh_inbound_crls);
        let live: Vec<AdmittedHboneTunnel> = self
            .tunnels
            .iter()
            .filter_map(|entry| entry.value().upgrade())
            .map(|inner| AdmittedHboneTunnel { inner })
            .collect();
        let mut revoked = 0usize;
        for tunnel in live {
            // Cheap pre-filter only: a tunnel that retires or is claimed after
            // this load is refused by `claim_revocation`'s compare-exchange
            // against the same word, so nothing depends on the check being
            // current.
            if tunnel.inner.state.load(Ordering::Acquire) != TUNNEL_LIVE {
                continue;
            }
            // One authorize plugin that unwinds must not take the rest of the
            // sweep — and every later publication — with it: the task would die
            // before `sweeps_completed` advanced, leaving every tunnel after it
            // in iteration order permanently un-swept while the log showed only
            // a task panic. Fail closed on the tunnel whose verdict is missing.
            // The shipped `release` profile is `panic = "abort"`, so this is the
            // dev/test-profile net; under `abort` the process is gone and no
            // tunnel is left silently unfenced either way.
            let reevaluate = self.reevaluate(&tunnel.inner.snapshot, &epoch, &policy, &trust);
            let outcome = std::panic::AssertUnwindSafe(reevaluate)
                .catch_unwind()
                .await;
            let reason = match outcome {
                Ok(reason) => reason,
                Err(_) => {
                    error!(
                        proxy_id = %tunnel.inner.snapshot.proxy.id,
                        config_generation = epoch.config_generation(),
                        "HBONE admission fence re-evaluation panicked; revoking the tunnel it \
                         could not judge"
                    );
                    Some(HboneRevocationReason::ReevaluationFailed)
                }
            };
            let Some(reason) = reason else {
                continue;
            };
            if tunnel.claim_revocation(reason) {
                revoked += 1;
                // Account BEFORE the cancellation edge is published: the relay
                // and every `revocations()` reader wake on that edge, so a
                // counter incremented afterwards is observably missing exactly
                // when someone looks. `Release` pairs with the `Acquire` load in
                // `revocations()` through the cancellation's own ordering.
                self.revocations[reason.index()].fetch_add(1, Ordering::Release);
                crate::plugins::prometheus_metrics::global_registry()
                    .record_hbone_tunnel_revocation(&tunnel.inner.snapshot.proxy.id, reason);
                // Per-TUNNEL record at `debug`: a namespace-wide DENY across a
                // few thousand live tunnels emits one of these each, which is
                // drill-down, not an operator event. The per-SWEEP `info!`
                // summary below is the operator line.
                debug!(
                    proxy_id = %tunnel.inner.snapshot.proxy.id,
                    reason = reason.as_str(),
                    config_generation = epoch.config_generation(),
                    "Revoked a live HBONE tunnel: its CONNECT would no longer be admitted \
                     under the current policy generation"
                );
                tunnel.publish_revocation();
            }
        }
        if revoked > 0 {
            info!(
                revoked,
                config_generation = epoch.config_generation(),
                "HBONE admission fence sweep revoked live tunnels"
            );
        } else {
            debug!(
                config_generation = epoch.config_generation(),
                "HBONE admission fence sweep left every live tunnel admitted"
            );
        }
    }

    /// Re-apply the CONNECT admission gates to one snapshot. `Some(reason)`
    /// means the tunnel must be revoked.
    ///
    /// Gate order is the CONNECT path's order, because the `reason` label on
    /// `ferrum_mesh_hbone_tunnel_revocations_total` and the sweep's log line
    /// are an operator's only attribution: a tunnel that fails two gates must
    /// be attributed the one the peer's next CONNECT would actually be refused
    /// with, or the rollout dashboard and the client-visible failure disagree.
    /// The peer's credential is decided by the mTLS handshake and
    /// `spiffe_identity` before any request exists, so the credential gate
    /// precedes the policy gates. The request path then authorizes in
    /// `handle_proxy_request_inner` BEFORE it branches into
    /// `handle_hbone_request`, which checks the PeerAuthentication transport
    /// mode and only then the relay-destination ownership guard — so the order
    /// here is credential, authorize, transport, destination. The proxy
    /// lifecycle check below is not one of those gates: a withdrawn proxy is
    /// never routed to at all, so it necessarily precedes every one of them.
    async fn reevaluate(
        &self,
        snapshot: &HboneAdmissionSnapshot,
        epoch: &RequestEpoch,
        policy: &MeshInboundTlsPolicy,
        trust: &SweepTrustView,
    ) -> Option<HboneRevocationReason> {
        let proxy = &snapshot.proxy;
        // A configured proxy must still be published under the same lifecycle
        // incarnation. Synthesized relay proxies are never in `config.proxies`;
        // their ownership guard below is the presence check.
        if let Some(admitted_generation) = snapshot.proxy_lifecycle_generation
            && epoch
                .plugin_cache
                .proxy_lifecycle_generation(&proxy.namespace, &proxy.id)
                != Some(admitted_generation)
        {
            return Some(HboneRevocationReason::ProxyWithdrawn);
        }

        if let Some(reason) = peer_credential_revocation(snapshot, trust) {
            return Some(reason);
        }

        if self.authorize_chain_denies(snapshot, epoch).await {
            return Some(HboneRevocationReason::AuthorizationDenied);
        }

        if mesh_inbound_peer_auth_transport_mismatch_for_policy(
            policy,
            snapshot.ctx.mesh_direction,
            snapshot.mesh_inbound_pre_handshake_app_port,
            proxy,
            snapshot.upstream_target.as_deref(),
            snapshot.is_tls,
            snapshot.has_verified_peer_certificate,
        )
        .is_some()
        {
            return Some(HboneRevocationReason::PeerAuthTransport);
        }

        let mesh = epoch.config.mesh.as_deref();
        let destination_owned = match snapshot.destination_gate {
            HboneRelayDestinationGate::InboundRelay => {
                let authority_owned = inbound_hbone_relay_effective_destination_decision(
                    proxy,
                    snapshot.upstream_target.as_deref(),
                    mesh,
                    snapshot.ctx.mesh_inbound_terminator_ip,
                )
                .is_ok();
                authority_owned && inbound_relay_resolved_ip_admitted(mesh, snapshot.resolved_ip)
            }
            HboneRelayDestinationGate::IngressRelay => {
                inbound_ingress_relay_effective_destination_allowed(
                    proxy,
                    snapshot.upstream_target.as_deref(),
                    mesh,
                    snapshot.ctx.mesh_inbound_listener_authz_port,
                )
            }
            HboneRelayDestinationGate::Datagram => {
                let (app_host, app_port) = snapshot
                    .upstream_target
                    .as_deref()
                    .map(|target| (target.host.as_str(), target.port))
                    .unwrap_or((proxy.backend_host.as_str(), proxy.backend_port));
                inbound_hbone_relay_destination_decision(
                    app_host,
                    app_port,
                    mesh,
                    snapshot.ctx.mesh_inbound_terminator_ip,
                )
                .is_ok()
                    || mesh_egress_udp_destination_allowed(app_host, app_port, mesh)
            }
            HboneRelayDestinationGate::Configured => true,
        };
        if !destination_owned {
            return Some(HboneRevocationReason::RelayDestination);
        }

        None
    }

    /// Re-run the re-evaluation-safe part of the admitting authorize chain.
    /// `true` denies, which the caller turns into
    /// [`HboneRevocationReason::AuthorizationDenied`].
    async fn authorize_chain_denies(
        &self,
        snapshot: &HboneAdmissionSnapshot,
        epoch: &RequestEpoch,
    ) -> bool {
        let proxy = &snapshot.proxy;
        // The authorize chain is protocol-scoped and the admitting view is
        // peer-selectable: an HBONE CONNECT carrying `content-type:
        // application/grpc` classifies as gRPC, and a gRPC-Web request resolves
        // an entirely separate view. Re-resolve exactly the view
        // `plugin_cache_view` resolved at admission, never a hardcoded HTTP one.
        let view = if snapshot.grpc_web_request {
            epoch
                .plugin_cache
                .grpc_web_request_view(&proxy.namespace, &proxy.id)
        } else {
            epoch
                .plugin_cache
                .request_view(&proxy.namespace, &proxy.id, snapshot.request_protocol)
        };
        // Only plugins whose `authorize` is free of side effects and external
        // I/O are re-run (`Plugin::reevaluates_live_admission`). A sweep that
        // consumed a rate-limit token or issued one ext_authz/OPA call per live
        // tunnel would revoke healthy, policy-compliant tunnels and drain a real
        // client's budget — a worse outcome than the stale admission this fence
        // exists to close.
        let authorize = view.authorize_plugins();
        let reevaluated: Vec<&Arc<dyn Plugin>> = authorize
            .iter()
            .filter(|plugin| plugin.reevaluates_live_admission())
            .collect();
        if reevaluated.is_empty() {
            return false;
        }
        self.reevaluations.fetch_add(1, Ordering::Relaxed);
        let mut ctx = snapshot.ctx.clone();
        ctx.metadata.insert(
            MESH_AUTHZ_REEVALUATION_METADATA_KEY.to_string(),
            "true".to_string(),
        );
        for plugin in reevaluated {
            match plugin.authorize(&mut ctx).await {
                PluginResult::Continue => {}
                PluginResult::Reject { .. } | PluginResult::RejectBinary { .. } => {
                    debug!(
                        proxy_id = %proxy.id,
                        plugin = plugin.name(),
                        deny_policy = ctx
                            .metadata
                            .get("mesh_authz.deny_policy")
                            .map(String::as_str)
                            .unwrap_or("<unset>"),
                        "Authorize chain denies a live HBONE tunnel's CONNECT under the current \
                         generation"
                    );
                    return true;
                }
            }
        }
        false
    }
}

/// The credential state one sweep re-checks peers against: the gateway trust
/// generation the CURRENT request epoch publishes and the CRL generation the
/// mesh inbound verifier currently enforces, plus the bundles compiled into
/// chain verifiers — WITH those CRLs — the first time a tunnel actually needs
/// one.
///
/// Trust is read from the epoch rather than from a live slot, which is what
/// every gateway-to-mesh trust decision in this codebase is required to do: a
/// slot read pairs whatever trust happens to be installed with whatever
/// configuration the reader holds, and that mixed generation is exactly what
/// [`crate::request_epoch::GatewayTrustEpoch`] exists to remove.
///
/// The CRL set is the opposite case and is deliberately read from its live slot
/// (issue #5574). It is not part of any accepted configuration generation — it
/// is the operator's standing revocation list, published by one writer and read
/// live by the inbound handshake verifier itself — so the sweep must read the
/// same slot the verifier does, or the fence and the next handshake would
/// police different records.
///
/// The trust epoch's `live` flag is deliberately NOT consulted. It fences
/// gateway-to-mesh EGRESS admission for the boundary of a trust publication,
/// and a fenced epoch carries the last accepted material forward unchanged;
/// treating that transient state as "trust unknown" would mass-revoke healthy
/// inbound tunnels on every publication that stages a trust change. The commit
/// that installs new material requests its own sweep, which is the pass that
/// decides.
struct SweepTrustView {
    /// The accepted gateway SVID snapshot, or `None` when the published
    /// generation carries no gateway identity at all.
    svid: Arc<Option<crate::identity::SvidBundle>>,
    generation: u64,
    /// The enforced CRL records and the generation they were published under,
    /// captured once for the whole pass so every tunnel in it is judged against
    /// one set.
    crls: crate::tls::CrlList,
    crl_generation: u64,
    verifiers: OnceLock<Option<crate::tls::spiffe::AdmittedPeerTrustAnchors>>,
}

impl SweepTrustView {
    fn for_epoch(
        epoch: &RequestEpoch,
        mesh_inbound_crls: &crate::tls::crl_policy::SharedEnforcedCrlSet,
    ) -> Self {
        let gateway_trust = epoch.gateway_trust();
        let enforced = mesh_inbound_crls.load();
        Self {
            svid: Arc::clone(gateway_trust.svid()),
            generation: gateway_trust.generation(),
            crls: Arc::clone(enforced.crls()),
            crl_generation: enforced.generation(),
            verifiers: OnceLock::new(),
        }
    }

    /// Compile (once) the anchors this generation publishes, policed by the
    /// enforced CRLs. `None` means the generation carries no trust material at
    /// all.
    fn anchors(&self) -> Option<&crate::tls::spiffe::AdmittedPeerTrustAnchors> {
        self.verifiers
            .get_or_init(|| {
                self.svid.as_ref().as_ref().map(|bundle| {
                    crate::tls::spiffe::AdmittedPeerTrustAnchors::compile(
                        &bundle.trust_bundles,
                        self.crls.as_slice(),
                    )
                })
            })
            .as_ref()
    }
}

/// Re-decide the credential half of admission for one snapshot (issues #5568
/// and #5574).
///
/// Expiry is decided BEFORE the chain, and that order is load-bearing: the
/// chain re-verification validates at the current instant, so an aged-out leaf
/// would fail it as an anchoring failure and be reported as `peer_trust`. The
/// narrower, peer-specific fact has to win, or an operator watching a CA
/// rotation sees expiries filed under trust withdrawal. Trust and revocation
/// are then decided by ONE chain verification against anchors compiled with the
/// enforced CRLs, so their relative attribution is webpki's own — see
/// [`HboneRevocationReason`].
fn peer_credential_revocation(
    snapshot: &HboneAdmissionSnapshot,
    trust: &SweepTrustView,
) -> Option<HboneRevocationReason> {
    let credential = snapshot.peer_credential.as_ref()?;

    if let Some(not_after) = credential.leaf_not_after
        && tokio::time::Instant::now() >= not_after
    {
        return Some(HboneRevocationReason::PeerExpired);
    }

    // A tunnel the gateway trust generation never anchored (a chain-only
    // inbound posture with no gateway SVID material) has no trust state to
    // regress from, so this gate can only produce false positives for it.
    //
    // The CRL half is bounded by the same marker rather than given its own
    // exemption: the re-check is ONE chain verification against the gateway
    // trust bundles, so without anchors from that material there is no path for
    // a CRL to police. A chain-only inbound posture's peers are policed by the
    // operator client-CA verifier, whose own CRL withdrawal already retires
    // established sessions through `tls::client_trust` (issue #3857).
    if !credential.anchored_at_admission {
        return None;
    }
    // Unchanged generations ⇒ unchanged material: skip the path building
    // entirely. This is what keeps an ordinary policy publication free of
    // certificate cryptography over every live tunnel. BOTH inputs have to be
    // unchanged — a CRL rotation that revokes an already-admitted leaf moves
    // only the second one, and skipping on the trust generation alone is
    // exactly the gap issue #5574 closes.
    if trust.generation == snapshot.gateway_trust_generation
        && trust.crl_generation == snapshot.mesh_inbound_crl_generation
    {
        return None;
    }
    let Some(anchors) = trust.anchors() else {
        // The published generation carries no gateway trust material at all,
        // while this tunnel was admitted under material that anchored it. That
        // is a definite answer — nothing is trusted — not an inability to
        // judge, so it is a withdrawal rather than a fence failure.
        return Some(HboneRevocationReason::PeerTrust);
    };
    let intermediates: &[Vec<u8>] = credential
        .intermediates_der
        .as_ref()
        .map_or(&[], |chain| chain.as_slice());
    match anchors.recheck(
        credential.spiffe_id.trust_domain(),
        &credential.leaf_der,
        intermediates,
    ) {
        crate::tls::spiffe::AdmittedPeerTrustVerdict::Trusted => None,
        crate::tls::spiffe::AdmittedPeerTrustVerdict::Withdrawn => {
            Some(HboneRevocationReason::PeerTrust)
        }
        crate::tls::spiffe::AdmittedPeerTrustVerdict::Revoked => {
            Some(HboneRevocationReason::PeerRevoked)
        }
        // Fail closed exactly like an authorize plugin that unwound: a tunnel
        // whose trust or revocation status cannot be judged is cut, not left
        // serving. An enforced CRL that cannot be attached to a verifier, or
        // that has itself reached `nextUpdate`, lands here rather than
        // silently degrading to "no revocation data".
        crate::tls::spiffe::AdmittedPeerTrustVerdict::Unverifiable => {
            Some(HboneRevocationReason::ReevaluationFailed)
        }
    }
}

/// Re-apply `connect_backend`'s post-DNS loopback screen
/// (`screen_ordinary_inbound_hbone_relay_dns_candidates`) to the address the
/// ordinary inbound relay actually dialled.
///
/// Authority matching admits a declared hostname WITHOUT resolving it, so the
/// authority decision alone cannot see a live tunnel pinned to `127.0.0.0/8`,
/// `::1`, or mapped IPv4 loopback. A slice change that withdraws the Sidecar
/// own-namespace privilege (Sidecar → Ambient/waypoint posture on the same
/// host/port) must cut that tunnel, exactly as it would refuse a fresh CONNECT.
/// `None` means nothing was resolved, so there is no screen to re-apply; a
/// missing mesh snapshot is already refused by the authority decision.
fn inbound_relay_resolved_ip_admitted(
    mesh: Option<&crate::modes::mesh::config::MeshConfig>,
    resolved_ip: Option<IpAddr>,
) -> bool {
    let (Some(mesh), Some(ip)) = (mesh, resolved_ip) else {
        return true;
    };
    mesh.screen_inbound_relay_resolved_ips([ip]).is_ok()
}
