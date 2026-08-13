//! Frontend client-trust (CRL / client-CA) generations and established-transport
//! retirement (issue #3857).
//!
//! # The problem this module owns
//!
//! Frontend TLS live reload rebuilds the verifier material used for **new
//! handshakes**. An already-established TLS transport keeps the verifier
//! generation it negotiated, so after an operator publishes a new CRL or removes
//! a CA from the client-CA bundle, the holder of a pre-reload connection could
//! keep opening new H2/H3 streams and new H1 keep-alive requests, and keep an
//! active WebSocket / TCP+TLS / DTLS session alive, under the *withdrawn* trust
//! decision. Certificate **expiry** is a different control and is enforced
//! elsewhere; this module is about an operator explicitly withdrawing authority.
//!
//! # Model
//!
//! Every frontend listener family that terminates client-certificate
//! authentication belongs to exactly one [`ClientTrustScope`] — a fixed,
//! compile-time set. A scope owns one [`ClientTrustDomain`]:
//!
//! - `generation` — monotonically advancing, bumped **only** after a validated,
//!   accepted candidate that *semantically* differs from the last accepted one.
//!   A malformed or unloadable candidate never reaches this module (the caller's
//!   rebuild fails first) and is recorded as `rejected`, retaining the last-good
//!   verifier, generation, material and sessions.
//! - `withdrawal_generation` — the generation at which authority was last
//!   *narrowed* (a trust anchor disappeared, or a new revocation appeared). This
//!   is the fence: a client-certificate-authenticated transport whose captured
//!   generation is strictly below it is retired and may admit no further work.
//!
//! An additive change (a CA added, a revocation removed, a CRL re-issued with the
//! same revocation set, a server cert/key rotation) advances `generation` only
//! when it is semantically different at all, and never moves
//! `withdrawal_generation` — so unaffected sessions are not churned.
//!
//! # Ordering, and why it fails closed
//!
//! Publication is: **(1) the caller applies the new material** (swaps the
//! `ServerConfig` slot / calls `Endpoint::set_server_config` / swaps the DTLS
//! generation), **(2)** `publish_accepted_material` bumps `generation`, **(3)**
//! stores `withdrawal_generation`, **(4)** sweeps registered sessions.
//!
//! Admission is the mirror image: a listener [`capture`]s the generation
//! **before** it loads the config it will hand to the handshake. Because the
//! publisher writes the config before the generation, a reader that observes the
//! new generation provably observed the new config; a reader that observes the
//! old generation may have picked up either config. So the captured generation is
//! always *at or older than* the material actually used — the conservative
//! direction. The cost is that a connection handshaking exactly across a
//! withdrawal can be retired despite already using the new material; the benefit
//! is that one can never escape the fence.
//!
//! The registration race is closed the same way, without a lock: a session is
//! inserted into the domain first and then re-checks the fence. A publication
//! that swept before the insert is caught by the re-check; one that swept after
//! sees the entry. A retired session can never be repopulated, because
//! [`ClientTrustSession::retire`] latches and [`ClientTrustSession::is_retired`]
//! is what every admission gate consults.
//!
//! # Scope of retirement
//!
//! Retirement is deliberately **conservative within a scope**: every
//! client-certificate-authenticated transport in the changed scope is retired,
//! rather than only those whose chain or serial is provably affected. Deciding
//! per-connection impact would require re-running path building against the
//! retained chain for every live transport at publish time, and getting it wrong
//! fails *open*. Precision is instead applied where it is safe — in the
//! **semantic diff** ([`ClientTrustMaterial::withdrawal_relative_to`]), which
//! refuses to retire anything at all unless authority actually narrowed.
//!
//! # Redaction
//!
//! Nothing here records or labels a serial, subject, issuer name, fingerprint,
//! certificate path, or any secret material. The material comparison keys are
//! SHA-256 digests held in memory only; metric labels are the closed
//! [`ClientTrustScope`] and [`ClientTrustRetirementReason`] vocabularies.

use std::collections::BTreeSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};

use crate::fips::approved::Sha256;
use arc_swap::ArcSwap;
use dashmap::DashMap;
use rustls::pki_types::CertificateRevocationListDer;
use tokio_util::sync::{CancellationToken, WaitForCancellationFutureOwned};
use x509_parser::prelude::FromDer;

/// The closed set of frontend listener families that terminate client
/// certificates and therefore own a client-trust generation.
///
/// This is the metric label dimension. It is compile-time closed on purpose:
/// a per-listener or per-certificate label would be unbounded cardinality and
/// would leak deployment topology into a scrape.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum ClientTrustScope {
    /// Proxy HTTPS / HTTP-2 listeners **and** TCP+TLS stream listeners. Both
    /// terminate with the same startup-loaded proxy frontend `ServerConfig`
    /// (`FERRUM_FRONTEND_TLS_*` + `FERRUM_TLS_CRL_FILE_PATH`), so they are one
    /// trust domain.
    ProxyFrontend,
    /// The QUIC / HTTP-3 listener. Separate from [`Self::ProxyFrontend`] even
    /// though the material is identical, because the H3 endpoint applies a
    /// reload asynchronously (`Endpoint::set_server_config` after the revision
    /// watch fires). Publishing its generation from the H3 listener itself is
    /// what keeps "captured generation ≤ material actually used" true there.
    ProxyH3,
    /// The admin HTTPS listener (`FERRUM_ADMIN_TLS_CLIENT_CA_BUNDLE_PATH`).
    AdminHttps,
    /// Frontend UDP + DTLS listeners (`FERRUM_DTLS_*`).
    FrontendDtls,
}

impl ClientTrustScope {
    /// Every scope, in index order.
    pub const ALL: [ClientTrustScope; 4] = [
        ClientTrustScope::ProxyFrontend,
        ClientTrustScope::ProxyH3,
        ClientTrustScope::AdminHttps,
        ClientTrustScope::FrontendDtls,
    ];

    /// Stable, fixed-cardinality metric / log label.
    pub const fn label(self) -> &'static str {
        match self {
            ClientTrustScope::ProxyFrontend => "proxy_frontend",
            ClientTrustScope::ProxyH3 => "proxy_h3",
            ClientTrustScope::AdminHttps => "admin_https",
            ClientTrustScope::FrontendDtls => "frontend_dtls",
        }
    }

    const fn index(self) -> usize {
        match self {
            ClientTrustScope::ProxyFrontend => 0,
            ClientTrustScope::ProxyH3 => 1,
            ClientTrustScope::AdminHttps => 2,
            ClientTrustScope::FrontendDtls => 3,
        }
    }
}

/// Closed set of reasons an established transport is retired.
///
/// Ordered by precedence: a candidate that both withdraws a CA and adds a
/// revocation reports [`Self::ClientCaWithdrawn`], the broader change.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ClientTrustRetirementReason {
    /// A trust anchor present in the last accepted client-CA bundle is absent
    /// from the accepted candidate.
    ClientCaWithdrawn,
    /// The accepted candidate revokes at least one (issuer, serial) pair that
    /// the last accepted CRL set did not.
    CrlChanged,
}

impl ClientTrustRetirementReason {
    /// Stable, fixed-cardinality metric / log label.
    pub const fn label(self) -> &'static str {
        match self {
            ClientTrustRetirementReason::ClientCaWithdrawn => "client_ca_withdrawn",
            ClientTrustRetirementReason::CrlChanged => "crl_changed",
        }
    }

    const fn index(self) -> usize {
        match self {
            ClientTrustRetirementReason::ClientCaWithdrawn => 0,
            ClientTrustRetirementReason::CrlChanged => 1,
        }
    }

    const fn from_index(index: u8) -> Option<Self> {
        match index {
            0 => Some(ClientTrustRetirementReason::ClientCaWithdrawn),
            1 => Some(ClientTrustRetirementReason::CrlChanged),
            _ => None,
        }
    }
}

const REASON_COUNT: usize = 2;
const SCOPE_COUNT: usize = ClientTrustScope::ALL.len();
/// Sentinel stored in `last_withdrawal_reason` before any withdrawal.
const NO_REASON: u8 = u8::MAX;

/// Outcome of one publication attempt, for logs and metrics.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ClientTrustPublicationOutcome {
    /// The scope had no accepted material yet; this candidate became the
    /// baseline. Never retires anything.
    Armed,
    /// The candidate is byte-for-byte semantically equal to the last accepted
    /// material. The generation does **not** advance and no session is touched.
    Unchanged,
    /// The candidate is semantically different but does not narrow authority
    /// (a CA was added, a revocation disappeared, a CRL was re-issued with new
    /// validity dates over the same revocation set). The generation advances;
    /// no session is retired.
    Advanced,
    /// The candidate narrows authority. The generation advances, the fence
    /// moves, and every client-certificate-authenticated session below the new
    /// generation is retired.
    Withdrawn,
}

impl ClientTrustPublicationOutcome {
    /// Stable, fixed-cardinality metric / log label.
    pub const fn label(self) -> &'static str {
        match self {
            ClientTrustPublicationOutcome::Armed => "armed",
            ClientTrustPublicationOutcome::Unchanged => "unchanged",
            ClientTrustPublicationOutcome::Advanced => "advanced",
            ClientTrustPublicationOutcome::Withdrawn => "withdrawn",
        }
    }
}

/// Result of [`publish_accepted_material`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ClientTrustPublication {
    /// The scope that was published into.
    pub scope: ClientTrustScope,
    /// The generation in force after the publication.
    pub generation: u64,
    /// What the publication did.
    pub outcome: ClientTrustPublicationOutcome,
    /// Why sessions were retired, when they were.
    pub reason: Option<ClientTrustRetirementReason>,
    /// How many established transports this publication retired.
    pub retired_sessions: usize,
}

impl ClientTrustPublication {
    /// Whether this publication narrowed authority and moved the admission
    /// fence. Callers log and alert on exactly this condition.
    pub fn withdrew(&self) -> bool {
        self.outcome == ClientTrustPublicationOutcome::Withdrawn
    }
}

/// The semantic identity of one accepted frontend client-trust snapshot.
///
/// Two snapshots compare equal exactly when they grant the same authority to the
/// same principals. Deliberately **not** a byte hash of the source material: a
/// CRL is normally re-issued on a schedule with a fresh `thisUpdate` /
/// `nextUpdate` / `crlNumber` and an unchanged revocation set, and treating that
/// as a change would advance the generation (and, with a naive fence, retire
/// every live session) on every routine re-issue.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ClientTrustMaterial {
    /// SHA-256 over each client-CA trust anchor's DER, deduplicated and sorted.
    /// Anchor *order* in the bundle is not authority, so the set is the identity.
    anchors: BTreeSet<[u8; 32]>,
    /// SHA-256 over `issuer DER || 0x00 || serial DER` for every revoked entry
    /// across every parsed CRL. Scoping each serial by its issuer is required:
    /// serial numbers are only unique within an issuer, so a bare-serial set
    /// would let a revocation under CA A mask the *appearance* of the same
    /// serial under CA B and suppress a real withdrawal.
    revocations: BTreeSet<[u8; 32]>,
}

/// A CRL that this module could not parse.
///
/// Surfaced to the caller so an unusable candidate is recorded as `rejected` and
/// the last accepted generation, verifier and sessions are all retained. The
/// error carries no bytes, no path, and no certificate field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientTrustMaterialError;

impl std::fmt::Display for ClientTrustMaterialError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("frontend client-trust material could not be parsed")
    }
}

impl std::error::Error for ClientTrustMaterialError {}

impl ClientTrustMaterial {
    /// Build the semantic identity from an already-validated candidate.
    ///
    /// `client_ca_pem` is the client-CA bundle exactly as handed to the verifier
    /// builder (`None` when the listener does no client authentication);
    /// `crls` is the accepted CRL list. Both must come from the **same** accepted
    /// generation as the `ServerConfig` the caller is about to publish, or the
    /// fence would describe material that was never served.
    pub fn from_parts(
        client_ca_pem: Option<&[u8]>,
        crls: &[CertificateRevocationListDer<'static>],
    ) -> Result<Self, ClientTrustMaterialError> {
        let mut anchors = BTreeSet::new();
        if let Some(pem) = client_ca_pem {
            let mut reader = pem;
            for cert in rustls_pemfile::certs(&mut reader) {
                let cert = cert.map_err(|_| ClientTrustMaterialError)?;
                anchors.insert(digest_of(&[cert.as_ref()]));
            }
        }

        let mut revocations = BTreeSet::new();
        for crl in crls {
            let (_rest, parsed) =
                x509_parser::revocation_list::CertificateRevocationList::from_der(crl.as_ref())
                    .map_err(|_| ClientTrustMaterialError)?;
            let issuer = parsed.issuer().as_raw();
            for revoked in parsed.iter_revoked_certificates() {
                revocations.insert(digest_of(&[issuer, &[0x00], revoked.raw_serial()]));
            }
        }

        Ok(Self {
            anchors,
            revocations,
        })
    }

    /// Decide whether moving from `previous` to `self` **narrows** the authority
    /// an already-authenticated peer holds.
    ///
    /// Returns `None` for every widening or lateral change, which is what keeps
    /// an additive CA rotation (new CA appended, overlapping with the old) and a
    /// routine CRL re-issue from churning live sessions.
    pub fn withdrawal_relative_to(
        &self,
        previous: &ClientTrustMaterial,
    ) -> Option<ClientTrustRetirementReason> {
        // A trust anchor that used to be accepted and no longer is invalidates
        // every chain that terminated at it. Checked first: it is the broader
        // withdrawal, and a bundle rotation commonly lands together with a CRL
        // update.
        if !previous.anchors.is_subset(&self.anchors) {
            return Some(ClientTrustRetirementReason::ClientCaWithdrawn);
        }
        // A revocation that is present now and was not before is a withdrawal of
        // exactly one credential. Removing a revocation, or re-issuing the same
        // set under new validity dates, is not.
        if !self.revocations.is_subset(&previous.revocations) {
            return Some(ClientTrustRetirementReason::CrlChanged);
        }
        None
    }
}

fn digest_of(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize()
}

/// Per-scope state. One instance per [`ClientTrustScope`], created once.
struct ClientTrustDomain {
    scope: ClientTrustScope,
    /// `true` once a baseline has been accepted. Until then [`capture`] returns
    /// `None` and listeners pay nothing at all — which is the default
    /// configuration, where `FERRUM_FRONTEND_TLS_LIVE_RELOAD_ENABLED` is off and
    /// no generation can ever advance.
    armed: AtomicBool,
    /// Monotonic accepted-material generation. Starts at `0` (unarmed).
    generation: AtomicU64,
    /// Generation at which authority was last narrowed; the admission fence.
    withdrawal_generation: AtomicU64,
    /// Reason index for the last withdrawal, or [`NO_REASON`].
    last_withdrawal_reason: AtomicU8,
    /// Last accepted semantic material.
    material: ArcSwap<Option<ClientTrustMaterial>>,
    /// Live client-certificate-authenticated transports, keyed by an internal
    /// session id. Only ever touched at connection setup/teardown and at
    /// publication — never on the request path.
    sessions: DashMap<u64, ClientTrustSession>,
    next_session_id: AtomicU64,
    /// Serializes publications so two concurrent accepted candidates cannot
    /// interleave their read-compare-store-sweep. Publications are rare
    /// (operator-driven reloads) and never happen on a data path.
    publish_lock: std::sync::Mutex<()>,
    /// Fixed-cardinality counters.
    publications: [AtomicU64; 4],
    retirements: [AtomicU64; REASON_COUNT],
    rejected_candidates: AtomicU64,
    fenced: AtomicU64,
}

impl ClientTrustDomain {
    fn new(scope: ClientTrustScope) -> Self {
        Self {
            scope,
            armed: AtomicBool::new(false),
            generation: AtomicU64::new(0),
            withdrawal_generation: AtomicU64::new(0),
            last_withdrawal_reason: AtomicU8::new(NO_REASON),
            material: ArcSwap::from_pointee(None),
            sessions: DashMap::new(),
            next_session_id: AtomicU64::new(1),
            publish_lock: std::sync::Mutex::new(()),
            publications: [
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
            ],
            retirements: [AtomicU64::new(0), AtomicU64::new(0)],
            rejected_candidates: AtomicU64::new(0),
            fenced: AtomicU64::new(0),
        }
    }

    fn record_publication(&self, outcome: ClientTrustPublicationOutcome) {
        let index = match outcome {
            ClientTrustPublicationOutcome::Armed => 0,
            ClientTrustPublicationOutcome::Unchanged => 1,
            ClientTrustPublicationOutcome::Advanced => 2,
            ClientTrustPublicationOutcome::Withdrawn => 3,
        };
        self.publications[index].fetch_add(1, Ordering::Relaxed);
    }

    /// Retire every registered session strictly below `fence`.
    fn sweep(&self, fence: u64, reason: ClientTrustRetirementReason) -> usize {
        let mut retired = 0usize;
        for entry in self.sessions.iter() {
            if entry.value().generation() < fence && entry.value().retire(reason) {
                retired += 1;
            }
        }
        retired
    }
}

fn domains() -> &'static [ClientTrustDomain; SCOPE_COUNT] {
    static DOMAINS: OnceLock<[ClientTrustDomain; SCOPE_COUNT]> = OnceLock::new();
    DOMAINS.get_or_init(|| {
        [
            ClientTrustDomain::new(ClientTrustScope::ProxyFrontend),
            ClientTrustDomain::new(ClientTrustScope::ProxyH3),
            ClientTrustDomain::new(ClientTrustScope::AdminHttps),
            ClientTrustDomain::new(ClientTrustScope::FrontendDtls),
        ]
    })
}

fn domain(scope: ClientTrustScope) -> &'static ClientTrustDomain {
    &domains()[scope.index()]
}

/// Publish one validated, accepted client-trust snapshot into `scope`.
///
/// **The caller must already have applied the corresponding material** (swapped
/// the `ServerConfig` slot, applied the QUIC server config, swapped the DTLS
/// generation) before calling this. See the module docs for why that order is
/// what makes the captured generation conservative rather than optimistic.
pub fn publish_accepted_material(
    scope: ClientTrustScope,
    material: ClientTrustMaterial,
) -> ClientTrustPublication {
    let domain = domain(scope);
    // Poisoning cannot make the state unsafe (every field is an atomic or an
    // `ArcSwap`), and refusing to publish on a poisoned lock would leave the
    // fence permanently behind the served material — the fail-open direction.
    let _publish_guard = domain
        .publish_lock
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    let previous = domain.material.load_full();
    let Some(previous_material) = previous.as_ref().as_ref() else {
        // First accepted snapshot for this scope: the baseline. Nothing was
        // authorized under an older generation, so nothing is retired.
        domain.material.store(Arc::new(Some(material)));
        let generation = domain.generation.fetch_add(1, Ordering::AcqRel) + 1;
        domain.armed.store(true, Ordering::Release);
        domain.record_publication(ClientTrustPublicationOutcome::Armed);
        return ClientTrustPublication {
            scope,
            generation,
            outcome: ClientTrustPublicationOutcome::Armed,
            reason: None,
            retired_sessions: 0,
        };
    };

    if *previous_material == material {
        let generation = domain.generation.load(Ordering::Acquire);
        domain.record_publication(ClientTrustPublicationOutcome::Unchanged);
        return ClientTrustPublication {
            scope,
            generation,
            outcome: ClientTrustPublicationOutcome::Unchanged,
            reason: None,
            retired_sessions: 0,
        };
    }

    let reason = material.withdrawal_relative_to(previous_material);
    domain.material.store(Arc::new(Some(material)));
    let generation = domain.generation.fetch_add(1, Ordering::AcqRel) + 1;

    let Some(reason) = reason else {
        domain.record_publication(ClientTrustPublicationOutcome::Advanced);
        return ClientTrustPublication {
            scope,
            generation,
            outcome: ClientTrustPublicationOutcome::Advanced,
            reason: None,
            retired_sessions: 0,
        };
    };

    // Move the fence BEFORE sweeping. A session registering concurrently either
    // lands in the map in time to be swept, or observes this store in its own
    // post-insert re-check. Neither can escape, and neither can be retired
    // twice.
    domain
        .last_withdrawal_reason
        .store(reason.index() as u8, Ordering::Release);
    domain
        .withdrawal_generation
        .store(generation, Ordering::Release);
    let retired = domain.sweep(generation, reason);
    domain.retirements[reason.index()].fetch_add(retired as u64, Ordering::Relaxed);
    domain.record_publication(ClientTrustPublicationOutcome::Withdrawn);

    ClientTrustPublication {
        scope,
        generation,
        outcome: ClientTrustPublicationOutcome::Withdrawn,
        reason: Some(reason),
        retired_sessions: retired,
    }
}

/// The last accepted semantic material for `scope`, when the scope is armed.
///
/// Used by the HTTP/3 listener to republish the proxy frontend's accepted
/// identity into its own scope after `Endpoint::set_server_config` has actually
/// applied it — the H3 endpoint is the only consumer that applies a reload
/// asynchronously, so it must publish its own generation rather than inherit
/// one that is already ahead of the material QUIC is handshaking with.
pub fn current_material(scope: ClientTrustScope) -> Option<ClientTrustMaterial> {
    domain(scope).material.load_full().as_ref().clone()
}

/// Record that a reload candidate for `scope` was refused.
///
/// The last accepted verifier, generation, material and every live session are
/// retained; this only makes the refusal observable.
pub fn record_rejected_candidate(scope: ClientTrustScope) {
    domain(scope)
        .rejected_candidates
        .fetch_add(1, Ordering::Relaxed);
}

/// The generation currently in force for `scope`, or `None` when the scope has
/// never accepted material (the default, live-reload-disabled configuration).
///
/// **Call this before loading the TLS configuration** the handshake will use.
#[inline]
pub fn capture(scope: ClientTrustScope) -> Option<ClientTrustAdmission> {
    let domain = domain(scope);
    if !domain.armed.load(Ordering::Acquire) {
        return None;
    }
    Some(ClientTrustAdmission {
        scope,
        generation: domain.generation.load(Ordering::Acquire),
    })
}

/// A captured generation, carried from the accept path to the point where the
/// handshake outcome is known.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClientTrustAdmission {
    scope: ClientTrustScope,
    generation: u64,
}

impl ClientTrustAdmission {
    /// The scope this admission was captured from.
    // Introspection surface for external tests; the bin target re-declares the
    // module tree, so an item used only from `tests/` is dead there.
    #[allow(dead_code)]
    pub fn scope(self) -> ClientTrustScope {
        self.scope
    }

    /// The captured generation.
    #[allow(dead_code)]
    pub fn generation(self) -> u64 {
        self.generation
    }

    /// Register an established transport that authenticated with a client
    /// certificate.
    ///
    /// Returns `None` when `client_cert_authenticated` is false — a transport
    /// that presented no gateway-verified client certificate holds no trust
    /// decision that a CRL or client-CA withdrawal can revoke, so it is neither
    /// tracked nor retired.
    ///
    /// The returned guard owns deregistration; clone the inner
    /// [`ClientTrustSession`] for per-request and per-session consumers.
    pub fn register(self, client_cert_authenticated: bool) -> Option<ClientTrustSessionGuard> {
        if !client_cert_authenticated {
            return None;
        }
        let domain = domain(self.scope);
        let id = domain.next_session_id.fetch_add(1, Ordering::Relaxed);
        let session = ClientTrustSession {
            inner: Arc::new(ClientTrustSessionInner {
                scope: self.scope,
                generation: self.generation,
                token: CancellationToken::new(),
                retired: AtomicBool::new(false),
            }),
        };
        domain.sessions.insert(id, session.clone());
        // Publish-then-recheck: a withdrawal that swept before this insert is
        // caught here, so a connection being registered across a publication
        // cannot escape the fence or repopulate the domain after it.
        if self.generation < domain.withdrawal_generation.load(Ordering::Acquire) {
            let reason = ClientTrustRetirementReason::from_index(
                domain.last_withdrawal_reason.load(Ordering::Acquire),
            )
            .unwrap_or(ClientTrustRetirementReason::ClientCaWithdrawn);
            if session.retire(reason) {
                domain.retirements[reason.index()].fetch_add(1, Ordering::Relaxed);
            }
        }
        Some(ClientTrustSessionGuard {
            id,
            session: Some(session),
        })
    }
}

struct ClientTrustSessionInner {
    scope: ClientTrustScope,
    generation: u64,
    token: CancellationToken,
    retired: AtomicBool,
}

/// A handle to one registered, client-certificate-authenticated transport.
///
/// Cheap to clone (one `Arc` bump). Clones are handed to per-request admission
/// gates and to long-lived session relays; none of them owns deregistration.
#[derive(Clone)]
pub struct ClientTrustSession {
    inner: Arc<ClientTrustSessionInner>,
}

impl std::fmt::Debug for ClientTrustSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientTrustSession")
            .field("scope", &self.inner.scope.label())
            .field("generation", &self.inner.generation)
            .field("retired", &self.is_retired())
            .finish()
    }
}

impl ClientTrustSession {
    /// The scope this transport was admitted under.
    #[allow(dead_code)] // External test / introspection surface.
    pub fn scope(&self) -> ClientTrustScope {
        self.inner.scope
    }

    /// The generation captured before the handshake that established this
    /// transport.
    pub fn generation(&self) -> u64 {
        self.inner.generation
    }

    /// Whether this transport's trust decision has been withdrawn.
    ///
    /// One relaxed atomic read of connection-local state — no lock, no shared
    /// counter, no allocation. This is the per-request / per-stream fence.
    #[inline]
    pub fn is_retired(&self) -> bool {
        self.inner.token.is_cancelled()
    }

    /// Resolves once this transport is retired. Cancel-safe; usable directly as
    /// a `tokio::select!` arm alongside the connection's serve future.
    pub fn retired(&self) -> tokio_util::sync::WaitForCancellationFuture<'_> {
        self.inner.token.cancelled()
    }

    /// An owned cancellation handle, for wrappers that must hold the future
    /// across polls (see [`TrustFencedStream`]).
    pub fn cancellation_token(&self) -> CancellationToken {
        self.inner.token.clone()
    }

    /// Latch this transport as retired. Returns `true` for the caller that won
    /// the latch, so accounting fires exactly once no matter how many
    /// publications or re-checks observe the same session.
    fn retire(&self, _reason: ClientTrustRetirementReason) -> bool {
        if self.inner.retired.swap(true, Ordering::AcqRel) {
            return false;
        }
        self.inner.token.cancel();
        true
    }

    /// Record that this transport refused a request / stream at the admission
    /// fence. Fixed-cardinality, scope-labelled only.
    #[inline]
    pub fn record_fenced(&self) {
        domain(self.inner.scope)
            .fenced
            .fetch_add(1, Ordering::Relaxed);
    }
}

/// Owns a registered session's presence in its domain. Dropping it deregisters
/// the transport on every exit path.
pub struct ClientTrustSessionGuard {
    id: u64,
    session: Option<ClientTrustSession>,
}

impl ClientTrustSessionGuard {
    /// The registered session handle. Clone it for request-path consumers.
    pub fn session(&self) -> &ClientTrustSession {
        self.session
            .as_ref()
            .expect("session is only taken in Drop, which consumes the guard")
    }
}

impl Drop for ClientTrustSessionGuard {
    fn drop(&mut self) {
        if let Some(session) = self.session.take() {
            domain(session.inner.scope).sessions.remove(&self.id);
        }
    }
}

/// Wrap a client-side byte stream so a trust withdrawal surfaces as an ordinary
/// transport failure.
///
/// Used by the TCP+TLS stream relay and the WebSocket relay, where there is no
/// request boundary to fence and the correct behaviour is to end the session.
/// Routing every termination through an `io::Error` means byte counters,
/// first-failure attribution, disconnect hooks, permits, and the stream summary
/// all complete exactly once through the paths those relays already have — no
/// second teardown path is introduced.
///
/// The error is a compiled-in literal and carries no certificate field.
pub struct TrustFencedStream<S> {
    inner: S,
    /// `None` when the transport carries no withdrawable trust decision (no
    /// client certificate, or an unarmed scope). The wrapper then costs one
    /// `Option` branch per poll and registers no waker at all, so a deployment
    /// that never enables frontend TLS live reload pays nothing measurable.
    retired: Option<Pin<Box<WaitForCancellationFutureOwned>>>,
    fired: bool,
}

/// The single client-visible / log-visible string for a fenced stream.
pub const TRUST_FENCED_STREAM_MESSAGE: &str = "frontend client trust withdrawn";

impl<S> TrustFencedStream<S> {
    /// Wrap `inner`, terminating it once `session` is retired. Passing `None`
    /// makes the wrapper a transparent pass-through.
    pub fn new(inner: S, session: Option<&ClientTrustSession>) -> Self {
        Self {
            inner,
            retired: session
                .map(|session| Box::pin(session.cancellation_token().cancelled_owned())),
            fired: false,
        }
    }

    /// Whether this wrapper is actually fencing anything.
    #[allow(dead_code)] // External test / introspection surface.
    pub fn is_fencing(&self) -> bool {
        self.retired.is_some()
    }

    fn poll_fence(&mut self, cx: &mut Context<'_>) -> Option<std::io::Error> {
        let retired = self.retired.as_mut()?;
        if self.fired {
            return Some(fenced_error());
        }
        if retired.as_mut().poll(cx).is_ready() {
            self.fired = true;
            return Some(fenced_error());
        }
        None
    }
}

fn fenced_error() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::ConnectionAborted,
        TRUST_FENCED_STREAM_MESSAGE,
    )
}

impl<S: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for TrustFencedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if let Some(error) = this.poll_fence(cx) {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for TrustFencedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        if let Some(error) = this.poll_fence(cx) {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut this.inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if let Some(error) = this.poll_fence(cx) {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // Shutdown must stay available after the fence fires so the relay can
        // still half-close the peer cleanly rather than leaking the socket.
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

/// Non-secret observability snapshot of one scope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClientTrustScopeSnapshot {
    /// The scope this row describes.
    pub scope: ClientTrustScope,
    /// Whether the scope has ever accepted material.
    pub armed: bool,
    /// The generation currently in force.
    pub generation: u64,
    /// The generation at which authority was last narrowed (`0` = never).
    pub withdrawal_generation: u64,
    /// Live registered client-certificate-authenticated transports.
    pub tracked_sessions: usize,
    /// Publications by outcome: armed, unchanged, advanced, withdrawn.
    pub publications: [u64; 4],
    /// Retired transports by reason index.
    pub retirements: [u64; REASON_COUNT],
    /// Reload candidates refused for this scope.
    pub rejected_candidates: u64,
    /// Requests / streams refused at the admission fence.
    pub fenced: u64,
}

/// Snapshot every scope. Cheap; used by `/metrics`, `/metrics/runtime` and tests.
pub fn snapshot() -> Vec<ClientTrustScopeSnapshot> {
    domains()
        .iter()
        .map(|domain| ClientTrustScopeSnapshot {
            scope: domain.scope,
            armed: domain.armed.load(Ordering::Acquire),
            generation: domain.generation.load(Ordering::Acquire),
            withdrawal_generation: domain.withdrawal_generation.load(Ordering::Acquire),
            tracked_sessions: domain.sessions.len(),
            publications: [
                domain.publications[0].load(Ordering::Relaxed),
                domain.publications[1].load(Ordering::Relaxed),
                domain.publications[2].load(Ordering::Relaxed),
                domain.publications[3].load(Ordering::Relaxed),
            ],
            retirements: [
                domain.retirements[0].load(Ordering::Relaxed),
                domain.retirements[1].load(Ordering::Relaxed),
            ],
            rejected_candidates: domain.rejected_candidates.load(Ordering::Relaxed),
            fenced: domain.fenced.load(Ordering::Relaxed),
        })
        .collect()
}

/// Render the bounded frontend client-trust families.
///
/// Emits nothing at all when no scope has ever accepted material, so a
/// deployment without frontend client-certificate live reload pays no scrape
/// bytes. Every label is from a closed compile-time vocabulary.
pub fn render_prometheus(output: &mut String, ns_label: &str) {
    let rows = snapshot();
    if !rows.iter().any(|row| row.armed) {
        return;
    }

    output.push_str(
        "# HELP ferrum_frontend_client_trust_generation Monotonic frontend client-CA/CRL trust generation currently in force for a listener scope.\n",
    );
    output.push_str("# TYPE ferrum_frontend_client_trust_generation gauge\n");
    for row in rows.iter().filter(|row| row.armed) {
        output.push_str(&format!(
            "ferrum_frontend_client_trust_generation{{scope=\"{}\"{}}} {}\n",
            row.scope.label(),
            ns_label,
            row.generation
        ));
    }

    output.push_str(
        "# HELP ferrum_frontend_client_trust_withdrawal_generation Generation at which frontend client-certificate authority was last narrowed for a listener scope (0 = never).\n",
    );
    output.push_str("# TYPE ferrum_frontend_client_trust_withdrawal_generation gauge\n");
    for row in rows.iter().filter(|row| row.armed) {
        output.push_str(&format!(
            "ferrum_frontend_client_trust_withdrawal_generation{{scope=\"{}\"{}}} {}\n",
            row.scope.label(),
            ns_label,
            row.withdrawal_generation
        ));
    }

    output.push_str(
        "# HELP ferrum_frontend_client_trust_tracked_connections Established client-certificate-authenticated frontend transports currently tracked for retirement.\n",
    );
    output.push_str("# TYPE ferrum_frontend_client_trust_tracked_connections gauge\n");
    for row in rows.iter().filter(|row| row.armed) {
        output.push_str(&format!(
            "ferrum_frontend_client_trust_tracked_connections{{scope=\"{}\"{}}} {}\n",
            row.scope.label(),
            ns_label,
            row.tracked_sessions
        ));
    }

    output.push_str(
        "# HELP ferrum_frontend_client_trust_publications_total Accepted frontend client-trust reload publications by bounded outcome.\n",
    );
    output.push_str("# TYPE ferrum_frontend_client_trust_publications_total counter\n");
    const OUTCOMES: [ClientTrustPublicationOutcome; 4] = [
        ClientTrustPublicationOutcome::Armed,
        ClientTrustPublicationOutcome::Unchanged,
        ClientTrustPublicationOutcome::Advanced,
        ClientTrustPublicationOutcome::Withdrawn,
    ];
    for row in rows.iter().filter(|row| row.armed) {
        for (index, outcome) in OUTCOMES.iter().enumerate() {
            output.push_str(&format!(
                "ferrum_frontend_client_trust_publications_total{{scope=\"{}\",outcome=\"{}\"{}}} {}\n",
                row.scope.label(),
                outcome.label(),
                ns_label,
                row.publications[index]
            ));
        }
    }

    output.push_str(
        "# HELP ferrum_frontend_client_trust_rejected_candidates_total Frontend client-trust reload candidates refused; the last accepted generation and its sessions are retained.\n",
    );
    output.push_str("# TYPE ferrum_frontend_client_trust_rejected_candidates_total counter\n");
    for row in rows.iter().filter(|row| row.armed) {
        output.push_str(&format!(
            "ferrum_frontend_client_trust_rejected_candidates_total{{scope=\"{}\"{}}} {}\n",
            row.scope.label(),
            ns_label,
            row.rejected_candidates
        ));
    }

    output.push_str(
        "# HELP ferrum_frontend_client_trust_retired_connections_total Established frontend transports retired because their client-certificate trust decision was withdrawn.\n",
    );
    output.push_str("# TYPE ferrum_frontend_client_trust_retired_connections_total counter\n");
    const REASONS: [ClientTrustRetirementReason; REASON_COUNT] = [
        ClientTrustRetirementReason::ClientCaWithdrawn,
        ClientTrustRetirementReason::CrlChanged,
    ];
    for row in rows.iter().filter(|row| row.armed) {
        for (index, reason) in REASONS.iter().enumerate() {
            output.push_str(&format!(
                "ferrum_frontend_client_trust_retired_connections_total{{scope=\"{}\",reason=\"{}\"{}}} {}\n",
                row.scope.label(),
                reason.label(),
                ns_label,
                row.retirements[index]
            ));
        }
    }

    output.push_str(
        "# HELP ferrum_frontend_client_trust_fenced_total Requests or streams refused before routing because the transport's client-certificate trust was withdrawn.\n",
    );
    output.push_str("# TYPE ferrum_frontend_client_trust_fenced_total counter\n");
    for row in rows.iter().filter(|row| row.armed) {
        output.push_str(&format!(
            "ferrum_frontend_client_trust_fenced_total{{scope=\"{}\"{}}} {}\n",
            row.scope.label(),
            ns_label,
            row.fenced
        ));
    }
}

/// Reset every domain. **Test seam only** — the registry is process-global, so
/// external test binaries need a way to isolate cases.
#[doc(hidden)]
#[allow(dead_code)] // External test seam only.
pub fn reset_for_test() {
    for domain in domains().iter() {
        let _guard = domain
            .publish_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        domain.sessions.clear();
        domain.armed.store(false, Ordering::Release);
        domain.generation.store(0, Ordering::Release);
        domain.withdrawal_generation.store(0, Ordering::Release);
        domain
            .last_withdrawal_reason
            .store(NO_REASON, Ordering::Release);
        domain.material.store(Arc::new(None));
        domain.next_session_id.store(1, Ordering::Release);
        for counter in domain.publications.iter() {
            counter.store(0, Ordering::Relaxed);
        }
        for counter in domain.retirements.iter() {
            counter.store(0, Ordering::Relaxed);
        }
        domain.rejected_candidates.store(0, Ordering::Relaxed);
        domain.fenced.store(0, Ordering::Relaxed);
    }
}

/// Force the fence for `scope` to `generation` without publishing material.
/// **Test seam only** — used to exercise the register-across-publication race
/// deterministically.
#[doc(hidden)]
#[allow(dead_code)] // External test seam only.
pub fn force_withdrawal_fence_for_test(
    scope: ClientTrustScope,
    generation: u64,
    reason: ClientTrustRetirementReason,
) {
    let domain = domain(scope);
    domain.armed.store(true, Ordering::Release);
    domain
        .last_withdrawal_reason
        .store(reason.index() as u8, Ordering::Release);
    domain
        .withdrawal_generation
        .store(generation, Ordering::Release);
}

/// Arm `scope` at `generation` without publishing material. **Test seam only.**
#[doc(hidden)]
#[allow(dead_code)] // External test seam only.
pub fn arm_at_generation_for_test(scope: ClientTrustScope, generation: u64) {
    let domain = domain(scope);
    domain.generation.store(generation, Ordering::Release);
    domain.armed.store(true, Ordering::Release);
}
