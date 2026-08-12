//! Protocol-neutral authorization lifetime for admitted streams.
//!
//! Authentication produces one authoritative monotonic deadline
//! (`RequestContext::credential_deadline_at`, `StreamConnectionContext::
//! credential_deadline_at`). Everything in this module consumes that deadline;
//! nothing here ever sees a token, a claim, a certificate field, an issuer, or
//! an absolute expiry timestamp.
//!
//! # Contract
//!
//! * The deadline is **anchored once**, at the moment the credential was
//!   accepted. Application activity — data frames, gRPC messages, Ping/Pong,
//!   relayed bytes — never extends it.
//! * The effective bound is the **earliest** of the accepted credential's
//!   authoritative deadline and the finite fallback maximum
//!   (`FERRUM_AUTHENTICATED_STREAM_MAX_LIFETIME_SECONDS`). Any other bound the
//!   protocol already enforces — a client `grpc-timeout`, listener/route drain,
//!   process shutdown, idle/read timeouts — composes on top, so the earliest
//!   applicable bound always wins.
//! * Unauthenticated traffic is out of scope: no principal was admitted, so
//!   there is no authorization lifetime to bound. Those streams are unaffected.
//! * A credential accepted **without** an authoritative expiry does not get an
//!   indefinite authenticated stream. It is bounded by the same finite fallback
//!   maximum, which is validated in every mode and cannot be configured to
//!   "unbounded".
//!
//! # Redaction
//!
//! The termination class is a compiled-in literal from a closed set and the
//! counters below carry no labels beyond a bounded protocol family. No route,
//! identity, subject, token, claim, certificate field, provider name, or
//! absolute expiry can reach either surface.

use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};

use crate::plugins::RequestContext;

/// Why an admitted authenticated stream was terminated by this contract.
///
/// A closed set of compiled-in literals. These are the only strings this
/// module can publish into a transaction summary, a metric, or a gRPC
/// `grpc-message`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamAuthTermination {
    /// The accepted credential's own authoritative deadline elapsed.
    CredentialExpired,
    /// The credential carried no authoritative expiry (or a later one), and the
    /// finite fallback maximum for authenticated streams elapsed.
    AuthenticatedStreamMaxLifetime,
}

impl StreamAuthTermination {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CredentialExpired => "credential_expired",
            Self::AuthenticatedStreamMaxLifetime => "authenticated_stream_max_lifetime",
        }
    }

    /// Fixed client-visible `grpc-message`. Deliberately free of expiry values,
    /// claims, subject identifiers, certificate fields, and provider detail.
    pub const fn grpc_message(self) -> &'static str {
        match self {
            Self::CredentialExpired => "credential expired",
            Self::AuthenticatedStreamMaxLifetime => "authenticated stream lifetime reached",
        }
    }

    /// Fixed message used when the deadline fires on an ordinary HTTP or SSE
    /// response — a flavor that has no terminal status metadata at all — and
    /// the response head has already been committed downstream.
    ///
    /// The body ends with this as a transport error, which resets an HTTP/2 or
    /// HTTP/3 stream and terminates an HTTP/1.1 chunked or SSE body without a
    /// terminating chunk. It is deliberately NOT a clean end of body: a client
    /// must be able to tell an authorization termination from a complete
    /// response. gRPC terminal metadata is never fabricated for these flavors.
    pub const fn http_termination_message(self) -> &'static str {
        match self {
            Self::CredentialExpired => "authenticated stream terminated: credential expired",
            Self::AuthenticatedStreamMaxLifetime => {
                "authenticated stream terminated: maximum lifetime reached"
            }
        }
    }

    /// Fixed message used when the deadline fires after response DATA has
    /// already been committed and the stream must be reset instead.
    pub const fn post_commit_message(self) -> &'static str {
        match self {
            Self::CredentialExpired => {
                "authenticated stream terminated: credential expired after response data"
            }
            Self::AuthenticatedStreamMaxLifetime => {
                "authenticated stream terminated: maximum lifetime reached after response data"
            }
        }
    }
}

/// Wire value of `grpc-status: 16` (`UNAUTHENTICATED`), emitted when an
/// admitted stream outlives the authorization lifetime of the credential that
/// admitted it. A compiled-in literal shared by every relay so no expiry value
/// can reach the wire and the frontends cannot drift.
pub const AUTHORIZATION_EXPIRED_GRPC_STATUS_HEADER: &str = "16";

/// The effective authorization bound for one admitted stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamAuthDeadline {
    pub at: tokio::time::Instant,
    pub termination: StreamAuthTermination,
}

/// Bounded protocol family for the termination counters below.
///
/// This is the ONLY dimension the counters carry. It is a closed compile-time
/// set, so the exported series count is fixed no matter how many routes,
/// consumers, or credentials exist.
///
/// # Why WebSocket is deliberately absent
///
/// WebSocket sessions are bounded by their OWN policy — the `WsSessionDeadline`
/// arbiter and `FERRUM_WEBSOCKET_MAX_LIFETIME_SECONDS` — which predates this
/// contract (issue #3738 / PR #3744) and has its own documented configuration
/// surface and its own `websocket.termination_reason` observability. Publishing
/// a `websocket` family here would name a series that this module's
/// `authenticated_stream_max_lifetime` counter can never describe: the
/// WebSocket maximum is a different operator knob. A family with no production
/// recorder is a false contract, so WebSocket is out of this inventory. If the
/// two policies are ever unified, add the family and the recorder in the same
/// change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamAuthProtocolFamily {
    /// Generic HTTP/1.1, HTTP/2, and HTTP/3 response or request bodies,
    /// including SSE.
    Http,
    /// Native gRPC (length-prefixed frames with HTTP trailers).
    Grpc,
    /// gRPC-Web, binary and text.
    GrpcWeb,
    /// Raw TCP / TCP+TLS stream proxying.
    StreamTcp,
    /// UDP / DTLS stream proxying.
    StreamUdp,
}

impl StreamAuthProtocolFamily {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Grpc => "grpc",
            Self::GrpcWeb => "grpc_web",
            Self::StreamTcp => "stream_tcp",
            Self::StreamUdp => "stream_udp",
        }
    }

    const fn index(self) -> usize {
        match self {
            Self::Http => 0,
            Self::Grpc => 1,
            Self::GrpcWeb => 2,
            Self::StreamTcp => 3,
            Self::StreamUdp => 4,
        }
    }

    const ALL: [Self; 5] = [
        Self::Http,
        Self::Grpc,
        Self::GrpcWeb,
        Self::StreamTcp,
        Self::StreamUdp,
    ];
}

/// One monotonic counter per (termination class, protocol family). Five families
/// times two classes is the complete, fixed series inventory.
static CREDENTIAL_EXPIRED: [AtomicU64; 5] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];
static MAX_LIFETIME: [AtomicU64; 5] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];

/// Record one authorization-lifetime termination.
///
/// Called exactly once per terminated stream, from the site that actually
/// performed the termination.
#[inline]
pub fn record_termination(termination: StreamAuthTermination, family: StreamAuthProtocolFamily) {
    let table = match termination {
        StreamAuthTermination::CredentialExpired => &CREDENTIAL_EXPIRED,
        StreamAuthTermination::AuthenticatedStreamMaxLifetime => &MAX_LIFETIME,
    };
    table[family.index()].fetch_add(1, Ordering::Relaxed);
}

/// Shared, once-only authorization-lifetime termination latch for ONE request.
///
/// A request can be bounded in two directions at the same time: the client
/// request-body upload (H1/H2 streaming and bidirectional uploads) and the
/// client-visible response body. Both are armed from the same absolute plan, so
/// both can become ready at the same instant on a bidirectional stream. This
/// latch makes the pair record exactly one termination for the stream: the
/// first direction to fire wins, and the loser observes the class instead of
/// counting a second one.
///
/// It carries no credential material — only the bounded class, encoded as a
/// small integer.
#[derive(Debug, Clone, Default)]
pub struct StreamAuthTerminationLatch(Arc<AtomicU8>);

const LATCH_NONE: u8 = 0;
const LATCH_CREDENTIAL_EXPIRED: u8 = 1;
const LATCH_MAX_LIFETIME: u8 = 2;

impl StreamAuthTerminationLatch {
    /// Latch this termination and record the fixed-cardinality counter, but
    /// only for the FIRST caller. Returns `true` when this call owned the
    /// termination (and therefore performed the single counter increment).
    pub fn record_once(
        &self,
        termination: StreamAuthTermination,
        family: StreamAuthProtocolFamily,
    ) -> bool {
        let code = match termination {
            StreamAuthTermination::CredentialExpired => LATCH_CREDENTIAL_EXPIRED,
            StreamAuthTermination::AuthenticatedStreamMaxLifetime => LATCH_MAX_LIFETIME,
        };
        let won = self
            .0
            .compare_exchange(LATCH_NONE, code, Ordering::AcqRel, Ordering::Acquire)
            .is_ok();
        if won {
            record_termination(termination, family);
        }
        won
    }

    /// The latched class, if this request's stream was ended by this contract.
    pub fn observed(&self) -> Option<StreamAuthTermination> {
        match self.0.load(Ordering::Acquire) {
            LATCH_CREDENTIAL_EXPIRED => Some(StreamAuthTermination::CredentialExpired),
            LATCH_MAX_LIFETIME => Some(StreamAuthTermination::AuthenticatedStreamMaxLifetime),
            _ => None,
        }
    }
}

/// Transport-level authorization close signal for ONE accepted downstream
/// client connection (issue #3815).
///
/// A response-body adapter can only act when the transport polls it, and hyper
/// does not poll a response body while its HTTP/2 pipe is parked on stream send
/// capacity or its HTTP/1.1 connection is parked on socket writability. Both are
/// client-controlled. This signal is the gateway's own lever over that
/// transport: the connection task selects on it beside the connection future, so
/// a stream whose authorization lifetime elapsed can be settled even when the
/// client is refusing to make progress.
///
/// Carries no credential material, no class, and no identity — it is a single
/// edge-triggered boolean. The bounded termination class travels through
/// [`StreamAuthTerminationLatch`] and the transaction summary as usual.
///
/// Cloning is cheap and every clone signals the same connection.
#[derive(Clone, Debug)]
pub struct AuthorizationConnectionCloser(Arc<tokio::sync::watch::Sender<bool>>);

impl AuthorizationConnectionCloser {
    /// Create one signal for one accepted connection.
    #[must_use]
    pub fn new() -> Self {
        // The initial receiver is dropped immediately; `subscribe()` mints the
        // connection task's receiver, and `send` on a receiver-less channel is a
        // deliberate no-op rather than an error worth reporting.
        let (sender, _initial) = tokio::sync::watch::channel(false);
        Self(Arc::new(sender))
    }

    /// A receiver for the connection task's `select!`.
    #[must_use]
    pub fn subscribe(&self) -> tokio::sync::watch::Receiver<bool> {
        self.0.subscribe()
    }

    /// Ask the connection task to close this client connection.
    ///
    /// Level-triggered and idempotent: a receiver created after this call still
    /// observes the closed state, and repeated calls are indistinguishable from
    /// one.
    pub fn request_close(&self) {
        let _ = self.0.send(true);
    }

    /// Whether a close has already been requested.
    #[must_use]
    pub fn close_requested(&self) -> bool {
        *self.0.borrow()
    }
}

impl Default for AuthorizationConnectionCloser {
    fn default() -> Self {
        Self::new()
    }
}

/// Resolve when [`AuthorizationConnectionCloser::request_close`] has been called
/// on the connection this receiver watches.
///
/// Stays pending forever once the signal can no longer arrive (every sender
/// gone), so it is safe as a permanently-armed `select!` arm: a dropped sender
/// must never be mistaken for a close request.
pub async fn authorization_close_requested(receiver: &mut tokio::sync::watch::Receiver<bool>) {
    if *receiver.borrow_and_update() {
        return;
    }
    while receiver.changed().await.is_ok() {
        if *receiver.borrow_and_update() {
            return;
        }
    }
    // `pending::<Infallible>()` has an uninhabited output, so the empty match
    // expresses "this await never resolves" as a type rather than as a panic.
    match std::future::pending::<std::convert::Infallible>().await {}
}

/// Snapshot of the authorization-lifetime termination counters for the runtime
/// metrics endpoint. Keys are the bounded protocol families; there is no other
/// label dimension.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct StreamAuthLifetimeCounters {
    /// Streams terminated because the accepted credential's own authoritative
    /// deadline elapsed, by bounded protocol family.
    pub credential_expired: std::collections::BTreeMap<&'static str, u64>,
    /// Streams terminated because the finite authenticated-stream fallback
    /// maximum elapsed, by bounded protocol family.
    pub authenticated_stream_max_lifetime: std::collections::BTreeMap<&'static str, u64>,
}

/// Read the termination counters. Monotonic, process-lifetime.
pub fn counters() -> StreamAuthLifetimeCounters {
    let mut snapshot = StreamAuthLifetimeCounters::default();
    for family in StreamAuthProtocolFamily::ALL {
        snapshot.credential_expired.insert(
            family.as_str(),
            CREDENTIAL_EXPIRED[family.index()].load(Ordering::Relaxed),
        );
        snapshot.authenticated_stream_max_lifetime.insert(
            family.as_str(),
            MAX_LIFETIME[family.index()].load(Ordering::Relaxed),
        );
    }
    snapshot
}

/// Process-wide validated `FERRUM_AUTHENTICATED_STREAM_MAX_LIFETIME_SECONDS`.
///
/// Stream listeners (TCP/TLS, UDP/DTLS) accept connections far from any
/// `EnvConfig` reference, and threading one validated scalar through every
/// accept-loop signature would add a parameter to a dozen hot-path functions
/// for no behavioral benefit. `EnvConfig::validate` publishes it once, after
/// range validation, so the value read here is always inside `1..=86400`.
/// The seeded default matches the documented default, so a stream admitted
/// before publication is bounded rather than unbounded.
static AUTHENTICATED_STREAM_MAX_LIFETIME_SECONDS: AtomicU64 = AtomicU64::new(3_600);

/// Publish the validated authenticated-stream maximum. Called from
/// `EnvConfig::validate` after the `1..=86400` range check.
pub fn publish_authenticated_stream_max_lifetime_seconds(seconds: u64) {
    AUTHENTICATED_STREAM_MAX_LIFETIME_SECONDS.store(seconds, Ordering::Relaxed);
}

/// Read the published authenticated-stream maximum.
pub fn authenticated_stream_max_lifetime_seconds() -> u64 {
    AUTHENTICATED_STREAM_MAX_LIFETIME_SECONDS.load(Ordering::Relaxed)
}

/// Whether this request committed an authenticated principal.
///
/// Mirrors the authentication boundary in
/// `plugins::utils::auth_flow::commit_authentication_attempt`: a principal is
/// a mapped Consumer or a permitted external identity. `auth_method` alone is
/// not sufficient evidence, because a stream-side mechanism may stamp it
/// without a principal.
#[inline]
pub fn request_is_authenticated(ctx: &RequestContext) -> bool {
    ctx.identified_consumer.is_some() || ctx.authenticated_identity.is_some()
}

/// Compute the effective authorization deadline for an admitted request.
///
/// `max_lifetime_seconds` is `EnvConfig::authenticated_stream_max_lifetime_seconds`,
/// which validation constrains to `1..=86400` in every mode — there is no
/// "unbounded" value to configure.
///
/// Returns `None` for unauthenticated requests, which this contract does not
/// bound.
///
/// The maximum is anchored at `grpc_deadline_received_at` — the monotonic
/// request-receipt instant, the same anchor the WebSocket arbiter uses — so a
/// slow request cannot buy extra authorized lifetime, and so H1 keep-alive,
/// H2, and H3 streams on one transport connection each get their own anchor
/// rather than inheriting the connection's.
pub fn effective_request_auth_deadline(
    ctx: &RequestContext,
    max_lifetime_seconds: u64,
) -> Option<StreamAuthDeadline> {
    if !request_is_authenticated(ctx) {
        return None;
    }
    let now = tokio::time::Instant::now();
    let maximum = ctx
        .grpc_deadline_received_at
        .checked_add(std::time::Duration::from_secs(max_lifetime_seconds))
        .unwrap_or(now);
    Some(earliest(ctx.credential_deadline_at, maximum))
}

/// Compute the effective authorization deadline for an admitted stream
/// (TCP/TLS, UDP/DTLS) session.
///
/// `anchor` is the monotonic instant at which the connection was admitted.
/// Returns `None` when the session admitted no authenticated principal.
pub fn effective_stream_auth_deadline(
    authenticated: bool,
    credential_deadline_at: Option<tokio::time::Instant>,
    anchor: tokio::time::Instant,
    max_lifetime_seconds: u64,
) -> Option<StreamAuthDeadline> {
    if !authenticated {
        return None;
    }
    let now = tokio::time::Instant::now();
    let maximum = anchor
        .checked_add(std::time::Duration::from_secs(max_lifetime_seconds))
        .unwrap_or(now);
    Some(earliest(credential_deadline_at, maximum))
}

/// Earliest-deadline-wins between the credential's own deadline and the finite
/// fallback maximum. A credential deadline that is exactly equal to the maximum
/// is attributed to the credential, matching the WebSocket arbiter.
fn earliest(
    credential_deadline_at: Option<tokio::time::Instant>,
    maximum: tokio::time::Instant,
) -> StreamAuthDeadline {
    match credential_deadline_at {
        Some(credential) if credential <= maximum => StreamAuthDeadline {
            at: credential,
            termination: StreamAuthTermination::CredentialExpired,
        },
        _ => StreamAuthDeadline {
            at: maximum,
            termination: StreamAuthTermination::AuthenticatedStreamMaxLifetime,
        },
    }
}

/// Compose an admitted request's authorization deadline with whatever absolute
/// bound the protocol already established (a client `grpc-timeout`, an RPC
/// deadline), returning the earliest.
///
/// Used by every H3 write and upload seam whose only prior bound was the
/// client's OPTIONAL RPC deadline (plus, on the upload side, a per-read
/// operator timeout) — neither of which stops a **continuously active** upload
/// or a **parked** downstream write from outliving the credential that
/// admitted the stream.
#[inline]
pub fn compose_absolute_bound(
    protocol_deadline_at: Option<tokio::time::Instant>,
    auth_deadline: Option<StreamAuthDeadline>,
) -> Option<tokio::time::Instant> {
    match (protocol_deadline_at, auth_deadline.map(|plan| plan.at)) {
        (Some(protocol), Some(authorization)) => Some(protocol.min(authorization)),
        (Some(protocol), None) => Some(protocol),
        (None, authorization) => authorization,
    }
}

/// Attribute an already-fired composed bound: `Some` when the authorization
/// deadline is the one that elapsed, `None` when only the protocol's own
/// deadline did.
///
/// A tie is attributed to authorization, matching the biased select-arm
/// ordering every relay uses: when both bounds are eligible, the security
/// decision is the one reported.
#[inline]
pub fn expired_authorization(
    auth_deadline: Option<StreamAuthDeadline>,
) -> Option<StreamAuthTermination> {
    auth_deadline
        .filter(|plan| tokio::time::Instant::now() >= plan.at)
        .map(|plan| plan.termination)
}

/// Transaction-summary metadata key carrying the bounded termination class.
///
/// Mirrors `websocket.termination_reason` for the body/stream paths so a log
/// consumer can distinguish a policy expiry from a backend or transport fault
/// without the error rate becoming ambiguous.
pub const STREAM_AUTH_TERMINATION_METADATA_KEY: &str = "authorization.termination_reason";
