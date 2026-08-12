//! HTTP/3 Extended CONNECT for UDP proxying — RFC 9298 over RFC 9297 capsules.
//!
//! # Interoperability profile
//!
//! This is the *complete and exact* profile the gateway implements. Anything
//! outside it is refused; nothing here is a private Ferrum framing.
//!
//! * **Bootstrap** — RFC 9298 §3 over HTTP/3 (RFC 9220 Extended CONNECT
//!   machinery): `:method = CONNECT`, `:protocol = connect-udp`,
//!   `:scheme = https`, `:authority` = the gateway authority, `:path` = the
//!   expansion of an RFC 6570 level-3 URI Template carrying the
//!   `target_host` and `target_port` variables. The gateway advertises
//!   `SETTINGS_ENABLE_CONNECT_PROTOCOL` when either the WebSocket or the
//!   CONNECT-UDP profile is enabled.
//! * **URI Template** — the RFC 9298 §2 default template
//!   `https://$HOST:$PORT/.well-known/masque/udp/{target_host}/{target_port}/`
//!   is supported verbatim. Operators may host the endpoint under a different
//!   prefix; the gateway requires only that the expanded path end with the
//!   three anchored segments `udp/{target_host}/{target_port}/` (trailing
//!   slash included, exactly as the template produces). Everything before
//!   `udp` is an ordinary Ferrum `listen_path` and is matched by the ordinary
//!   router, so CONNECT-UDP requests are routed, authenticated, authorized,
//!   rate-limited, and logged by the same pipeline as every other request.
//! * **Payload encoding** — HTTP Datagrams (RFC 9297) carried as **DATAGRAM
//!   capsules** (`Capsule Type = 0x00`) on the CONNECT stream. The gateway
//!   does **not** negotiate `SETTINGS_H3_DATAGRAM`, so QUIC DATAGRAM frames
//!   are never used in either direction; RFC 9297 §3.5 defines the DATAGRAM
//!   capsule as carrying "the same semantics" as a QUIC DATAGRAM frame, so
//!   this is an interoperable encoding of the same HTTP Datagrams and not an
//!   alternative framing. A compliant RFC 9298 client that has not received
//!   `SETTINGS_H3_DATAGRAM = 1` uses exactly this encoding.
//! * **Datagram payload format** — RFC 9298 §5: a Context ID varint followed
//!   by the unmodified UDP payload. Only Context ID `0` (UDP payloads) is
//!   registered. Well-formed datagrams naming any other context are dropped
//!   (RFC 9298 §4), never proxied.
//! * **Capsule Protocol signalling** — the 200 response carries
//!   `Capsule-Protocol: ?1` (RFC 9297 §3.4). The field is written after
//!   response-header policy so no plugin can remove or forge it.
//! * **Unknown capsule types** — silently dropped and skipped (RFC 9297 §3.1),
//!   subject to the same length ceiling as a DATAGRAM capsule.
//!
//! # Bounds (all fail closed)
//!
//! | Bound | Source |
//! |---|---|
//! | Concurrent sessions | `FERRUM_HTTP3_CONNECT_UDP_MAX_SESSIONS` |
//! | Idle lifetime | `FERRUM_HTTP3_CONNECT_UDP_IDLE_TIMEOUT_SECONDS` |
//! | Datagram payload | `FERRUM_HTTP3_CONNECT_UDP_MAX_DATAGRAM_BYTES`, itself capped by the RFC 9298 §5 ceiling of 65527 |
//! | Capsule length | payload ceiling + [`CAPSULE_FRAMING_SLACK_BYTES`] |
//! | Buffered partial capsule | at most [`CapsuleDecoder::feed_limit`] × 2 (the decoder's documented hard ceiling), reachable when one chunk completes a partial capsule and opens the next |
//! | Target | must be a configured upstream destination of the matched proxy |
//!
//! There is no *queue* between the two directions: the client-bound relay
//! awaits `send_data` (QUIC stream flow control is the backpressure) and the
//! target-bound relay awaits `UdpSocket::send`. Excess is dropped by the kernel
//! socket buffer, which is the correct behaviour for a UDP tunnel.
//!
//! That is not the same as "one buffer per session". Writing `P` for the
//! configured payload ceiling, a live tunnel can concurrently hold:
//!
//! * the decoder's transient buffer, bounded at `2 × (P + 8 + 16)` — the
//!   ceiling above, not one capsule;
//! * the target-bound receive buffer, `P + 1` (one extra byte so an oversized
//!   datagram is detectable rather than silently truncated);
//! * the client-bound framing scratch plus the framed capsule still owned by an
//!   `h3` `send_data` future that QUIC send flow control has blocked, roughly
//!   `2 × (P + 9)`.
//!
//! So the conservative per-session bound is about `5 × P` — roughly 320 KiB at
//! the 65527-byte default, and roughly 80 MiB across the 256-session default.
//! Operators who care about footprint should lower
//! `FERRUM_HTTP3_CONNECT_UDP_MAX_DATAGRAM_BYTES`, which scales every term.
//!
//! # Relationship to Ferrum policy
//!
//! The tunnel destination is chosen by the client (RFC 9298 semantics), so it
//! is *admitted*, not load balanced: the requested `target_host:target_port`
//! must match a destination already configured for the matched proxy — its
//! `backend_host:backend_port`, or one of the referenced upstream's targets.
//! A request naming anything else is refused with 403 before any socket is
//! created, so a CONNECT-UDP route can never reach further than the ordinary
//! HTTP route on the same proxy. Because no HTTP backend is dialled, a claimed
//! half-open circuit-breaker probe slot is released immediately (the session
//! is not a probe outcome), and no load-balancer connection is charged.
//!
//! Live sessions are re-checked against the published config generation. A
//! reload that deletes the proxy or removes the destination from its upstream
//! tears the session down; it is never grandfathered.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use h3::server::RequestStream;
use http::{Response, StatusCode};
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

use crate::config::types::{Proxy, UpstreamTarget};
use crate::load_balancer::LoadBalancerCache;
use crate::plugins::{Plugin, RequestContext, TransactionSummary};
use crate::proxy::ProxyState;
use crate::request_epoch::RequestEpoch;

/// RFC 9298 §5: "endpoints MUST NOT send HTTP Datagrams with a UDP Proxying
/// Payload field longer than 65527 using Context ID zero."
pub const CONNECT_UDP_MAX_PAYLOAD_BYTES: usize = 65_527;

/// RFC 9297 §3.5 DATAGRAM capsule type.
const CAPSULE_TYPE_DATAGRAM: u64 = 0x00;

/// Headroom added to the payload ceiling to derive the accepted capsule
/// length: an 8-byte Context ID varint is the largest legal prefix inside a
/// DATAGRAM capsule value.
pub const CAPSULE_FRAMING_SLACK_BYTES: usize = 8;

/// Longest capsule *header* (type varint + length varint) we can face.
const MAX_CAPSULE_HEADER_BYTES: usize = 16;

/// Supervisor tick ceiling. Idle expiry, drain, and config-withdrawal are all
/// observed at this cadence, so it also bounds how long a withdrawn route can
/// keep relaying.
const SUPERVISOR_TICK: Duration = Duration::from_secs(1);

/// Grace given to the client-bound relay to flush and `finish()` the QUIC
/// stream after the supervisor decides to close.
const CLOSE_GRACE: Duration = Duration::from_secs(1);

// ---------------------------------------------------------------------------
// Extended CONNECT classification
// ---------------------------------------------------------------------------

/// Which Extended CONNECT profile an HTTP/3 request names.
///
/// An unregistered `:protocol` token never reaches this classifier: the h3
/// layer fails `Protocol::from_str`, treats the request as malformed, and
/// resets the stream with `H3_MESSAGE_ERROR` (RFC 9114 §4.1.2). The
/// [`Self::Unsupported`] arm therefore covers registered-but-unimplemented
/// values (today, `webtransport`), which the caller refuses with 405.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H3ExtendedConnect {
    /// Not a CONNECT request, or a CONNECT with no `:protocol`.
    None,
    /// RFC 9220 `:protocol = websocket`.
    WebSocket,
    /// RFC 9298 `:protocol = connect-udp`.
    ConnectUdp,
    /// A registered `:protocol` this gateway does not implement.
    Unsupported,
}

/// Classify the Extended CONNECT `:protocol` of an inbound HTTP/3 request.
///
/// One extension lookup, no allocation. Called once per request stream.
#[inline]
pub fn classify_h3_extended_connect<B>(req: &http::Request<B>) -> H3ExtendedConnect {
    if req.method() != http::Method::CONNECT {
        return H3ExtendedConnect::None;
    }
    match req.extensions().get::<h3::ext::Protocol>() {
        None => H3ExtendedConnect::None,
        Some(protocol) if *protocol == h3::ext::Protocol::WEB_SOCKET => {
            H3ExtendedConnect::WebSocket
        }
        Some(protocol) if *protocol == h3::ext::Protocol::CONNECT_UDP => {
            H3ExtendedConnect::ConnectUdp
        }
        Some(_) => H3ExtendedConnect::Unsupported,
    }
}

// ---------------------------------------------------------------------------
// Request shape (RFC 9298 §3 pseudo-headers, RFC 9297 §3.2 forbidden fields)
// ---------------------------------------------------------------------------

/// The only `:scheme` an RFC 9298 request may carry on this listener. RFC 9298
/// §3 bootstraps over an HTTPS origin, and the H3 frontend has no other scheme
/// to offer, so anything else is a malformed message rather than a route miss.
pub const CONNECT_UDP_SCHEME: &str = "https";

/// Why a `connect-udp` Extended CONNECT is malformed independently of its URI
/// template expansion.
///
/// Every arm is a fixed, field-specific client body; none echoes attacker
/// bytes. All of them are decided **before** a UDP socket exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectUdpRequestRejection {
    /// `:scheme` absent or empty.
    SchemeMissing,
    /// `:scheme` present but not the HTTPS scheme this listener serves.
    SchemeNotHttps,
    /// `:authority` absent or empty — RFC 9298 §3 requires the proxy authority.
    AuthorityMissing,
    /// RFC 9297 §3.2: `Content-Length` is forbidden on a Capsule Protocol
    /// message.
    ForbiddenContentLength,
    /// RFC 9297 §3.2: `Content-Type` is forbidden on a Capsule Protocol
    /// message.
    ForbiddenContentType,
    /// RFC 9297 §3.2: `Transfer-Encoding` is forbidden on a Capsule Protocol
    /// message.
    ForbiddenTransferEncoding,
}

impl ConnectUdpRequestRejection {
    /// Stable, low-cardinality label for logs and transaction records.
    pub fn reason(self) -> &'static str {
        match self {
            Self::SchemeMissing => "connect_udp_scheme_missing",
            Self::SchemeNotHttps => "connect_udp_scheme_not_https",
            Self::AuthorityMissing => "connect_udp_authority_missing",
            Self::ForbiddenContentLength => "connect_udp_content_length_forbidden",
            Self::ForbiddenContentType => "connect_udp_content_type_forbidden",
            Self::ForbiddenTransferEncoding => "connect_udp_transfer_encoding_forbidden",
        }
    }

    /// Field-specific client diagnostic. Fixed literal: never interpolated.
    pub fn client_error_body(self) -> &'static str {
        match self {
            Self::SchemeMissing => r#"{"error":"CONNECT-UDP requires the :scheme pseudo-header"}"#,
            Self::SchemeNotHttps => {
                r#"{"error":"CONNECT-UDP requires the https :scheme on this listener"}"#
            }
            Self::AuthorityMissing => {
                r#"{"error":"CONNECT-UDP requires the :authority pseudo-header"}"#
            }
            Self::ForbiddenContentLength => {
                r#"{"error":"Content-Length is forbidden on a Capsule Protocol message"}"#
            }
            Self::ForbiddenContentType => {
                r#"{"error":"Content-Type is forbidden on a Capsule Protocol message"}"#
            }
            Self::ForbiddenTransferEncoding => {
                r#"{"error":"Transfer-Encoding is forbidden on a Capsule Protocol message"}"#
            }
        }
    }
}

/// Validate the RFC 9298 §3 request pseudo-header shape.
///
/// The dispatcher classifies only `:method` + `:protocol`; without this the
/// handler would *assume* HTTPS and open a tunnel for a request whose `:scheme`
/// was absent, empty, or something else entirely. Authority and path stay the
/// router's business — the path is validated by
/// [`parse_connect_udp_target`] after the shared H3 policy-path
/// canonicalization, and the authority is the same one
/// `check_host_authority_consistency` already reconciled against `Host` — so
/// this only adds the two checks neither of those makes.
pub fn validate_connect_udp_request_shape(
    uri: &http::Uri,
) -> Result<(), ConnectUdpRequestRejection> {
    match uri.scheme_str() {
        None => return Err(ConnectUdpRequestRejection::SchemeMissing),
        Some("") => {
            return Err(ConnectUdpRequestRejection::SchemeMissing);
        }
        Some(scheme) if !scheme.eq_ignore_ascii_case(CONNECT_UDP_SCHEME) => {
            return Err(ConnectUdpRequestRejection::SchemeNotHttps);
        }
        Some(_) => {}
    }
    match uri.authority() {
        None => Err(ConnectUdpRequestRejection::AuthorityMissing),
        Some(authority) if authority.as_str().is_empty() => {
            Err(ConnectUdpRequestRejection::AuthorityMissing)
        }
        Some(_) => Ok(()),
    }
}

/// Classify one header field name against RFC 9297 §3.2, which forbids
/// `Content-Length`, `Content-Type`, and `Transfer-Encoding` on any message
/// that uses the Capsule Protocol.
///
/// Returns `None` for every other name, including `Capsule-Protocol` itself.
#[inline]
pub fn forbidden_capsule_protocol_field(name: &str) -> Option<ConnectUdpRequestRejection> {
    if name.eq_ignore_ascii_case("content-length") {
        Some(ConnectUdpRequestRejection::ForbiddenContentLength)
    } else if name.eq_ignore_ascii_case("content-type") {
        Some(ConnectUdpRequestRejection::ForbiddenContentType)
    } else if name.eq_ignore_ascii_case("transfer-encoding") {
        Some(ConnectUdpRequestRejection::ForbiddenTransferEncoding)
    } else {
        None
    }
}

/// First RFC 9297 §3.2 violation in a field-name sequence, if any.
///
/// Used on both the raw client header block (before routing and plugins) and
/// the plugin/policy-finalized outbound map (immediately before a socket would
/// be created), so neither a client nor a `request_transformer` can put a
/// forbidden field on a Capsule Protocol message.
pub fn first_forbidden_capsule_protocol_field<'a, I>(names: I) -> Option<ConnectUdpRequestRejection>
where
    I: IntoIterator<Item = &'a str>,
{
    names.into_iter().find_map(forbidden_capsule_protocol_field)
}

/// Strip the RFC 9297 §3.2 fields a *response* may not carry.
///
/// `Transfer-Encoding` is already removed by the shared hop-by-hop strip; the
/// other two are ordinary end-to-end fields that response-header policy is free
/// to author, so they are removed here — after that policy runs and before the
/// transport writes `Capsule-Protocol` — rather than merely rejected.
pub fn strip_forbidden_capsule_protocol_response_fields(headers: &mut HashMap<String, String>) {
    headers.retain(|name, _| forbidden_capsule_protocol_field(name).is_none());
}

// ---------------------------------------------------------------------------
// Target parsing (RFC 9298 §2 / §3)
// ---------------------------------------------------------------------------

/// A validated RFC 9298 tunnel destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectUdpTarget {
    /// Lowercased DNS name, or the canonical text form of an IP literal.
    pub host: String,
    pub port: u16,
}

/// Why a `:path` is not a usable RFC 9298 template expansion.
///
/// Each arm maps to one fixed, field-specific client body. No attacker-supplied
/// bytes are ever echoed back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectUdpTargetRejection {
    /// The path does not end with `udp/{target_host}/{target_port}/`.
    TemplateAnchorMissing,
    /// RFC 6570 expansion of the RFC 9298 template always ends in `/`.
    TrailingSlashMissing,
    /// `target_host` expanded empty — forbidden by RFC 9298 §3.
    TargetHostEmpty,
    /// `target_host` is longer than a DNS name may be.
    TargetHostTooLong,
    /// `target_host` is neither an IPv4 literal, an IPv6 literal, nor a
    /// syntactically valid DNS name.
    TargetHostMalformed,
    /// `target_port` expanded empty — forbidden by RFC 9298 §3.
    TargetPortEmpty,
    /// `target_port` is not a bare decimal integer.
    TargetPortMalformed,
    /// `target_port` is outside 1–65535.
    TargetPortOutOfRange,
}

impl ConnectUdpTargetRejection {
    /// Stable, low-cardinality label for logs and transaction records.
    pub fn reason(self) -> &'static str {
        match self {
            Self::TemplateAnchorMissing => "template_anchor_missing",
            Self::TrailingSlashMissing => "trailing_slash_missing",
            Self::TargetHostEmpty => "target_host_empty",
            Self::TargetHostTooLong => "target_host_too_long",
            Self::TargetHostMalformed => "target_host_malformed",
            Self::TargetPortEmpty => "target_port_empty",
            Self::TargetPortMalformed => "target_port_malformed",
            Self::TargetPortOutOfRange => "target_port_out_of_range",
        }
    }

    /// Field-specific client diagnostic. Fixed literal: never interpolated.
    pub fn client_error_body(self) -> &'static str {
        match self {
            Self::TemplateAnchorMissing => {
                r#"{"error":"CONNECT-UDP path does not expand the connect-udp URI template"}"#
            }
            Self::TrailingSlashMissing => {
                r#"{"error":"CONNECT-UDP path must end with a trailing slash"}"#
            }
            Self::TargetHostEmpty => r#"{"error":"CONNECT-UDP target_host is empty"}"#,
            Self::TargetHostTooLong => r#"{"error":"CONNECT-UDP target_host is too long"}"#,
            Self::TargetHostMalformed => {
                r#"{"error":"CONNECT-UDP target_host is not a valid host name or IP literal"}"#
            }
            Self::TargetPortEmpty => r#"{"error":"CONNECT-UDP target_port is empty"}"#,
            Self::TargetPortMalformed => {
                r#"{"error":"CONNECT-UDP target_port is not a decimal integer"}"#
            }
            Self::TargetPortOutOfRange => {
                r#"{"error":"CONNECT-UDP target_port is outside 1-65535"}"#
            }
        }
    }
}

/// Longest DNS name we accept for `target_host` (RFC 1035 presentation form).
const MAX_TARGET_HOST_LEN: usize = 253;

/// Parse the RFC 9298 `target_host` / `target_port` variables out of an
/// already-canonicalized request path.
///
/// The caller must pass the path *after*
/// [`crate::policy_path::canonicalize_policy_path`], which has already decoded
/// every accepted percent-escape to one literal byte and refused ambiguous,
/// encoded-separator, and traversal forms. That is what makes a single
/// segment split unambiguous here — the RFC 9298 requirement that IPv6 colons
/// be percent-encoded is satisfied by clients and undone by canonicalization,
/// so both `2001:db8::1` and `2001%3Adb8%3A%3A1` arrive as the same literal.
pub fn parse_connect_udp_target(path: &str) -> Result<ConnectUdpTarget, ConnectUdpTargetRejection> {
    if !path.ends_with('/') {
        return Err(ConnectUdpTargetRejection::TrailingSlashMissing);
    }
    // `/a/udp/h/p/` -> ["", "a", "udp", "h", "p", ""]
    let segments: Vec<&str> = path.split('/').collect();
    // Anchor + host + port + the empty tail produced by the trailing slash.
    if segments.len() < 4 {
        return Err(ConnectUdpTargetRejection::TemplateAnchorMissing);
    }
    let anchor = segments[segments.len() - 4];
    if !anchor.eq_ignore_ascii_case("udp") {
        return Err(ConnectUdpTargetRejection::TemplateAnchorMissing);
    }
    let raw_host = segments[segments.len() - 3];
    let raw_port = segments[segments.len() - 2];

    let host = validate_target_host(raw_host)?;
    let port = validate_target_port(raw_port)?;
    Ok(ConnectUdpTarget { host, port })
}

fn validate_target_host(raw: &str) -> Result<String, ConnectUdpTargetRejection> {
    if raw.is_empty() {
        return Err(ConnectUdpTargetRejection::TargetHostEmpty);
    }
    if raw.len() > MAX_TARGET_HOST_LEN {
        return Err(ConnectUdpTargetRejection::TargetHostTooLong);
    }
    // RFC 9298 §3 expands IPv6 literals without brackets (the colons are
    // percent-encoded instead). A bracketed form is not template output, and
    // admitting both spellings would give one destination two identities in
    // the allow-list comparison below — refuse it.
    if raw.contains(':') {
        return match raw.parse::<Ipv6Addr>() {
            // Canonical lowercase text form so allow-list comparison is exact.
            Ok(addr) => Ok(addr.to_string()),
            Err(_) => Err(ConnectUdpTargetRejection::TargetHostMalformed),
        };
    }
    if let Ok(addr) = raw.parse::<Ipv4Addr>() {
        return Ok(addr.to_string());
    }
    // DNS name: strict LDH labels. No trailing root dot, no empty label, no
    // underscore — the same strictness the passthrough SNI validator applies,
    // so a name that can be tunnelled is a name that can be routed.
    if raw.ends_with('.') {
        return Err(ConnectUdpTargetRejection::TargetHostMalformed);
    }
    for label in raw.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(ConnectUdpTargetRejection::TargetHostMalformed);
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(ConnectUdpTargetRejection::TargetHostMalformed);
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(ConnectUdpTargetRejection::TargetHostMalformed);
        }
    }
    Ok(raw.to_ascii_lowercase())
}

fn validate_target_port(raw: &str) -> Result<u16, ConnectUdpTargetRejection> {
    if raw.is_empty() {
        return Err(ConnectUdpTargetRejection::TargetPortEmpty);
    }
    if raw.len() > 5 || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ConnectUdpTargetRejection::TargetPortMalformed);
    }
    // At most five ASCII digits, so this cannot overflow.
    let value: u32 = raw
        .parse()
        .map_err(|_| ConnectUdpTargetRejection::TargetPortMalformed)?;
    if value == 0 || value > u16::MAX as u32 {
        return Err(ConnectUdpTargetRejection::TargetPortOutOfRange);
    }
    Ok(value as u16)
}

// ---------------------------------------------------------------------------
// Destination admission
// ---------------------------------------------------------------------------

/// The configured destination a CONNECT-UDP request named, once admitted.
///
/// The variant carries the matched [`UpstreamTarget`] rather than collapsing to
/// a bool, because the transport a destination requires is per-target metadata:
/// screening it is only sound against the member the CLIENT named, never
/// against whichever member a load balancer happened to pick.
#[derive(Debug, Clone)]
pub enum AdmittedConnectUdpDestination {
    /// The route's own `backend_host:backend_port`. A route backend carries no
    /// per-target transport tags, so a direct UDP dial is the only transport it
    /// can describe.
    RouteBackend,
    /// A target of the route's upstream, already screened for direct dialability.
    UpstreamTarget(Box<UpstreamTarget>),
}

/// Why a client-named CONNECT-UDP destination was refused.
///
/// Both variants produce the same client-visible 403 with the same body: a
/// probe must not learn from the refusal whether the destination exists in the
/// route's configuration. They differ only in the gateway-side log/phase reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectUdpDestinationRefusal {
    /// Not a destination this route is configured to reach.
    NotConfigured,
    /// Configured, but reaching it requires a transport that a direct UDP
    /// socket cannot provide — HBONE, sidecar mTLS, cross-cluster east-west, or
    /// a Unix socket.
    TransportRequired(&'static str),
}

impl ConnectUdpDestinationRefusal {
    /// Stable gateway-side reason token (logs and the rejection phase label).
    pub fn reason(self) -> &'static str {
        match self {
            Self::NotConfigured => "connect_udp_target_not_allowed",
            Self::TransportRequired(_) => "connect_udp_target_transport_required",
        }
    }
}

/// Admit the CLIENT-REQUESTED `host:port` against `proxy`'s configured
/// destination set, screening the exact matched target's required transport.
///
/// This is the whole CONNECT-UDP authorization surface for the destination: the
/// client picks the target (RFC 9298), but the set it may pick from is the set
/// the operator already configured for this route, and it may only be tunnelled
/// if THAT target is one a direct UDP socket may reach. Evaluated against the
/// load-balancer snapshot of the request's epoch, so it cannot straddle two
/// reload generations.
///
/// Two properties are deliberate:
///
/// * No load-balancer selection is consulted. A CONNECT-UDP tunnel is admitted,
///   never balanced, so an unrelated member's health, circuit-breaker state, or
///   transport tags can neither authorize nor refuse the requested destination.
/// * The screening runs over EVERY matching target, not the first one. An
///   upstream may legitimately list one `host:port` more than once (differing
///   weights, localities, or subsets), and a direct duplicate must not launder a
///   sibling that requires HBONE, mesh mTLS, cross-cluster, or Unix dispatch.
pub fn admit_connect_udp_destination(
    proxy: &Proxy,
    lb_snapshot: &crate::load_balancer::LoadBalancerCacheInner,
    host: &str,
    port: u16,
) -> Result<AdmittedConnectUdpDestination, ConnectUdpDestinationRefusal> {
    let Some(upstream_id) = proxy.upstream_id.as_deref() else {
        return if proxy.backend_port == port && proxy.backend_host.eq_ignore_ascii_case(host) {
            Ok(AdmittedConnectUdpDestination::RouteBackend)
        } else {
            Err(ConnectUdpDestinationRefusal::NotConfigured)
        };
    };
    let Some(upstream) =
        LoadBalancerCache::get_upstream_from(lb_snapshot, &proxy.namespace, upstream_id)
    else {
        return Err(ConnectUdpDestinationRefusal::NotConfigured);
    };

    let mut admitted: Option<&UpstreamTarget> = None;
    for target in &upstream.targets {
        if target.port != port || !target.host.eq_ignore_ascii_case(host) {
            continue;
        }
        if let Some(reason) =
            crate::proxy::backend_dispatch::direct_network_http_transport_refusal(Some(target))
        {
            return Err(ConnectUdpDestinationRefusal::TransportRequired(reason));
        }
        if admitted.is_none() {
            admitted = Some(target);
        }
    }
    match admitted {
        Some(target) => Ok(AdmittedConnectUdpDestination::UpstreamTarget(Box::new(
            target.clone(),
        ))),
        None => Err(ConnectUdpDestinationRefusal::NotConfigured),
    }
}

/// Boolean projection of [`admit_connect_udp_destination`] for callers that only
/// need "is this still an admissible destination" — notably the live
/// generation re-check, which fails the tunnel closed on any refusal, including
/// a reload that newly tags the destination as requiring another transport.
pub fn destination_is_configured(
    proxy: &Proxy,
    lb_snapshot: &crate::load_balancer::LoadBalancerCacheInner,
    host: &str,
    port: u16,
) -> bool {
    admit_connect_udp_destination(proxy, lb_snapshot, host, port).is_ok()
}

// ---------------------------------------------------------------------------
// QUIC varints (RFC 9000 §16) — the capsule and context-ID encoding
// ---------------------------------------------------------------------------

/// Decode a varint at `pos`, advancing it. `None` means "not enough bytes yet"
/// — a varint has no malformed encoding, only a truncated one.
fn read_varint(buf: &[u8], pos: &mut usize) -> Option<u64> {
    let first = *buf.get(*pos)?;
    let len = 1usize << (first >> 6);
    if buf.len() - *pos < len {
        return None;
    }
    let mut value = u64::from(first & 0x3f);
    for offset in 1..len {
        value = (value << 8) | u64::from(buf[*pos + offset]);
    }
    *pos += len;
    Some(value)
}

/// Encoded length of `value` as a QUIC varint.
const fn varint_len(value: u64) -> usize {
    if value < 1 << 6 {
        1
    } else if value < 1 << 14 {
        2
    } else if value < 1 << 30 {
        4
    } else {
        8
    }
}

/// Append `value` as a QUIC varint. Values above 2^62-1 are unrepresentable
/// and never produced here: every call site passes a capsule type, a capsule
/// length bounded by the payload ceiling, or context ID 0.
fn write_varint(out: &mut BytesMut, value: u64) {
    match varint_len(value) {
        1 => out.put_u8(value as u8),
        2 => out.put_u16(0x4000 | value as u16),
        4 => out.put_u32(0x8000_0000 | value as u32),
        _ => out.put_u64(0xc000_0000_0000_0000 | value),
    }
}

// ---------------------------------------------------------------------------
// Capsule decoding (RFC 9297 §3)
// ---------------------------------------------------------------------------

/// One decoded capsule, already classified against the RFC 9298 profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapsuleEvent {
    /// A DATAGRAM capsule carrying a Context ID 0 UDP payload.
    UdpPayload(Bytes),
    /// A well-formed DATAGRAM capsule naming an unregistered context. RFC 9298
    /// §4 says to drop it; the caller counts it and does not proxy it.
    UnregisteredContext(u64),
    /// A well-formed capsule of a type this endpoint does not implement.
    /// RFC 9297 §3.1 requires silently dropping and skipping it.
    UnknownCapsuleType(u64),
}

/// Fatal capsule-stream faults. Every arm terminates the session; none is
/// recoverable, because a length-framed stream cannot be resynchronized.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapsuleDecodeError {
    /// A capsule declared a length above the configured ceiling.
    CapsuleTooLarge,
    /// A DATAGRAM capsule whose value is too short to hold a Context ID.
    DatagramCapsuleTruncated,
    /// A Context ID 0 payload above the RFC 9298 §5 ceiling.
    PayloadTooLarge,
    /// More unparsed bytes accumulated than one maximum capsule can occupy —
    /// a peer dribbling an unterminated capsule header.
    BufferOverflow,
    /// The client closed its send direction with a partially received capsule
    /// still buffered. RFC 9297 §3.3: "If the stream is closed in the middle of
    /// a capsule, this MUST be treated as a malformed message" — a clean FIN
    /// does not make a truncated capsule stream a successful EOF.
    TruncatedAtStreamEnd,
}

impl CapsuleDecodeError {
    pub fn reason(self) -> &'static str {
        match self {
            Self::CapsuleTooLarge => "capsule_too_large",
            Self::DatagramCapsuleTruncated => "datagram_capsule_truncated",
            Self::PayloadTooLarge => "payload_too_large",
            Self::BufferOverflow => "capsule_buffer_overflow",
            Self::TruncatedAtStreamEnd => "capsule_truncated_at_stream_end",
        }
    }
}

/// Incremental RFC 9297 capsule reader over the CONNECT stream.
///
/// Holds at most one partially received capsule. `max_capsule_value` is the
/// configured payload ceiling plus [`CAPSULE_FRAMING_SLACK_BYTES`], so a peer
/// cannot make the gateway buffer more than that regardless of how it chunks
/// its DATA frames.
pub struct CapsuleDecoder {
    buf: BytesMut,
    max_capsule_value: usize,
    max_udp_payload: usize,
}

impl CapsuleDecoder {
    pub fn new(max_udp_payload: usize) -> Self {
        let max_capsule_value = max_udp_payload.saturating_add(CAPSULE_FRAMING_SLACK_BYTES);
        Self {
            buf: BytesMut::with_capacity(max_capsule_value.min(16 * 1024)),
            max_capsule_value,
            max_udp_payload,
        }
    }

    /// Largest legal capsule on the wire: header plus value.
    fn buffer_ceiling(&self) -> usize {
        self.max_capsule_value
            .saturating_add(MAX_CAPSULE_HEADER_BYTES)
    }

    /// Largest slice a caller may hand to [`Self::push`] at once. Feeding in
    /// units of this size and draining between pushes is what keeps the
    /// transient buffer at twice one capsule rather than at one DATA frame,
    /// which QUIC stream flow control alone would allow to be megabytes.
    pub fn feed_limit(&self) -> usize {
        self.buffer_ceiling()
    }

    /// Accept up to [`Self::feed_limit`] bytes of the CONNECT stream. The
    /// caller must drain [`Self::decode_next`] to exhaustion between pushes;
    /// the hard ceiling here is twice one capsule, which is reachable only when
    /// a chunk completes a partial capsule and opens the next one.
    pub fn push(&mut self, chunk: &[u8]) -> Result<(), CapsuleDecodeError> {
        if self.buf.len().saturating_add(chunk.len()) > self.buffer_ceiling().saturating_mul(2) {
            return Err(CapsuleDecodeError::BufferOverflow);
        }
        self.buf.extend_from_slice(chunk);
        Ok(())
    }

    /// Bytes of a partially received capsule still held after the caller has
    /// drained [`Self::decode_next`] to exhaustion.
    ///
    /// Only ever nonzero mid-capsule, so it is exactly the RFC 9297 §3.3
    /// "stream closed in the middle of a capsule" predicate.
    ///
    /// `#[allow(dead_code)]` because the binary target compiles this module
    /// tree separately from the library and only the external test crates read
    /// this accessor; production asks the same question via
    /// [`Self::finish_stream`].
    #[allow(dead_code)]
    pub fn buffered_len(&self) -> usize {
        self.buf.len()
    }

    /// Classify the end of the client's send direction.
    ///
    /// A FIN with nothing buffered is an ordinary, clean close of the capsule
    /// stream (RFC 9298 §3.1 ends the tunnel with the stream). A FIN with a
    /// partial capsule still buffered is a malformed message, NOT an EOF, and
    /// the caller must terminate the request stream with an error rather than
    /// finishing the response cleanly.
    pub fn finish_stream(&self) -> Result<(), CapsuleDecodeError> {
        if self.buf.is_empty() {
            Ok(())
        } else {
            Err(CapsuleDecodeError::TruncatedAtStreamEnd)
        }
    }

    /// Pop the next complete capsule, or `None` when more bytes are needed.
    pub fn decode_next(&mut self) -> Result<Option<CapsuleEvent>, CapsuleDecodeError> {
        let mut cursor = 0usize;
        let Some(capsule_type) = read_varint(&self.buf, &mut cursor) else {
            return Ok(None);
        };
        let Some(length) = read_varint(&self.buf, &mut cursor) else {
            return Ok(None);
        };
        if length > self.max_capsule_value as u64 {
            return Err(CapsuleDecodeError::CapsuleTooLarge);
        }
        let length = length as usize;
        if self.buf.len() - cursor < length {
            return Ok(None);
        }

        // The capsule is complete: consume the header, then the value.
        self.buf.advance(cursor);
        let mut value = self.buf.split_to(length);

        if capsule_type != CAPSULE_TYPE_DATAGRAM {
            return Ok(Some(CapsuleEvent::UnknownCapsuleType(capsule_type)));
        }

        let mut value_cursor = 0usize;
        let Some(context_id) = read_varint(&value, &mut value_cursor) else {
            return Err(CapsuleDecodeError::DatagramCapsuleTruncated);
        };
        if context_id != 0 {
            return Ok(Some(CapsuleEvent::UnregisteredContext(context_id)));
        }
        value.advance(value_cursor);
        if value.len() > self.max_udp_payload {
            return Err(CapsuleDecodeError::PayloadTooLarge);
        }
        Ok(Some(CapsuleEvent::UdpPayload(value.freeze())))
    }
}

/// Encode a UDP payload as a Context ID 0 DATAGRAM capsule, appending into
/// `out` and returning the framed capsule.
///
/// `out` is reused across datagrams so the client-bound relay amortizes its
/// allocation instead of allocating per packet.
pub fn encode_udp_datagram_capsule(out: &mut BytesMut, payload: &[u8]) -> Bytes {
    // Context ID 0 is a single varint byte.
    let value_len = 1 + payload.len();
    out.reserve(varint_len(CAPSULE_TYPE_DATAGRAM) + varint_len(value_len as u64) + value_len);
    write_varint(out, CAPSULE_TYPE_DATAGRAM);
    write_varint(out, value_len as u64);
    write_varint(out, 0);
    out.extend_from_slice(payload);
    out.split().freeze()
}

// ---------------------------------------------------------------------------
// Tunnel socket (RFC 9298 §3.1)
// ---------------------------------------------------------------------------

/// What a `UdpSocket::send` failure means for the tunnel.
///
/// Factored out of the relay so the policy is one testable decision rather than
/// an inline `debug!` that swallows everything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpSendFault {
    /// Drop this datagram and keep relaying. Either the datagram was too large
    /// for the path (RFC 9298 §3.1 forbids fragmenting it, so dropping is the
    /// required behaviour) or the error is an ICMP-derived / transient
    /// condition reported for an earlier datagram on a connected socket. UDP is
    /// lossy by design; the tunnel is not.
    DropDatagram,
    /// The socket itself is unusable. Continuing would present a live tunnel
    /// that silently discards everything the client sends, so the request
    /// stream is torn down instead.
    Terminal,
}

impl UdpSendFault {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DropDatagram => "datagram_dropped",
            Self::Terminal => "socket_unusable",
        }
    }
}

/// Whether an `io::Error` from a connected UDP `send` is per-datagram loss
/// rather than a dead socket.
///
/// `EMSGSIZE` (and its Windows spelling `WSAEMSGSIZE`) is called out
/// explicitly: with the do-not-fragment policy installed by
/// [`bind_tunnel_socket`], an over-MTU datagram is *supposed* to fail this way,
/// and treating it as a dead socket would let one oversized payload kill a
/// healthy tunnel.
pub fn classify_udp_send_error(error: &std::io::Error) -> UdpSendFault {
    #[cfg(unix)]
    if let Some(code) = error.raw_os_error()
        && matches!(
            code,
            libc::EMSGSIZE
                | libc::EAGAIN
                | libc::ENOBUFS
                | libc::EINTR
                | libc::ECONNREFUSED
                | libc::EHOSTUNREACH
                | libc::ENETUNREACH
                | libc::ENETDOWN
                | libc::EHOSTDOWN
        )
    {
        return UdpSendFault::DropDatagram;
    }
    // `WSAEMSGSIZE`. Windows links no `libc` here, so the code is spelled out.
    #[cfg(windows)]
    if error.raw_os_error() == Some(10040) {
        return UdpSendFault::DropDatagram;
    }
    match error.kind() {
        std::io::ErrorKind::WouldBlock
        | std::io::ErrorKind::Interrupted
        | std::io::ErrorKind::ConnectionRefused
        | std::io::ErrorKind::HostUnreachable
        | std::io::ErrorKind::NetworkUnreachable
        | std::io::ErrorKind::NetworkDown => UdpSendFault::DropDatagram,
        _ => UdpSendFault::Terminal,
    }
}

#[cfg(unix)]
fn apply_dont_fragment(socket: &socket2::Socket, is_ipv4: bool) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;
    crate::socket_opts::set_udp_dont_fragment(socket.as_raw_fd(), is_ipv4)
}

#[cfg(not(unix))]
fn apply_dont_fragment(_socket: &socket2::Socket, _is_ipv4: bool) -> std::io::Result<()> {
    Ok(())
}

/// Build the tunnel's UDP socket with IP fragmentation disabled.
///
/// RFC 9298 §3.1: "the proxy MUST NOT introduce IP fragmentation" and the IPv4
/// DF bit "MUST be set if possible". The socket is therefore constructed
/// through `socket2` so the platform option can be installed *before* the
/// socket is handed to Tokio and before a single datagram can be sent:
///
/// * Linux — `IP_MTU_DISCOVER` / `IPV6_MTU_DISCOVER` = `PMTUDISC_DO`, which
///   sets DF and turns an over-MTU send into `EMSGSIZE`
///   ([`classify_udp_send_error`] keeps that per-datagram).
/// * Apple/BSD — `IP_DONTFRAG` / `IPV6_DONTFRAG`.
/// * Everywhere else (notably Windows, where Ferrum links no Winsock binding) —
///   [`crate::socket_opts::UDP_DONT_FRAGMENT_SUPPORTED`] is `false` and this is
///   documented best effort: the socket is created without the option and the
///   caller logs that the guarantee is unavailable.
///
/// On a platform that *does* expose the option, a `setsockopt` failure is
/// fatal: the tunnel is refused rather than opened without the guarantee.
fn bind_tunnel_socket(bind_addr: SocketAddr) -> std::io::Result<std::net::UdpSocket> {
    let is_ipv4 = bind_addr.is_ipv4();
    let domain = if is_ipv4 {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let socket = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    // Before bind, so no datagram can ever leave this socket fragmentable.
    apply_dont_fragment(&socket, is_ipv4)?;
    socket.set_nonblocking(true)?;
    socket.bind(&bind_addr.into())?;
    Ok(socket.into())
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

/// Why a tunnel ended. Low-cardinality: safe as a log field and a metric label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionEnd {
    ClientClosed,
    TargetRelayEnded,
    TargetSocketUnusable,
    Idle,
    Draining,
    RouteWithdrawn,
    RouteAuthorizationUnreconstructable,
    CapsuleProtocolError,
}

impl SessionEnd {
    fn as_str(self) -> &'static str {
        match self {
            Self::ClientClosed => "client_closed",
            Self::TargetRelayEnded => "target_relay_ended",
            Self::TargetSocketUnusable => "target_socket_unusable",
            Self::Idle => "idle_timeout",
            Self::Draining => "gateway_draining",
            Self::RouteWithdrawn => "route_withdrawn",
            Self::RouteAuthorizationUnreconstructable => "route_authorization_unreconstructable",
            Self::CapsuleProtocolError => "capsule_protocol_error",
        }
    }

    /// How the CONNECT stream's send half must be closed for this outcome.
    fn close_kind(self) -> StreamCloseKind {
        match self {
            // RFC 9297 §3.3 / §3.5: a malformed or truncated capsule stream is
            // a malformed HTTP message, not a successful end of response.
            Self::CapsuleProtocolError => StreamCloseKind::MessageError,
            // The tunnel was established and then could not be honoured. A
            // clean FIN would tell the client the session ended normally.
            Self::TargetSocketUnusable => StreamCloseKind::InternalError,
            Self::ClientClosed
            | Self::TargetRelayEnded
            | Self::Idle
            | Self::Draining
            | Self::RouteWithdrawn
            | Self::RouteAuthorizationUnreconstructable => StreamCloseKind::Clean,
        }
    }
}

/// How the client-bound relay terminates the QUIC send half.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StreamCloseKind {
    /// Ordinary end of tunnel: FIN the capsule stream.
    Clean,
    /// RFC 9114 §4.1.2 malformed request/response: reset with
    /// `H3_MESSAGE_ERROR`.
    MessageError,
    /// The gateway cannot complete the tunnel honestly: reset with
    /// `H3_INTERNAL_ERROR`.
    InternalError,
}

/// Outcome of one `recv_data` round in the client-bound relay.
///
/// Carries no borrow of the QUIC receive half on purpose: `recv_data` hands
/// back an `impl Buf` that captures `&mut` on the stream, so the halt decision
/// has to be made *after* that borrow ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClientRelayStep {
    /// Chunk consumed; keep reading.
    Continue,
    /// Clean FIN on a capsule boundary.
    ClientFin,
    /// Transport-level read failure; the client is gone.
    StreamError,
    /// RFC 9297 capsule-stream fault. Halt the receive half and reset the send
    /// half — never a clean EOF.
    CapsuleFault(CapsuleDecodeError),
    /// The connected UDP socket is unusable (see [`UdpSendFault::Terminal`]).
    SocketUnusable,
}

/// Everything the handler needs that is not already an `Arc` on `ProxyState`.
pub(crate) struct ConnectUdpRequest {
    pub(crate) state: Arc<ProxyState>,
    pub(crate) request_guard: crate::overload::RequestGuard,
    pub(crate) per_ip_guard: Option<crate::proxy::PerIpRequestGuard>,
    pub(crate) epoch: Arc<RequestEpoch>,
    pub(crate) proxy: Arc<Proxy>,
    pub(crate) ctx: RequestContext,
    pub(crate) plugins: Arc<Vec<Arc<dyn Plugin>>>,
    pub(crate) initial_response_header_policy_plugins: Arc<Vec<Arc<dyn Plugin>>>,
    pub(crate) plugin_execution_ns: u64,
    pub(crate) start_time: Instant,
    /// Canonicalized client-requested path — the RFC 9298 template expansion.
    pub(crate) request_path: String,
    pub(crate) proxy_headers: HashMap<String, String>,
    pub(crate) cb_target_key: Option<String>,
    pub(crate) cb_is_half_open_probe: bool,
    /// Whether plugin/policy route overrides shaped the proxy this request was
    /// admitted against.
    ///
    /// The admitted destination set is computed from the *route-override
    /// effective* proxy, but the reload re-check can only look the proxy up by
    /// `(namespace, id)` and therefore only ever recovers the base shape. When
    /// overrides were in play the exact effective authorization cannot be
    /// reconstructed from a new generation, so the tunnel fails closed instead
    /// of being re-admitted against a route it was never admitted against.
    pub(crate) route_overrides_applied: bool,
}

/// RFC 9298 entry point, called from `handle_h3_request` once routing,
/// authentication, authorization, admission, and the `before_proxy` plugin
/// phase have all run.
pub(crate) async fn handle_h3_connect_udp(
    mut stream: RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    request: ConnectUdpRequest,
) -> Result<(), anyhow::Error> {
    let ConnectUdpRequest {
        state,
        request_guard,
        per_ip_guard,
        epoch,
        proxy,
        ctx,
        plugins,
        initial_response_header_policy_plugins,
        plugin_execution_ns,
        start_time,
        request_path,
        proxy_headers,
        cb_target_key,
        cb_is_half_open_probe,
        route_overrides_applied,
    } = request;

    // A CONNECT-UDP tunnel dials no HTTP backend, so it can neither confirm nor
    // refute a half-open circuit-breaker probe. The dispatcher therefore does
    // not consult the breaker for CONNECT-UDP at all and these arrive as
    // `(None, false)`; this stays as defense in depth, because a claimed slot
    // held for the session lifetime would wedge the breaker closed.
    crate::http3::websocket::release_h3_ws_circuit_breaker_probe_on_admission_reject(
        &state,
        &proxy,
        cb_target_key.as_deref(),
        cb_is_half_open_probe,
    );

    // Defense in depth: the dispatcher already gated this.
    if !state.env_config.http3_connect_udp_enabled {
        return reject(
            &mut stream,
            &state,
            &plugins,
            &ctx,
            &initial_response_header_policy_plugins,
            StatusCode::NOT_IMPLEMENTED,
            r#"{"error":"CONNECT-UDP over HTTP/3 is disabled on this gateway"}"#,
            "connect_udp_disabled",
            plugin_execution_ns,
            start_time,
            &request_path,
            HashMap::new(),
        )
        .await;
    }

    // RFC 9297 §3.2 forbids Content-Length, Content-Type, and Transfer-Encoding
    // on a message that uses the Capsule Protocol. The dispatcher already
    // refused a client that sent one; this repeats the check over the
    // POLICY-FINALIZED outbound map, so a `request_transformer` (or any other
    // `before_proxy` plugin) cannot add one back. Still before any socket
    // exists.
    if let Some(rejection) =
        first_forbidden_capsule_protocol_field(proxy_headers.keys().map(String::as_str))
    {
        warn!(
            proxy_id = %proxy.id,
            reason = rejection.reason(),
            "Rejected HTTP/3 CONNECT-UDP: policy-finalized headers violate RFC 9297 §3.2"
        );
        return reject(
            &mut stream,
            &state,
            &plugins,
            &ctx,
            &initial_response_header_policy_plugins,
            StatusCode::BAD_REQUEST,
            rejection.client_error_body(),
            rejection.reason(),
            plugin_execution_ns,
            start_time,
            &request_path,
            HashMap::new(),
        )
        .await;
    }

    let target = match parse_connect_udp_target(&request_path) {
        Ok(target) => target,
        Err(rejection) => {
            warn!(
                proxy_id = %proxy.id,
                reason = rejection.reason(),
                "Rejected HTTP/3 CONNECT-UDP: malformed target template"
            );
            return reject(
                &mut stream,
                &state,
                &plugins,
                &ctx,
                &initial_response_header_policy_plugins,
                StatusCode::BAD_REQUEST,
                rejection.client_error_body(),
                "connect_udp_target_malformed",
                plugin_execution_ns,
                start_time,
                &request_path,
                HashMap::new(),
            )
            .await;
        }
    };

    // The ONE destination decision, bound to the client-requested target on the
    // request's own epoch and against the route-override-effective proxy. No
    // load-balanced member was selected for this request (see
    // `UpstreamSelection::unselected` on the H3 dispatch path), so nothing here
    // can be decided by a target the client did not name — and the matched
    // target's own transport requirement is screened, so a destination that
    // must ride HBONE, sidecar mTLS, an east-west cross-cluster leg, or a Unix
    // socket is never tunnelled over a direct UDP dial.
    let destination =
        admit_connect_udp_destination(&proxy, &epoch.load_balancer, &target.host, target.port);
    let admitted = match destination {
        Ok(admitted) => admitted,
        Err(refusal) => {
            // No target identity is echoed, and both refusal kinds share one
            // status and body: a probe must learn neither the configured
            // destination set nor which of its members are directly dialable.
            warn!(
                proxy_id = %proxy.id,
                reason = refusal.reason(),
                "Rejected HTTP/3 CONNECT-UDP: target is not an admissible destination"
            );
            return reject(
                &mut stream,
                &state,
                &plugins,
                &ctx,
                &initial_response_header_policy_plugins,
                StatusCode::FORBIDDEN,
                r#"{"error":"CONNECT-UDP target is not an allowed destination for this route"}"#,
                refusal.reason(),
                plugin_execution_ns,
                start_time,
                &request_path,
                HashMap::new(),
            )
            .await;
        }
    };
    let via_upstream_target = matches!(admitted, AdmittedConnectUdpDestination::UpstreamTarget(_));
    debug!(
        proxy_id = %proxy.id,
        via_upstream_target,
        "HTTP/3 CONNECT-UDP: client-requested destination admitted"
    );

    // Backend egress policy, applied to the REQUESTED host (and this route's
    // effective `dns_override`) rather than to whatever host an LB selection
    // would have produced. The generic H3 dispatch path runs this guard on its
    // selected target and is deliberately skipped for CONNECT-UDP, so this is
    // where a denied literal is refused. The dial-time resolver below screens
    // resolved addresses too; this additionally covers the override and keeps
    // the refusal ahead of any lookup. Same status and body as an unconfigured
    // destination, so it stays a non-disclosing refusal.
    if let Some(reason) = crate::proxy::denied_literal_backend_or_dns_override(
        &target.host,
        &proxy,
        &state.env_config.backend_allow_ips,
    ) {
        warn!(
            proxy_id = %proxy.id,
            reason,
            "Rejected HTTP/3 CONNECT-UDP: backend egress policy denies the requested target"
        );
        return reject(
            &mut stream,
            &state,
            &plugins,
            &ctx,
            &initial_response_header_policy_plugins,
            StatusCode::FORBIDDEN,
            r#"{"error":"CONNECT-UDP target is not an allowed destination for this route"}"#,
            "connect_udp_target_egress_denied",
            plugin_execution_ns,
            start_time,
            &request_path,
            HashMap::new(),
        )
        .await;
    }

    // `None` means the limiter is disabled by configuration; a present limiter
    // is the only thing that can refuse.
    let session_permit = match state.h3_connect_udp_sessions.as_ref() {
        Some(limit) => match Arc::clone(limit).try_acquire_owned() {
            Ok(permit) => Some(permit),
            Err(_) => {
                warn!(
                    proxy_id = %proxy.id,
                    max_sessions = state.env_config.http3_connect_udp_max_sessions,
                    "Rejected HTTP/3 CONNECT-UDP: concurrent session limit reached"
                );
                return reject(
                    &mut stream,
                    &state,
                    &plugins,
                    &ctx,
                    &initial_response_header_policy_plugins,
                    StatusCode::SERVICE_UNAVAILABLE,
                    r#"{"error":"CONNECT-UDP session limit exceeded"}"#,
                    "connect_udp_session_limit",
                    plugin_execution_ns,
                    start_time,
                    &request_path,
                    HashMap::new(),
                )
                .await;
            }
        },
        None => None,
    };

    // Resolve with the dial-time, policy-screened resolver: every candidate is
    // checked against the backend IP policy as one set, so a mixed answer
    // cannot smuggle a denied address (the same guard ordinary backend dialling
    // uses). Bounded by the route's connect budget.
    //
    // The effective per-proxy `dns_override` is passed through with the same
    // highest precedence ordinary dispatch gives it, so a route that pins its
    // destination address does not silently dial a different one here — while a
    // denied override still fails the whole lookup instead of becoming an
    // unscreened dial. `proxy` is the route-override-effective shape, so an
    // override installed by a plugin route override is the one honoured.
    let connect_budget = Duration::from_millis(proxy.backend_connect_timeout_ms.max(1));
    let resolved = match tokio::time::timeout(
        connect_budget,
        state
            .dns_cache
            .resolve_all_fresh_with_override(&target.host, proxy.dns_override.as_deref()),
    )
    .await
    {
        Ok(Ok(addresses)) => addresses,
        Ok(Err(error)) => {
            warn!(
                proxy_id = %proxy.id,
                error = %error,
                "HTTP/3 CONNECT-UDP: target DNS resolution failed"
            );
            return reject(
                &mut stream,
                &state,
                &plugins,
                &ctx,
                &initial_response_header_policy_plugins,
                StatusCode::BAD_GATEWAY,
                r#"{"error":"CONNECT-UDP target could not be resolved"}"#,
                "connect_udp_dns_error",
                plugin_execution_ns,
                start_time,
                &request_path,
                proxy_status_headers("dns_error"),
            )
            .await;
        }
        Err(_) => {
            warn!(
                proxy_id = %proxy.id,
                "HTTP/3 CONNECT-UDP: target DNS resolution timed out"
            );
            return reject(
                &mut stream,
                &state,
                &plugins,
                &ctx,
                &initial_response_header_policy_plugins,
                StatusCode::GATEWAY_TIMEOUT,
                r#"{"error":"CONNECT-UDP target resolution timed out"}"#,
                "connect_udp_dns_timeout",
                plugin_execution_ns,
                start_time,
                &request_path,
                proxy_status_headers("dns_timeout"),
            )
            .await;
        }
    };
    let Some(target_ip) = resolved.first().copied() else {
        return reject(
            &mut stream,
            &state,
            &plugins,
            &ctx,
            &initial_response_header_policy_plugins,
            StatusCode::BAD_GATEWAY,
            r#"{"error":"CONNECT-UDP target could not be resolved"}"#,
            "connect_udp_dns_error",
            plugin_execution_ns,
            start_time,
            &request_path,
            proxy_status_headers("dns_error"),
        )
        .await;
    };
    let target_addr = SocketAddr::new(target_ip, target.port);

    // RFC 9298 §3.1: one connected UDP socket per tunnel, so the kernel
    // enforces the 5-tuple and off-path packets never enter the session.
    let bind_addr: SocketAddr = match target_ip {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    if !crate::socket_opts::UDP_DONT_FRAGMENT_SUPPORTED {
        debug!(
            proxy_id = %proxy.id,
            "HTTP/3 CONNECT-UDP: this target exposes no do-not-fragment socket option; \
             RFC 9298 §3.1 non-fragmentation is best effort here"
        );
    }
    let socket = match bind_tunnel_socket(bind_addr).and_then(UdpSocket::from_std) {
        Ok(socket) => socket,
        Err(error) => {
            warn!(
                proxy_id = %proxy.id,
                error = %error,
                "HTTP/3 CONNECT-UDP: failed to create the non-fragmenting tunnel socket"
            );
            return reject(
                &mut stream,
                &state,
                &plugins,
                &ctx,
                &initial_response_header_policy_plugins,
                StatusCode::BAD_GATEWAY,
                r#"{"error":"CONNECT-UDP tunnel socket could not be created"}"#,
                "connect_udp_socket_error",
                plugin_execution_ns,
                start_time,
                &request_path,
                proxy_status_headers("proxy_internal_error"),
            )
            .await;
        }
    };
    if let Err(error) = socket.connect(target_addr).await {
        warn!(
            proxy_id = %proxy.id,
            error = %error,
            "HTTP/3 CONNECT-UDP: failed to connect tunnel socket"
        );
        return reject(
            &mut stream,
            &state,
            &plugins,
            &ctx,
            &initial_response_header_policy_plugins,
            StatusCode::BAD_GATEWAY,
            r#"{"error":"CONNECT-UDP tunnel socket could not be created"}"#,
            "connect_udp_socket_error",
            plugin_execution_ns,
            start_time,
            &request_path,
            proxy_status_headers("destination_unavailable"),
        )
        .await;
    }
    let socket = Arc::new(socket);

    // Accounting handoff: the request becomes a long-lived connection so
    // graceful drain waits for it and it is not double-counted as a request.
    let session_guard = crate::overload::ConnectionGuard::new(&state.overload);
    drop(request_guard);

    // ── 200 + Capsule-Protocol (RFC 9297 §3.4) ──────────────────────────
    let mut response_headers: HashMap<String, String> = HashMap::new();
    crate::plugins::apply_initial_response_header_policies(
        &initial_response_header_policy_plugins,
        &mut response_headers,
    );
    crate::proxy::headers::strip_client_response_hop_by_hop_headers(&mut response_headers);
    // RFC 9297 §3.2 forbids Content-Length, Content-Type, and Transfer-Encoding
    // on a Capsule Protocol message. The hop-by-hop strip above already removed
    // Transfer-Encoding; the other two are ordinary end-to-end fields that
    // response-header policy is free to author, so they are removed here —
    // after that policy has run, before the transport-owned signal is written.
    strip_forbidden_capsule_protocol_response_fields(&mut response_headers);
    // Transport-owned and written last: policy may not remove or forge the
    // signal that puts this stream into the Capsule Protocol.
    response_headers.insert("capsule-protocol".to_string(), "?1".to_string());
    let response = match crate::proxy::headers::apply_response_headers(
        Response::builder().status(StatusCode::OK),
        &response_headers,
    )
    .body(())
    {
        Ok(response) => response,
        Err(error) => {
            return Err(anyhow::anyhow!(
                "failed to build H3 CONNECT-UDP 200 response: {error}"
            ));
        }
    };
    crate::proxy::record_request(&state, 200);
    if let Err(error) = stream.send_response(response).await {
        return Err(anyhow::anyhow!(
            "H3 CONNECT-UDP send_response failed: {error}"
        ));
    }
    // The tunnel is established; per-IP *request* accounting ends here exactly
    // as it does for an H3 WebSocket upgrade.
    drop(per_ip_guard);

    emit_session_summary(
        &proxy,
        &ctx,
        &proxy_headers,
        &plugins,
        plugin_execution_ns,
        start_time,
        &target,
        target_ip,
        &request_path,
    )
    .await;

    info!(
        proxy_id = %proxy.id,
        target_port = target.port,
        "HTTP/3 CONNECT-UDP (RFC 9298) tunnel established"
    );

    let end = relay(
        stream,
        &state,
        &proxy,
        &epoch,
        socket,
        &target,
        start_time,
        route_overrides_applied,
    )
    .await;

    debug!(
        proxy_id = %proxy.id,
        reason = end.as_str(),
        "HTTP/3 CONNECT-UDP tunnel closed"
    );

    // Explicit: the permit and the connection guard release here, after both
    // relays are gone and the socket is dropped.
    drop(session_permit);
    drop(session_guard);
    Ok(())
}

/// Feed one client DATA chunk through the capsule decoder and relay every
/// complete Context ID 0 payload to the tunnel target.
///
/// Extracted from the relay task so the borrow of the QUIC receive half ends
/// with the call: the caller acts on the returned step *after* that, which is
/// what lets it halt the receive half on a fault.
async fn relay_client_chunk(
    decoder: &mut CapsuleDecoder,
    chunk: &mut impl Buf,
    socket: &UdpSocket,
    activity: &AtomicU64,
    session_start: Instant,
    proxy_id: &str,
) -> ClientRelayStep {
    let feed_limit = decoder.feed_limit();
    while chunk.has_remaining() {
        let slice_len = chunk.chunk().len().min(feed_limit);
        if let Err(error) = decoder.push(&chunk.chunk()[..slice_len]) {
            return ClientRelayStep::CapsuleFault(error);
        }
        chunk.advance(slice_len);
        loop {
            match decoder.decode_next() {
                Ok(Some(CapsuleEvent::UdpPayload(payload))) => {
                    activity.store(
                        session_start.elapsed().as_millis() as u64,
                        Ordering::Relaxed,
                    );
                    if let Err(error) = socket.send(&payload).await {
                        match classify_udp_send_error(&error) {
                            // Includes the `EMSGSIZE` that the RFC 9298 §3.1
                            // do-not-fragment policy produces for an over-path
                            // datagram: drop it, keep the tunnel.
                            UdpSendFault::DropDatagram => debug!(
                                proxy_id = %proxy_id,
                                "H3 CONNECT-UDP client relay: datagram dropped: {error}"
                            ),
                            // The socket is unusable. Continuing would present
                            // a live tunnel that silently discards everything
                            // the client sends.
                            UdpSendFault::Terminal => {
                                warn!(
                                    proxy_id = %proxy_id,
                                    fault = UdpSendFault::Terminal.as_str(),
                                    "H3 CONNECT-UDP client relay: tunnel socket is unusable: \
                                     {error}"
                                );
                                return ClientRelayStep::SocketUnusable;
                            }
                        }
                    }
                }
                // RFC 9298 §4 / RFC 9297 §3.1: drop and keep parsing.
                Ok(Some(CapsuleEvent::UnregisteredContext(_)))
                | Ok(Some(CapsuleEvent::UnknownCapsuleType(_))) => {}
                Ok(None) => break,
                Err(error) => return ClientRelayStep::CapsuleFault(error),
            }
        }
    }
    ClientRelayStep::Continue
}

/// Drive both directions until one ends or a lifecycle bound fires.
#[allow(clippy::too_many_arguments)]
async fn relay(
    stream: RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    state: &Arc<ProxyState>,
    proxy: &Arc<Proxy>,
    epoch: &Arc<RequestEpoch>,
    socket: Arc<UdpSocket>,
    target: &ConnectUdpTarget,
    session_start: Instant,
    route_overrides_applied: bool,
) -> SessionEnd {
    let max_payload = state.env_config.http3_connect_udp_max_datagram_bytes;
    let idle_seconds = state.env_config.http3_connect_udp_idle_timeout_seconds;
    let idle_timeout = Duration::from_secs(idle_seconds);
    let (mut h3_send, mut h3_recv) = stream.split();

    // Millisecond-resolution activity clock shared by both relays, seeded at
    // tunnel establishment so the idle window is measured from the 200 rather
    // than from the start of the request. Relaxed is sufficient: the supervisor
    // only needs eventual visibility within a tick.
    let last_activity = Arc::new(AtomicU64::new(session_start.elapsed().as_millis() as u64));

    let to_target_socket = Arc::clone(&socket);
    let to_target_activity = Arc::clone(&last_activity);
    let to_target_proxy_id = proxy.id.clone();
    // client → target: decode capsules off the CONNECT stream.
    let mut to_target = tokio::spawn(async move {
        let mut decoder = CapsuleDecoder::new(max_payload);
        loop {
            // The chunk `recv_data` yields captures `&mut h3_recv`, so the
            // decision it produces has to be a borrow-free value: the halt
            // calls below need the receive half back.
            let step = match h3_recv.recv_data().await {
                Ok(Some(mut chunk)) => {
                    relay_client_chunk(
                        &mut decoder,
                        &mut chunk,
                        &to_target_socket,
                        &to_target_activity,
                        session_start,
                        &to_target_proxy_id,
                    )
                    .await
                }
                // FIN. RFC 9298 §3.1 ends the tunnel with the stream — but only
                // a FIN on a capsule boundary is an EOF. RFC 9297 §3.3: a
                // stream closed in the middle of a capsule is a malformed
                // message, never a successful end of the capsule stream.
                Ok(None) => match decoder.finish_stream() {
                    Ok(()) => ClientRelayStep::ClientFin,
                    Err(error) => ClientRelayStep::CapsuleFault(error),
                },
                Err(error) => {
                    debug!(
                        proxy_id = %to_target_proxy_id,
                        "H3 CONNECT-UDP client relay: stream error: {error}"
                    );
                    ClientRelayStep::StreamError
                }
            };
            match step {
                ClientRelayStep::Continue => {}
                ClientRelayStep::ClientFin | ClientRelayStep::StreamError => {
                    return SessionEnd::ClientClosed;
                }
                ClientRelayStep::CapsuleFault(error) => {
                    warn!(
                        proxy_id = %to_target_proxy_id,
                        reason = error.reason(),
                        "H3 CONNECT-UDP client relay: capsule stream fault"
                    );
                    // RFC 9114 §4.1.2 malformed message. Halting with an
                    // explicit code — rather than dropping the half, which
                    // surfaces as `STOP_SENDING(0)` — is what makes the fault
                    // distinguishable from a clean end of request.
                    h3_recv.stop_sending(h3::error::Code::H3_MESSAGE_ERROR);
                    return SessionEnd::CapsuleProtocolError;
                }
                ClientRelayStep::SocketUnusable => {
                    h3_recv.stop_sending(h3::error::Code::H3_INTERNAL_ERROR);
                    return SessionEnd::TargetSocketUnusable;
                }
            }
        }
    });

    let (close_tx, mut close_rx) = tokio::sync::oneshot::channel::<StreamCloseKind>();
    let from_target_socket = Arc::clone(&socket);
    let from_target_activity = Arc::clone(&last_activity);
    let from_target_proxy_id = proxy.id.clone();
    // target → client: frame each datagram as a Context ID 0 DATAGRAM capsule.
    let mut from_target = tokio::spawn(async move {
        // One extra byte so an oversized datagram is detectable rather than
        // silently truncated into a corrupted tunnel payload.
        let mut buf = vec![0u8; max_payload + 1];
        let mut out = BytesMut::with_capacity(4096);
        // How the send half must be closed. The supervisor decides for the
        // outcomes it observes and hands the verdict over `close_rx`; the two
        // outcomes this task decides for itself are ordinary ends of tunnel.
        let mut close_kind = StreamCloseKind::Clean;
        let end = loop {
            let received = tokio::select! {
                biased;
                supervisor = &mut close_rx => {
                    if let Ok(kind) = supervisor {
                        close_kind = kind;
                    }
                    break SessionEnd::ClientClosed;
                }
                received = from_target_socket.recv(&mut buf) => received,
            };
            match received {
                Ok(len) if len > max_payload => {
                    // RFC 9298 §3.1: oversized datagrams are silently dropped
                    // rather than fragmented or truncated.
                    debug!(
                        proxy_id = %from_target_proxy_id,
                        "H3 CONNECT-UDP target relay: oversized datagram dropped"
                    );
                }
                Ok(len) => {
                    from_target_activity.store(
                        session_start.elapsed().as_millis() as u64,
                        Ordering::Relaxed,
                    );
                    let capsule = encode_udp_datagram_capsule(&mut out, &buf[..len]);
                    if let Err(error) = h3_send.send_data(capsule).await {
                        debug!(
                            proxy_id = %from_target_proxy_id,
                            "H3 CONNECT-UDP target relay: send_data failed: {error}"
                        );
                        break SessionEnd::ClientClosed;
                    }
                }
                Err(error) => {
                    debug!(
                        proxy_id = %from_target_proxy_id,
                        "H3 CONNECT-UDP target relay: socket error: {error}"
                    );
                    break SessionEnd::TargetRelayEnded;
                }
            }
        };
        match close_kind {
            // Ordinary end of tunnel: FIN so the client sees an orderly end of
            // the capsule stream.
            StreamCloseKind::Clean => {
                if let Err(error) = h3_send.finish().await {
                    debug!(
                        proxy_id = %from_target_proxy_id,
                        "H3 CONNECT-UDP target relay: finish failed: {error}"
                    );
                }
            }
            // RFC 9297 §3.3/§3.5 malformed capsule stream, or a tunnel the
            // gateway can no longer honour. A clean FIN here would tell the
            // client the session ended normally, which is exactly the
            // indistinguishability RFC 9114 §4.1.2 exists to prevent.
            StreamCloseKind::MessageError => {
                h3_send.stop_stream(h3::error::Code::H3_MESSAGE_ERROR);
            }
            StreamCloseKind::InternalError => {
                h3_send.stop_stream(h3::error::Code::H3_INTERNAL_ERROR);
            }
        }
        end
    });

    let admitted_generation = epoch.config_generation;
    let mut ticker = tokio::time::interval(SUPERVISOR_TICK);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Consume the immediate first tick so the first liveness check happens one
    // interval from now.
    ticker.tick().await;

    // Which relay, if either, already resolved. A `JoinHandle` panics when
    // polled after completion, so the teardown below must never re-await one.
    let mut to_target_finished = false;
    let mut from_target_finished = false;
    let end = loop {
        tokio::select! {
            joined = &mut to_target => {
                to_target_finished = true;
                break joined.unwrap_or(SessionEnd::ClientClosed);
            }
            joined = &mut from_target => {
                from_target_finished = true;
                break joined.unwrap_or(SessionEnd::TargetRelayEnded);
            }
            // Race-free: the token retains cancellation, so a drain that began
            // before this branch was polled is still delivered.
            () = state.overload.wait_for_drain_start() => {
                break SessionEnd::Draining;
            }
            _ = ticker.tick() => {
                if !idle_timeout.is_zero() {
                    let now_ms = session_start.elapsed().as_millis() as u64;
                    let last_ms = last_activity.load(Ordering::Relaxed);
                    if Duration::from_millis(now_ms.saturating_sub(last_ms)) >= idle_timeout {
                        break SessionEnd::Idle;
                    }
                }
                // Reload / delete: revalidate against the currently published
                // epoch, not the one this request was admitted under.
                let current = state.request_epoch.load();
                if current.config_generation != admitted_generation {
                    // The admitted destination set was computed from the
                    // ROUTE-OVERRIDE-EFFECTIVE proxy, but the only handle a new
                    // generation gives us is `(namespace, id)`, which resolves
                    // to the BASE shape. When overrides were applied, a
                    // targeted destination recheck against the base route would
                    // silently re-admit a tunnel whose overriding policy or
                    // upstream may have been changed or removed — and it would
                    // pass whenever the requested destination also happens to
                    // sit on the base route. That is not the authorization this
                    // request was admitted under, so it fails closed instead of
                    // being approximated.
                    if route_overrides_applied {
                        break SessionEnd::RouteAuthorizationUnreconstructable;
                    }
                    // Re-runs the FULL admission, transport screening included,
                    // so a reload that newly requires HBONE / mesh mTLS /
                    // cross-cluster / Unix dispatch for this destination
                    // withdraws the live direct-UDP tunnel instead of letting it
                    // outlive the policy that would now refuse it.
                    let still_admitted = current
                        .proxy_by_namespaced_id(&proxy.namespace, &proxy.id)
                        .is_some_and(|live| {
                            destination_is_configured(
                                live,
                                &current.load_balancer,
                                &target.host,
                                target.port,
                            )
                        });
                    if !still_admitted {
                        break SessionEnd::RouteWithdrawn;
                    }
                }
            }
        }
    };

    // Teardown. `abort()` only *requests* cancellation: it returns before the
    // task has released the QUIC stream half and its `Arc<UdpSocket>` clone. If
    // the caller dropped the session permit and the connection guard at that
    // point, the gateway would advertise a free tunnel slot (and a drained
    // connection) while an aborted task still owned the resources. So every
    // handle is joined before this function returns. The graceful send-half
    // close is capped by `CLOSE_GRACE`; after that, cancellation is requested
    // and its acknowledgement is awaited so a second timeout cannot detach a
    // task that still owns session resources.
    //
    // Order matters: stop reading the client stream first, then let the
    // client-bound relay flush and close within its grace before it is aborted.
    if !to_target_finished {
        to_target.abort();
    }
    let _ = close_tx.send(end.close_kind());
    if !from_target_finished
        && tokio::time::timeout(CLOSE_GRACE, &mut from_target)
            .await
            .is_err()
    {
        // Still running after the flush grace. Abort, then join: an aborted
        // handle resolves as `Err(JoinError::cancelled)` only once the task has
        // actually stopped, which is what proves the send half is released.
        // A `JoinHandle` must never be polled after it has completed, so this
        // second wait is reached only on the timed-out branch.
        from_target.abort();
        // Await the cancellation acknowledgement itself. A second timeout
        // would be allowed to drop this handle and detach the task, releasing
        // the session permit while it could still own the QUIC send half and
        // socket clone.
        let _ = from_target.await;
    }
    if !to_target_finished {
        // Aborted above and never polled to completion, so joining it here is
        // both safe and the point at which the receive half and the socket
        // clone are provably gone.
        let _ = to_target.await;
    }
    end
}

/// `Proxy-Status` (RFC 9209) with a fixed error type. No target identity, DNS
/// answer, or resolver detail is ever placed in a client-visible header.
fn proxy_status_headers(error_type: &str) -> HashMap<String, String> {
    HashMap::from([(
        "proxy-status".to_string(),
        format!("ferrum-edge; error={error_type}"),
    )])
}

/// Single rejection boundary: transaction log, metric, and a policy-finalized
/// error response, in the same order as every other H3 admission refusal.
#[allow(clippy::too_many_arguments)]
async fn reject<S>(
    stream: &mut RequestStream<S, Bytes>,
    state: &ProxyState,
    plugins: &[Arc<dyn Plugin>],
    ctx: &RequestContext,
    initial_response_header_policy_plugins: &[Arc<dyn Plugin>],
    status: StatusCode,
    body: &'static str,
    rejection_phase: &str,
    plugin_execution_ns: u64,
    start_time: Instant,
    request_path: &str,
    headers: HashMap<String, String>,
) -> Result<(), anyhow::Error>
where
    S: h3::quic::RecvStream + h3::quic::SendStream<Bytes>,
{
    crate::proxy::log_rejected_request_with_path(
        plugins,
        ctx,
        status.as_u16(),
        start_time,
        rejection_phase,
        plugin_execution_ns,
        Some(request_path),
    )
    .await;
    crate::proxy::record_request(state, status.as_u16());
    crate::http3::websocket::send_h3_reject_body(
        stream,
        status,
        Bytes::from_static(body.as_bytes()),
        headers,
        initial_response_header_policy_plugins,
    )
    .await;
    Ok(())
}

/// Access-log record emitted when the tunnel is established, mirroring the H3
/// WebSocket upgrade summary so all long-lived H3 sessions are auditable the
/// same way.
#[allow(clippy::too_many_arguments)]
async fn emit_session_summary(
    proxy: &Proxy,
    ctx: &RequestContext,
    proxy_headers: &HashMap<String, String>,
    plugins: &[Arc<dyn Plugin>],
    plugin_execution_ns: u64,
    start_time: Instant,
    target: &ConnectUdpTarget,
    target_ip: IpAddr,
    request_path: &str,
) {
    if plugins.is_empty() {
        return;
    }
    let total_ms = start_time.elapsed().as_secs_f64() * 1000.0;
    let plugin_execution_ms = plugin_execution_ns as f64 / 1_000_000.0;
    let plugin_external_io_ms =
        ctx.plugin_http_call_ns.load(Ordering::Relaxed) as f64 / 1_000_000.0;
    let gateway_overhead_ms = (total_ms - plugin_execution_ms).max(0.0);

    let mut metadata = crate::proxy::clone_log_metadata(ctx);
    metadata.insert(
        "extended_connect_protocol".to_string(),
        "connect-udp".to_string(),
    );

    let summary = TransactionSummary {
        namespace: proxy.namespace.clone(),
        timestamp_received: ctx.timestamp_received.to_rfc3339(),
        client_ip: ctx.client_ip.clone(),
        consumer_username: ctx.effective_identity().map(str::to_owned),
        auth_method: ctx.auth_method,
        http_method: "CONNECT".to_string(),
        request_path: request_path.to_owned(),
        proxy_id: Some(proxy.id.clone()),
        proxy_name: proxy.name.clone(),
        backend_target: Some(format!("udp://{}:{}", target.host, target.port)),
        backend_resolved_ip: Some(target_ip.to_string()),
        response_status_code: 200,
        latency_total_ms: total_ms,
        latency_gateway_processing_ms: total_ms,
        latency_backend_ttfb_ms: 0.0,
        latency_backend_total_ms: 0.0,
        latency_plugin_execution_ms: plugin_execution_ms,
        latency_plugin_external_io_ms: plugin_external_io_ms,
        latency_gateway_overhead_ms: gateway_overhead_ms,
        request_user_agent: proxy_headers.get("user-agent").cloned(),
        metadata,
        ai_usage_export: ctx.ai_usage_export.clone(),
        proxy_lifecycle_generation: ctx.proxy_lifecycle_generation,
        ..TransactionSummary::default()
    };
    crate::plugins::log_with_mirror(plugins, &summary, ctx).await;
}
