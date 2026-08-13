//! Datagram-safe client-address metadata (PROXY protocol v2 DGRAM envelope).
//!
//! UDP and DTLS listeners behind a datagram load balancer only ever observe the
//! balancer's own socket address, so the original client identity is lost for
//! authorization, rate limiting, and audit. TCP solves this with the PROXY
//! protocol, but that framing is connection-borne: it is written once, ahead of
//! the byte stream, and nothing in it survives datagram boundaries.
//!
//! This module defines the datagram equivalent Ferrum accepts (issue #3289):
//! a PROXY protocol v2 header carrying the `DGRAM` transport byte, prepended to
//! **every** datagram, with the application payload following the declared
//! address block.
//!
//! ```text
//!  0                12      13      14          16
//!  +----------------+-------+-------+-----------+----------------+---------+
//!  | v2 signature   |ver_cmd|fam_tp | addr_len  |  address block | payload |
//!  |   (12 bytes)   |  1 B  |  1 B  |  u16 BE   |  addr_len B    |    …    |
//!  +----------------+-------+-------+-----------+----------------+---------+
//! ```
//!
//! Per-datagram (rather than first-datagram-only) framing is deliberate. A
//! session-scoped header would let any later datagram from the same 4-tuple
//! inherit an identity it never proved, and datagram delivery is unordered and
//! lossy, so there is no "first" datagram to rely on.
//!
//! # Security model
//!
//! The mechanism is off unless an operator sets `stream_proxy_protocol: true`
//! on the `udp` / `dtls` proxy. When it is on:
//!
//! - The socket peer must be inside `FERRUM_TRUSTED_PROXIES`. An untrusted peer
//!   is dropped outright — the datagram is never parsed and never forwarded.
//! - The socket peer remains `source.ip` / `direct_client_ip` **always**. Only
//!   the authenticated envelope may set `remote.ip` / `client_ip`.
//! - When `FERRUM_DATAGRAM_PROXY_PROTOCOL_SECRET` is configured, every datagram
//!   must additionally carry a valid HMAC-SHA-256 tag ([`AUTH_TLV_TYPE`]) that
//!   covers the whole header *and* the payload. Source addresses are trivially
//!   spoofable on UDP, so this is the only thing that makes trust in a datagram
//!   peer meaningful on a network the operator does not fully control. The tag
//!   binds metadata to payload; it is not an anti-replay mechanism (a verbatim
//!   replay of a datagram remains possible, exactly as it is for plain UDP).
//! - Anything else fails closed: no signature, truncated header, oversized
//!   address block, wrong address family, any transport but `DGRAM` on a
//!   `PROXY` command (`STREAM` — i.e. a TCP header replayed onto the datagram
//!   path — is refused whatever family it declares, `AF_UNSPEC` included),
//!   malformed TLVs, a missing or invalid authentication tag, or a destination
//!   port that does not match the receiving listener. There is no fallback to
//!   the socket peer, because that would silently downgrade a spoofed datagram
//!   into an accepted one.
//!
//! The HMAC tag authenticates the destination bytes but is keyed by a
//! process-global secret, so a valid envelope minted for listener port A would
//! otherwise verify on listener port B. The gate therefore captures the
//! receiving `listen_port` at construction and refuses an identity-bearing
//! `PROXY` envelope whose declared destination port differs, before any
//! session, demux allocation, plugin hook, or backend send. `LOCAL` and
//! `AF_UNSPEC` still never set a forwarded identity; they are not dest-port
//! bound, because they cannot confer one.
//!
//! Diagnostics are field-specific but bounded: they name the field and, at
//! most, the offending numeric code or length. Payload bytes, tag bytes,
//! secrets, and addresses asserted inside the envelope never appear in a log
//! record.
//!
//! # Relationship to the TCP PROXY parser
//!
//! [`crate::proxy::proxy_protocol`] is the connection-borne TCP parser (v1
//! text and v2 binary, STREAM transport, one header per connection). This
//! module is a separate per-datagram parser: it requires `DGRAM` transport,
//! walks the auth-TLV region, binds destination port to the receiving
//! listener, and never allocates. Signature, version, family codes, and the
//! 512-byte address-block cap MUST stay aligned with that parser; a spec-level
//! fix must update both. Do not collapse them into one abstraction — the
//! datagram path's transport, auth-TLV, dest-port, and hot-path checks would
//! be lost.
//!
//! # Spec references
//!
//! - PROXY protocol v2: <https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt>
//!   (section 2.2; `0x02` is the spec's `DGRAM` transport, and TLV type
//!   `0xE0`.. is reserved for application use.)

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use crate::fips::approved::HmacSha256Key;
use crate::proxy::client_ip::TrustedProxies;

/// PROXY protocol v2 12-byte signature.
///
/// Keep byte-identical to [`crate::proxy::proxy_protocol`]'s `V2_SIG`. The
/// parsers are deliberately separate; this constant is the shared spec token.
const V2_SIG: &[u8; 12] = b"\r\n\r\n\x00\r\nQUIT\n";
/// Signature + `ver_cmd` + `fam_transport` + `addr_len`.
const FIXED_HEADER_LEN: usize = 16;
/// Maximum accepted address-block length (fixed addresses plus TLVs). Matches
/// the TCP parser's `V2_MAX_ADDR_LEN` so one deployment cannot need two
/// different budgets.
const MAX_ADDR_BLOCK_LEN: u16 = 512;
/// `AF_INET` fixed address block: 4 + 4 + 2 + 2. Matches the TCP parser.
const INET_ADDR_LEN: usize = 12;
/// `AF_INET6` fixed address block: 16 + 16 + 2 + 2. Matches the TCP parser.
const INET6_ADDR_LEN: usize = 36;

/// TLV type carrying the HMAC-SHA-256 authentication tag.
///
/// `0xE0`..`0xEF` is the PROXY v2 application-reserved TLV range, so this
/// cannot collide with a registered TLV.
pub const AUTH_TLV_TYPE: u8 = 0xE0;
/// Length of the authentication tag value.
pub const AUTH_TAG_LEN: usize = 32;

/// Minimum accepted length of `FERRUM_DATAGRAM_PROXY_PROTOCOL_SECRET`.
pub const MIN_DATAGRAM_SECRET_BYTES: usize = 32;

/// Why a datagram's client-address metadata was refused.
///
/// Every variant is a fail-closed drop. Values are bounded: a code or a length,
/// never payload bytes, addresses under construction, or tag material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatagramMetadataError {
    /// The socket peer is not inside `FERRUM_TRUSTED_PROXIES`.
    UntrustedPeer,
    /// Fewer bytes than the fixed 16-byte header.
    TruncatedHeader { len: usize },
    /// The datagram did not begin with the PROXY v2 signature.
    InvalidSignature,
    /// Version nibble was not `2`.
    UnsupportedVersion(u8),
    /// Command nibble was neither `LOCAL` (0x0) nor `PROXY` (0x1).
    UnsupportedCommand(u8),
    /// Declared address block exceeds [`MAX_ADDR_BLOCK_LEN`].
    AddressBlockTooLong(u16),
    /// The datagram ended before the declared address block did.
    TruncatedAddressBlock { declared: u16, available: usize },
    /// Address family is neither `AF_UNSPEC`, `AF_INET`, nor `AF_INET6`.
    UnsupportedAddressFamily(u8),
    /// Transport byte is not `DGRAM`. A `STREAM` header on this path is a TCP
    /// PROXY header replayed onto a datagram listener.
    NonDatagramTransport(u8),
    /// The declared family needs more fixed address bytes than were supplied.
    AddressBlockTooShortForFamily { family: u8, len: usize },
    /// A TLV ran past the end of the address block, or declared a length the
    /// block cannot hold.
    MalformedTlv,
    /// More than one authentication TLV was present.
    DuplicateAuthenticationTag,
    /// The listener requires an authentication tag and none was present.
    MissingAuthenticationTag,
    /// The authentication TLV did not carry [`AUTH_TAG_LEN`] bytes.
    InvalidAuthenticationTagLength(usize),
    /// The authentication tag did not verify under the configured secret.
    AuthenticationTagMismatch,
    /// A secret is configured but no key could be derived from it, so nothing
    /// can be verified. Fail-closed rather than silently unauthenticated.
    AuthenticationKeyUnavailable,
    /// A later datagram on an established session carried a different
    /// forwarded client than the one the session was admitted with.
    ForwardedClientChanged,
    /// An identity-bearing `PROXY` envelope declared a destination port that
    /// is not this listener's `listen_port`. Prevents a process-global HMAC
    /// secret from making a valid envelope for listener A portable onto
    /// listener B.
    DestinationPortMismatch,
}

impl DatagramMetadataError {
    /// Fixed-cardinality label for metrics and log fields.
    pub fn reason(&self) -> &'static str {
        match self {
            Self::UntrustedPeer => "untrusted_peer",
            Self::TruncatedHeader { .. } => "truncated_header",
            Self::InvalidSignature => "invalid_signature",
            Self::UnsupportedVersion(_) => "unsupported_version",
            Self::UnsupportedCommand(_) => "unsupported_command",
            Self::AddressBlockTooLong(_) => "address_block_too_long",
            Self::TruncatedAddressBlock { .. } => "truncated_address_block",
            Self::UnsupportedAddressFamily(_) => "unsupported_address_family",
            Self::NonDatagramTransport(_) => "non_datagram_transport",
            Self::AddressBlockTooShortForFamily { .. } => "address_block_too_short",
            Self::MalformedTlv => "malformed_tlv",
            Self::DuplicateAuthenticationTag => "duplicate_authentication_tag",
            Self::MissingAuthenticationTag => "missing_authentication_tag",
            Self::InvalidAuthenticationTagLength(_) => "invalid_authentication_tag_length",
            Self::AuthenticationTagMismatch => "authentication_tag_mismatch",
            Self::AuthenticationKeyUnavailable => "authentication_key_unavailable",
            Self::ForwardedClientChanged => "forwarded_client_changed",
            Self::DestinationPortMismatch => "destination_port_mismatch",
        }
    }
}

impl std::fmt::Display for DatagramMetadataError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UntrustedPeer => f.write_str(
                "socket peer is not in FERRUM_TRUSTED_PROXIES, so its datagram client-address \
                 metadata may not set client_ip",
            ),
            Self::TruncatedHeader { len } => write!(
                f,
                "datagram is {len} bytes, shorter than the {FIXED_HEADER_LEN}-byte PROXY v2 header"
            ),
            Self::InvalidSignature => {
                f.write_str("datagram does not begin with the PROXY v2 signature")
            }
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported PROXY protocol version {version}")
            }
            Self::UnsupportedCommand(command) => {
                write!(f, "unsupported PROXY v2 command 0x{command:02x}")
            }
            Self::AddressBlockTooLong(len) => write!(
                f,
                "PROXY v2 address block length {len} exceeds the {MAX_ADDR_BLOCK_LEN}-byte cap"
            ),
            Self::TruncatedAddressBlock {
                declared,
                available,
            } => write!(
                f,
                "PROXY v2 header declares a {declared}-byte address block but only {available} \
                 bytes follow the fixed header"
            ),
            Self::UnsupportedAddressFamily(family) => {
                write!(f, "unsupported PROXY v2 address family 0x{family:02x}")
            }
            Self::NonDatagramTransport(transport) => write!(
                f,
                "PROXY v2 transport 0x{transport:02x} is not DGRAM (0x02); a stream header is not \
                 valid on a udp/dtls listener"
            ),
            Self::AddressBlockTooShortForFamily { family, len } => write!(
                f,
                "PROXY v2 address family 0x{family:02x} needs a longer fixed address block than \
                 the {len} bytes supplied"
            ),
            Self::MalformedTlv => f.write_str("malformed TLV in the PROXY v2 address block"),
            Self::DuplicateAuthenticationTag => {
                f.write_str("more than one datagram authentication TLV present")
            }
            Self::MissingAuthenticationTag => f.write_str(
                "FERRUM_DATAGRAM_PROXY_PROTOCOL_SECRET is configured but the datagram carried no \
                 authentication TLV",
            ),
            Self::InvalidAuthenticationTagLength(len) => write!(
                f,
                "datagram authentication TLV carries {len} bytes, expected {AUTH_TAG_LEN}"
            ),
            Self::AuthenticationTagMismatch => {
                f.write_str("datagram authentication tag did not verify")
            }
            Self::AuthenticationKeyUnavailable => f.write_str(
                "FERRUM_DATAGRAM_PROXY_PROTOCOL_SECRET is configured but no authentication key \
                 could be derived from it",
            ),
            Self::ForwardedClientChanged => f.write_str(
                "datagram carried a different forwarded client than the established session was \
                 admitted with",
            ),
            Self::DestinationPortMismatch => {
                f.write_str("PROXY v2 destination port does not match the receiving listener")
            }
        }
    }
}

impl std::error::Error for DatagramMetadataError {}

/// The two addresses a datagram listener keeps for one client flow.
///
/// `socket_peer` is what the kernel reported and is the only value that can
/// route a reply. `forwarded` is the authenticated original client, present
/// only when trusted metadata supplied it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DatagramClientIdentity {
    /// Direct socket peer. Always `source.ip` / `direct_client_ip`.
    pub socket_peer: SocketAddr,
    /// Authenticated forwarded client. When present it becomes `remote.ip` /
    /// `client_ip`; otherwise the socket peer serves as both.
    pub forwarded: Option<SocketAddr>,
}

impl DatagramClientIdentity {
    /// Identity for a listener without datagram client-address metadata.
    #[inline]
    pub fn direct(socket_peer: SocketAddr) -> Self {
        Self {
            socket_peer,
            forwarded: None,
        }
    }

    /// The resolved client endpoint: forwarded when authenticated, else the peer.
    #[inline]
    pub fn resolved(&self) -> SocketAddr {
        self.forwarded.unwrap_or(self.socket_peer)
    }

    /// Refuse a datagram whose forwarded client disagrees with the one this
    /// session was admitted with.
    ///
    /// A datagram load balancer that emits this envelope allocates a distinct
    /// source port per client flow, so one Ferrum session maps to one client.
    /// Rather than silently attributing a second client's traffic to the first
    /// session's identity, the mismatch is a fail-closed drop.
    #[inline]
    pub fn matches_session(&self, session_forwarded: Option<SocketAddr>) -> bool {
        self.forwarded == session_forwarded
    }
}

/// A decoded datagram: the authenticated identity plus the application payload.
#[derive(Debug, Clone, Copy)]
pub struct DecodedDatagram<'a> {
    /// Bytes after the metadata header — what the backend or DTLS engine sees.
    pub payload: &'a [u8],
    /// Forwarded client address, `None` for a `LOCAL` / `AF_UNSPEC` envelope
    /// (a balancer's own health probe keeps the socket peer as its identity).
    pub forwarded: Option<SocketAddr>,
}

/// Per-listener trust gate for datagram client-address metadata.
///
/// Built once per listener at spawn from the process-wide trust boundary, the
/// optional shared secret, and the receiving `listen_port`. Reload reconstructs
/// the gate with the live port rather than inheriting another listener's
/// binding. The receive path only calls [`Self::decode`], which allocates
/// nothing.
pub struct DatagramClientAddressGate {
    trusted_proxies: Arc<TrustedProxies>,
    /// Whether the operator configured a secret. Derived from the exact
    /// configured byte string: any nonempty value means authentication is
    /// mandatory, and only an absent or empty value leaves trust resting on the
    /// peer address alone (documented as the weaker posture). The value is
    /// never trimmed, normalized, or measured — doing so could turn a
    /// configured requirement into no requirement at all.
    authentication_required: bool,
    /// Pre-derived HMAC key over those exact bytes. `None` while
    /// `authentication_required` only if the approved HMAC module refused the
    /// key material, which then fails every datagram closed rather than
    /// downgrading the listener to unauthenticated metadata.
    auth_key: Option<HmacSha256Key>,
    /// Exact receiving listener port captured at construction. Identity-bearing
    /// `PROXY` envelopes must declare this destination port.
    listener_port: u16,
}

impl std::fmt::Debug for DatagramClientAddressGate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render the key material or anything derived from it.
        f.debug_struct("DatagramClientAddressGate")
            .field("authenticated", &self.authentication_required)
            .field("listener_port", &self.listener_port)
            .finish()
    }
}

impl DatagramClientAddressGate {
    /// Build a gate. `secret` is the raw `FERRUM_DATAGRAM_PROXY_PROTOCOL_SECRET`
    /// value, used verbatim: only an absent or empty value leaves the gate on
    /// peer-address trust. A whitespace-only or whitespace-bearing secret is a
    /// secret like any other — trimming it here would silently key the listener
    /// with different bytes than `EnvConfig` validated, or drop the
    /// authentication requirement entirely.
    ///
    /// `listener_port` is this listener's exact receiving port. It is captured
    /// here so decode can refuse a portable envelope without consulting any
    /// per-datagram caller-supplied identity.
    pub fn new(
        trusted_proxies: Arc<TrustedProxies>,
        secret: Option<&str>,
        listener_port: u16,
    ) -> Self {
        let secret = secret.filter(|value| !value.is_empty());
        let auth_key = match secret {
            Some(value) => HmacSha256Key::new_from_slice(value.as_bytes()).ok(),
            None => None,
        };
        Self {
            trusted_proxies,
            authentication_required: secret.is_some(),
            auth_key,
            listener_port,
        }
    }

    /// Whether every datagram must carry a valid authentication tag.
    #[inline]
    pub fn requires_authentication(&self) -> bool {
        self.authentication_required
    }

    /// Whether any peer at all can satisfy the trust boundary.
    ///
    /// An empty `FERRUM_TRUSTED_PROXIES` means no datagram can ever be
    /// admitted; the listener reports that once at startup rather than dropping
    /// every datagram silently.
    #[inline]
    pub fn has_trusted_peers(&self) -> bool {
        !self.trusted_proxies.is_empty()
    }

    /// Decode one datagram received from `socket_peer`.
    ///
    /// Borrows `datagram`; the returned payload is a subslice, so the hot path
    /// performs no copy and no allocation.
    pub fn decode<'a>(
        &self,
        datagram: &'a [u8],
        socket_peer: &SocketAddr,
    ) -> Result<DecodedDatagram<'a>, DatagramMetadataError> {
        if !self.trusted_proxies.contains(&socket_peer.ip()) {
            return Err(DatagramMetadataError::UntrustedPeer);
        }
        let parsed = parse_datagram_header_inner(datagram)?;
        // With no secret configured, a supplied tag is simply not honored:
        // verifying nothing against nothing would present authenticated-looking
        // metadata. The tag bytes stay inside the address block either way and
        // never reach the payload.
        if self.authentication_required {
            // A configured secret that produced no key cannot verify anything,
            // so the listener refuses rather than admitting metadata the
            // operator asked to have authenticated.
            let Some(key) = self.auth_key.as_ref() else {
                return Err(DatagramMetadataError::AuthenticationKeyUnavailable);
            };
            verify_authentication_tag(key, datagram, &parsed)?;
        }
        // Bind identity-bearing envelopes to this listener before the caller
        // can allocate a session or demux slot. `LOCAL` / `AF_UNSPEC` leave
        // `forwarded` unset and are not dest-port bound.
        if parsed.forwarded.is_some() && parsed.destination_port != Some(self.listener_port) {
            return Err(DatagramMetadataError::DestinationPortMismatch);
        }
        Ok(DecodedDatagram {
            payload: &datagram[parsed.header_len..],
            forwarded: parsed.forwarded,
        })
    }
}

/// Byte ranges and decoded fields of one metadata header.
struct ParsedDatagramHeader {
    /// Total metadata length; the payload starts here.
    header_len: usize,
    forwarded: Option<SocketAddr>,
    /// Declared destination port from an `AF_INET` / `AF_INET6` address block.
    /// `None` for `AF_UNSPEC` (no addresses). Not a trust decision; the gate
    /// compares it to the receiving listener after authentication.
    destination_port: Option<u16>,
    /// Absolute `[start, end)` of the authentication tag value, when present.
    auth_tag: Option<(usize, usize)>,
}

/// Parse the metadata header, without any trust, dest-port, or authentication
/// decision. Hostile-input entry for the fuzz lane: bounded, allocation-free,
/// and it never returns payload, tag, or secret material.
pub(crate) fn parse_datagram_header(datagram: &[u8]) -> Result<(), DatagramMetadataError> {
    parse_datagram_header_inner(datagram).map(|_| ())
}

/// Parse the metadata header, without any trust or authentication decision.
fn parse_datagram_header_inner(
    datagram: &[u8],
) -> Result<ParsedDatagramHeader, DatagramMetadataError> {
    if datagram.len() < FIXED_HEADER_LEN {
        return Err(DatagramMetadataError::TruncatedHeader {
            len: datagram.len(),
        });
    }
    if &datagram[..V2_SIG.len()] != V2_SIG {
        return Err(DatagramMetadataError::InvalidSignature);
    }
    let ver_cmd = datagram[12];
    let fam_transport = datagram[13];
    let addr_len = u16::from_be_bytes([datagram[14], datagram[15]]);

    let version = ver_cmd >> 4;
    if version != 2 {
        return Err(DatagramMetadataError::UnsupportedVersion(version));
    }
    if addr_len > MAX_ADDR_BLOCK_LEN {
        return Err(DatagramMetadataError::AddressBlockTooLong(addr_len));
    }
    let available = datagram.len() - FIXED_HEADER_LEN;
    if (addr_len as usize) > available {
        return Err(DatagramMetadataError::TruncatedAddressBlock {
            declared: addr_len,
            available,
        });
    }
    let header_len = FIXED_HEADER_LEN + addr_len as usize;
    let block = &datagram[FIXED_HEADER_LEN..header_len];

    let command = ver_cmd & 0x0f;
    let family = fam_transport >> 4;
    let transport = fam_transport & 0x0f;

    // `LOCAL` is the balancer's own traffic (health probes): no forwarded
    // address, but the envelope is still parsed and authenticated so a bare
    // datagram cannot masquerade as one.
    let is_local = match command {
        0x00 => true,
        0x01 => false,
        other => return Err(DatagramMetadataError::UnsupportedCommand(other)),
    };

    // Every `PROXY` envelope must state that it describes a datagram flow —
    // including the `AF_UNSPEC` shape, which carries no address to check. Doing
    // this only for the address-bearing families would leave a TCP `STREAM`
    // header accepted verbatim on a udp/dtls listener as long as its family
    // nibble were zeroed, which is exactly the replay the module and
    // `docs/tcp_udp_proxy.md` promise to refuse.
    //
    // `LOCAL` keeps the spec's semantics: the sender is speaking for itself,
    // the receiver must ignore the address block, and `fam_transport` is
    // conventionally `0x00`. It never sets a forwarded identity, so it cannot
    // launder a stream header into a client address.
    if !is_local {
        require_datagram_transport(transport)?;
    }

    let (forwarded, fixed_len, destination_port) = match family {
        // AF_UNSPEC — no address is carried.
        0x00 => (None, 0usize, None),
        0x01 => {
            if block.len() < INET_ADDR_LEN {
                return Err(DatagramMetadataError::AddressBlockTooShortForFamily {
                    family,
                    len: block.len(),
                });
            }
            let src = Ipv4Addr::new(block[0], block[1], block[2], block[3]);
            let port = u16::from_be_bytes([block[8], block[9]]);
            let dest_port = u16::from_be_bytes([block[10], block[11]]);
            (
                Some(SocketAddr::new(IpAddr::V4(src), port)),
                INET_ADDR_LEN,
                Some(dest_port),
            )
        }
        0x02 => {
            if block.len() < INET6_ADDR_LEN {
                return Err(DatagramMetadataError::AddressBlockTooShortForFamily {
                    family,
                    len: block.len(),
                });
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&block[..16]);
            let port = u16::from_be_bytes([block[32], block[33]]);
            let dest_port = u16::from_be_bytes([block[34], block[35]]);
            (
                Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port)),
                INET6_ADDR_LEN,
                Some(dest_port),
            )
        }
        // AF_UNIX (0x03) and anything else cannot address a datagram client.
        other => return Err(DatagramMetadataError::UnsupportedAddressFamily(other)),
    };

    let auth_tag = find_authentication_tag(&block[fixed_len..], FIXED_HEADER_LEN + fixed_len)?;

    Ok(ParsedDatagramHeader {
        header_len,
        // A LOCAL envelope never sets a client identity even if it carried
        // addresses; the balancer is speaking for itself.
        forwarded: if is_local {
            None
        } else {
            forwarded.map(crate::util::client_identity::canonical_socket_addr)
        },
        destination_port,
        auth_tag,
    })
}

#[inline]
fn require_datagram_transport(transport: u8) -> Result<(), DatagramMetadataError> {
    // 0x02 is DGRAM. UNSPEC (0x00) is refused here on purpose: a `PROXY`
    // envelope must state that it describes a datagram flow, whatever family it
    // declares.
    if transport == 0x02 {
        Ok(())
    } else {
        Err(DatagramMetadataError::NonDatagramTransport(transport))
    }
}

/// Walk the TLV region and locate the single authentication TLV, if any.
///
/// `tlv_base` is the TLV region's absolute offset inside the datagram, so the
/// returned range can address the original buffer without a second walk.
fn find_authentication_tag(
    tlvs: &[u8],
    tlv_base: usize,
) -> Result<Option<(usize, usize)>, DatagramMetadataError> {
    let mut offset = 0usize;
    let mut found: Option<(usize, usize)> = None;
    while offset < tlvs.len() {
        // type (1) + length (2) + value
        if tlvs.len() - offset < 3 {
            return Err(DatagramMetadataError::MalformedTlv);
        }
        let tlv_type = tlvs[offset];
        let value_len = u16::from_be_bytes([tlvs[offset + 1], tlvs[offset + 2]]) as usize;
        let value_start = offset + 3;
        let Some(value_end) = value_start.checked_add(value_len) else {
            return Err(DatagramMetadataError::MalformedTlv);
        };
        if value_end > tlvs.len() {
            return Err(DatagramMetadataError::MalformedTlv);
        }
        if tlv_type == AUTH_TLV_TYPE {
            if found.is_some() {
                return Err(DatagramMetadataError::DuplicateAuthenticationTag);
            }
            if value_len != AUTH_TAG_LEN {
                return Err(DatagramMetadataError::InvalidAuthenticationTagLength(
                    value_len,
                ));
            }
            found = Some((tlv_base + value_start, tlv_base + value_end));
        }
        offset = value_end;
    }
    Ok(found)
}

/// Verify the tag over everything except the tag value itself.
///
/// The MAC covers the complete datagram with the 32 tag bytes elided, so the
/// version/command/family/transport bytes, the forwarded addresses, every other
/// TLV, and the payload are all bound. Eliding rather than zeroing keeps the
/// hot path free of a scratch copy of the header.
fn verify_authentication_tag(
    key: &HmacSha256Key,
    datagram: &[u8],
    parsed: &ParsedDatagramHeader,
) -> Result<(), DatagramMetadataError> {
    let Some((tag_start, tag_end)) = parsed.auth_tag else {
        return Err(DatagramMetadataError::MissingAuthenticationTag);
    };
    let mut mac = key.begin();
    mac.update(&datagram[..tag_start]);
    mac.update(&datagram[tag_end..]);
    let expected = mac.finalize().into_bytes();
    let verified = crate::plugins::utils::auth_flow::constant_time_eq(
        &expected,
        &datagram[tag_start..tag_end],
    );
    if verified {
        Ok(())
    } else {
        Err(DatagramMetadataError::AuthenticationTagMismatch)
    }
}

/// Build a datagram carrying client-address metadata.
///
/// Ferrum never emits this envelope in production — a datagram load balancer
/// does — so this exists for the external conformance tests and for operators
/// generating fixtures. It is the normative encoder for the format above.
#[allow(dead_code)] // Used by external tests; the gateway only ever decodes.
pub fn encode_datagram_with_metadata(
    source: SocketAddr,
    destination: SocketAddr,
    payload: &[u8],
    auth_key: Option<&HmacSha256Key>,
) -> Vec<u8> {
    let source = crate::util::client_identity::canonical_socket_addr(source);
    let destination = crate::util::client_identity::canonical_socket_addr(destination);
    let (family, fixed): (u8, Vec<u8>) = match (source.ip(), destination.ip()) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            let mut fixed = Vec::with_capacity(INET_ADDR_LEN);
            fixed.extend_from_slice(&src.octets());
            fixed.extend_from_slice(&dst.octets());
            fixed.extend_from_slice(&source.port().to_be_bytes());
            fixed.extend_from_slice(&destination.port().to_be_bytes());
            (0x01, fixed)
        }
        (src, dst) => {
            let to_v6 = |ip: IpAddr| match ip {
                IpAddr::V4(v4) => v4.to_ipv6_mapped(),
                IpAddr::V6(v6) => v6,
            };
            let mut fixed = Vec::with_capacity(INET6_ADDR_LEN);
            fixed.extend_from_slice(&to_v6(src).octets());
            fixed.extend_from_slice(&to_v6(dst).octets());
            fixed.extend_from_slice(&source.port().to_be_bytes());
            fixed.extend_from_slice(&destination.port().to_be_bytes());
            (0x02, fixed)
        }
    };

    let tlv_len = if auth_key.is_some() {
        3 + AUTH_TAG_LEN
    } else {
        0
    };
    let addr_len = (fixed.len() + tlv_len) as u16;
    let mut out = Vec::with_capacity(FIXED_HEADER_LEN + addr_len as usize + payload.len());
    out.extend_from_slice(V2_SIG);
    out.push(0x21); // version 2, PROXY command
    out.push((family << 4) | 0x02); // family + DGRAM
    out.extend_from_slice(&addr_len.to_be_bytes());
    out.extend_from_slice(&fixed);

    match auth_key {
        None => {
            out.extend_from_slice(payload);
            out
        }
        Some(key) => {
            out.push(AUTH_TLV_TYPE);
            out.extend_from_slice(&(AUTH_TAG_LEN as u16).to_be_bytes());
            let tag_start = out.len();
            out.extend_from_slice(&[0u8; AUTH_TAG_LEN]);
            out.extend_from_slice(payload);
            let mut mac = key.begin();
            mac.update(&out[..tag_start]);
            mac.update(&out[tag_start + AUTH_TAG_LEN..]);
            let tag = mac.finalize().into_bytes();
            out[tag_start..tag_start + AUTH_TAG_LEN].copy_from_slice(&tag);
            out
        }
    }
}
