//! Client IP extraction with trusted proxy support.
//!
//! When the gateway sits behind load balancers, CDNs, or reverse proxies, the
//! TCP socket address (`remote_addr`) is the proxy's IP — not the real client's.
//! This module resolves the true originating client IP from `X-Forwarded-For`
//! (XFF) and recognizes the original HTTP or HTTPS scheme from
//! `X-Forwarded-Proto`, but only when the direct peer belongs to the
//! trusted-proxy set.
//!
//! # Security model
//!
//! A malicious client can prepend arbitrary IPs to `X-Forwarded-For`. Only the
//! **rightmost** entries — those appended by infrastructure you control — are
//! trustworthy. The algorithm:
//!
//! 1. Parse the XFF header into a list of IPs (left-to-right order).
//! 2. Walk from right to left. While the entry matches a trusted proxy CIDR,
//!    skip it and continue.
//! 3. The first non-trusted, valid entry is the real client IP.
//! 4. If a malformed (unparseable) entry is encountered after the trusted
//!    suffix, **stop the walk** and fall back to the socket address. Continuing
//!    leftward would reach more attacker-controlled entries — fail closed.
//! 5. If all entries are trusted (or XFF is absent/empty), fall back to the
//!    TCP socket address.
//!
//! # Configuration
//!
//! Set `FERRUM_TRUSTED_PROXIES` to a comma-separated list of CIDRs and/or IPs:
//!
//! ```text
//! FERRUM_TRUSTED_PROXIES=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,::1
//! ```
//!
//! When unset (empty), XFF headers are **ignored** and the socket IP is always
//! used — which is the secure default for edge deployments.

use crate::util::cidr::CidrSet;
use std::net::IpAddr;
use tracing::debug;

/// A parsed set of trusted proxy CIDRs for efficient IP matching.
///
/// A thin wrapper over the shared [`CidrSet`](crate::util::cidr::CidrSet)
/// primitive, so trusted-proxy matching and the backend egress allow/deny
/// lists share one implementation and cannot drift.
#[derive(Debug, Clone, Default)]
pub struct TrustedProxies {
    cidrs: CidrSet,
}

impl TrustedProxies {
    /// Parse a comma-separated list of CIDRs/IPs into a `TrustedProxies` set.
    ///
    /// Accepts formats like: `10.0.0.0/8`, `192.168.1.1`, `::1`, `fd00::/8`
    /// Whitespace around entries is trimmed. Invalid entries are logged and skipped.
    pub fn parse(raw: &str) -> Self {
        let (cidrs, invalid) = CidrSet::parse_lenient(raw);
        for entry in &invalid {
            tracing::warn!(
                "Ignoring invalid trusted proxy entry: {:?}. Expected IP or CIDR notation.",
                entry
            );
        }
        if !cidrs.is_empty() {
            tracing::info!(
                "Configured {} trusted proxy CIDR(s) for forwarded client metadata",
                cidrs.len()
            );
        }
        Self { cidrs }
    }

    /// Parse a comma-separated list of CIDRs/IPs, failing if any entry is invalid.
    ///
    /// Unlike `parse()` which skips invalid entries, this method returns an error
    /// if the input is non-empty but produces zero valid CIDRs. Used for security-
    /// critical allowlists (e.g., admin API) where a typo must not silently fail open.
    pub fn parse_strict(raw: &str) -> Result<Self, String> {
        let cidrs = CidrSet::parse_strict(raw)?;
        if !cidrs.is_empty() {
            tracing::info!("Configured {} admin allowed CIDR(s)", cidrs.len());
        }
        Ok(Self { cidrs })
    }

    /// Returns an empty set (forwarded client metadata will be ignored).
    #[allow(dead_code)] // Used by tests
    pub fn none() -> Self {
        Self {
            cidrs: CidrSet::default(),
        }
    }

    /// Returns the number of configured CIDR entries.
    #[allow(dead_code)] // Used by tests
    pub fn len(&self) -> usize {
        self.cidrs.len()
    }

    /// Returns true if no trusted proxies are configured.
    pub fn is_empty(&self) -> bool {
        self.cidrs.is_empty()
    }

    /// Check whether the given IP belongs to any trusted proxy CIDR.
    pub fn contains(&self, ip: &IpAddr) -> bool {
        self.cidrs.contains(ip)
    }

    /// Whether a comma-separated CIDR/IP list permits **every** source address
    /// of some family — a literal `/0` or a union spanning the whole family
    /// (e.g. `0.0.0.0/1,128.0.0.0/1`). Such an allowlist makes the XFF
    /// trusted-proxy filter match every source, so it provides no real
    /// restriction. Delegates to the shared `CidrSet` so the canonicalization
    /// matches the runtime filter; side-effect free, safe for config
    /// classification at startup.
    pub fn cidr_list_permits_all(raw: &str) -> bool {
        crate::util::cidr::CidrSet::parse_lenient(raw)
            .0
            .permits_all_family()
    }
}

/// Return the original HTTP-family client-facing scheme reported through a
/// trusted proxy chain.
///
/// A singleton `X-Forwarded-Proto` value is the overwrite-only contract: the
/// directly connected trusted proxy vouches for that original scheme. A
/// multi-value list is accepted only when it has the same cardinality as the
/// `X-Forwarded-For` list. Its scheme is selected at the first untrusted XFF
/// entry found after walking the validated trusted suffix from right to left,
/// so safely appended chains preserve the browser-facing value instead of the
/// nearest hop's value. Malformed or misaligned trusted suffixes return `None`.
/// Callers must never use this result for an untrusted socket peer because the
/// headers may then be client-controlled.
pub fn trusted_forwarded_request_scheme<'a, 'b>(
    socket_addr: &IpAddr,
    forwarded_for_values: impl IntoIterator<Item = &'a [u8]>,
    forwarded_proto_values: impl IntoIterator<Item = &'b [u8]>,
    trusted_proxies: &TrustedProxies,
) -> Option<&'static str> {
    if !trusted_proxies.contains(socket_addr) {
        return None;
    }

    // Track the rightmost non-trusted XFF entry without allocating a temporary
    // vector. Any malformed entry clears the candidate; a later untrusted
    // entry restores it because that later entry is the boundary reached first
    // by the canonical right-to-left trust walk.
    let mut forwarded_for_count = 0usize;
    let mut client_boundary = None;
    for value in forwarded_for_values {
        for entry in value.split(|byte| *byte == b',') {
            let index = forwarded_for_count;
            forwarded_for_count += 1;
            let entry = trim_header_ows(entry);
            client_boundary = match std::str::from_utf8(entry)
                .ok()
                .and_then(|entry| entry.parse::<IpAddr>().ok())
            {
                Some(ip) if trusted_proxies.contains(&ip) => client_boundary,
                Some(_) => Some(index),
                None => None,
            };
        }
    }

    let mut forwarded_proto_count = 0usize;
    let mut singleton_proto = None;
    let mut boundary_proto = None;
    let mut trusted_proto_suffix_valid = true;
    for value in forwarded_proto_values {
        for proto in value.split(|byte| *byte == b',') {
            let index = forwarded_proto_count;
            forwarded_proto_count += 1;
            let proto = recognized_forwarded_proto(trim_header_ows(proto));
            if index == 0 {
                singleton_proto = proto;
            }
            if client_boundary.is_some_and(|boundary| index >= boundary) && proto.is_none() {
                trusted_proto_suffix_valid = false;
            }
            if client_boundary == Some(index) {
                boundary_proto = proto;
            }
        }
    }

    if forwarded_proto_count == 1 {
        return singleton_proto;
    }
    if forwarded_proto_count == forwarded_for_count && trusted_proto_suffix_valid {
        boundary_proto
    } else {
        None
    }
}

fn recognized_forwarded_proto(value: &[u8]) -> Option<&'static str> {
    match value {
        proto if proto.eq_ignore_ascii_case(b"http") => Some("http"),
        proto if proto.eq_ignore_ascii_case(b"https") => Some("https"),
        _ => None,
    }
}

fn trim_header_ows(value: &[u8]) -> &[u8] {
    let start = value
        .iter()
        .position(|byte| !matches!(*byte, b' ' | b'\t'))
        .unwrap_or(value.len());
    let end = value
        .iter()
        .rposition(|byte| !matches!(*byte, b' ' | b'\t'))
        .map_or(start, |index| index + 1);
    &value[start..end]
}

/// Resolve the real client IP from the request context.
///
/// When trusted proxies are configured and the request contains an
/// `X-Forwarded-For` header, walks the XFF chain right-to-left, skipping
/// trusted proxy IPs, and returns the first untrusted IP.
/// IPv4-mapped IPv6 results are canonicalized to native IPv4 before the value
/// enters request accounting or plugin execution.
///
/// When no trusted proxies are configured, returns the canonical socket IP.
///
/// The `socket_addr` variant accepts a pre-parsed `IpAddr` to avoid redundant
/// parsing on the hot path when the caller already has a parsed IP.
#[allow(dead_code)] // Used by external test crates via public API
pub fn resolve_client_ip(
    socket_ip: &str,
    xff_header: Option<&str>,
    trusted_proxies: &TrustedProxies,
) -> String {
    // Parse the socket IP once; if unparseable, return it as-is
    let socket_addr: IpAddr = match socket_ip.parse() {
        Ok(ip) => ip,
        Err(_) => return socket_ip.to_string(),
    };

    // Fast path: no trusted proxies configured — always use socket IP.
    if trusted_proxies.is_empty() {
        return socket_addr.to_canonical().to_string();
    }

    resolve_client_ip_parsed(socket_ip, &socket_addr, xff_header, trusted_proxies)
}

/// Like `resolve_client_ip` but accepts a pre-parsed `IpAddr` so callers on
/// the hot path avoid parsing the socket IP string twice. The returned text is
/// canonicalized before it becomes the request client identity.
pub fn resolve_client_ip_parsed(
    socket_ip: &str,
    socket_addr: &IpAddr,
    xff_header: Option<&str>,
    trusted_proxies: &TrustedProxies,
) -> String {
    // No XFF header — use socket IP
    let xff = match xff_header {
        Some(h) if !h.trim().is_empty() => h,
        _ => return socket_addr.to_canonical().to_string(),
    };

    // If the direct connection is NOT from a trusted proxy, the XFF header
    // could be entirely attacker-controlled — ignore it.
    if !trusted_proxies.contains(socket_addr) {
        debug!(
            socket_ip = socket_ip,
            "Direct connection not from trusted proxy; ignoring X-Forwarded-For"
        );
        return socket_addr.to_canonical().to_string();
    }

    // Walk XFF entries right-to-left without collecting into a Vec.
    // rsplit(',') yields entries from right to left directly.
    for entry in xff.rsplit(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        match entry.parse::<IpAddr>() {
            Ok(ip) => {
                if !trusted_proxies.contains(&ip) {
                    // First untrusted IP = real client
                    return ip.to_canonical().to_string();
                }
                // This is a trusted proxy, keep walking left
            }
            Err(_) => {
                // Unparseable entry after the trusted suffix — stop the walk.
                // Entries to the left are MORE attacker-controlled; continuing
                // would let a spoofed IP feed ACLs, rate limits, and logs.
                // Fail closed: fall through to the socket address below.
                debug!(
                    entry = entry,
                    "Malformed X-Forwarded-For entry after trusted suffix; \
                     falling back to socket address"
                );
                break;
            }
        }
    }

    // All XFF entries were trusted proxies — fall back to socket IP
    socket_addr.to_canonical().to_string()
}

/// Resolve a configured single-hop real-IP header from a trusted direct proxy.
///
/// Unlike `X-Forwarded-For`, configured headers such as `CF-Connecting-IP` or
/// `X-Real-IP` are expected to contain exactly one IP address. The AWS
/// `CloudFront-Viewer-Address` form (`ip:source-port`) is also accepted.
/// Comma-separated chains or malformed values are ignored so client-controlled
/// header text cannot feed ACLs, rate limits, or logs.
pub fn resolve_real_ip_header(
    socket_ip: &str,
    socket_addr: &IpAddr,
    header_value: &str,
    trusted_proxies: &TrustedProxies,
) -> Option<String> {
    if !trusted_proxies.contains(socket_addr) {
        debug!(
            socket_ip = socket_ip,
            "Direct connection not from trusted proxy; ignoring configured real-IP header"
        );
        return None;
    }

    let value = header_value.trim();
    if value.is_empty() || value.contains(',') {
        debug!(
            value = value,
            "Configured real-IP header must contain a single IP address or IP:port value"
        );
        return None;
    }

    match parse_single_real_ip_value(value) {
        Ok(ip) => Some(ip.to_canonical().to_string()),
        Err(_) => {
            debug!(
                value = value,
                "Configured real-IP header was not a parseable IP address or IP:port value"
            );
            None
        }
    }
}

fn parse_single_real_ip_value(value: &str) -> Result<IpAddr, std::net::AddrParseError> {
    value
        .parse::<IpAddr>()
        .or_else(|_| value.parse::<std::net::SocketAddr>().map(|addr| addr.ip()))
}

/// Resolve client IP when a caller has already performed targeted header
/// lookups from the request.
///
/// If a configured real-IP header is present, that single-hop header is the
/// only forwarded source considered. Rejected real-IP values return `None` so
/// callers keep the socket IP rather than falling through to XFF. When the
/// configured real-IP header is absent, this falls back to the XFF walk.
pub fn resolve_forwarded_client_ip(
    socket_ip: &str,
    socket_addr: &IpAddr,
    real_ip_header_value: Option<&str>,
    xff_header: Option<&str>,
    trusted_proxies: &TrustedProxies,
) -> Option<String> {
    if trusted_proxies.is_empty() {
        return None;
    }

    if let Some(value) = real_ip_header_value {
        return resolve_real_ip_header(socket_ip, socket_addr, value, trusted_proxies);
    }

    let resolved = resolve_client_ip_parsed(socket_ip, socket_addr, xff_header, trusted_proxies);
    if resolved == socket_ip {
        None
    } else {
        Some(resolved)
    }
}
