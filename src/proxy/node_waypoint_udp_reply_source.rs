//! NodeWaypoint UDP/DTLS **reply-source authorization** publication (issue
//! #3286).
//!
//! # The gap this closes
//!
//! `tc_inbound` admits a datagram to an enrolled pod only when it carries the
//! NodeWaypoint relay's auth mark AND comes from an authorized source. For the
//! relay's *backend dial* the source is a configured node address, so the TCP
//! proof carries over unchanged. For the relay's *reply* it does not: a
//! NodeWaypoint UDP/DTLS reply is not route-selected, it is PINNED (via
//! `IP_PKTINFO`/`IPV6_PKTINFO` on an `IP_TRANSPARENT` socket) to the exact local
//! address the client addressed. On the ordinary Service path that address is
//! the Service ClusterIP — never a node PodCIDR gateway address, and therefore
//! never in `FERRUM_NODE_IPS`/`FERRUM_NODE_IPS6`. So a correctly marked,
//! correctly scoped, correctly attributed reply died in this node's own guard,
//! and only a direct dial to a trusted node address ever completed.
//!
//! Un-pinning the reply is not a fix (a `connect()`ed client — every DTLS client
//! — discards a reply whose source is not the address it dialed), and widening
//! the node-IP set to ClusterIPs would hand every `CAP_NET_ADMIN`/`SO_MARK`
//! capable workload a generic lane to enrolled pods.
//!
//! # What is authorized
//!
//! Exactly the reply's own two-tuple: `(pinned source address, listener port)`.
//! Both are knowable in advance and both are exact — no CIDR, no service range,
//! no port-blind form. `FERRUM_UDP_REPLY_SOURCES`/`FERRUM_UDP_REPLY_SOURCES6`
//! supply only the SOURCE half of the guard's proof; the relay auth mark is
//! still required, TCP never reads these maps, and nothing here admits an
//! unmarked datagram.
//!
//! # Ownership: why this is a directory and not a map write
//!
//! The node-agent is the sole writer of every BPF map, and the mesh proxy's
//! bpffs mount is deliberately **read-only** — a writable one would also let the
//! proxy rewrite the pinned original-destination identity records. So the proxy
//! publishes CLAIMS and the node-agent reconciles them into the maps, reusing
//! the established proxy→node-agent channel: the pod registry directory the
//! proxy already writes `.ready` markers into.
//!
//! One file per authorized reply source under
//! `<registry dir>/.udp-reply-src/`, named
//! `<family>-<hex address>-<port>` ([`encode_claim`]). The name is generated
//! from a parsed [`IpAddr`], never from operator text, and the node-agent parses
//! it strictly ([`decode_claim`]); anything else authorizes nothing.
//!
//! # Lifecycle and ordering
//!
//! Publication is bound to the SERVING lifecycle, not to configuration.
//! [`NodeWaypointUdpSteering`](super::node_waypoint_udp_steering) owns the call
//! and only ever passes destinations whose listeners are bound on the accepted
//! serving generation, so a candidate config authorizes nothing by being parsed.
//! Within one reconcile:
//!
//! * the previous generation is torn down first (steering rules removed, then
//!   claims withdrawn),
//! * the new claims are published BEFORE the steering rules that will send
//!   traffic at them, so no datagram is ever steered to a listener whose reply
//!   the guard would drop,
//! * on teardown the order reverses — rules first, then claims — so nothing is
//!   steered at an address whose authorization is about to disappear.
//!
//! Every failure is fail-closed: a publication that cannot be written refuses
//! the whole generation and tears the datapath down, and a withdrawal that
//! cannot be completed is never recorded as done, so the next reconcile retries
//! it. Claims a crashed predecessor left behind are reaped by the successor's
//! mandatory first-pass teardown, exactly like its steering rules.

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use crate::capture::{MAX_NODE_WAYPOINT_UDP_STEER_DESTINATIONS, NodeWaypointUdpSteerDestination};

/// Directory under the pod registry root carrying the proxy's reply-source
/// claims. A dot-prefixed sibling of the pod files, like the readiness markers,
/// so a claim can never be mistaken for a pod UID entry.
pub const NODE_WAYPOINT_UDP_REPLY_SOURCE_DIR: &str = ".udp-reply-src";

/// Encode one authorized reply source as a claim file name.
///
/// Hex rather than the textual address form on purpose: an IPv6 address has
/// many textual spellings (`::1` / `0:0:0:0:0:0:0:1`) but exactly one byte
/// sequence, so a fixed-width hex rendering makes the claim set a true set —
/// two spellings of one address cannot become two files, and the node-agent's
/// parse is a total function on a closed charset with no separator ambiguity.
pub fn encode_claim(source: &NodeWaypointUdpSteerDestination) -> String {
    use std::fmt::Write as _;

    let mut name = String::with_capacity(40);
    // Writing into a `String` is infallible, and the rendering is fixed-width,
    // which is what makes the parse below a total inverse.
    match source.ip {
        IpAddr::V4(addr) => {
            name.push_str("4-");
            for octet in addr.octets() {
                let _ = write!(name, "{octet:02x}");
            }
        }
        IpAddr::V6(addr) => {
            name.push_str("6-");
            for octet in addr.octets() {
                let _ = write!(name, "{octet:02x}");
            }
        }
    }
    let _ = write!(name, "-{}", source.port);
    name
}

/// Strictly parse a claim file name back into an authorized reply source.
///
/// `None` for anything that is not exactly the shape [`encode_claim`] produces:
/// wrong family tag, wrong address width, non-lowercase-hex digits, a missing or
/// extra separator, a non-numeric or out-of-range port, or port `0` (no listener
/// binds it, so it can only be junk). An unrecognized name authorizes nothing,
/// which is the fail-closed answer.
pub fn decode_claim(name: &str) -> Option<NodeWaypointUdpSteerDestination> {
    let mut parts = name.split('-');
    let family = parts.next()?;
    let addr = parts.next()?;
    let port_text = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    // Lowercase hex only. Accepting uppercase would make two names describe one
    // address, and the claim set would stop being a set.
    if !addr
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    let ip = match family {
        "4" if addr.len() == 8 => {
            let mut octets = [0u8; 4];
            decode_hex_octets(addr, &mut octets)?;
            IpAddr::from(octets)
        }
        "6" if addr.len() == 32 => {
            let mut octets = [0u8; 16];
            decode_hex_octets(addr, &mut octets)?;
            IpAddr::from(octets)
        }
        _ => return None,
    };
    // Round-trip the port for the same canonicality reason: `+80`, ` 80`, and
    // `080` all parse to 80, and three names for one source would defeat the
    // set semantics the whole-set replacement depends on. Port 0 is never bound
    // by a listener, so it can only be junk.
    let port: u16 = port_text.parse().ok()?;
    if port == 0 || port.to_string() != port_text {
        return None;
    }
    Some(NodeWaypointUdpSteerDestination { ip, port })
}

fn decode_hex_octets(hex: &str, out: &mut [u8]) -> Option<()> {
    let bytes = hex.as_bytes();
    if bytes.len() != out.len() * 2 {
        return None;
    }
    for (slot, pair) in out.iter_mut().zip(bytes.chunks_exact(2)) {
        let high = (pair[0] as char).to_digit(16)?;
        let low = (pair[1] as char).to_digit(16)?;
        *slot = ((high << 4) | low) as u8;
    }
    Some(())
}

/// Publishes the authorized reply-source set for the serving generation.
///
/// Behind a trait so the steering reconcile's ordering and fail-closed
/// behaviour are testable without a registry directory, a node-agent, or root.
pub trait NodeWaypointUdpReplySourcePublisher: Send + Sync + 'static {
    /// Replace the whole published set with exactly `sources`. An empty slice
    /// is a retraction, and must be as reliable as a publication — a failure
    /// here means the caller may NOT record the withdrawal as done.
    fn publish(&self, sources: &[NodeWaypointUdpSteerDestination]) -> Result<(), String>;
}

/// Production publisher: one claim file per authorized reply source under the
/// pod registry directory the node-agent already polls.
pub struct RegistryDirReplySourcePublisher {
    dir: PathBuf,
}

impl RegistryDirReplySourcePublisher {
    /// `registry_dir` is the pod registry root
    /// (`FERRUM_MESH_NODE_WAYPOINT_POD_REGISTRY_DIR`); the claim subdirectory is
    /// appended here so no caller can pick a different one.
    pub fn new(registry_dir: impl AsRef<Path>) -> Self {
        Self {
            dir: registry_dir.as_ref().join(NODE_WAYPOINT_UDP_REPLY_SOURCE_DIR),
        }
    }
}

impl NodeWaypointUdpReplySourcePublisher for RegistryDirReplySourcePublisher {
    fn publish(&self, sources: &[NodeWaypointUdpSteerDestination]) -> Result<(), String> {
        if sources.len() > MAX_NODE_WAYPOINT_UDP_STEER_DESTINATIONS {
            return Err(format!(
                "refusing to authorize {} NodeWaypoint UDP/DTLS reply sources; the bound is {}",
                sources.len(),
                MAX_NODE_WAYPOINT_UDP_STEER_DESTINATIONS
            ));
        }
        std::fs::create_dir_all(&self.dir).map_err(|error| {
            format!(
                "failed to create the NodeWaypoint UDP reply-source claim directory: {}",
                io_detail(&error)
            )
        })?;

        let desired: BTreeSet<String> = sources.iter().map(encode_claim).collect();

        // Withdraw first. A failure aborts before anything new is authorized,
        // and the node-agent reads this directory as a set snapshot, so a
        // partially applied pass can only ever narrow what is authorized.
        let entries = std::fs::read_dir(&self.dir).map_err(|error| {
            format!(
                "failed to read the NodeWaypoint UDP reply-source claim directory: {}",
                io_detail(&error)
            )
        })?;
        for entry in entries {
            let entry = entry.map_err(|error| {
                format!(
                    "failed to enumerate NodeWaypoint UDP reply-source claims: {}",
                    io_detail(&error)
                )
            })?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                // Not a name this publisher can have written, so it authorizes
                // nothing the node-agent will parse. Removing it is still the
                // right answer: this directory is Ferrum-owned.
                remove_claim(&entry.path())?;
                continue;
            };
            if !desired.contains(name) {
                remove_claim(&entry.path())?;
            }
        }

        for name in &desired {
            let path = self.dir.join(name);
            std::fs::write(&path, b"").map_err(|error| {
                format!(
                    "failed to authorize a NodeWaypoint UDP/DTLS reply source: {}",
                    io_detail(&error)
                )
            })?;
        }
        Ok(())
    }
}

fn remove_claim(path: &Path) -> Result<(), String> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "failed to withdraw a NodeWaypoint UDP/DTLS reply source: {}",
            io_detail(&error)
        )),
    }
}

/// Diagnostics carry the failure CLASS, never the path: the registry root is
/// operator-configured and the claim name embeds a Service address, and neither
/// belongs in a log line an operator reads for a filesystem fault.
fn io_detail(error: &std::io::Error) -> String {
    error.kind().to_string()
}

/// Read every currently claimed reply source from a registry directory.
///
/// The node-agent's side of the contract. Returns the parsed, deduplicated set
/// plus the number of entries that could not be parsed, so the caller can
/// surface a bounded diagnostic without echoing any file name. An absent
/// directory is an empty set, not an error: the proxy creates it on its first
/// publication, and "nothing claimed" is the correct fail-closed reading.
pub fn read_claims(
    registry_dir: &Path,
) -> Result<(BTreeSet<NodeWaypointUdpSteerDestination>, usize), String> {
    let dir = registry_dir.join(NODE_WAYPOINT_UDP_REPLY_SOURCE_DIR);
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok((BTreeSet::new(), 0));
        }
        Err(error) => {
            return Err(format!(
                "failed to read the NodeWaypoint UDP reply-source claim directory: {}",
                io_detail(&error)
            ));
        }
    };

    let mut claims = BTreeSet::new();
    let mut unparsed = 0usize;
    for entry in entries {
        let entry = entry.map_err(|error| {
            format!(
                "failed to enumerate NodeWaypoint UDP reply-source claims: {}",
                io_detail(&error)
            )
        })?;
        let name = entry.file_name();
        match name.to_str().and_then(decode_claim) {
            Some(claim) => {
                claims.insert(claim);
            }
            None => unparsed += 1,
        }
    }
    Ok((claims, unparsed))
}

// Contract coverage lives in
// `tests/unit/gateway_core/node_waypoint_udp_reply_source_tests.rs` (claim
// round-trip incl. IPv4/IPv6 parity, strict decode refusals, whole-set
// replacement, withdraw-before-add ordering, and the bound).
