//! NodeWaypoint UDP/DTLS **reply-source authorization** publication and
//! acknowledgement (issue #3286).
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
//! # Ownership: why this is a file channel and not a map write
//!
//! The node-agent is the sole writer of every BPF map, and the mesh proxy's
//! bpffs mount is deliberately **read-only** — a writable one would also let the
//! proxy rewrite the pinned original-destination identity records. So the proxy
//! publishes a DESIRED generation and the node-agent applies it, reusing the
//! established proxy→node-agent channel: the pod registry directory that already
//! carries `.ready` markers one way and `.udp-not-ready` acknowledgements the
//! other.
//!
//! # The channel is a generation, not a directory of claims
//!
//! Under `<registry dir>/.udp-reply-src/` there are exactly two well-known
//! files, and nothing else in the directory means anything:
//!
//! * `desired` — written ONLY by the proxy. One bounded, strictly parsed
//!   manifest holding the WHOLE authorized set plus the generation that names
//!   it. Written to a temporary sibling and `rename`d into place, so a reader
//!   observes either the entire previous generation or the entire new one. A
//!   directory of one file per claim could be — and, on the 250 ms node-agent
//!   poll, regularly would be — observed mid-rewrite as a partial set.
//! * `applied` — written ONLY by the node-agent, and only after the COMPLETE
//!   IPv4 + IPv6 set of that exact generation is live in both BPF maps. It names
//!   the generation it applied and nothing else.
//!
//! A generation is `(owner, sequence)`. The owner is a per-process random token
//! (16 lowercase hex digits, [`RegistryDirReplySourcePublisher::new`]) and the
//! sequence is monotonic within that owner, bumped whenever the desired set
//! changes. It is not a secret and is never treated as one: it exists so that an
//! acknowledgement written for a predecessor process, for an earlier set, or for
//! a differently ordered rendering of a set can never be read as proof about the
//! generation a live proxy is asking for. The manifest's claim lines are
//! strictly ascending in the destination order, so one set has exactly one
//! rendering and a reordered file is refused rather than normalized.
//!
//! # Lifecycle and ordering
//!
//! Publication is bound to the SERVING lifecycle, not to configuration.
//! [`NodeWaypointUdpSteering`](super::node_waypoint_udp_steering) owns the call
//! and only ever passes destinations whose listeners are bound on the accepted
//! serving generation, so a candidate config authorizes nothing by being parsed.
//! Within one reconcile:
//!
//! * steering rules for the outgoing generation are removed first,
//! * the new generation is published, and then the reconcile waits for the
//!   node-agent to acknowledge THAT EXACT generation before any steering rule is
//!   installed — publishing a claim is not evidence that a map holds it, and the
//!   window between the two is exactly the steered-but-unanswerable black hole
//!   this channel exists to close,
//! * on teardown the order reverses — rules first, then the empty generation —
//!   and the withdrawal is not proven until the node-agent acknowledges the
//!   empty generation too.
//!
//! Every failure is fail-closed: a publication that cannot be written refuses
//! the whole generation and tears the datapath down, a pending or stale
//! acknowledgement keeps the rules absent and retries on the next reconcile
//! (there is no wait, no sleep, and no blocked worker), and a withdrawal that
//! cannot be proven is never recorded as done. A crashed predecessor's rules are
//! reaped by the successor's mandatory first-pass teardown; its `applied` file
//! carries a different owner and therefore satisfies nothing.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::capture::{MAX_NODE_WAYPOINT_UDP_STEER_DESTINATIONS, NodeWaypointUdpSteerDestination};

/// Directory under the pod registry root carrying the reply-source channel. A
/// dot-prefixed sibling of the pod files, like the readiness markers, so a
/// channel file can never be mistaken for a pod UID entry.
pub const NODE_WAYPOINT_UDP_REPLY_SOURCE_DIR: &str = ".udp-reply-src";

/// The proxy-written desired generation. Proxy writes, node-agent reads.
pub const NODE_WAYPOINT_UDP_REPLY_SOURCE_DESIRED_FILE: &str = "desired";

/// The node-agent-written acknowledgement. Node-agent writes, proxy reads.
pub const NODE_WAYPOINT_UDP_REPLY_SOURCE_APPLIED_FILE: &str = "applied";

/// Manifest and acknowledgement leaders. Distinct so an acknowledgement can
/// never be parsed as a desired generation, or the reverse.
const MANIFEST_MAGIC: &str = "ferrum-udp-reply-src";
const ACK_MAGIC: &str = "ferrum-udp-reply-src-ack";
const PROTOCOL_VERSION: &str = "v1";

/// Owner tokens are exactly this many lowercase hex digits. Fixed width so the
/// parse is total and a padded or truncated spelling is not a second name for
/// one owner.
const OWNER_TOKEN_CHARS: usize = 16;

/// `6-` + 32 hex digits + `-` + 5 port digits + `\n`.
const MAX_CLAIM_LINE_BYTES: usize = 41;

/// Magic (20) + space + version (2) + space + owner (16) + space + a 20-digit
/// `u64` + space + a 3-digit count + `\n`, with slack.
const MAX_HEADER_BYTES: usize = 96;

/// Hard read bound for the desired generation. Anything larger is refused
/// outright rather than parsed: the writer is Ferrum, so an oversized file is a
/// fault or a plant, never a bigger legitimate set.
const MAX_MANIFEST_BYTES: usize =
    MAX_HEADER_BYTES + MAX_CLAIM_LINE_BYTES * MAX_NODE_WAYPOINT_UDP_STEER_DESTINATIONS;

/// Hard read bound for the acknowledgement, which is exactly one header line.
const MAX_ACK_BYTES: usize = MAX_HEADER_BYTES;

/// One coherent publication of the authorized reply-source set.
///
/// `owner` is process-unique and `sequence` is monotonic within it, so equality
/// answers exactly one question: "is the set the node-agent proved applied the
/// set this process is asking for right now?"
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplySourceGeneration {
    owner: String,
    sequence: u64,
}

impl ReplySourceGeneration {
    /// The publishing process's token. Diagnostics only; never a credential.
    #[allow(dead_code)] // Diagnostic/test accessor; the token is compared as a whole.
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// Monotonic position within [`Self::owner`].
    #[allow(dead_code)] // Diagnostic/test accessor.
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Sentinel generation for a steering instance with no publication channel
    /// (non-Linux, or no registry directory). Nothing is authorized and nothing
    /// is materialized there, so the pair is trivially coherent. It can never be
    /// confused with a real generation: the parser requires 16 lowercase hex
    /// digits for an owner and a nonzero sequence, so this value cannot come off
    /// disk and cannot be written to it.
    pub(crate) fn inert() -> Self {
        Self {
            owner: "inert".to_string(),
            sequence: 0,
        }
    }
}

/// The desired generation as the node-agent reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesiredReplySources {
    /// The generation to acknowledge once — and only once — the whole set below
    /// is live in BOTH BPF map families.
    pub generation: ReplySourceGeneration,
    /// The complete authorized set, ascending and deduplicated by construction:
    /// the parser refuses any other rendering.
    pub sources: Vec<NodeWaypointUdpSteerDestination>,
}

/// Encode one authorized reply source as a manifest claim line.
///
/// Hex rather than the textual address form on purpose: an IPv6 address has
/// many textual spellings (`::1` / `0:0:0:0:0:0:0:1`) but exactly one byte
/// sequence, so a fixed-width hex rendering makes the claim set a true set —
/// two spellings of one address cannot become two lines, and the node-agent's
/// parse is a total function on a closed charset with no separator ambiguity.
pub fn encode_claim(source: &NodeWaypointUdpSteerDestination) -> String {
    use std::fmt::Write as _;

    let mut name = String::with_capacity(MAX_CLAIM_LINE_BYTES);
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

/// Strictly parse a claim line back into an authorized reply source.
///
/// `None` for anything that is not exactly the shape [`encode_claim`] produces:
/// wrong family tag, wrong address width, non-lowercase-hex digits, a missing or
/// extra separator, a non-numeric or out-of-range port, or port `0` (no listener
/// binds it, so it can only be junk). An unrecognized line authorizes nothing,
/// which is the fail-closed answer — and because it appears inside a counted
/// manifest, it refuses the WHOLE generation rather than narrowing it.
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
    let port = parse_canonical_u64(port_text)?;
    if port == 0 || port > u16::MAX as u64 {
        return None;
    }
    Some(NodeWaypointUdpSteerDestination {
        ip,
        port: port as u16,
    })
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

/// Decimal with exactly one spelling. `+7`, ` 7`, and `007` all parse to 7, and
/// three spellings of one number would make the manifest non-canonical.
fn parse_canonical_u64(token: &str) -> Option<u64> {
    let value: u64 = token.parse().ok()?;
    if value.to_string() != token {
        return None;
    }
    Some(value)
}

fn parse_owner(token: &str) -> Option<String> {
    if token.len() != OWNER_TOKEN_CHARS {
        return None;
    }
    if !token
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    Some(token.to_string())
}

/// Render the whole desired generation. `sources` must already be ascending and
/// deduplicated — [`RegistryDirReplySourcePublisher::publish`] guarantees it,
/// and [`parse_manifest`] refuses anything else.
fn render_manifest(
    generation: &ReplySourceGeneration,
    sources: &[NodeWaypointUdpSteerDestination],
) -> String {
    use std::fmt::Write as _;

    let mut body = String::with_capacity(MAX_HEADER_BYTES + sources.len() * MAX_CLAIM_LINE_BYTES);
    let _ = writeln!(
        body,
        "{MANIFEST_MAGIC} {PROTOCOL_VERSION} {} {} {}",
        generation.owner,
        generation.sequence,
        sources.len()
    );
    for source in sources {
        let _ = writeln!(body, "{}", encode_claim(source));
    }
    body
}

/// Strictly parse the desired generation.
///
/// Total and closed: a wrong magic or version, a non-canonical owner or
/// sequence, a count that disagrees with the body, an over-bound count, a claim
/// line that is not exactly a claim, a duplicate or out-of-order claim, trailing
/// bytes, a missing final newline, or non-UTF-8 all yield `None` — which the
/// caller turns into a refusal of the WHOLE generation. There is deliberately no
/// arm that salvages a prefix: a narrowed set acknowledged as complete is the
/// exact failure this channel exists to prevent.
fn parse_manifest(bytes: &[u8]) -> Option<DesiredReplySources> {
    let text = std::str::from_utf8(bytes).ok()?;
    if !text.ends_with('\n') {
        return None;
    }
    let mut lines = text.split('\n');

    let mut header = lines.next()?.split(' ');
    if header.next()? != MANIFEST_MAGIC || header.next()? != PROTOCOL_VERSION {
        return None;
    }
    let owner = parse_owner(header.next()?)?;
    let sequence = parse_canonical_u64(header.next()?)?;
    let count = parse_canonical_u64(header.next()?)?;
    if header.next().is_some() {
        return None;
    }
    // Sequence 0 is never published, so it can only be junk or a sentinel.
    if sequence == 0 || count > MAX_NODE_WAYPOINT_UDP_STEER_DESTINATIONS as u64 {
        return None;
    }

    let count = count as usize;
    let mut sources: Vec<NodeWaypointUdpSteerDestination> = Vec::with_capacity(count);
    let mut previous: Option<NodeWaypointUdpSteerDestination> = None;
    for _ in 0..count {
        let claim = decode_claim(lines.next()?)?;
        // Strictly ascending: one set has exactly one rendering, so a duplicate
        // or a reordered file cannot become a second name for a generation.
        if let Some(previous) = previous
            && claim <= previous
        {
            return None;
        }
        previous = Some(claim);
        sources.push(claim);
    }
    // Exactly the empty tail the final newline produces, and nothing after it.
    if !lines.next()?.is_empty() || lines.next().is_some() {
        return None;
    }

    Some(DesiredReplySources {
        generation: ReplySourceGeneration { owner, sequence },
        sources,
    })
}

fn parse_ack(bytes: &[u8]) -> Option<ReplySourceGeneration> {
    let text = std::str::from_utf8(bytes).ok()?;
    if !text.ends_with('\n') {
        return None;
    }
    let mut lines = text.split('\n');
    let mut header = lines.next()?.split(' ');
    if !lines.next()?.is_empty() || lines.next().is_some() {
        return None;
    }
    if header.next()? != ACK_MAGIC || header.next()? != PROTOCOL_VERSION {
        return None;
    }
    let owner = parse_owner(header.next()?)?;
    let sequence = parse_canonical_u64(header.next()?)?;
    if sequence == 0 || header.next().is_some() {
        return None;
    }
    Some(ReplySourceGeneration { owner, sequence })
}

/// Publishes the authorized reply-source set for the serving generation and
/// reports what the node-agent has acknowledged.
///
/// Behind a trait so the steering reconcile's ordering, acknowledgement gating,
/// and fail-closed behaviour are testable without a registry directory, a
/// node-agent, or root.
pub trait NodeWaypointUdpReplySourcePublisher: Send + Sync + 'static {
    /// Publish exactly `sources` as the desired generation, replacing whatever
    /// was published before, and return the generation that names it. An empty
    /// slice is a retraction, and must be as reliable as a publication — a
    /// failure here means the caller may NOT record the withdrawal as done.
    ///
    /// Republishing an unchanged set returns the SAME generation, so a
    /// reconcile that is merely waiting for the node-agent cannot walk the
    /// sequence forward faster than the acknowledgement can chase it.
    fn publish(
        &self,
        sources: &[NodeWaypointUdpSteerDestination],
    ) -> Result<ReplySourceGeneration, String>;

    /// The generation the node-agent has proven live in BOTH BPF map families,
    /// or `None` when it has proven nothing. Never blocks.
    fn acknowledged(&self) -> Result<Option<ReplySourceGeneration>, String>;
}

/// Production publisher: one atomically replaced manifest under the pod registry
/// directory the node-agent already polls.
pub struct RegistryDirReplySourcePublisher {
    dir: PathBuf,
    /// Secure-random process owner. `None` makes every publication fail closed;
    /// a predictable fallback could collide with a predecessor and let its
    /// acknowledgement satisfy this process.
    owner: Option<String>,
    /// Next sequence to hand out. Monotonic for the life of the process even
    /// across a mutex poisoning, so a sequence is never reused for a different
    /// set — which is what would let a stale acknowledgement satisfy a
    /// generation it never saw.
    next_sequence: AtomicU64,
    /// The set most recently published, with its sequence, so an unchanged
    /// republication keeps its generation.
    last: Mutex<Option<(u64, Vec<NodeWaypointUdpSteerDestination>)>>,
}

impl RegistryDirReplySourcePublisher {
    /// `registry_dir` is the pod registry root
    /// (`FERRUM_MESH_NODE_WAYPOINT_POD_REGISTRY_DIR`); the channel subdirectory
    /// is appended here so no caller can pick a different one.
    pub fn new(registry_dir: impl AsRef<Path>) -> Self {
        Self {
            dir: registry_dir
                .as_ref()
                .join(NODE_WAYPOINT_UDP_REPLY_SOURCE_DIR),
            owner: owner_token(),
            next_sequence: AtomicU64::new(1),
            last: Mutex::new(None),
        }
    }
}

impl NodeWaypointUdpReplySourcePublisher for RegistryDirReplySourcePublisher {
    fn publish(
        &self,
        sources: &[NodeWaypointUdpSteerDestination],
    ) -> Result<ReplySourceGeneration, String> {
        let owner = self.owner.as_deref().ok_or_else(|| {
            "secure randomness is unavailable for the NodeWaypoint UDP reply-source owner"
                .to_string()
        })?;
        if sources.len() > MAX_NODE_WAYPOINT_UDP_STEER_DESTINATIONS {
            return Err(format!(
                "refusing to authorize {} NodeWaypoint UDP/DTLS reply sources; the bound is {}",
                sources.len(),
                MAX_NODE_WAYPOINT_UDP_STEER_DESTINATIONS
            ));
        }
        // Canonicalize here rather than trusting the caller: the manifest's
        // ascending-and-unique invariant is what makes one set have one
        // rendering, and therefore what makes an acknowledgement exact.
        let mut canonical = sources.to_vec();
        canonical.sort_unstable();
        canonical.dedup();

        std::fs::create_dir_all(&self.dir).map_err(|error| {
            format!(
                "failed to create the NodeWaypoint UDP reply-source channel directory: {}",
                io_detail(&error)
            )
        })?;

        let mut last = lock_recovering(&self.last);
        let sequence = match last.as_ref() {
            Some((sequence, published)) if published == &canonical => *sequence,
            _ => self
                .next_sequence
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |sequence| {
                    sequence.checked_add(1)
                })
                .map_err(|_| {
                    "NodeWaypoint UDP reply-source generation sequence is exhausted".to_string()
                })?,
        };
        let generation = ReplySourceGeneration {
            owner: owner.to_string(),
            sequence,
        };
        let body = render_manifest(&generation, &canonical);

        // Forget the recorded set BEFORE the write: if the rename fails, what
        // the node-agent can read is unknown, and reusing this sequence for a
        // later set would let an acknowledgement of the old one satisfy it.
        *last = None;
        atomic_write(
            &self.dir,
            NODE_WAYPOINT_UDP_REPLY_SOURCE_DESIRED_FILE,
            owner,
            body.as_bytes(),
        )?;
        *last = Some((sequence, canonical));
        Ok(generation)
    }

    fn acknowledged(&self) -> Result<Option<ReplySourceGeneration>, String> {
        let last = lock_recovering(&self.last);
        let Some((sequence, sources)) = last.as_ref() else {
            return Ok(None);
        };
        let Some(owner) = self.owner.as_ref() else {
            return Ok(None);
        };
        let expected = DesiredReplySources {
            generation: ReplySourceGeneration {
                owner: owner.clone(),
                sequence: *sequence,
            },
            sources: sources.clone(),
        };

        // The acknowledgement alone is insufficient: a predecessor can write
        // a late proof after a successor has replaced `desired`, and hostile or
        // corrupt content can preserve `(owner, sequence)` while changing the
        // set. Bind the proof to this publisher's exact manifest, checking on
        // both sides of the acknowledgement read so an already-superseded
        // publication never satisfies the serving reconcile.
        if read_desired_generation_in(&self.dir)?.as_ref() != Some(&expected) {
            return Ok(None);
        }
        let acknowledged = read_acknowledgement_in(&self.dir)?;
        if acknowledged.as_ref() != Some(&expected.generation) {
            return Ok(None);
        }
        if read_desired_generation_in(&self.dir)?.as_ref() != Some(&expected) {
            return Ok(None);
        }
        Ok(acknowledged)
    }
}

/// A per-process token identifying the publishing proxy on the channel.
///
/// NOT a secret and never treated as one: it is written in clear to a file both
/// halves read, and it authorizes nothing by itself. Its only job is to make an
/// acknowledgement left by a crashed predecessor — or by a differently ordered
/// history — unable to satisfy this process's generation. If the selected
/// cryptographic provider cannot supply randomness, publication fails closed;
/// a PID/time fallback is not process-unique across every restart environment.
fn owner_token() -> Option<String> {
    use crate::fips::backend::rand::SecureRandom as _;
    use std::fmt::Write as _;

    let mut bytes = [0u8; OWNER_TOKEN_CHARS / 2];
    let rng = crate::fips::backend::rand::SystemRandom::new();
    if rng.fill(&mut bytes).is_err() {
        return None;
    }
    let mut token = String::with_capacity(OWNER_TOKEN_CHARS);
    for byte in bytes {
        let _ = write!(token, "{byte:02x}");
    }
    Some(token)
}

/// Temporary-file tag for the node-agent's acknowledgement writes, so the two
/// halves of the channel can never stage into the same temporary name.
fn acknowledger_tag() -> Result<String, String> {
    owner_token()
        .map(|token| format!("agent{token}"))
        .ok_or_else(|| {
            "secure randomness is unavailable for a NodeWaypoint UDP acknowledgement write"
                .to_string()
        })
}

fn lock_recovering<T>(lock: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    // A poisoned lock carries a plain value here, and the sequence source is an
    // atomic, so recovering is sound: the worst case is that the next
    // publication bumps the sequence when it did not have to.
    lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Stage into a temporary sibling and `rename` into place.
///
/// `rename` within one directory is atomic, which is the entire reason the
/// channel is a manifest: a reader on a 250 ms poll observes the whole previous
/// generation or the whole new one, never a partially rewritten set.
fn atomic_write(dir: &Path, name: &str, tag: &str, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write as _;

    let temp = dir.join(format!(".tmp.{name}.{tag}"));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let mut file = options.open(&temp).map_err(|error| {
        format!(
            "failed to create a NodeWaypoint UDP reply-source staging file: {}",
            io_detail(&error)
        )
    })?;
    let staged = file.write_all(bytes).and_then(|()| file.sync_all());
    if let Err(error) = staged {
        let _ = std::fs::remove_file(&temp);
        return Err(format!(
            "failed to stage a NodeWaypoint UDP reply-source channel write: {}",
            io_detail(&error)
        ));
    }
    std::fs::rename(&temp, dir.join(name)).map_err(|error| {
        let _ = std::fs::remove_file(&temp);
        format!(
            "failed to publish a NodeWaypoint UDP reply-source channel write: {}",
            io_detail(&error)
        )
    })
}

/// Read at most `max` bytes of a channel file. `Ok(None)` means absent.
///
/// Over-bound content is an ERROR, not a truncation: the writer is Ferrum, so an
/// oversized file is a fault or a plant and the fail-closed answer is to refuse
/// the generation. A non-regular entry is refused before any read, so a FIFO
/// planted in this directory cannot park the reader.
fn read_bounded(path: &Path, max: usize) -> Result<Option<Vec<u8>>, String> {
    use std::io::Read as _;

    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(format!(
                "failed to open a NodeWaypoint UDP reply-source channel file: {}",
                io_detail(&error)
            ));
        }
    };
    let metadata = file.metadata().map_err(|error| {
        format!(
            "failed to stat a NodeWaypoint UDP reply-source channel file: {}",
            io_detail(&error)
        )
    })?;
    if !metadata.is_file() {
        return Err(
            "a NodeWaypoint UDP reply-source channel entry is not a regular file".to_string(),
        );
    }
    let mut buffer = Vec::with_capacity(max.min(4096) + 1);
    (&mut file)
        .take(max as u64 + 1)
        .read_to_end(&mut buffer)
        .map_err(|error| {
            format!(
                "failed to read a NodeWaypoint UDP reply-source channel file: {}",
                io_detail(&error)
            )
        })?;
    if buffer.len() > max {
        return Err("a NodeWaypoint UDP reply-source channel file exceeds its bound".to_string());
    }
    Ok(Some(buffer))
}

/// Read the proxy's desired generation.
///
/// The node-agent's side of the contract. `Ok(None)` is "nothing published",
/// which is the correct fail-closed reading and not an error: the proxy creates
/// the channel on its first publication. An unreadable, over-bound, or malformed
/// manifest is an ERROR, so the caller revokes rather than retaining.
pub fn read_desired_generation(registry_dir: &Path) -> Result<Option<DesiredReplySources>, String> {
    let dir = registry_dir.join(NODE_WAYPOINT_UDP_REPLY_SOURCE_DIR);
    read_desired_generation_in(&dir)
}

fn read_desired_generation_in(dir: &Path) -> Result<Option<DesiredReplySources>, String> {
    let path = dir.join(NODE_WAYPOINT_UDP_REPLY_SOURCE_DESIRED_FILE);
    let Some(bytes) = read_bounded(&path, MAX_MANIFEST_BYTES)? else {
        return Ok(None);
    };
    parse_manifest(&bytes).map(Some).ok_or_else(|| {
        "the published NodeWaypoint UDP reply-source generation is malformed".to_string()
    })
}

/// Read the node-agent's acknowledgement, if any.
pub fn read_acknowledgement(registry_dir: &Path) -> Result<Option<ReplySourceGeneration>, String> {
    read_acknowledgement_in(&registry_dir.join(NODE_WAYPOINT_UDP_REPLY_SOURCE_DIR))
}

fn read_acknowledgement_in(dir: &Path) -> Result<Option<ReplySourceGeneration>, String> {
    let path = dir.join(NODE_WAYPOINT_UDP_REPLY_SOURCE_APPLIED_FILE);
    let Some(bytes) = read_bounded(&path, MAX_ACK_BYTES)? else {
        return Ok(None);
    };
    // A malformed acknowledgement acknowledges NOTHING. That is the pending
    // answer rather than an error: the datapath simply stays unsteered until the
    // node-agent writes a well-formed one.
    Ok(parse_ack(&bytes))
}

/// Record that `generation`'s COMPLETE IPv4 + IPv6 set is live in both maps.
///
/// The node-agent's only write on this channel, and the only statement the proxy
/// accepts as proof. Callers must have retracted any earlier acknowledgement and
/// applied the whole set before calling it.
pub fn write_acknowledgement(
    registry_dir: &Path,
    generation: &ReplySourceGeneration,
) -> Result<(), String> {
    let dir = registry_dir.join(NODE_WAYPOINT_UDP_REPLY_SOURCE_DIR);
    let body = format!(
        "{ACK_MAGIC} {PROTOCOL_VERSION} {} {}\n",
        generation.owner,
        generation.sequence
    );
    atomic_write(
        &dir,
        NODE_WAYPOINT_UDP_REPLY_SOURCE_APPLIED_FILE,
        &acknowledger_tag()?,
        body.as_bytes(),
    )
}

/// Remove any acknowledgement.
///
/// Called before the node-agent touches a map for a new generation and on every
/// refusal, so an acknowledgement never outlives the state it described. An
/// absent file is success — "nothing is acknowledged" is exactly the intent.
pub fn clear_acknowledgement(registry_dir: &Path) -> Result<(), String> {
    let path = registry_dir
        .join(NODE_WAYPOINT_UDP_REPLY_SOURCE_DIR)
        .join(NODE_WAYPOINT_UDP_REPLY_SOURCE_APPLIED_FILE);
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "failed to retract the NodeWaypoint UDP reply-source acknowledgement: {}",
            io_detail(&error)
        )),
    }
}

/// Diagnostics carry the failure CLASS, never the path: the registry root is
/// operator-configured and a claim embeds a Service address, and neither belongs
/// in a log line an operator reads for a filesystem fault.
fn io_detail(error: &std::io::Error) -> String {
    error.kind().to_string()
}

// Contract coverage lives in
// `tests/unit/gateway_core/node_waypoint_udp_reply_source_tests.rs` (claim
// round-trip incl. IPv4/IPv6 parity, strict decode refusals, atomic whole-set
// publication, generation identity/monotonicity, stale and foreign
// acknowledgement refusal, and the bound) and in
// `tests/integration/mesh_node_waypoint_udp_scope_tests.rs` (the node-agent's
// apply-then-acknowledge half).
