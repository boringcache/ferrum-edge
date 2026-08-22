//! NodeWaypoint UDP/DTLS reply-source publication and acknowledgement contracts
//! (issue #3286).
//!
//! `tc_inbound` admits a marked datagram to an enrolled pod only from an
//! authorized source. A NodeWaypoint UDP/DTLS reply is source-PINNED to the
//! address the client addressed, which on the Service path is the Service
//! ClusterIP — never a configured node IP. This channel is what authorizes
//! exactly that `(address, port)` pair AND what proves the authorization is
//! live, so the properties pinned here are all security properties, not
//! conveniences:
//!
//! * the claim line is a total, canonical, byte-exact encoding of the pair, so
//!   the published set really is a SET (two spellings of one address, or of one
//!   port, cannot become two authorizations);
//! * decoding is strict, and a bad line refuses the WHOLE generation rather than
//!   narrowing it;
//! * publication is ONE atomically renamed manifest, so a reader on a 250 ms
//!   poll can never observe a partially rewritten set;
//! * a generation is `(owner, sequence)` and an acknowledgement satisfies only
//!   the generation it names — an earlier set, a differently ordered rendering,
//!   or a predecessor process's leftover proof satisfies nothing;
//! * IPv4 and IPv6 are at parity, because a dual-stack waypoint that authorized
//!   one family would black-hole the other.

use std::net::IpAddr;

use ferrum_edge::capture::{
    MAX_NODE_WAYPOINT_UDP_STEER_DESTINATIONS, NodeWaypointUdpSteerDestination,
};
use ferrum_edge::proxy::node_waypoint_udp_reply_source::{
    NODE_WAYPOINT_UDP_REPLY_SOURCE_APPLIED_FILE, NODE_WAYPOINT_UDP_REPLY_SOURCE_DESIRED_FILE,
    NODE_WAYPOINT_UDP_REPLY_SOURCE_DIR, NodeWaypointUdpReplySourcePublisher,
    RegistryDirReplySourcePublisher, ReplySourceGeneration, clear_acknowledgement, decode_claim,
    encode_claim, read_acknowledgement, read_desired_generation, write_acknowledgement,
};

/// This proxy's own pod identity for the tests below. Lowercase hex and
/// interior dashes, exactly the shape `parse_relay_pod_uid` admits.
const RELAY_POD_UID: &str = "11111111-2222-3333-4444-555555555555";

/// Both UDP admission lanes must sit behind the NON-FORGEABLE sender proof
/// (issues #3956, #3957).
///
/// A source-shape contract rather than a datapath one, because the classifier
/// cannot be executed off a live kernel — the datapath proof is the
/// `node_waypoint.udp.listener_deny_forged_relay_mark` live assertion. What it
/// pins is the property both competing fixes got wrong in opposite directions:
///
/// * #3956 deleted the reply-source lane and kept `node source + mark`;
/// * #3957 deleted the node-source lane and kept `reply tuple + mark`.
///
/// Every attribute in both of those is chosen by whoever emits the packet, so
/// each fix left the other lane forgeable AND broke half the datapath. The
/// invariant is therefore not "one lane is gone" but "NEITHER lane is reachable
/// without `udp_relay_sender_authorized`, and BOTH lanes still exist".
#[test]
fn tc_inbound_udp_admission_requires_the_non_forgeable_relay_sender_proof() {
    let source = include_str!("../../../ebpf/ferrum-ebpf/src/tc_inbound.rs");
    let udp_arms = source
        .split("IPPROTO_UDP => {")
        .skip(1)
        .map(|arm| arm.split("_ => Ok(TC_ACT_OK)").next().unwrap_or(arm))
        .collect::<Vec<_>>();

    assert_eq!(udp_arms.len(), 2, "IPv4 and IPv6 UDP arms must be checked");
    for arm in udp_arms {
        // Both source lanes survive: the backend dial leaves from a node
        // address and the source-pinned reply leaves from a ClusterIP, so
        // deleting either one black-holes half the NodeWaypoint UDP datapath.
        assert!(
            arm.contains("enrolled_destination_authorized(ctx, source_is_node)"),
            "the relay's backend dial lane must remain, or direct-node UDP relay is black-holed"
        );
        assert!(
            arm.contains("udp_reply_source"),
            "the source-pinned reply lane must remain, or Service-path UDP relay is black-holed"
        );
        // ...but neither is reachable except inside the sender proof, and the
        // sender proof is the FIRST thing the arm evaluates.
        let sender_gate = arm
            .find("if udp_relay_sender_authorized(ctx) {")
            .expect("every UDP arm must gate admission on the relay sender proof");
        for forgeable in [
            "enrolled_destination_authorized(ctx, source_is_node)",
            "udp_reply_source",
        ] {
            assert!(
                arm.find(forgeable).expect("lane present") > sender_gate,
                "a forgeable source lane must never be evaluated outside the relay sender proof"
            );
        }
        // Hosted kernel-verifier contract: LLVM kept a UDP-port Result live
        // across `bpf_skb_cgroup_id` and the helper-zero path was rejected
        // (`R9 !read_ok`). No port value/result may be bound before the
        // sender proof returns; each later use parses independently.
        assert!(
            !arm.contains("let ports = udp_ports"),
            "a UDP-port Result must not be live across bpf_skb_cgroup_id"
        );
        let first_ports = arm
            .find("udp_ports4(")
            .or_else(|| arm.find("udp_ports6("))
            .expect("every UDP arm still parses ports for the reply-source lane and DNS carve-out");
        assert!(
            first_ports > sender_gate,
            "UDP ports must be parsed only after the cgroup helper has returned"
        );
        assert!(
            arm.contains("dns_response_allowed"),
            "the DNS carve-out for unauthenticated legitimate replies must remain"
        );
        assert!(
            arm.contains("drop_unsupported_enrolled_destination()"),
            "malformed UDP port parsing must fail closed rather than admit"
        );
    }

    // The sender proof itself reads a kernel-provided socket identity and fails
    // closed on the zero it returns when no socket is attached to the skb.
    let helper = source
        .split("fn udp_relay_sender_authorized(ctx: &TcContext) -> bool {")
        .nth(1)
        .expect("relay sender proof helper");
    let body = helper.split("\n}").next().expect("helper body");
    assert!(
        body.contains("bpf_skb_cgroup_id(ctx.skb.skb)"),
        "the sender proof must come from the kernel's socket cgroup, not from packet contents"
    );
    assert!(
        body.contains("if cgroup_id == 0 {") && body.contains("return false;"),
        "an unavailable socket identity must deny, never fall through"
    );
    assert!(
        body.contains("udp_reply_sources_enabled()"),
        "the sender proof must be fenced by the same shared generation gate as the source proof"
    );
    assert!(
        body.contains("FERRUM_UDP_RELAY_CGROUPS.get(&cgroup_id)"),
        "the sender proof must be an exact lookup of the node-agent-resolved relay cgroup set"
    );

    // TCP is untouched: it must not read any of the three UDP maps.
    let tcp_arms = source
        .split("IPPROTO_TCP => {")
        .skip(1)
        .map(|arm| arm.split("IPPROTO_UDP => {").next().unwrap_or(arm))
        .collect::<Vec<_>>();
    assert_eq!(tcp_arms.len(), 2, "IPv4 and IPv6 TCP arms must be checked");
    for arm in tcp_arms {
        assert!(
            !arm.contains("udp_relay_sender_authorized") && !arm.contains("udp_reply_source"),
            "the TCP arm must stay byte-for-byte unchanged by the UDP admission fix"
        );
    }
}

/// The live #3957 replay must carry the exact published `(ClusterIP, port)`
/// tuple. An ephemeral source port would be rejected by the old classifier too
/// and could therefore report a false security pass.
#[test]
fn forged_relay_live_probe_uses_the_exact_reply_source_port() {
    let live = include_str!("../../../tests/k8s/node_waypoint_ebpf_live/run.sh");
    let helper = live
        .split("udp_forged_relay_probe_from() {")
        .nth(1)
        .expect("forged relay helper")
        .split("\n}\n")
        .next()
        .expect("forged relay helper body");

    assert!(
        helper.contains("socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)"),
        "the occupied wildcard listener port requires a raw packet for an exact replay"
    );
    assert!(
        helper.contains("s.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, mark)"),
        "the probe must carry the public relay mark"
    );
    assert!(
        helper.contains("struct.pack(\"!HHHH\", port, port, udp_len, 0)"),
        "the forged UDP source port must equal the published listener port"
    );
    assert!(
        !helper.contains("s.bind((source, 0))"),
        "an ephemeral source port does not exercise the reply-source admission lane"
    );
    assert!(
        live.contains("add: [\"NET_ADMIN\", \"NET_RAW\"]"),
        "the live forger must be able to set the mark and emit the exact raw tuple"
    );
}

/// An ACTIVE generation — including the active-empty headless shape — carries
/// the publishing proxy's own pod identity. An INACTIVE withdrawal deliberately
/// does not.
///
/// The asymmetry is the whole withdrawal contract: inactive authorizes nothing,
/// so requiring an identity for it would make teardown fail exactly on the
/// deployments that most need it — and an unprovable withdrawal is what leaves
/// a predecessor's authorization live.
#[test]
fn a_generation_names_its_relay_identity_and_a_withdrawal_does_not() {
    let registry = tempfile::tempdir().expect("registry dir");
    let publisher = RegistryDirReplySourcePublisher::new(registry.path(), Some(RELAY_POD_UID));

    publisher
        .publish(&[source("10.96.0.10", 5300)], true)
        .expect("publication");
    let desired = read_desired_generation(registry.path())
        .expect("read desired generation")
        .expect("a generation is published");
    assert_eq!(
        desired.relay_pod_uid.as_deref(),
        Some(RELAY_POD_UID),
        "a non-empty generation must name the relay whose cgroup the node-agent resolves"
    );
    assert!(
        desired.generation.active(),
        "a non-empty source set implies active"
    );

    let active_empty = publisher.publish(&[], true).expect("active-empty");
    let headless = read_desired_generation(registry.path())
        .expect("read desired generation")
        .expect("an active-empty generation is published");
    assert!(
        headless.sources.is_empty()
            && headless.relay_pod_uid.as_deref() == Some(RELAY_POD_UID)
            && headless.generation.active()
            && active_empty.sequence() > desired.generation.sequence(),
        "a bound headless listener keeps the relay identity with zero ClusterIP sources"
    );

    publisher.publish(&[], false).expect("withdrawal");
    let withdrawn = read_desired_generation(registry.path())
        .expect("read desired generation")
        .expect("a withdrawal is published");
    assert!(
        withdrawn.sources.is_empty()
            && withdrawn.relay_pod_uid.is_none()
            && !withdrawn.generation.active(),
        "a withdrawal authorizes nothing and therefore names no relay"
    );
}

/// A proxy that cannot name its own pod refuses to authorize anything, but can
/// still prove a withdrawal.
///
/// Fail-closed in the direction that matters: without a relay identity the
/// node-agent cannot resolve the relay cgroup, so admitting the source tuples
/// anyway would be exactly the #3957 replay — a listener-wide `(address, port)`
/// claim with no non-forgeable proof beside it.
#[test]
fn a_proxy_without_a_relay_identity_authorizes_nothing_but_still_withdraws() {
    let registry = tempfile::tempdir().expect("registry dir");
    let publisher = RegistryDirReplySourcePublisher::new(registry.path(), None);

    assert!(
        publisher
            .publish(&[source("10.96.0.10", 5300)], true)
            .is_err(),
        "a non-empty set with no relay identity must be refused, not published unproven"
    );
    assert!(
        publisher.publish(&[], true).is_err(),
        "an active-empty generation with no relay identity must be refused: that is the \
         headless listener whose sender proof could not be resolved"
    );
    assert_eq!(
        read_desired_generation(registry.path()).expect("read desired generation"),
        None,
        "a refused publication must leave no manifest behind"
    );

    let generation = publisher
        .publish(&[], false)
        .expect("withdrawal must stay provable");
    write_acknowledgement(registry.path(), &generation).expect("node-agent proof");
    assert_eq!(
        publisher.acknowledged().expect("bound proof"),
        Some(generation),
        "an inactive generation must still be acknowledgeable so teardown can be proven"
    );
}

/// An unusable relay identity is normalized to "no identity" at construction
/// rather than written to the channel.
///
/// The publisher is the one place that knows the value came from this process's
/// own environment, so a value that could never be a path-safe pod UID becomes
/// a refusal to authorize here — never a manifest the node-agent has to refuse
/// later, and never a token that reaches a filesystem path.
#[test]
fn an_unusable_relay_identity_is_refused_at_the_publisher() {
    for uid in ["", "   ", "../escape", "a/b", "UPPER", "-lead", "trail-"] {
        let registry = tempfile::tempdir().expect("registry dir");
        let publisher = RegistryDirReplySourcePublisher::new(registry.path(), Some(uid));
        assert!(
            publisher
                .publish(&[source("10.96.0.10", 5300)], true)
                .is_err(),
            "an unusable relay identity ({uid:?}) must authorize nothing"
        );
    }
}

/// A SET but unusable relay identity is distinguishable from an ABSENT one
/// (issue #4021, follow-up 2).
///
/// Both normalize to `None` and both refuse every ACTIVE publication, but only
/// one is an operator misconfiguration — and the startup `warn!` in
/// `arm_mesh_runtime_startup` fires only when the env var is ABSENT. Without
/// this distinction a mistyped `FERRUM_MESH_NODE_WAYPOINT_RELAY_POD_UID`
/// leaves the operator with nothing but the steering reconcile's generic
/// "active generation could not be published" while the UDP relay is
/// permanently dark. The constructor emits its own `warn!` for this case; the
/// flag is the observable half of that decision.
#[test]
fn a_set_but_rejected_relay_identity_is_distinguishable_from_an_absent_one() {
    let registry = tempfile::tempdir().expect("registry dir");

    assert!(
        !RegistryDirReplySourcePublisher::new(registry.path(), None).relay_pod_uid_rejected(),
        "an absent identity is not a rejected one; the startup warning already covers it"
    );
    assert!(
        !RegistryDirReplySourcePublisher::new(registry.path(), Some(RELAY_POD_UID))
            .relay_pod_uid_rejected(),
        "an accepted identity must not report a rejection"
    );

    for uid in ["", "   ", "../escape", "a/b", "UPPER", "-lead", "trail-"] {
        let publisher = RegistryDirReplySourcePublisher::new(registry.path(), Some(uid));
        assert!(
            publisher.relay_pod_uid_rejected(),
            "a set-but-unusable relay identity ({uid:?}) must be reported as REJECTED, not \
             silently indistinguishable from unset"
        );
    }

    // A rejection must still leave the publication behavior of "no identity"
    // exactly as it was: refuse ACTIVE, keep INACTIVE withdrawal provable.
    let publisher = RegistryDirReplySourcePublisher::new(registry.path(), Some("UPPER"));
    assert!(publisher.publish(&[], true).is_err());
    publisher
        .publish(&[], false)
        .expect("withdrawal must stay provable with a rejected identity");
}

fn source(ip: &str, port: u16) -> NodeWaypointUdpSteerDestination {
    NodeWaypointUdpSteerDestination {
        ip: ip.parse::<IpAddr>().expect("reply source address"),
        port,
    }
}

fn channel_dir(registry: &std::path::Path) -> std::path::PathBuf {
    registry.join(NODE_WAYPOINT_UDP_REPLY_SOURCE_DIR)
}

fn desired_path(registry: &std::path::Path) -> std::path::PathBuf {
    channel_dir(registry).join(NODE_WAYPOINT_UDP_REPLY_SOURCE_DESIRED_FILE)
}

/// Entries the channel directory holds, so a test can prove the whole set rides
/// ONE file rather than one file per authorization.
fn channel_entries(registry: &std::path::Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(channel_dir(registry)) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .map(|entry| {
            entry
                .expect("channel entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    names
}

fn published_sources(registry: &std::path::Path) -> Vec<NodeWaypointUdpSteerDestination> {
    read_desired_generation(registry)
        .expect("read desired generation")
        .expect("a generation is published")
        .sources
}

fn overwrite_desired(registry: &std::path::Path, body: &str) {
    std::fs::create_dir_all(channel_dir(registry)).expect("channel dir");
    std::fs::write(desired_path(registry), body.as_bytes()).expect("overwrite desired");
}

// ── Claim encoding ─────────────────────────────────────────────────────────

/// The round trip is the whole ABI between the proxy and the node-agent: what
/// the proxy authorizes must be exactly what the node-agent writes into the BPF
/// map. IPv4 and IPv6 are asserted together so a family cannot be added to one
/// side only.
#[test]
fn a_claim_round_trips_exactly_on_both_families() {
    for reply_source in [
        source("10.96.0.10", 5300),
        source("10.96.0.10", 65535),
        source("0.0.0.0", 1),
        source("fd00:10:96::a", 5300),
        source("::1", 8443),
        source("2001:db8::1", 1),
    ] {
        let name = encode_claim(&reply_source);
        assert_eq!(
            decode_claim(&name),
            Some(reply_source),
            "claim {name} must decode back to the exact source it was written for"
        );
    }
}

/// An IPv6 address has many textual spellings but one byte sequence. If the
/// claim were textual, `::1` and its expanded form would become two lines and
/// therefore two authorizations for one source — and a withdrawal of one
/// spelling would leave the other live.
#[test]
fn ipv6_spellings_of_one_address_produce_one_claim() {
    let compact = source("::1", 4433);
    let expanded = source("0:0:0:0:0:0:0:1", 4433);
    assert_eq!(compact, expanded, "both spellings parse to one address");
    assert_eq!(encode_claim(&compact), encode_claim(&expanded));
}

/// The port is part of the authorization, so it must be part of the identity.
#[test]
fn one_address_on_two_ports_is_two_distinct_claims() {
    let a = encode_claim(&source("10.96.0.10", 5300));
    let b = encode_claim(&source("10.96.0.10", 5301));
    assert_ne!(a, b);
}

/// Decoding is a gate, not a parser convenience: anything that is not exactly
/// the shape `encode_claim` writes must authorize NOTHING. Each case here is a
/// line that a naive decoder would accept while describing either a different
/// source or a second name for the same one.
#[test]
fn a_malformed_claim_authorizes_nothing() {
    for name in [
        // Not a claim at all.
        "",
        ".ready",
        "pod-uid-1",
        // Textual address forms — one address would gain several names.
        "4-10.96.0.10-5300",
        "6-::1-5300",
        // Uppercase hex: a second name for one address.
        "4-0A60000A-5300",
        // Wrong address width for the declared family.
        "4-0a60000a0a-5300",
        "4-0a6000-5300",
        "6-0a60000a-5300",
        // Unknown family tag.
        "5-0a60000a-5300",
        "-0a60000a-5300",
        // Extra / missing separators.
        "4-0a60000a-5300-extra",
        "4-0a60000a",
        "40a60000a5300",
        // Non-canonical or invalid ports.
        "4-0a60000a-05300",
        "4-0a60000a-+5300",
        "4-0a60000a-65536",
        "4-0a60000a-",
        "4-0a60000a-abc",
        // Port 0 is never bound by a listener, so a claim for it is junk.
        "4-0a60000a-0",
        "6-fd00001000960000000000000000000a-0",
    ] {
        assert_eq!(
            decode_claim(name),
            None,
            "{name:?} must not authorize a reply source"
        );
    }
}

// ── Atomic whole-set publication ───────────────────────────────────────────

/// The whole authorized set rides ONE file that is renamed into place. The
/// node-agent polls this channel every 250 ms, so a directory of one file per
/// authorization would regularly be read mid-rewrite as a partial — and
/// therefore silently narrowed — set.
#[test]
fn the_whole_set_is_published_as_one_file() {
    let registry = tempfile::tempdir().expect("registry dir");
    let publisher = RegistryDirReplySourcePublisher::new(registry.path(), Some(RELAY_POD_UID));
    publisher
        .publish(
            &[
                source("10.96.0.10", 5300),
                source("10.96.0.11", 5301),
                source("fd00:10:96::a", 5300),
            ],
            true,
        )
        .expect("publication");

    assert_eq!(
        channel_entries(registry.path()),
        vec![NODE_WAYPOINT_UDP_REPLY_SOURCE_DESIRED_FILE.to_string()],
        "three authorizations must ride one atomically replaced manifest, and the staging \
         temporary must not survive the rename"
    );
    assert_eq!(
        published_sources(registry.path()),
        vec![
            source("10.96.0.10", 5300),
            source("10.96.0.11", 5301),
            source("fd00:10:96::a", 5300),
        ],
        "the reader sees the whole set, ascending and complete"
    );
}

/// The node-agent reads this channel as a set snapshot, so publication must
/// converge it exactly: a source dropped from the serving generation loses its
/// authorization in the same pass that authorizes the new one.
#[test]
fn publishing_replaces_the_whole_set() {
    let registry = tempfile::tempdir().expect("registry dir");
    let publisher = RegistryDirReplySourcePublisher::new(registry.path(), Some(RELAY_POD_UID));

    publisher
        .publish(
            &[source("10.96.0.10", 5300), source("10.96.0.11", 5301)],
            true,
        )
        .expect("first publication");
    assert_eq!(
        published_sources(registry.path()),
        vec![source("10.96.0.10", 5300), source("10.96.0.11", 5301)]
    );

    // The second generation drops .10 and adds .12. The dropped one must be
    // gone, not merely shadowed.
    publisher
        .publish(
            &[source("10.96.0.11", 5301), source("10.96.0.12", 5302)],
            true,
        )
        .expect("second publication");
    assert_eq!(
        published_sources(registry.path()),
        vec![source("10.96.0.11", 5301), source("10.96.0.12", 5302)],
        "a withdrawn reply source must lose its authorization in the same pass"
    );
}

/// An INACTIVE publication is a full retraction, and it is the path the steering
/// teardown, shutdown, and `Drop` all take. It must be a POSITIVE statement —
/// an inactive generation the node-agent can acknowledge — not an absent channel.
#[test]
fn an_empty_publication_withdraws_everything() {
    let registry = tempfile::tempdir().expect("registry dir");
    let publisher = RegistryDirReplySourcePublisher::new(registry.path(), Some(RELAY_POD_UID));

    publisher
        .publish(
            &[source("10.96.0.10", 5300), source("fd00:10:96::a", 5300)],
            true,
        )
        .expect("publication");
    assert_eq!(published_sources(registry.path()).len(), 2);

    let retraction = publisher.publish(&[], false).expect("retraction");
    let desired = read_desired_generation(registry.path())
        .expect("read desired generation")
        .expect("the empty generation is still a published generation");
    assert!(
        desired.sources.is_empty(),
        "a retraction must leave no authorized reply source behind"
    );
    assert_eq!(desired.generation, retraction);
}

/// The published set is canonical regardless of what the caller passed, so one
/// set has exactly one rendering — which is what makes an acknowledgement of a
/// generation an acknowledgement of a SET.
#[test]
fn publication_canonicalizes_order_and_duplicates() {
    let registry = tempfile::tempdir().expect("registry dir");
    let publisher = RegistryDirReplySourcePublisher::new(registry.path(), Some(RELAY_POD_UID));

    let scrambled = publisher
        .publish(
            &[
                source("fd00:10:96::a", 5300),
                source("10.96.0.11", 5301),
                source("10.96.0.10", 5300),
                source("10.96.0.11", 5301),
            ],
            true,
        )
        .expect("scrambled publication");
    assert_eq!(
        published_sources(registry.path()),
        vec![
            source("10.96.0.10", 5300),
            source("10.96.0.11", 5301),
            source("fd00:10:96::a", 5300),
        ]
    );

    // The same SET in a different order is the same generation, so an
    // acknowledgement already given for it still holds.
    let reordered = publisher
        .publish(
            &[
                source("10.96.0.11", 5301),
                source("fd00:10:96::a", 5300),
                source("10.96.0.10", 5300),
            ],
            true,
        )
        .expect("reordered publication");
    // A reordering of one set must not manufacture a new generation.
    assert_eq!(scrambled, reordered);
}

/// Republishing the same set must be idempotent AND keep its generation — the
/// reconcile republishes on every pass while it waits for the node-agent, and a
/// sequence that walked forward each pass could never be caught.
#[test]
fn republishing_the_same_set_keeps_its_generation() {
    let registry = tempfile::tempdir().expect("registry dir");
    let publisher = RegistryDirReplySourcePublisher::new(registry.path(), Some(RELAY_POD_UID));
    let sources = [source("10.96.0.10", 5300), source("fd00:10:96::a", 5300)];

    let first = publisher.publish(&sources, true).expect("first");
    let bytes = std::fs::read(desired_path(registry.path())).expect("manifest");
    let second = publisher.publish(&sources, true).expect("second");

    assert_eq!(first, second);
    assert_eq!(
        std::fs::read(desired_path(registry.path())).expect("manifest"),
        bytes,
        "an unchanged republication must be byte-identical"
    );
}

/// A CHANGED set must be a new generation, or an acknowledgement of the old set
/// would be read as proof about the new one.
#[test]
fn a_changed_set_advances_the_generation() {
    let registry = tempfile::tempdir().expect("registry dir");
    let publisher = RegistryDirReplySourcePublisher::new(registry.path(), Some(RELAY_POD_UID));

    let first = publisher
        .publish(&[source("10.96.0.10", 5300)], true)
        .expect("first");
    let second = publisher
        .publish(
            &[source("10.96.0.10", 5300), source("10.96.0.11", 5301)],
            true,
        )
        .expect("second");
    let back = publisher
        .publish(&[source("10.96.0.10", 5300)], true)
        .expect("back to the first set");

    assert_eq!(first.owner(), second.owner());
    assert!(second.sequence() > first.sequence());
    assert!(
        back.sequence() > second.sequence(),
        "returning to an earlier SET must not return to its generation: an \
         acknowledgement of that older generation described a map state two \
         changes ago"
    );
}

/// The bound is refused as a whole rather than truncated: authorizing an
/// arbitrary subset would silently black-hole the rest while reporting success.
#[test]
fn an_over_bound_publication_is_refused_entirely() {
    let registry = tempfile::tempdir().expect("registry dir");
    let publisher = RegistryDirReplySourcePublisher::new(registry.path(), Some(RELAY_POD_UID));
    let baseline = publisher
        .publish(&[source("10.96.0.10", 5300)], true)
        .expect("baseline publication");

    let over_bound = MAX_NODE_WAYPOINT_UDP_STEER_DESTINATIONS + 1;
    let too_many: Vec<NodeWaypointUdpSteerDestination> = (0..over_bound)
        .map(|index| source("10.96.0.10", 5300 + index as u16))
        .collect();
    assert!(
        publisher.publish(&too_many, true).is_err(),
        "a set larger than the bound must be refused, not truncated"
    );

    let desired = read_desired_generation(registry.path())
        .expect("read desired generation")
        .expect("the baseline generation is still published");
    assert_eq!(desired.generation, baseline);
    assert_eq!(
        desired.sources,
        vec![source("10.96.0.10", 5300)],
        "a refused publication must not have partially applied"
    );
}

// ── The node-agent's read side ─────────────────────────────────────────────

/// The node-agent starts before the proxy has ever published. An absent channel
/// means "nothing is claimed", which is the correct fail-closed reading — not an
/// error that would make the agent retain a previous set.
#[test]
fn an_absent_channel_reads_as_nothing_published() {
    let registry = tempfile::tempdir().expect("registry dir");
    assert!(
        read_desired_generation(registry.path())
            .expect("read desired generation")
            .is_none()
    );
    assert!(
        read_acknowledgement(registry.path())
            .expect("read acknowledgement")
            .is_none()
    );
}

/// Every corruption refuses the WHOLE generation. A parser that salvaged a
/// prefix would hand the node-agent a narrowed set to acknowledge as complete,
/// which is precisely the steered-but-unanswerable failure this channel closes.
#[test]
fn a_malformed_generation_is_refused_whole() {
    let registry = tempfile::tempdir().expect("registry dir");
    let publisher = RegistryDirReplySourcePublisher::new(registry.path(), Some(RELAY_POD_UID));
    let generation = publisher
        .publish(&[source("10.96.0.10", 5300)], true)
        .expect("publication");
    let owner = generation.owner().to_string();

    let a = encode_claim(&source("10.96.0.10", 5300));
    let b = encode_claim(&source("10.96.0.11", 5301));
    let uid = RELAY_POD_UID;
    let bodies = [
        // Wrong leader / version. `v1` named no relay identity; `v2` equated
        // empty sources with withdrawal. Honouring either would apply the
        // wrong half of the classifier's conjunction.
        format!("ferrum-udp-reply-src-ack v3 {owner} 1 active 1 {uid}\n{a}\n"),
        format!("ferrum-udp-reply-src v1 {owner} 1 1 {uid}\n{a}\n"),
        format!("ferrum-udp-reply-src v1 {owner} 1 1\n{a}\n"),
        format!("ferrum-udp-reply-src v2 {owner} 1 1 {uid}\n{a}\n"),
        format!("{owner} 1 active 1 {uid}\n{a}\n"),
        // Owner is not exactly sixteen lowercase hex digits.
        format!(
            "ferrum-udp-reply-src v3 {} 1 active 1 {uid}\n{a}\n",
            &owner[..15]
        ),
        format!(
            "ferrum-udp-reply-src v3 {}Z 1 active 1 {uid}\n{a}\n",
            &owner[..15]
        ),
        format!("ferrum-udp-reply-src v3 {}0 1 active 1 {uid}\n{a}\n", owner),
        // Non-canonical / absent / zero sequence and count.
        format!("ferrum-udp-reply-src v3 {owner} 01 active 1 {uid}\n{a}\n"),
        format!("ferrum-udp-reply-src v3 {owner} 0 active 1 {uid}\n{a}\n"),
        format!("ferrum-udp-reply-src v3 {owner} 1 active 01 {uid}\n{a}\n"),
        format!("ferrum-udp-reply-src v3 {owner} 1 {uid}\n{a}\n"),
        // Malformed / ambiguous serving-state tokens.
        format!("ferrum-udp-reply-src v3 {owner} 1 Active 1 {uid}\n{a}\n"),
        format!("ferrum-udp-reply-src v3 {owner} 1 ACTIVE 1 {uid}\n{a}\n"),
        format!("ferrum-udp-reply-src v3 {owner} 1 on 1 {uid}\n{a}\n"),
        format!("ferrum-udp-reply-src v3 {owner} 1 1 1 {uid}\n{a}\n"),
        format!("ferrum-udp-reply-src v3 {owner} 1 serving 1 {uid}\n{a}\n"),
        format!("ferrum-udp-reply-src v3 {owner} 1  1 {uid}\n{a}\n"),
        // Active-without-identity, inactive-with-sources, inactive-with-identity.
        format!("ferrum-udp-reply-src v3 {owner} 1 active 1 -\n{a}\n"),
        format!("ferrum-udp-reply-src v3 {owner} 1 active 0 -\n"),
        format!("ferrum-udp-reply-src v3 {owner} 1 inactive 1 {uid}\n{a}\n"),
        format!("ferrum-udp-reply-src v3 {owner} 1 inactive 1 -\n{a}\n"),
        format!("ferrum-udp-reply-src v3 {owner} 1 inactive 0 {uid}\n"),
        // A relay identity that is not a path-safe pod UID token.
        format!("ferrum-udp-reply-src v3 {owner} 1 active 1 ../escape\n{a}\n"),
        format!("ferrum-udp-reply-src v3 {owner} 1 active 1 a/b\n{a}\n"),
        format!("ferrum-udp-reply-src v3 {owner} 1 active 1 UPPER\n{a}\n"),
        format!("ferrum-udp-reply-src v3 {owner} 1 active 1 -lead\n{a}\n"),
        format!("ferrum-udp-reply-src v3 {owner} 1 active 1 trail-\n{a}\n"),
        format!(
            "ferrum-udp-reply-src v3 {owner} 1 active 1 {}\n{a}\n",
            "a".repeat(65)
        ),
        // Count disagrees with the body — the truncation case a per-file
        // directory could not even detect.
        format!("ferrum-udp-reply-src v3 {owner} 1 active 2 {uid}\n{a}\n"),
        format!("ferrum-udp-reply-src v3 {owner} 1 active 1 {uid}\n{a}\n{b}\n"),
        // Over the destination bound.
        format!(
            "ferrum-udp-reply-src v3 {owner} 1 active {} {uid}\n{a}\n",
            MAX_NODE_WAYPOINT_UDP_STEER_DESTINATIONS + 1
        ),
        // Duplicate and out-of-order claims: one set must have one rendering.
        format!("ferrum-udp-reply-src v3 {owner} 1 active 2 {uid}\n{a}\n{a}\n"),
        format!("ferrum-udp-reply-src v3 {owner} 1 active 2 {uid}\n{b}\n{a}\n"),
        // A claim line that is not exactly a claim refuses everything, rather
        // than being skipped so the rest can be acknowledged as complete.
        format!("ferrum-udp-reply-src v3 {owner} 1 active 2 {uid}\n{a}\n4-10.96.0.11-5301\n"),
        // Framing: no trailing newline, trailing junk, extra header token.
        format!("ferrum-udp-reply-src v3 {owner} 1 active 1 {uid}\n{a}"),
        format!("ferrum-udp-reply-src v3 {owner} 1 active 1 {uid}\n{a}\n\n"),
        format!("ferrum-udp-reply-src v3 {owner} 1 active 1 {uid} extra\n{a}\n"),
        format!("ferrum-udp-reply-src  v3 {owner} 1 active 1 {uid}\n{a}\n"),
        String::new(),
        "\n".to_string(),
    ];

    for body in bodies {
        overwrite_desired(registry.path(), &body);
        assert!(
            read_desired_generation(registry.path()).is_err(),
            "a malformed generation must be refused whole, never partially parsed: {body:?}"
        );
    }
}

/// A file larger than the bound is refused before it is parsed. The writer is
/// Ferrum, so an oversized channel file is a fault or a plant — never a bigger
/// legitimate set.
#[test]
fn an_over_bound_generation_file_is_refused_before_parsing() {
    let registry = tempfile::tempdir().expect("registry dir");
    let publisher = RegistryDirReplySourcePublisher::new(registry.path(), Some(RELAY_POD_UID));
    let generation = publisher
        .publish(&[source("10.96.0.10", 5300)], true)
        .expect("publication");

    let mut body = format!(
        "ferrum-udp-reply-src v3 {} 1 active 1 {RELAY_POD_UID}\n{}\n",
        generation.owner(),
        encode_claim(&source("10.96.0.10", 5300))
    );
    // Well past `MAX_HEADER_BYTES + 41 * 128`, and still well-formed up front.
    body.push_str(&"#".repeat(64 * 1024));
    overwrite_desired(registry.path(), &body);

    assert!(
        read_desired_generation(registry.path()).is_err(),
        "an over-bound channel file authorizes nothing"
    );
}

/// A non-regular entry planted in the channel would otherwise park the reader
/// (a FIFO blocks on open/read). It is refused before any byte is read.
#[cfg(unix)]
#[test]
fn a_non_regular_channel_entry_is_refused() {
    let registry = tempfile::tempdir().expect("registry dir");
    std::fs::create_dir_all(desired_path(registry.path())).expect("directory in place of a file");
    assert!(
        read_desired_generation(registry.path()).is_err(),
        "only an ordinary file may carry a generation"
    );
}

// ── Acknowledgement ────────────────────────────────────────────────────────

/// The acknowledgement is the proof the steering reconcile gates on: it must
/// name exactly the generation whose complete set is live.
#[test]
fn an_acknowledgement_satisfies_only_the_generation_it_names() {
    let registry = tempfile::tempdir().expect("registry dir");
    let publisher = RegistryDirReplySourcePublisher::new(registry.path(), Some(RELAY_POD_UID));

    let first = publisher
        .publish(&[source("10.96.0.10", 5300)], true)
        .expect("first");
    // Publishing is a request; nothing is acknowledged until the node-agent
    // has actually applied it to both map families.
    let before = publisher.acknowledged().expect("read acknowledgement");
    assert_eq!(before, None);

    write_acknowledgement(registry.path(), &first).expect("acknowledge the first generation");
    let acknowledged = publisher.acknowledged().expect("read acknowledgement");
    assert_eq!(acknowledged, Some(first.clone()));

    // The serving set changes. The acknowledgement on disk still describes the
    // OLD one, so it must not satisfy the new generation.
    let second = publisher
        .publish(
            &[source("10.96.0.10", 5300), source("10.96.0.11", 5301)],
            true,
        )
        .expect("second");
    assert_ne!(first, second);
    let stale = publisher.acknowledged().expect("read acknowledgement");
    assert_eq!(
        stale, None,
        "a stale acknowledgement must prove nothing about the publisher's current generation"
    );
}

/// A crashed predecessor's acknowledgement carries a different owner. The
/// successor republishes from sequence 1, so without the owner its very first
/// generation would be "already acknowledged" by a proof about a set the node
/// may no longer hold.
#[test]
fn a_predecessor_acknowledgement_never_satisfies_a_successor() {
    let registry = tempfile::tempdir().expect("registry dir");

    let predecessor = RegistryDirReplySourcePublisher::new(registry.path(), Some(RELAY_POD_UID));
    let old = predecessor
        .publish(&[source("10.96.0.10", 5300)], true)
        .expect("predecessor publication");
    write_acknowledgement(registry.path(), &old).expect("predecessor acknowledgement");

    // A restart: a new process, a new owner, and the same desired set.
    let successor = RegistryDirReplySourcePublisher::new(registry.path(), Some(RELAY_POD_UID));
    let new = successor
        .publish(&[source("10.96.0.10", 5300)], true)
        .expect("successor publication");

    // Each process publishes under its own owner token, and the successor's
    // sequence restarts — so ONLY the owner distinguishes the two generations.
    assert_ne!(new.owner(), old.owner());
    assert_eq!(new.sequence(), old.sequence());

    // Model the predecessor finishing a map apply late, after the successor's
    // desired manifest is already current. Neither process may treat that proof
    // as covering its current publication.
    write_acknowledgement(registry.path(), &old).expect("late predecessor acknowledgement");
    assert_eq!(successor.acknowledged().expect("successor proof"), None);
    assert_eq!(predecessor.acknowledged().expect("predecessor proof"), None);
}

/// `(owner, sequence)` names one exact canonical set. If the manifest is
/// corrupted while preserving those two fields, the raw acknowledgement still
/// parses but the publisher must refuse it because the content no longer
/// matches the set this process published.
#[test]
fn an_acknowledgement_is_bound_to_the_exact_manifest_content() {
    let registry = tempfile::tempdir().expect("registry dir");
    let publisher = RegistryDirReplySourcePublisher::new(registry.path(), Some(RELAY_POD_UID));
    let generation = publisher
        .publish(&[source("10.96.0.10", 5300)], true)
        .expect("publication");

    overwrite_desired(
        registry.path(),
        &format!(
            "ferrum-udp-reply-src v3 {} {} active 1 {RELAY_POD_UID}\n{}\n",
            generation.owner(),
            generation.sequence(),
            encode_claim(&source("10.96.0.11", 5301))
        ),
    );
    write_acknowledgement(registry.path(), &generation).expect("raw acknowledgement");

    assert_eq!(
        read_acknowledgement(registry.path()).expect("raw proof"),
        Some(generation),
        "the acknowledgement file itself is deliberately only a generation identity"
    );
    assert_eq!(
        publisher.acknowledged().expect("bound proof"),
        None,
        "the serving publisher must bind that identity back to its exact canonical set"
    );
}

/// A torn or foreign acknowledgement acknowledges NOTHING. That is the pending
/// answer — the datapath simply stays unsteered — rather than a fault.
#[test]
fn a_malformed_acknowledgement_acknowledges_nothing() {
    let registry = tempfile::tempdir().expect("registry dir");
    let publisher = RegistryDirReplySourcePublisher::new(registry.path(), Some(RELAY_POD_UID));
    let generation = publisher
        .publish(&[source("10.96.0.10", 5300)], true)
        .expect("publication");
    let owner = generation.owner().to_string();
    let applied = channel_dir(registry.path()).join(NODE_WAYPOINT_UDP_REPLY_SOURCE_APPLIED_FILE);

    for body in [
        // A DESIRED manifest is not an acknowledgement.
        format!("ferrum-udp-reply-src v3 {owner} 1 inactive 0 -\n"),
        // Neither is a predecessor's `v1`/`v2` proof, nor a future `v4` one,
        // nor a `v3` proof missing the serving-state token.
        format!("ferrum-udp-reply-src-ack v1 {owner} 1\n"),
        format!("ferrum-udp-reply-src-ack v2 {owner} 1\n"),
        format!("ferrum-udp-reply-src-ack v4 {owner} 1 active\n"),
        format!("ferrum-udp-reply-src-ack v3 {owner} 1\n"),
        format!("ferrum-udp-reply-src-ack v3 {owner} 1 ACTIVE\n"),
        format!("ferrum-udp-reply-src-ack v3 {owner} 0 active\n"),
        format!("ferrum-udp-reply-src-ack v3 {owner} 01 active\n"),
        format!("ferrum-udp-reply-src-ack v3 {} 1 active\n", &owner[..15]),
        format!("ferrum-udp-reply-src-ack v3 {owner} 1 active extra\n"),
        format!("ferrum-udp-reply-src-ack v3 {owner} 1 active"),
        format!("ferrum-udp-reply-src-ack v3 {owner} 1 active\n\n"),
        String::new(),
    ] {
        std::fs::write(&applied, body.as_bytes()).expect("write acknowledgement");
        assert_eq!(
            publisher.acknowledged().expect("read acknowledgement"),
            None,
            "a malformed acknowledgement must prove nothing: {body:?}"
        );
    }

    // And the well-formed one still works, so the refusals above are the
    // parser being strict rather than the reader being broken.
    write_acknowledgement(registry.path(), &generation).expect("acknowledge");
    let acknowledged = publisher.acknowledged().expect("read acknowledgement");
    assert_eq!(acknowledged, Some(generation));
}

/// Retraction is what makes a refusal fail closed: the node-agent removes the
/// acknowledgement BEFORE it touches a map, so a crash mid-apply leaves no proof
/// behind.
#[test]
fn clearing_the_acknowledgement_leaves_nothing_proven() {
    let registry = tempfile::tempdir().expect("registry dir");
    let publisher = RegistryDirReplySourcePublisher::new(registry.path(), Some(RELAY_POD_UID));
    let generation = publisher
        .publish(&[source("10.96.0.10", 5300)], true)
        .expect("publication");
    write_acknowledgement(registry.path(), &generation).expect("acknowledge");
    assert!(
        read_acknowledgement(registry.path())
            .expect("read acknowledgement")
            .is_some()
    );

    clear_acknowledgement(registry.path()).expect("clear");
    let cleared = publisher.acknowledged().expect("read acknowledgement");
    assert_eq!(cleared, None);
    // Idempotent: an absent acknowledgement is exactly the intended state.
    clear_acknowledgement(registry.path()).expect("clear again");
    clear_acknowledgement(tempfile::tempdir().expect("empty registry").path())
        .expect("clear an untouched registry");
}

/// Both families survive the full proxy→node-agent round trip together, and the
/// acknowledgement covers them as one generation. A channel that could prove one
/// family live while the other was not would black-hole the other.
#[test]
fn both_families_ride_one_acknowledged_generation() {
    let registry = tempfile::tempdir().expect("registry dir");
    let publisher = RegistryDirReplySourcePublisher::new(registry.path(), Some(RELAY_POD_UID));
    let v4 = source("10.96.0.10", 5300);
    let v6 = source("fd00:10:96::a", 5300);
    let generation = publisher.publish(&[v4, v6], true).expect("publication");

    let desired = read_desired_generation(registry.path())
        .expect("read desired generation")
        .expect("a generation is published");
    assert_eq!(desired.sources, vec![v4, v6]);
    assert_eq!(desired.generation, generation);

    write_acknowledgement(registry.path(), &desired.generation).expect("acknowledge");
    assert_eq!(
        publisher.acknowledged().expect("read acknowledgement"),
        Some(generation),
        "one acknowledgement covers the whole dual-stack set, never one family"
    );
}

/// The acknowledgement is bound to the generation VALUE, so it survives being
/// read back through a fresh handle — the node-agent and the proxy are separate
/// processes and neither can rely on the other's memory.
#[test]
fn an_acknowledgement_round_trips_across_processes() {
    let registry = tempfile::tempdir().expect("registry dir");
    let publisher = RegistryDirReplySourcePublisher::new(registry.path(), Some(RELAY_POD_UID));
    let generation = publisher
        .publish(&[source("10.96.0.10", 5300)], true)
        .expect("publication");

    // The node-agent's side: read the desired generation, then acknowledge the
    // value it read rather than one it was handed in memory.
    let observed: ReplySourceGeneration = read_desired_generation(registry.path())
        .expect("read desired generation")
        .expect("a generation is published")
        .generation;
    write_acknowledgement(registry.path(), &observed).expect("acknowledge");

    let acknowledged = publisher.acknowledged().expect("read acknowledgement");
    assert_eq!(acknowledged, Some(generation));
}

/// A bound headless/VIP-less listener publishes ACTIVE with zero sources and a
/// relay identity. That is not a withdrawal: the node-agent must still be able
/// to prove the sender set live so the direct-node lane stays usable.
#[test]
fn an_active_empty_generation_names_the_relay_and_is_acknowledgeable() {
    let registry = tempfile::tempdir().expect("registry dir");
    let publisher = RegistryDirReplySourcePublisher::new(registry.path(), Some(RELAY_POD_UID));

    let generation = publisher.publish(&[], true).expect("active-empty");
    assert!(generation.active());
    let desired = read_desired_generation(registry.path())
        .expect("read desired generation")
        .expect("active-empty is a published generation");
    assert!(desired.sources.is_empty());
    assert_eq!(desired.relay_pod_uid.as_deref(), Some(RELAY_POD_UID));
    assert!(desired.generation.active());
    assert_eq!(desired.generation, generation);

    write_acknowledgement(registry.path(), &generation).expect("node-agent proof");
    assert_eq!(
        publisher.acknowledged().expect("bound proof"),
        Some(generation),
        "an active-empty generation must be acknowledgeable so the sender proof can settle"
    );
}

/// Active-empty and inactive-empty are distinct identities. A stale
/// acknowledgement of one can never satisfy the other, even though both have
/// zero ClusterIP sources.
#[test]
fn an_active_empty_to_inactive_empty_transition_advances_the_generation() {
    let registry = tempfile::tempdir().expect("registry dir");
    let publisher = RegistryDirReplySourcePublisher::new(registry.path(), Some(RELAY_POD_UID));

    let active = publisher.publish(&[], true).expect("active-empty");
    write_acknowledgement(registry.path(), &active).expect("ack active-empty");
    assert_eq!(
        publisher.acknowledged().expect("proof"),
        Some(active.clone())
    );

    let inactive = publisher.publish(&[], false).expect("withdrawal");
    assert_eq!(active.owner(), inactive.owner());
    assert!(
        inactive.sequence() > active.sequence(),
        "active-empty ↔ inactive-empty must mint a new sequence"
    );
    assert!(active.active() && !inactive.active());
    assert_eq!(
        publisher.acknowledged().expect("stale active ack"),
        None,
        "a stale active-empty acknowledgement must not satisfy the inactive withdrawal"
    );

    write_acknowledgement(registry.path(), &inactive).expect("ack inactive");
    assert_eq!(
        publisher.acknowledged().expect("inactive proof"),
        Some(inactive.clone())
    );

    let active_again = publisher.publish(&[], true).expect("re-serve");
    assert!(active_again.sequence() > inactive.sequence());
    assert_eq!(
        publisher.acknowledged().expect("stale inactive ack"),
        None,
        "a stale inactive acknowledgement must not satisfy a later active-empty generation"
    );
}

/// Direct-node (no ClusterIP) coverage is IPv4/IPv6-agnostic: an active-empty
/// generation carries no claim lines, so it cannot silently authorize one
/// family. The node-source lane does not consult these maps.
#[test]
fn an_active_empty_generation_authorizes_no_clusterip_tuple_on_either_family() {
    let registry = tempfile::tempdir().expect("registry dir");
    let publisher = RegistryDirReplySourcePublisher::new(registry.path(), Some(RELAY_POD_UID));
    publisher
        .publish(
            &[source("10.96.0.10", 5300), source("fd00:10:96::a", 5300)],
            true,
        )
        .expect("dual-stack ClusterIP");
    publisher.publish(&[], true).expect("headless");
    assert!(
        published_sources(registry.path()).is_empty(),
        "dropping every ClusterIP tuple while the listener stays bound must authorize none"
    );
    let desired = read_desired_generation(registry.path())
        .expect("read")
        .expect("published");
    assert!(desired.generation.active());
    assert_eq!(desired.relay_pod_uid.as_deref(), Some(RELAY_POD_UID));
}
