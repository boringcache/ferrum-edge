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

/// A node address and the fixed relay mark are packet-controlled attributes.
/// Keep UDP off the TCP-only node-source admission lane so a capable same-node
/// workload cannot bypass the waypoint's attribution and authorization.
#[test]
fn tc_inbound_udp_never_authorizes_a_node_source_without_an_exact_claim() {
    let source = include_str!("../../../ebpf/ferrum-ebpf/src/tc_inbound.rs");
    let udp_arms = source
        .split("IPPROTO_UDP => {")
        .skip(1)
        .map(|arm| arm.split("_ => Ok(TC_ACT_OK)").next().unwrap_or(arm))
        .collect::<Vec<_>>();

    assert_eq!(udp_arms.len(), 2, "IPv4 and IPv6 UDP arms must be checked");
    for arm in udp_arms {
        assert!(
            !arm.contains("enrolled_destination_authorized(ctx, source_is_node)"),
            "UDP must not trust the forgeable node-source plus public-mark proof"
        );
        assert!(
            arm.contains("udp_reply_source"),
            "UDP relay admission must retain the exact live source claim"
        );
    }
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
    let publisher = RegistryDirReplySourcePublisher::new(registry.path());
    publisher
        .publish(&[
            source("10.96.0.10", 5300),
            source("10.96.0.11", 5301),
            source("fd00:10:96::a", 5300),
        ])
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
    let publisher = RegistryDirReplySourcePublisher::new(registry.path());

    publisher
        .publish(&[source("10.96.0.10", 5300), source("10.96.0.11", 5301)])
        .expect("first publication");
    assert_eq!(
        published_sources(registry.path()),
        vec![source("10.96.0.10", 5300), source("10.96.0.11", 5301)]
    );

    // The second generation drops .10 and adds .12. The dropped one must be
    // gone, not merely shadowed.
    publisher
        .publish(&[source("10.96.0.11", 5301), source("10.96.0.12", 5302)])
        .expect("second publication");
    assert_eq!(
        published_sources(registry.path()),
        vec![source("10.96.0.11", 5301), source("10.96.0.12", 5302)],
        "a withdrawn reply source must lose its authorization in the same pass"
    );
}

/// An empty publication is a full retraction, and it is the path the steering
/// teardown, shutdown, and `Drop` all take. It must be a POSITIVE statement —
/// an empty generation the node-agent can acknowledge — not an absent channel.
#[test]
fn an_empty_publication_withdraws_everything() {
    let registry = tempfile::tempdir().expect("registry dir");
    let publisher = RegistryDirReplySourcePublisher::new(registry.path());

    publisher
        .publish(&[source("10.96.0.10", 5300), source("fd00:10:96::a", 5300)])
        .expect("publication");
    assert_eq!(published_sources(registry.path()).len(), 2);

    let retraction = publisher.publish(&[]).expect("retraction");
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
    let publisher = RegistryDirReplySourcePublisher::new(registry.path());

    let scrambled = publisher
        .publish(&[
            source("fd00:10:96::a", 5300),
            source("10.96.0.11", 5301),
            source("10.96.0.10", 5300),
            source("10.96.0.11", 5301),
        ])
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
        .publish(&[
            source("10.96.0.11", 5301),
            source("fd00:10:96::a", 5300),
            source("10.96.0.10", 5300),
        ])
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
    let publisher = RegistryDirReplySourcePublisher::new(registry.path());
    let sources = [source("10.96.0.10", 5300), source("fd00:10:96::a", 5300)];

    let first = publisher.publish(&sources).expect("first");
    let bytes = std::fs::read(desired_path(registry.path())).expect("manifest");
    let second = publisher.publish(&sources).expect("second");

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
    let publisher = RegistryDirReplySourcePublisher::new(registry.path());

    let first = publisher
        .publish(&[source("10.96.0.10", 5300)])
        .expect("first");
    let second = publisher
        .publish(&[source("10.96.0.10", 5300), source("10.96.0.11", 5301)])
        .expect("second");
    let back = publisher
        .publish(&[source("10.96.0.10", 5300)])
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
    let publisher = RegistryDirReplySourcePublisher::new(registry.path());
    let baseline = publisher
        .publish(&[source("10.96.0.10", 5300)])
        .expect("baseline publication");

    let over_bound = MAX_NODE_WAYPOINT_UDP_STEER_DESTINATIONS + 1;
    let too_many: Vec<NodeWaypointUdpSteerDestination> = (0..over_bound)
        .map(|index| source("10.96.0.10", 5300 + index as u16))
        .collect();
    assert!(
        publisher.publish(&too_many).is_err(),
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
    let publisher = RegistryDirReplySourcePublisher::new(registry.path());
    let generation = publisher
        .publish(&[source("10.96.0.10", 5300)])
        .expect("publication");
    let owner = generation.owner().to_string();

    let a = encode_claim(&source("10.96.0.10", 5300));
    let b = encode_claim(&source("10.96.0.11", 5301));
    let bodies = [
        // Wrong leader / version.
        format!("ferrum-udp-reply-src-ack v1 {owner} 1 1\n{a}\n"),
        format!("ferrum-udp-reply-src v2 {owner} 1 1\n{a}\n"),
        format!("{owner} 1 1\n{a}\n"),
        // Owner is not exactly sixteen lowercase hex digits.
        format!("ferrum-udp-reply-src v1 {} 1 1\n{a}\n", &owner[..15]),
        format!("ferrum-udp-reply-src v1 {}Z 1 1\n{a}\n", &owner[..15]),
        format!("ferrum-udp-reply-src v1 {}0 1 1\n{a}\n", owner),
        // Non-canonical / absent / zero sequence and count.
        format!("ferrum-udp-reply-src v1 {owner} 01 1\n{a}\n"),
        format!("ferrum-udp-reply-src v1 {owner} 0 1\n{a}\n"),
        format!("ferrum-udp-reply-src v1 {owner} 1 01\n{a}\n"),
        format!("ferrum-udp-reply-src v1 {owner} 1\n{a}\n"),
        // Count disagrees with the body — the truncation case a per-file
        // directory could not even detect.
        format!("ferrum-udp-reply-src v1 {owner} 1 2\n{a}\n"),
        format!("ferrum-udp-reply-src v1 {owner} 1 1\n{a}\n{b}\n"),
        // Over the destination bound.
        format!(
            "ferrum-udp-reply-src v1 {owner} 1 {}\n{a}\n",
            MAX_NODE_WAYPOINT_UDP_STEER_DESTINATIONS + 1
        ),
        // Duplicate and out-of-order claims: one set must have one rendering.
        format!("ferrum-udp-reply-src v1 {owner} 1 2\n{a}\n{a}\n"),
        format!("ferrum-udp-reply-src v1 {owner} 1 2\n{b}\n{a}\n"),
        // A claim line that is not exactly a claim refuses everything, rather
        // than being skipped so the rest can be acknowledged as complete.
        format!("ferrum-udp-reply-src v1 {owner} 1 2\n{a}\n4-10.96.0.11-5301\n"),
        // Framing: no trailing newline, trailing junk, extra header token.
        format!("ferrum-udp-reply-src v1 {owner} 1 1\n{a}"),
        format!("ferrum-udp-reply-src v1 {owner} 1 1\n{a}\n\n"),
        format!("ferrum-udp-reply-src v1 {owner} 1 1 extra\n{a}\n"),
        format!("ferrum-udp-reply-src  v1 {owner} 1 1\n{a}\n"),
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
    let publisher = RegistryDirReplySourcePublisher::new(registry.path());
    let generation = publisher
        .publish(&[source("10.96.0.10", 5300)])
        .expect("publication");

    let mut body = format!(
        "ferrum-udp-reply-src v1 {} 1 1\n{}\n",
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
    let publisher = RegistryDirReplySourcePublisher::new(registry.path());

    let first = publisher
        .publish(&[source("10.96.0.10", 5300)])
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
        .publish(&[source("10.96.0.10", 5300), source("10.96.0.11", 5301)])
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

    let predecessor = RegistryDirReplySourcePublisher::new(registry.path());
    let old = predecessor
        .publish(&[source("10.96.0.10", 5300)])
        .expect("predecessor publication");
    write_acknowledgement(registry.path(), &old).expect("predecessor acknowledgement");

    // A restart: a new process, a new owner, and the same desired set.
    let successor = RegistryDirReplySourcePublisher::new(registry.path());
    let new = successor
        .publish(&[source("10.96.0.10", 5300)])
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
    let publisher = RegistryDirReplySourcePublisher::new(registry.path());
    let generation = publisher
        .publish(&[source("10.96.0.10", 5300)])
        .expect("publication");

    overwrite_desired(
        registry.path(),
        &format!(
            "ferrum-udp-reply-src v1 {} {} 1\n{}\n",
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
    let publisher = RegistryDirReplySourcePublisher::new(registry.path());
    let generation = publisher
        .publish(&[source("10.96.0.10", 5300)])
        .expect("publication");
    let owner = generation.owner().to_string();
    let applied = channel_dir(registry.path()).join(NODE_WAYPOINT_UDP_REPLY_SOURCE_APPLIED_FILE);

    for body in [
        // A DESIRED manifest is not an acknowledgement.
        format!("ferrum-udp-reply-src v1 {owner} 1 0\n"),
        format!("ferrum-udp-reply-src-ack v2 {owner} 1\n"),
        format!("ferrum-udp-reply-src-ack v1 {owner} 0\n"),
        format!("ferrum-udp-reply-src-ack v1 {owner} 01\n"),
        format!("ferrum-udp-reply-src-ack v1 {} 1\n", &owner[..15]),
        format!("ferrum-udp-reply-src-ack v1 {owner} 1 extra\n"),
        format!("ferrum-udp-reply-src-ack v1 {owner} 1"),
        format!("ferrum-udp-reply-src-ack v1 {owner} 1\n\n"),
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
    let publisher = RegistryDirReplySourcePublisher::new(registry.path());
    let generation = publisher
        .publish(&[source("10.96.0.10", 5300)])
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
    let publisher = RegistryDirReplySourcePublisher::new(registry.path());
    let v4 = source("10.96.0.10", 5300);
    let v6 = source("fd00:10:96::a", 5300);
    let generation = publisher.publish(&[v4, v6]).expect("publication");

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
    let publisher = RegistryDirReplySourcePublisher::new(registry.path());
    let generation = publisher
        .publish(&[source("10.96.0.10", 5300)])
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
