//! NodeWaypoint UDP/DTLS reply-source authorization contracts (issue #3286).
//!
//! `tc_inbound` admits a marked datagram to an enrolled pod only from an
//! authorized source. A NodeWaypoint UDP/DTLS reply is source-PINNED to the
//! address the client addressed, which on the Service path is the Service
//! ClusterIP — never a configured node IP. These claims are what authorize
//! exactly that `(address, port)` pair, so the properties pinned here are all
//! security properties, not conveniences:
//!
//! * the claim name is a total, canonical, byte-exact encoding of the pair, so
//!   the claim set really is a SET (two spellings of one address, or of one
//!   port, cannot become two authorizations);
//! * decoding is strict, so nothing that is not exactly a claim ever authorizes
//!   anything;
//! * publication is a WHOLE-SET replacement that withdraws before it adds, so a
//!   partially applied pass can only narrow the authorized set;
//! * IPv4 and IPv6 are at parity, because a dual-stack waypoint that authorized
//!   one family would black-hole the other.

use std::collections::BTreeSet;
use std::net::IpAddr;

use ferrum_edge::capture::{
    MAX_NODE_WAYPOINT_UDP_STEER_DESTINATIONS, NodeWaypointUdpSteerDestination,
};
use ferrum_edge::proxy::node_waypoint_udp_reply_source::{
    NODE_WAYPOINT_UDP_REPLY_SOURCE_DIR, NodeWaypointUdpReplySourcePublisher,
    RegistryDirReplySourcePublisher, decode_claim, encode_claim, read_claims,
};

fn source(ip: &str, port: u16) -> NodeWaypointUdpSteerDestination {
    NodeWaypointUdpSteerDestination {
        ip: ip.parse::<IpAddr>().expect("reply source address"),
        port,
    }
}

fn claim_names(dir: &std::path::Path) -> BTreeSet<String> {
    let claims = dir.join(NODE_WAYPOINT_UDP_REPLY_SOURCE_DIR);
    let Ok(entries) = std::fs::read_dir(&claims) else {
        return BTreeSet::new();
    };
    entries
        .map(|entry| {
            entry
                .expect("claim entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect()
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
/// claim name were textual, `::1` and its expanded form would become two files
/// and therefore two authorizations for one source — and a withdrawal of one
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
/// name that a naive decoder would accept while describing either a different
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

// ── Publication as a whole-set replacement ─────────────────────────────────

/// The node-agent reads this directory as a set snapshot, so publication must
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
        claim_names(registry.path()),
        BTreeSet::from([
            encode_claim(&source("10.96.0.10", 5300)),
            encode_claim(&source("10.96.0.11", 5301)),
        ])
    );

    // The second generation drops .10 and adds .12. The dropped one must be
    // gone, not merely shadowed.
    publisher
        .publish(&[source("10.96.0.11", 5301), source("10.96.0.12", 5302)])
        .expect("second publication");
    assert_eq!(
        claim_names(registry.path()),
        BTreeSet::from([
            encode_claim(&source("10.96.0.11", 5301)),
            encode_claim(&source("10.96.0.12", 5302)),
        ]),
        "a withdrawn reply source must lose its authorization in the same pass"
    );
}

/// An empty publication is a full retraction, and it is the path the steering
/// teardown, shutdown, and `Drop` all take. It must leave nothing authorized.
#[test]
fn an_empty_publication_withdraws_everything() {
    let registry = tempfile::tempdir().expect("registry dir");
    let publisher = RegistryDirReplySourcePublisher::new(registry.path());

    publisher
        .publish(&[source("10.96.0.10", 5300), source("fd00:10:96::a", 5300)])
        .expect("publication");
    assert_eq!(claim_names(registry.path()).len(), 2);

    publisher.publish(&[]).expect("retraction");
    assert!(
        claim_names(registry.path()).is_empty(),
        "a retraction must leave no authorized reply source behind"
    );
    assert_eq!(
        read_claims(registry.path()).expect("read claims").0.len(),
        0
    );
}

/// This directory is Ferrum-owned. Anything in it that this publisher did not
/// write is reaped, so a crashed predecessor's claims — or junk — cannot outlive
/// the generation that owns the datapath.
#[test]
fn publication_reaps_foreign_entries_from_the_claim_directory() {
    let registry = tempfile::tempdir().expect("registry dir");
    let claims = registry.path().join(NODE_WAYPOINT_UDP_REPLY_SOURCE_DIR);
    std::fs::create_dir_all(&claims).expect("claim dir");
    // A predecessor's real claim, and a name no decoder accepts.
    std::fs::write(claims.join(encode_claim(&source("10.96.0.99", 9999))), b"")
        .expect("stale claim");
    std::fs::write(claims.join("not-a-claim"), b"").expect("junk entry");

    let publisher = RegistryDirReplySourcePublisher::new(registry.path());
    publisher
        .publish(&[source("10.96.0.10", 5300)])
        .expect("publication");

    assert_eq!(
        claim_names(registry.path()),
        BTreeSet::from([encode_claim(&source("10.96.0.10", 5300))]),
        "only the serving generation's reply sources may remain authorized"
    );
}

/// Republishing the same set must be idempotent — the reconcile calls this on
/// every changed generation and the node-agent polls the result continuously.
#[test]
fn republishing_the_same_set_is_idempotent() {
    let registry = tempfile::tempdir().expect("registry dir");
    let publisher = RegistryDirReplySourcePublisher::new(registry.path());
    let sources = [source("10.96.0.10", 5300), source("fd00:10:96::a", 5300)];

    publisher.publish(&sources).expect("first");
    let first = claim_names(registry.path());
    publisher.publish(&sources).expect("second");
    assert_eq!(claim_names(registry.path()), first);
}

/// The bound is refused as a whole rather than truncated: authorizing an
/// arbitrary subset would silently black-hole the rest while reporting success.
#[test]
fn an_over_bound_publication_is_refused_entirely() {
    let registry = tempfile::tempdir().expect("registry dir");
    let publisher = RegistryDirReplySourcePublisher::new(registry.path());
    publisher
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
    assert_eq!(
        claim_names(registry.path()),
        BTreeSet::from([encode_claim(&source("10.96.0.10", 5300))]),
        "a refused publication must not have partially applied"
    );
}

// ── The node-agent's read side ─────────────────────────────────────────────

/// The node-agent starts before the proxy has ever published. An absent
/// directory means "nothing is claimed", which is the correct fail-closed
/// reading — not an error that would make the agent retain a previous set.
#[test]
fn an_absent_claim_directory_reads_as_nothing_authorized() {
    let registry = tempfile::tempdir().expect("registry dir");
    let (claims, unparsed) = read_claims(registry.path()).expect("read claims");
    assert!(claims.is_empty());
    assert_eq!(unparsed, 0);
}

/// Unparseable entries are counted, never guessed at. The count is all the
/// node-agent may report: a claim name embeds a Service address and does not
/// belong in a log line.
#[test]
fn unparseable_entries_are_counted_and_authorize_nothing() {
    let registry = tempfile::tempdir().expect("registry dir");
    let claims = registry.path().join(NODE_WAYPOINT_UDP_REPLY_SOURCE_DIR);
    std::fs::create_dir_all(&claims).expect("claim dir");
    std::fs::write(claims.join(encode_claim(&source("10.96.0.10", 5300))), b"").expect("claim");
    std::fs::write(claims.join("4-10.96.0.10-5300"), b"").expect("textual");
    std::fs::write(claims.join("garbage"), b"").expect("garbage");

    let (parsed, unparsed) = read_claims(registry.path()).expect("read claims");
    assert_eq!(
        parsed,
        BTreeSet::from([source("10.96.0.10", 5300)]),
        "only exactly-encoded claims authorize a reply source"
    );
    assert_eq!(unparsed, 2);
}

/// Both families survive the full proxy→node-agent round trip together.
#[test]
fn both_families_survive_the_publication_round_trip() {
    let registry = tempfile::tempdir().expect("registry dir");
    let publisher = RegistryDirReplySourcePublisher::new(registry.path());
    let v4 = source("10.96.0.10", 5300);
    let v6 = source("fd00:10:96::a", 5300);
    publisher.publish(&[v4, v6]).expect("publication");

    let (parsed, unparsed) = read_claims(registry.path()).expect("read claims");
    assert_eq!(unparsed, 0);
    assert_eq!(parsed, BTreeSet::from([v4, v6]));
}
