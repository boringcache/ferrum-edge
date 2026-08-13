//! Tests for the shared single-use replay authority
//! (`ferrum_edge::plugins::utils::replay_authority`).
//!
//! This is the one abstraction behind `jwks_auth`'s DPoP proofs (issue #3834)
//! and `hmac_auth`'s `ferrum-hmac-v2` nonces (issue #3837), so the contracts
//! below are the security properties both plugins inherit:
//!
//! * atomic check-and-insert with exactly one winner under concurrency;
//! * capacity that prunes only **expired** markers and refuses otherwise —
//!   never evicting a live marker to admit a new request — with each live
//!   authority enforcing its own admitted cap against the shared lane so an
//!   equivalent reload that raises or lowers capacity takes effect without
//!   forgetting history;
//! * exact TTL boundary semantics;
//! * lane ownership that survives an equivalent reload and converges for
//!   equivalent replicas, while isolating distinct namespaces / policies /
//!   sub-domains;
//! * bounded, tombstoned lane retirement.

use std::sync::{Arc, Barrier};
use std::time::Duration;

use ferrum_edge::plugins::utils::redis_rate_limiter::{RedisConfig, RedisRateLimitClient};
use ferrum_edge::plugins::utils::replay_authority::{
    MAX_PROCESS_REPLAY_LANES, ReplayAdmission, ReplayAuthority, ReplayDomain, ReplayScope,
    admit_process_at, counters, monotonic_millis, process_lane, process_lane_registered_for_tests,
    process_max_entries, shared_authority_degraded, shared_health_snapshot, validate_scope_backend,
};

const PROFILE: &str = "ferrum-replay-authority-tests-v1";
const RETENTION: Duration = Duration::from_secs(600);

/// A distinct protection domain per test, so parallel suite siblings cannot
/// consume one another's lanes or markers.
fn domain(sub: &str) -> ReplayDomain {
    ReplayDomain::new(PROFILE, "ferrum", "replay_authority_tests", sub, "0")
}

fn process_authority(sub: &str, max_entries: usize) -> ReplayAuthority {
    ReplayAuthority::process("test", &domain(sub), max_entries, RETENTION, 8)
        .expect("process lane should be created")
}

// ── atomic check-and-insert ─────────────────────────────────────────

#[tokio::test]
async fn sequential_replay_of_the_same_marker_is_rejected() {
    let authority = process_authority("sequential", 16);
    let marker = domain("sequential").marker(&[b"consumer", b"nonce-1"]);

    assert_eq!(authority.admit(&marker).await, ReplayAdmission::Admitted);
    assert_eq!(authority.admit(&marker).await, ReplayAdmission::Replay);
    assert_eq!(authority.admit(&marker).await, ReplayAdmission::Replay);
}

#[tokio::test]
async fn a_distinct_marker_is_admitted_independently() {
    let authority = process_authority("distinct", 16);
    let first = domain("distinct").marker(&[b"consumer", b"nonce-1"]);
    let second = domain("distinct").marker(&[b"consumer", b"nonce-2"]);

    assert_eq!(authority.admit(&first).await, ReplayAdmission::Admitted);
    assert_eq!(authority.admit(&second).await, ReplayAdmission::Admitted);
}

/// Two simultaneous claims of one previously unseen marker have exactly one
/// winner. The decision and the insertion happen under a single entry guard, so
/// there is no read-then-write window for a second request to slip through.
#[test]
fn concurrent_claims_of_one_unseen_marker_have_exactly_one_winner() {
    const WORKERS: usize = 32;
    let authority = Arc::new(process_authority("concurrent", 64));
    let marker = domain("concurrent").marker(&[b"consumer", b"contended"]);
    let barrier = Arc::new(Barrier::new(WORKERS));

    let workers: Vec<_> = (0..WORKERS)
        .map(|_| {
            let authority = Arc::clone(&authority);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                admit_process_at(&authority, &marker, monotonic_millis())
                    .expect("process authority")
            })
        })
        .collect();

    let admitted = workers
        .into_iter()
        .map(|worker| worker.join().expect("worker should not panic"))
        .filter(|outcome| *outcome == ReplayAdmission::Admitted)
        .count();
    assert_eq!(admitted, 1, "exactly one concurrent claim may win");
}

/// Concurrent claims of *distinct* markers must all succeed: the entry guard
/// must not serialize independent admissions into false replays.
#[test]
fn concurrent_distinct_markers_are_all_admitted() {
    const WORKERS: usize = 32;
    let authority = Arc::new(process_authority("concurrent-distinct", WORKERS));
    let barrier = Arc::new(Barrier::new(WORKERS));

    let workers: Vec<_> = (0..WORKERS)
        .map(|idx| {
            let authority = Arc::clone(&authority);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let label = idx.to_string();
                let marker = domain("concurrent-distinct").marker(&[b"consumer", label.as_bytes()]);
                barrier.wait();
                admit_process_at(&authority, &marker, monotonic_millis())
                    .expect("process authority")
            })
        })
        .collect();

    assert!(
        workers
            .into_iter()
            .map(|worker| worker.join().expect("worker should not panic"))
            .all(|outcome| outcome == ReplayAdmission::Admitted)
    );
}

// ── capacity never forgets a live marker ────────────────────────────

/// This is the core of issue #3834: at capacity the authority prunes expired
/// markers and refuses otherwise. Filling a lane must never make an unexpired
/// marker reusable.
#[test]
fn capacity_refuses_rather_than_evicting_a_live_marker() {
    let authority = process_authority("capacity", 2);
    let now = monotonic_millis();
    let first = domain("capacity").marker(&[b"c", b"first"]);
    let second = domain("capacity").marker(&[b"c", b"second"]);
    let third = domain("capacity").marker(&[b"c", b"third"]);

    assert_eq!(
        admit_process_at(&authority, &first, now),
        Some(ReplayAdmission::Admitted)
    );
    assert_eq!(
        admit_process_at(&authority, &second, now),
        Some(ReplayAdmission::Admitted)
    );
    // The lane is full and nothing is expired: the NEW request is refused.
    assert_eq!(
        admit_process_at(&authority, &third, now),
        Some(ReplayAdmission::CapacityRefused)
    );
    // …and the marker the pressure was supposed to displace is still live.
    assert_eq!(
        admit_process_at(&authority, &first, now),
        Some(ReplayAdmission::Replay),
        "capacity pressure must not make an unexpired marker reusable"
    );
    assert_eq!(
        admit_process_at(&authority, &second, now),
        Some(ReplayAdmission::Replay)
    );
}

/// Once the retained markers expire, their slots are reclaimed and new requests
/// are admitted again — capacity degrades into refusal, not into a permanent
/// outage.
#[test]
fn expired_markers_are_reclaimed_to_admit_new_requests() {
    let authority = process_authority("capacity-reclaim", 2);
    let now = monotonic_millis();
    let first = domain("capacity-reclaim").marker(&[b"c", b"first"]);
    let second = domain("capacity-reclaim").marker(&[b"c", b"second"]);
    let third = domain("capacity-reclaim").marker(&[b"c", b"third"]);

    assert_eq!(
        admit_process_at(&authority, &first, now),
        Some(ReplayAdmission::Admitted)
    );
    assert_eq!(
        admit_process_at(&authority, &second, now),
        Some(ReplayAdmission::Admitted)
    );

    let after_expiry = now + RETENTION.as_millis() as u64 + 1;
    assert_eq!(
        admit_process_at(&authority, &third, after_expiry),
        Some(ReplayAdmission::Admitted),
        "an expired slot is reclaimable"
    );

    let lane = process_lane(&authority).expect("process lane");
    let cap = process_max_entries(&authority).expect("process capacity");
    assert!(
        lane.retained_entries() <= cap,
        "reclamation must respect the hard capacity bound"
    );
}

/// A zero-usable-capacity lane refuses rather than admitting unprotected.
#[test]
fn a_single_slot_lane_still_rejects_a_live_duplicate_before_refusing() {
    let authority = process_authority("capacity-one", 1);
    let now = monotonic_millis();
    let marker = domain("capacity-one").marker(&[b"c", b"only"]);
    let other = domain("capacity-one").marker(&[b"c", b"other"]);

    assert_eq!(
        admit_process_at(&authority, &marker, now),
        Some(ReplayAdmission::Admitted)
    );
    // A live duplicate is a REPLAY, decided before any capacity handling.
    assert_eq!(
        admit_process_at(&authority, &marker, now),
        Some(ReplayAdmission::Replay)
    );
    assert_eq!(
        admit_process_at(&authority, &other, now),
        Some(ReplayAdmission::CapacityRefused)
    );
}

// ── TTL boundaries ──────────────────────────────────────────────────

/// A marker protects through its exact last millisecond and becomes reusable
/// only strictly after the horizon elapses.
#[test]
fn marker_protection_covers_the_exact_retention_boundary() {
    let authority = process_authority("ttl", 8);
    let now = monotonic_millis();
    let marker = domain("ttl").marker(&[b"c", b"boundary"]);
    let retention_millis = RETENTION.as_millis() as u64;

    assert_eq!(
        admit_process_at(&authority, &marker, now),
        Some(ReplayAdmission::Admitted)
    );
    assert_eq!(
        admit_process_at(&authority, &marker, now + retention_millis - 1),
        Some(ReplayAdmission::Replay),
        "one millisecond before expiry the marker is still live"
    );
    assert_eq!(
        admit_process_at(&authority, &marker, now + retention_millis),
        Some(ReplayAdmission::Admitted),
        "at the horizon the marker has expired"
    );
}

/// A late wakeup far past the horizon must not resurrect protection, and the
/// re-admission must carry a full fresh interval.
#[test]
fn re_admission_after_expiry_starts_a_full_fresh_interval() {
    let authority = process_authority("ttl-late", 8);
    let now = monotonic_millis();
    let marker = domain("ttl-late").marker(&[b"c", b"late"]);
    let retention_millis = RETENTION.as_millis() as u64;

    assert_eq!(
        admit_process_at(&authority, &marker, now),
        Some(ReplayAdmission::Admitted)
    );
    let late = now + retention_millis * 10;
    assert_eq!(
        admit_process_at(&authority, &marker, late),
        Some(ReplayAdmission::Admitted)
    );
    assert_eq!(
        admit_process_at(&authority, &marker, late + retention_millis - 1),
        Some(ReplayAdmission::Replay),
        "the re-admitted marker must carry a complete protection interval"
    );
}

// ── lane ownership across reloads and replicas ──────────────────────

/// An equivalent reload must inherit live markers. This is the reload replay
/// opening from issue #3834: a rebuilt plugin generation that resolves the same
/// protection domain must join the same lane, not start empty.
#[test]
fn an_equivalent_reload_inherits_live_markers() {
    let marker = domain("reload").marker(&[b"c", b"proof"]);
    let now = monotonic_millis();

    let original = process_authority("reload", 8);
    assert_eq!(
        admit_process_at(&original, &marker, now),
        Some(ReplayAdmission::Admitted)
    );
    // Retire the generation that made the claim, exactly as a plugin-cache
    // rebuild does, and construct an equivalent replacement.
    drop(original);
    let reloaded = process_authority("reload", 8);
    assert_eq!(
        admit_process_at(&reloaded, &marker, now),
        Some(ReplayAdmission::Replay),
        "a rebuilt generation must not accept an already-admitted proof"
    );
}

/// Two independently constructed authorities for one policy identity share a
/// lane — the single-process analogue of two replicas converging on one shared
/// keyspace.
#[test]
fn equivalent_authorities_share_one_lane() {
    let marker = domain("shared-lane").marker(&[b"c", b"proof"]);
    let now = monotonic_millis();

    let first = process_authority("shared-lane", 8);
    let second = process_authority("shared-lane", 8);
    assert_eq!(
        admit_process_at(&first, &marker, now),
        Some(ReplayAdmission::Admitted)
    );
    assert_eq!(
        admit_process_at(&second, &marker, now),
        Some(ReplayAdmission::Replay)
    );
}

/// A widened retention on a later generation must not shorten an existing
/// marker's protection, and a *narrowed* one must not either: the stored expiry
/// only ever moves forward.
#[test]
fn an_existing_marker_keeps_at_least_its_admitted_interval() {
    let marker = domain("retention-change").marker(&[b"c", b"proof"]);
    let now = monotonic_millis();

    let long = ReplayAuthority::process(
        "test",
        &domain("retention-change"),
        8,
        Duration::from_secs(600),
        8,
    )
    .expect("lane");
    assert_eq!(
        admit_process_at(&long, &marker, now),
        Some(ReplayAdmission::Admitted)
    );

    // A replacement generation declaring a much shorter retention joins the
    // same lane; the already-admitted marker keeps its original expiry.
    let short = ReplayAuthority::process(
        "test",
        &domain("retention-change"),
        8,
        Duration::from_secs(1),
        8,
    )
    .expect("lane");
    assert_eq!(
        admit_process_at(&short, &marker, now + 5_000),
        Some(ReplayAdmission::Replay),
        "a shorter replacement retention must not expire an existing marker early"
    );
}

/// An equivalent reload that lowers capacity must start refusing new markers
/// at the new cap without forgetting any live marker or isolating onto a
/// fresh lane.
#[test]
fn equivalent_reload_decrease_enforces_new_capacity_without_forgetting_live_markers() {
    let first = domain("capacity-decrease").marker(&[b"c", b"first"]);
    let second = domain("capacity-decrease").marker(&[b"c", b"second"]);
    let third = domain("capacity-decrease").marker(&[b"c", b"third"]);
    let now = monotonic_millis();

    let original = process_authority("capacity-decrease", 2);
    assert_eq!(
        admit_process_at(&original, &first, now),
        Some(ReplayAdmission::Admitted)
    );
    assert_eq!(
        admit_process_at(&original, &second, now),
        Some(ReplayAdmission::Admitted)
    );
    drop(original);

    let lowered = process_authority("capacity-decrease", 1);
    assert_eq!(
        process_max_entries(&lowered),
        Some(1),
        "the replacement generation must enforce its own admitted cap"
    );
    assert_eq!(
        admit_process_at(&lowered, &first, now),
        Some(ReplayAdmission::Replay),
        "lowering capacity must not forget a live marker"
    );
    assert_eq!(
        admit_process_at(&lowered, &second, now),
        Some(ReplayAdmission::Replay),
        "every live marker from the prior generation must stay claimed"
    );
    assert_eq!(
        admit_process_at(&lowered, &third, now),
        Some(ReplayAdmission::CapacityRefused),
        "a lowered cap must refuse new admissions while live markers remain"
    );
    let lane = process_lane(&lowered).expect("shared lane");
    assert_eq!(
        lane.retained_entries(),
        2,
        "live markers must remain even when they exceed the new cap"
    );
}

/// An equivalent reload that raises capacity must restore headroom against
/// the same marker history without reopening an already-claimed proof.
#[test]
fn equivalent_reload_increase_restores_headroom_without_reopening_live_markers() {
    let first = domain("capacity-increase").marker(&[b"c", b"first"]);
    let second = domain("capacity-increase").marker(&[b"c", b"second"]);
    let now = monotonic_millis();

    let original = process_authority("capacity-increase", 1);
    assert_eq!(
        admit_process_at(&original, &first, now),
        Some(ReplayAdmission::Admitted)
    );
    assert_eq!(
        admit_process_at(&original, &second, now),
        Some(ReplayAdmission::CapacityRefused)
    );
    drop(original);

    let raised = process_authority("capacity-increase", 2);
    assert_eq!(
        process_max_entries(&raised),
        Some(2),
        "the replacement generation must enforce the raised cap"
    );
    assert_eq!(
        admit_process_at(&raised, &first, now),
        Some(ReplayAdmission::Replay),
        "raising capacity must not reopen an already-claimed proof"
    );
    assert_eq!(
        admit_process_at(&raised, &second, now),
        Some(ReplayAdmission::Admitted),
        "raising capacity must restore headroom on the same lane"
    );
}

/// Two independently constructed authorities for one domain each enforce the
/// cap they were admitted with. Construction order must not freeze the first
/// constructor's cap onto the shared lane.
#[test]
fn equivalent_authorities_enforce_their_own_capacity_regardless_of_construction_order() {
    let now = monotonic_millis();

    for (sub, first_cap, second_cap) in [
        ("capacity-order-high-first", 4, 2),
        ("capacity-order-low-first", 2, 4),
    ] {
        let first_marker = domain(sub).marker(&[b"c", b"first"]);
        let second_marker = domain(sub).marker(&[b"c", b"second"]);
        let third_marker = domain(sub).marker(&[b"c", b"third"]);

        let first = process_authority(sub, first_cap);
        let second = process_authority(sub, second_cap);
        assert_eq!(process_max_entries(&first), Some(first_cap));
        assert_eq!(process_max_entries(&second), Some(second_cap));

        assert_eq!(
            admit_process_at(&first, &first_marker, now),
            Some(ReplayAdmission::Admitted)
        );
        assert_eq!(
            admit_process_at(&second, &second_marker, now),
            Some(ReplayAdmission::Admitted)
        );

        let (low, high) = if first_cap < second_cap {
            (&first, &second)
        } else {
            (&second, &first)
        };

        assert_eq!(
            admit_process_at(low, &third_marker, now),
            Some(ReplayAdmission::CapacityRefused),
            "the lower-cap authority must refuse at its own cap (sub={sub})"
        );
        assert_eq!(
            admit_process_at(high, &third_marker, now),
            Some(ReplayAdmission::Admitted),
            "the higher-cap authority must still have headroom (sub={sub})"
        );
        assert_eq!(
            admit_process_at(&first, &first_marker, now),
            Some(ReplayAdmission::Replay)
        );
        assert_eq!(
            admit_process_at(&second, &second_marker, now),
            Some(ReplayAdmission::Replay)
        );
    }
}

// ── domain isolation ────────────────────────────────────────────────

#[test]
fn distinct_domains_do_not_share_markers() {
    let now = monotonic_millis();
    let left = process_authority("isolation-a", 8);
    let right = process_authority("isolation-b", 8);
    let left_marker = domain("isolation-a").marker(&[b"c", b"proof"]);
    let right_marker = domain("isolation-b").marker(&[b"c", b"proof"]);

    assert_ne!(left_marker.digest(), right_marker.digest());
    assert_eq!(
        admit_process_at(&left, &left_marker, now),
        Some(ReplayAdmission::Admitted)
    );
    assert_eq!(
        admit_process_at(&right, &right_marker, now),
        Some(ReplayAdmission::Admitted),
        "one policy's history must not suppress another's"
    );
}

#[test]
fn every_domain_component_participates_in_the_identity() {
    let base = ReplayDomain::new(PROFILE, "ns", "plugin", "config", "sub");
    let parts: [&[u8]; 2] = [b"c", b"n"];
    let base_marker = base.marker(&parts).digest();

    for variant in [
        ReplayDomain::new("other-profile", "ns", "plugin", "config", "sub"),
        ReplayDomain::new(PROFILE, "other-ns", "plugin", "config", "sub"),
        ReplayDomain::new(PROFILE, "ns", "other-plugin", "config", "sub"),
        ReplayDomain::new(PROFILE, "ns", "plugin", "other-config", "sub"),
        ReplayDomain::new(PROFILE, "ns", "plugin", "config", "other-sub"),
    ] {
        assert_ne!(base_marker, variant.marker(&parts).digest());
    }
}

/// Field framing: a component boundary cannot be forged by embedding a
/// delimiter, because every field is length-prefixed.
#[test]
fn domain_and_marker_fields_are_length_framed() {
    assert_ne!(
        ReplayDomain::new(PROFILE, "a", "bc", "d", "e")
            .marker(&[b"x"])
            .digest(),
        ReplayDomain::new(PROFILE, "ab", "c", "d", "e")
            .marker(&[b"x"])
            .digest(),
    );
    let one = domain("framing");
    assert_ne!(
        one.marker(&[b"ab", b"c"]).digest(),
        one.marker(&[b"a", b"bc"]).digest(),
    );
    assert_ne!(
        one.marker(&[b"a|b"]).digest(),
        one.marker(&[b"a", b"b"]).digest(),
    );
}

// ── retirement / bounded garbage collection ─────────────────────────

/// A retired lane is a tombstone: it stays registered while any marker is live,
/// and is reclaimed only once every marker has expired.
#[test]
fn a_retired_lane_is_reclaimed_only_after_every_marker_expires() {
    let lane_domain = domain("retirement");
    let marker = lane_domain.marker(&[b"c", b"proof"]);
    let now = monotonic_millis();

    {
        let authority =
            ReplayAuthority::process("test", &lane_domain, 8, RETENTION, 8).expect("lane");
        assert_eq!(
            admit_process_at(&authority, &marker, now),
            Some(ReplayAdmission::Admitted)
        );
    }
    // The plugin generation is gone but the lane is still registered, so its
    // live marker keeps protecting.
    assert!(process_lane_registered_for_tests(&lane_domain));

    // Creating any new lane runs the bounded cold-path reclamation. While the
    // marker is live the retired lane must survive it.
    let _keepalive = process_authority("retirement-probe", 4);
    assert!(
        process_lane_registered_for_tests(&lane_domain),
        "a lane retaining a live marker must never be reclaimed"
    );

    let rejoined = ReplayAuthority::process("test", &lane_domain, 8, RETENTION, 8).expect("lane");
    assert_eq!(
        admit_process_at(&rejoined, &marker, now),
        Some(ReplayAdmission::Replay)
    );
}

#[test]
fn the_process_lane_registry_is_bounded() {
    // The bound is a real cap rather than advisory; asserting the constant is
    // exported and non-zero keeps a future change from silently unbounding it.
    assert!(MAX_PROCESS_REPLAY_LANES > 0);
    assert_eq!(MAX_PROCESS_REPLAY_LANES, 1_024);
}

// ── configuration admission ─────────────────────────────────────────

#[test]
fn scope_parsing_admits_exactly_two_declarations() {
    assert_eq!(
        ReplayScope::parse("p", "replay_scope", "process").expect("process"),
        ReplayScope::Process
    );
    assert_eq!(
        ReplayScope::parse("p", "replay_scope", " SHARED ").expect("shared"),
        ReplayScope::Shared
    );
    for invalid in ["", "local", "redis", "prosess", "Process-local"] {
        assert!(ReplayScope::parse("p", "replay_scope", invalid).is_err());
    }
}

/// `shared` without a backend would silently be process-local — the exact
/// "multi-replica production configuration falls back to local acceptance"
/// failure — and a provisioned backend nothing consults is equally a
/// misconfiguration.
#[test]
fn scope_and_backend_must_agree() {
    assert!(validate_scope_backend("p", "replay_scope", ReplayScope::Shared, true).is_ok());
    assert!(validate_scope_backend("p", "replay_scope", ReplayScope::Process, false).is_ok());

    let missing_backend =
        validate_scope_backend("p", "replay_scope", ReplayScope::Shared, false).unwrap_err();
    assert!(missing_backend.contains("sync_mode"));

    let unused_backend =
        validate_scope_backend("p", "replay_scope", ReplayScope::Process, true).unwrap_err();
    assert!(unused_backend.contains("shared"));
}

// ── observability ───────────────────────────────────────────────────

/// Counters move on the paths they claim to describe. They are process-global
/// and monotonic, so the assertions are on deltas rather than absolute values.
#[tokio::test]
async fn counters_record_replay_and_capacity_outcomes() {
    let before = counters();
    let authority = process_authority("counters", 1);
    let marker = domain("counters").marker(&[b"c", b"proof"]);
    let other = domain("counters").marker(&[b"c", b"other"]);

    assert_eq!(authority.admit(&marker).await, ReplayAdmission::Admitted);
    assert_eq!(authority.admit(&marker).await, ReplayAdmission::Replay);
    assert_eq!(
        authority.admit(&other).await,
        ReplayAdmission::CapacityRefused
    );

    let after = counters();
    assert!(after.admitted_process > before.admitted_process);
    assert!(after.replay_rejected > before.replay_rejected);
    assert!(after.capacity_refused > before.capacity_refused);
    assert!(after.process_lanes >= 1);
}

/// The public snapshot must stay label-free. Serializing it and checking that
/// only the fixed field names appear is the structural guard against someone
/// adding a namespace, policy id, or marker to it later.
#[test]
fn the_counter_snapshot_carries_no_labels() {
    let value = serde_json::to_value(counters()).expect("counters serialize");
    let object = value.as_object().expect("counters are an object");
    let mut names: Vec<&str> = object.keys().map(String::as_str).collect();
    names.sort_unstable();
    assert_eq!(
        names,
        vec![
            "admitted_process",
            "admitted_shared",
            "authority_unavailable",
            "capacity_refused",
            "legacy_unsafe_profile_accepted",
            "process_lanes",
            "replay_rejected",
            "shared_authorities",
            "shared_authorities_unavailable",
        ]
    );
    assert!(
        object.values().all(serde_json::Value::is_number),
        "every counter must be a bare number: no label, identity, or error text"
    );
}

/// Neither a domain nor a marker may print recoverable proof material.
#[test]
fn debug_renderings_never_disclose_marker_material() {
    let one = domain("debug");
    let marker = one.marker(&[b"super-secret-nonce", b"consumer-42"]);
    assert_eq!(format!("{one:?}"), "ReplayDomain(<digest>)");
    assert_eq!(format!("{marker:?}"), "ReplayMarker(<digest>)");

    let authority = process_authority("debug", 4);
    let rendered = format!("{authority:?}");
    assert!(rendered.contains("process"));
    assert!(!rendered.contains("secret"));
}

// ── shared authority fails closed ───────────────────────────────────

/// A `shared` authority whose backend cannot be reached rejects the protected
/// request. There is deliberately no fallback to process-local acceptance: a
/// per-replica fallback would reinstate exactly the cross-replica bypass the
/// shared authority exists to close.
///
/// The endpoint is a closed loopback port, so this exercises the real
/// connect-failure path (the same one a timeout, a partition, or an
/// authentication rejection lands on) without needing a live server.
#[tokio::test]
async fn a_shared_authority_with_an_unreachable_backend_fails_closed() {
    let _serialized = shared_health_guard_async().await;
    let config = RedisConfig::from_plugin_config(
        &serde_json::json!({
            "sync_mode": "redis",
            // Port 1 is reserved and never listening.
            "redis_url": "redis://127.0.0.1:1",
            "redis_connect_timeout_seconds": 1,
        }),
        "ferrum:replay_authority_tests:unreachable",
    )
    .expect("redis config parses")
    .expect("sync_mode redis yields a config");

    let client = Arc::new(RedisRateLimitClient::new(config, None, false, None));
    let authority = ReplayAuthority::shared(client, RETENTION);
    assert_eq!(authority.mode(), "shared");

    let marker = domain("shared-unreachable").marker(&[b"c", b"proof"]);
    assert_eq!(
        authority.admit(&marker).await,
        ReplayAdmission::AuthorityUnavailable,
        "an unreachable shared backend must reject, never admit locally"
    );
    // Still unavailable on a second attempt: nothing silently degrades into a
    // local lane that would start accepting.
    assert_eq!(
        authority.admit(&marker).await,
        ReplayAdmission::AuthorityUnavailable
    );

    // A shared authority contributes nothing to any process lane.
    assert!(process_lane(&authority).is_none());
}

/// The shared authority is registered for readiness/metrics, and its outage is
/// observable without retaining the client, its endpoint, or its credentials.
#[tokio::test]
async fn an_unavailable_shared_authority_is_visible_in_the_counters() {
    let _serialized = shared_health_guard_async().await;
    let config = RedisConfig::from_plugin_config(
        &serde_json::json!({
            "sync_mode": "redis",
            "redis_url": "redis://127.0.0.1:1",
            "redis_connect_timeout_seconds": 1,
        }),
        "ferrum:replay_authority_tests:observable",
    )
    .expect("redis config parses")
    .expect("sync_mode redis yields a config");

    let client = Arc::new(RedisRateLimitClient::new(config, None, false, None));
    client.mark_unavailable_for_test();
    let authority = ReplayAuthority::shared(Arc::clone(&client), RETENTION);

    let marker = domain("shared-observable").marker(&[b"c", b"proof"]);
    let before = counters();
    assert_eq!(
        authority.admit(&marker).await,
        ReplayAdmission::AuthorityUnavailable
    );
    let after = counters();
    assert!(after.authority_unavailable > before.authority_unavailable);
    assert!(after.shared_authorities >= 1);
    assert!(
        after.shared_authorities_unavailable >= 1,
        "a degraded shared authority must be visible to readiness"
    );
    assert!(shared_authority_degraded());
}

// ── shared-authority health for readiness ───────────────────────────
//
// `SHARED_AUTHORITIES` is a process-global registry, so these cases serialize
// against each other. Nothing else in this test binary constructs a `shared`
// authority (every other `shared` configuration in the unit suite is a rejected
// config), so a serialized case observes only its own registrations.
/// A tokio mutex rather than a `std` one so the async cases can hold it across
/// their awaits without a `!Send` guard.
static SHARED_HEALTH_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn shared_health_guard() -> tokio::sync::MutexGuard<'static, ()> {
    SHARED_HEALTH_LOCK.blocking_lock()
}

async fn shared_health_guard_async() -> tokio::sync::MutexGuard<'static, ()> {
    SHARED_HEALTH_LOCK.lock().await
}

fn unreachable_shared_client(prefix: &str) -> Arc<RedisRateLimitClient> {
    let config = RedisConfig::from_plugin_config(
        &serde_json::json!({
            "sync_mode": "redis",
            // Port 1 is reserved and never listening.
            "redis_url": "redis://127.0.0.1:1",
            "redis_connect_timeout_seconds": 1,
            // Long enough that no background recovery dial races an assertion.
            "redis_health_check_interval_seconds": 3600,
        }),
        prefix,
    )
    .expect("redis config parses")
    .expect("sync_mode redis yields a config");
    Arc::new(RedisRateLimitClient::new(config, None, false, None))
}

/// The bounded aggregate readiness consumes: an unavailable shared authority is
/// visible, recovery clears it, and a retired plugin generation stops counting.
#[test]
fn shared_authority_health_tracks_outage_recovery_and_retirement() {
    let _serialized = shared_health_guard();
    let baseline = shared_health_snapshot();

    let client = unreachable_shared_client("ferrum:replay_authority_tests:health");
    let authority = ReplayAuthority::shared(Arc::clone(&client), RETENTION);

    let registered = shared_health_snapshot();
    assert_eq!(
        registered.shared_authorities,
        baseline.shared_authorities + 1,
        "a live shared authority is counted exactly once"
    );
    assert!(registered.required());
    assert_eq!(
        registered.shared_authorities_unavailable, baseline.shared_authorities_unavailable,
        "a freshly built client has not proven itself unavailable yet"
    );

    // An outage is readiness-relevant, not a per-request error.
    client.mark_unavailable_for_test();
    let degraded = shared_health_snapshot();
    assert_eq!(
        degraded.shared_authorities_unavailable,
        baseline.shared_authorities_unavailable + 1
    );
    assert!(degraded.unavailable());
    assert!(shared_authority_degraded());

    // Recovery restores it with no rebuild and no config reload.
    assert!(client.publish_reachable_for_test());
    let recovered = shared_health_snapshot();
    assert_eq!(
        recovered.shared_authorities_unavailable, baseline.shared_authorities_unavailable,
        "a recovered backend must stop failing readiness"
    );
    assert_eq!(recovered.shared_authorities, baseline.shared_authorities + 1);

    // Retiring the generation drops it from the aggregate: the registry holds
    // weak handles precisely so an old generation can neither hold readiness
    // down nor inflate the count.
    drop(authority);
    drop(client);
    let retired = shared_health_snapshot();
    assert_eq!(
        retired.shared_authorities, baseline.shared_authorities,
        "a retired plugin generation must not remain counted"
    );
    assert_eq!(
        retired.shared_authorities_unavailable,
        baseline.shared_authorities_unavailable
    );
}

/// One backend shared by several providers is one authority, not several.
/// `jwks_auth` builds a single Redis client per plugin generation and hands it
/// to every `shared` provider, so a per-provider registration would report one
/// backend as many and inflate a readiness aggregate.
#[test]
fn one_backend_shared_by_several_authorities_is_counted_once() {
    let _serialized = shared_health_guard();
    let baseline = shared_health_snapshot();

    let client = unreachable_shared_client("ferrum:replay_authority_tests:dedupe");
    let first = ReplayAuthority::shared(Arc::clone(&client), RETENTION);
    let second = ReplayAuthority::shared(Arc::clone(&client), RETENTION);
    let third = ReplayAuthority::shared(Arc::clone(&client), RETENTION);

    assert_eq!(
        shared_health_snapshot().shared_authorities,
        baseline.shared_authorities + 1,
        "three providers over one backend are one shared authority"
    );

    drop((first, second, third));
    drop(client);
    assert_eq!(
        shared_health_snapshot().shared_authorities,
        baseline.shared_authorities
    );
}

// ── bounded, redacted shared claim ──────────────────────────────────

/// How the fake backend answers the `SET` that carries a replay claim.
#[derive(Clone, Copy)]
enum ClaimBehavior {
    /// Accepted, authenticated, screened — and then simply never answered.
    Silent,
    /// A RESP error reply (`-NOAUTH …`, `-WRONGPASS …`, `-OOM …`).
    Error(&'static str),
    /// A reply that is not valid RESP for this command: protocol uncertainty.
    Garbage,
    /// The socket closes with no reply at all: a partition mid-command.
    Disconnect,
    /// The command IS executed and the reply is then lost. A later attempt sees
    /// the key that the lost command created.
    ExecutedThenLost,
}

/// A minimal RESP server that completes connection setup and the topology
/// screen, then answers the replay claim per [`ClaimBehavior`].
///
/// The interesting shapes here are the ones a *connect* timeout cannot catch:
/// the peer accepts the TCP connection, authenticates, and answers `INFO`
/// cleanly, so the client holds a screened, usable connection — and only then
/// misbehaves.
async fn spawn_claim_redis_server(
    behavior: ClaimBehavior,
) -> (u16, tokio::sync::oneshot::Sender<()>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake redis");
    let port = listener.local_addr().expect("local addr").port();
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    // Server-side record of whether the claim key exists, for `ExecutedThenLost`.
    let claimed = Arc::new(std::sync::atomic::AtomicBool::new(false));

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                accepted = listener.accept() => {
                    let Ok((mut stream, _)) = accepted else { break };
                    let claimed = Arc::clone(&claimed);
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 16 * 1024];
                        loop {
                            let read = match stream.read(&mut buf).await {
                                Ok(0) | Err(_) => break,
                                Ok(read) => read,
                            };
                            let chunk = &buf[..read];
                            let contains = |needle: &[u8]| {
                                chunk.windows(needle.len()).any(|window| window == needle)
                            };
                            let reply: Vec<u8> = if contains(b"SET") {
                                match behavior {
                                    ClaimBehavior::Silent => continue,
                                    ClaimBehavior::Disconnect => break,
                                    ClaimBehavior::Error(text) => text.as_bytes().to_vec(),
                                    ClaimBehavior::Garbage => b"@not-resp\r\n".to_vec(),
                                    ClaimBehavior::ExecutedThenLost => {
                                        if claimed.swap(true, std::sync::atomic::Ordering::SeqCst) {
                                            // The key the lost command created is
                                            // still there: `SET NX` declines.
                                            b"$-1\r\n".to_vec()
                                        } else {
                                            // Executed, then the reply is lost.
                                            break;
                                        }
                                    }
                                }
                            } else if contains(b"INFO") {
                                let text = "# Cluster\r\ncluster_enabled:0\r\n";
                                format!("${}\r\n{text}\r\n", text.len()).into_bytes()
                            } else {
                                // The redis crate pipelines connection setup, so
                                // reply once per command array in the chunk.
                                let commands =
                                    chunk.iter().filter(|&&byte| byte == b'*').count().max(1);
                                b"+OK\r\n".repeat(commands)
                            };
                            if stream.write_all(&reply).await.is_err() {
                                break;
                            }
                        }
                    });
                }
            }
        }
    });

    (port, shutdown_tx)
}

fn claim_client(port: u16, prefix: &str) -> Arc<RedisRateLimitClient> {
    let config = RedisConfig::from_plugin_config(
        &serde_json::json!({
            "sync_mode": "redis",
            "redis_url": format!("redis://127.0.0.1:{port}/0"),
            // The admitted Redis timeout contract, reused as the response bound.
            "redis_connect_timeout_seconds": 1,
            "redis_health_check_interval_seconds": 3600,
        }),
        prefix,
    )
    .expect("redis config parses")
    .expect("sync_mode redis yields a config");
    Arc::new(RedisRateLimitClient::new(config, None, false, None))
}

/// A connected backend that never answers the claim must produce a fixed
/// fail-closed result inside the admitted bound, not hold the protected request.
#[tokio::test]
async fn a_connected_backend_that_never_answers_fails_closed_within_the_bound() {
    let _serialized = shared_health_guard_async().await;
    let (port, shutdown) = spawn_claim_redis_server(ClaimBehavior::Silent).await;
    let client = claim_client(port, "ferrum:replay_authority_tests:silent");
    let authority = ReplayAuthority::shared(Arc::clone(&client), RETENTION);
    let marker = domain("shared-silent").marker(&[b"c", b"proof"]);

    let started = std::time::Instant::now();
    let outcome = authority.admit(&marker).await;
    let elapsed = started.elapsed();

    assert_eq!(
        outcome,
        ReplayAdmission::AuthorityUnavailable,
        "an unanswered claim is uncertainty, never local acceptance"
    );
    assert!(
        elapsed < Duration::from_secs(15),
        "the claim must be bounded by the configured Redis timeout, took {elapsed:?}"
    );
    assert!(
        !client.is_available(),
        "an unanswered claim marks the backend unavailable so readiness can see it"
    );

    let _ = shutdown.send(());
}

/// The claim primitive publishes no backend text and no key material.
///
/// A `RedisError` renders server-supplied detail, and the key IS the replay
/// marker, so the claim path may only log a fixed classification beside the
/// already-redacted endpoint.
#[tokio::test]
async fn the_shared_claim_primitive_publishes_no_backend_or_key_material() {
    let _serialized = shared_health_guard_async().await;
    let config = RedisConfig::from_plugin_config(
        &serde_json::json!({
            "sync_mode": "redis",
            "redis_url": "redis://claim-user:claim-password@127.0.0.1:1/0",
            "redis_connect_timeout_seconds": 1,
        }),
        "ferrum:replay_authority_tests:redaction",
    )
    .expect("redis config parses")
    .expect("sync_mode redis yields a config");

    // The one endpoint rendering the claim path may log strips userinfo.
    let redacted = config.redacted_url();
    assert!(!redacted.contains("claim-user"));
    assert!(!redacted.contains("claim-password"));

    let client = Arc::new(RedisRateLimitClient::new(config, None, false, None));
    let authority = ReplayAuthority::shared(Arc::clone(&client), RETENTION);
    let marker = domain("shared-redaction").marker(&[b"consumer-1", b"nonce-1"]);

    assert_eq!(
        authority.admit(&marker).await,
        ReplayAdmission::AuthorityUnavailable
    );

    // Nothing about the authority, the marker, or the outcome renders proof
    // material: the classification set is fixed and content-free.
    assert_eq!(format!("{marker:?}"), "ReplayMarker(<digest>)");
    assert_eq!(
        format!("{authority:?}"),
        "ReplayAuthority { mode: \"shared\" }"
    );
    for outcome in [
        ReplayAdmission::Admitted,
        ReplayAdmission::Replay,
        ReplayAdmission::CapacityRefused,
        ReplayAdmission::AuthorityUnavailable,
    ] {
        let classification = outcome.classification();
        assert!(
            [
                "admitted",
                "replay",
                "capacity_refused",
                "authority_unavailable"
            ]
            .contains(&classification),
            "classification must come from the closed set: {classification}"
        );
    }
}

/// Every shared-backend uncertainty class fails closed with the same fixed
/// classification. None of them may admit, and none may fall back to a local
/// lane.
#[tokio::test]
async fn every_shared_backend_uncertainty_class_fails_closed() {
    let _serialized = shared_health_guard_async().await;

    for (label, behavior) in [
        // Authentication rejection: the client cannot enforce here at all.
        (
            "authentication",
            ClaimBehavior::Error("-NOAUTH Authentication required.\r\n"),
        ),
        (
            "wrong_credentials",
            ClaimBehavior::Error("-WRONGPASS invalid username-password pair\r\n"),
        ),
        // Capacity: a Redis that refuses the write under memory pressure or an
        // eviction policy is an unavailable authority, never an acceptance.
        (
            "capacity",
            ClaimBehavior::Error("-OOM command not allowed when used memory > 'maxmemory'.\r\n"),
        ),
        // Protocol uncertainty: the reply is not something this command can mean.
        ("protocol", ClaimBehavior::Garbage),
        // Partition: the socket dies mid-command.
        ("partition", ClaimBehavior::Disconnect),
    ] {
        let (port, shutdown) = spawn_claim_redis_server(behavior).await;
        let client = claim_client(port, "ferrum:replay_authority_tests:uncertainty");
        let authority = ReplayAuthority::shared(Arc::clone(&client), RETENTION);
        let marker = domain("shared-uncertainty").marker(&[b"c", label.as_bytes()]);

        assert_eq!(
            authority.admit(&marker).await,
            ReplayAdmission::AuthorityUnavailable,
            "{label}: uncertainty must reject the protected request"
        );
        assert!(
            !client.is_available(),
            "{label}: the outage must be visible to readiness"
        );
        assert!(
            process_lane(&authority).is_none(),
            "{label}: a shared authority must never acquire a local lane"
        );

        // Still refused on retry: nothing degrades into local acceptance.
        assert_eq!(
            authority.admit(&marker).await,
            ReplayAdmission::AuthorityUnavailable
        );

        drop(authority);
        drop(client);
        let _ = shutdown.send(());
    }
}

/// A command Redis executed whose reply was then lost must stay fail closed on
/// retry, because the marker the lost command wrote is still there.
///
/// This is the one case where "the authority is uncertain" and "the claim
/// happened" are both true. The client sees `AuthorityUnavailable` and refuses,
/// and the retry observes the existing key as a replay — so losing a reply can
/// cost the client one request, never a second acceptance.
#[tokio::test]
async fn a_claim_whose_reply_was_lost_stays_fail_closed_on_retry() {
    let _serialized = shared_health_guard_async().await;

    let (port, shutdown) = spawn_claim_redis_server(ClaimBehavior::ExecutedThenLost).await;
    let client = claim_client(port, "ferrum:replay_authority_tests:lost-reply");
    let authority = ReplayAuthority::shared(Arc::clone(&client), RETENTION);
    let marker = domain("shared-lost-reply").marker(&[b"c", b"nonce"]);

    assert_eq!(
        authority.admit(&marker).await,
        ReplayAdmission::AuthorityUnavailable,
        "an unacknowledged claim is uncertain and must refuse the request"
    );
    assert!(!client.is_available());

    // The background recovery checker reconnects and republishes availability.
    // Recovery must restore service — and must not reopen the lost claim.
    assert!(client.publish_reachable_for_test());
    assert!(client.is_available());

    assert_eq!(
        authority.admit(&marker).await,
        ReplayAdmission::Replay,
        "the marker the lost command wrote is still there, so the retry is a replay"
    );

    drop(authority);
    drop(client);
    let _ = shutdown.send(());
}
