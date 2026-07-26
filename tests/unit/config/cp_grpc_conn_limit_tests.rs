//! Unit coverage for CP gRPC pre-authentication connection admission
//! (private advisory GHSA-2xqr-7j7p-77qp).
//!
//! Two halves:
//!
//! * `EnvConfig::validate_cp_grpc_connection_limits` — safe defaults, the
//!   fail-closed bound checks, and CP-mode scoping.
//! * `ConnLimiter` behaviour that the CP listener depends on and that the
//!   admin-surface tests do not cover: bounded per-IP map cardinality under a
//!   hostile source-address sweep, and per-IP/global interaction.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use ferrum_edge::config::{EnvConfig, OperatingMode};
use ferrum_edge::util::conn_limit::{ConnLimiter, ConnRejectReason, MAX_CONN_LIMIT};

fn cp_config(max_connections: usize, max_connections_per_ip: usize) -> EnvConfig {
    EnvConfig {
        mode: OperatingMode::ControlPlane,
        cp_grpc_max_connections: max_connections,
        cp_grpc_max_connections_per_ip: max_connections_per_ip,
        ..EnvConfig::default()
    }
}

fn ipv4(n: u32) -> IpAddr {
    IpAddr::V4(Ipv4Addr::from(n))
}

#[test]
fn defaults_are_bounded_and_consistent() {
    let defaults = EnvConfig::default();
    assert_eq!(
        defaults.cp_grpc_max_connections, 1024,
        "the CP gRPC listener must ship with a finite default cap"
    );
    assert_eq!(defaults.cp_grpc_max_connections_per_ip, 64);
    assert!(
        defaults.cp_grpc_max_connections_per_ip < defaults.cp_grpc_max_connections,
        "the default per-IP share must be reachable within the default global cap"
    );

    // The shipped defaults validate in CP mode.
    let cp = EnvConfig {
        mode: OperatingMode::ControlPlane,
        ..defaults
    };
    cp.validate_cp_grpc_connection_limits()
        .expect("default CP limits are valid");
}

#[test]
fn per_ip_cap_above_global_cap_is_refused() {
    let error = cp_config(64, 128)
        .validate_cp_grpc_connection_limits()
        .expect_err("an unreachable per-IP cap is a misconfiguration");
    assert!(
        error.contains("FERRUM_CP_GRPC_MAX_CONNECTIONS_PER_IP"),
        "error should name the offending variable: {error}"
    );
}

#[test]
fn per_ip_cap_equal_to_global_cap_is_allowed() {
    cp_config(64, 64)
        .validate_cp_grpc_connection_limits()
        .expect("an exactly-reachable per-IP cap is valid");
}

#[test]
fn disabled_caps_validate() {
    // 0 = unlimited on both knobs is a deliberate operator opt-out, and a
    // per-IP cap alongside an unlimited global cap is a legitimate posture.
    cp_config(0, 0)
        .validate_cp_grpc_connection_limits()
        .expect("both disabled");
    cp_config(0, 32)
        .validate_cp_grpc_connection_limits()
        .expect("per-IP only");
    cp_config(32, 0)
        .validate_cp_grpc_connection_limits()
        .expect("global only");
}

#[test]
fn out_of_range_caps_are_refused_rather_than_silently_clamped() {
    let error = cp_config(MAX_CONN_LIMIT + 1, 0)
        .validate_cp_grpc_connection_limits()
        .expect_err("global cap beyond the semaphore ceiling");
    assert!(error.contains("FERRUM_CP_GRPC_MAX_CONNECTIONS"), "{error}");

    let error = cp_config(0, MAX_CONN_LIMIT + 1)
        .validate_cp_grpc_connection_limits()
        .expect_err("per-IP cap beyond the semaphore ceiling");
    assert!(
        error.contains("FERRUM_CP_GRPC_MAX_CONNECTIONS_PER_IP"),
        "{error}"
    );
}

#[test]
fn non_cp_modes_are_not_gated() {
    // Only CP mode builds the limiter; a stray variable elsewhere must not
    // fail an unrelated gateway's startup.
    let database = EnvConfig {
        mode: OperatingMode::Database,
        ..cp_config(64, 128)
    };
    database
        .validate_cp_grpc_connection_limits()
        .expect("database mode is unaffected");
}

#[test]
fn hostile_source_cardinality_stays_bounded_by_the_global_cap() {
    // A client cycling source addresses must not grow the per-IP map: entries
    // exist only while a permit is live and are evicted at zero.
    let limiter = Arc::new(ConnLimiter::new(8, 2));

    let mut held = Vec::new();
    let mut rejected = 0u32;
    for n in 0..4096u32 {
        match limiter.try_acquire(ipv4(0x0a00_0000 + n)) {
            Ok(permit) => held.push(permit),
            Err(reason) => {
                assert_eq!(reason, ConnRejectReason::MaxConnections);
                rejected += 1;
            }
        }
    }

    assert_eq!(held.len(), 8, "global cap admits exactly 8");
    assert_eq!(rejected, 4096 - 8);
    assert!(
        limiter.tracked_source_ips() <= 8,
        "per-IP map must never exceed the global cap, saw {}",
        limiter.tracked_source_ips()
    );
    assert_eq!(limiter.snapshot().active_connections, 8);

    held.clear();
    assert_eq!(limiter.snapshot().active_connections, 0);
    assert_eq!(
        limiter.tracked_source_ips(),
        0,
        "every per-IP entry is evicted once its permits release"
    );
}

#[test]
fn one_source_cannot_consume_the_global_budget() {
    // The advisory's core per-IP requirement: a single host is capped well
    // below the global pool, leaving room for legitimate peers.
    let limiter = Arc::new(ConnLimiter::new(16, 4));

    let mut attacker = Vec::new();
    for _ in 0..4 {
        attacker.push(
            limiter
                .try_acquire(ipv4(0xc000_0201))
                .expect("attacker within its share"),
        );
    }
    let reason = limiter
        .try_acquire(ipv4(0xc000_0201))
        .err()
        .expect("attacker beyond its per-IP share");
    assert_eq!(reason, ConnRejectReason::MaxConnectionsPerIp);

    // 12 global slots remain for everyone else.
    let mut others = Vec::new();
    for n in 0..12u32 {
        others.push(
            limiter
                .try_acquire(ipv4(0x0a00_0100 + n))
                .expect("legitimate peer admitted"),
        );
    }
    assert_eq!(limiter.snapshot().active_connections, 16);

    let snapshot = limiter.snapshot();
    assert_eq!(snapshot.rejected_max_connections_per_ip, 1);
    assert_eq!(snapshot.rejected_total(), 1);

    // Releasing one attacker slot lets a legitimate peer in immediately.
    attacker.pop();
    limiter
        .try_acquire(ipv4(0x0a00_0200))
        .expect("permit released by drop is reusable");
}

#[test]
fn ipv4_and_ipv6_sources_are_accounted_separately() {
    let limiter = Arc::new(ConnLimiter::new(0, 1));
    let _v4 = limiter
        .try_acquire(IpAddr::V4(Ipv4Addr::LOCALHOST))
        .expect("v4 admitted");
    let _v6 = limiter
        .try_acquire(IpAddr::V6(Ipv6Addr::LOCALHOST))
        .expect("v6 is a distinct source");
    assert!(
        limiter
            .try_acquire(IpAddr::V4(Ipv4Addr::LOCALHOST))
            .is_err(),
        "v4 source is at its per-IP cap"
    );
    assert_eq!(limiter.tracked_source_ips(), 2);
}
